---
title: "How Cernity works: from packet to investigation"
nav: "Architecture & data flow"
order: 2
---

# How Cernity works: from packet to investigation

**Suricata sees traffic and writes observations. A shipper sends those observations to Cernity. Cernity analyzes them and sends findings to your SIEM.** Each step is a separate service with a separate responsibility.

You do not point the SIEM at a packet capture interface. You do not need Zeek on every sensor for the core Cernity pipeline. And installing Cernity centrally does not automatically collect the remote sensor's files.

## Follow one connection through the system

```text
MONITORED NETWORK
A client connects to a server
        │ copied traffic from a TAP / SPAN / virtual mirror
        ▼
SENSOR HOST
Suricata: captures packets and writes local EVE JSON
        │ eve-alerts.json + eve-nsm.json
        ▼
Fluent Bit: tails the files, parses JSON, adds sensor identity
        │ outgoing Kafka-protocol connection
        │ SASL/SCRAM authentication + TLS, TCP 19092
        ▼
CENTRAL CERNITY HOST
Redpanda: holds events in topics for consumers
        │ flow / dns / tls / http / raw / other topics
        ▼
Detectors: compare observations and produce candidate findings
        ▼
finding-service: applies lifecycle, context, and delivery decisions
        ▼
findings-forwarder: formats and sends findings
        │ your chosen SIEM ingestion protocol
        ▼
YOUR SIEM
Stored finding documents → analyst investigation → case decision
```

The arrows from Suricata to Fluent Bit are local file reads. The next arrow is a network connection initiated by the sensor. The final arrow is initiated by Cernity. These are not one shared connection.

## 1. Packet visibility comes first

Suricata can analyze only the packets it receives. A mirror on an internet uplink can see routed egress but miss two internal machines talking through a switch. An internal fan-out detector cannot reconstruct traffic that never reached the sensor.

Encrypted traffic often still exposes addresses, ports, sizes, and some handshake metadata. It does not automatically expose HTTP paths or transferred files. TLS logging is not decryption.

A monitoring sensor typically has a capture interface for mirrored traffic and a management interface with a routable address. The management path carries telemetry to Cernity. See [sensor dependencies](/docs/sensor-dependencies/) before selecting a capture point.

## 2. Suricata creates the observations

EVE is Suricata's JSON logging format. One line can be a flow summary, an alert, a DNS transaction, or another observation. The supplied shipper reads two configured files:

- `eve-alerts.json` contains alert events.
- `eve-nsm.json` contains flow, protocol, file metadata, anomaly, and statistics events you enable.

Splitting is a convention used by the supplied configuration, not a requirement of all Suricata installations. Existing deployments may have one `eve.json`; the logger and shipper paths must agree. Merely changing a filename does not enable a protocol logger.

## 3. Fluent Bit moves the data off the sensor

Fluent Bit runs on the host with access to the Suricata log directory. It opens the EVE files read-only, follows appended lines, parses each line as JSON, and applies `route.lua`.

The routing function stamps `tenant` and `sensor_id` from configured environment variables, chooses a topic based on `event_type`, and uses the source IP as the Kafka message key when available. A **topic** is a named stream of messages. A **partition** is an ordered lane within that stream. Ordering within a partition is not global ordering across all sensors or topics.

The shipper connects to `CENTRAL_HOST:19092`. Suricata itself is not making this Kafka connection. The central host does not SSH into the sensor to pull files. The [sensor transport guide](/docs/sensor-transport/) traces the exact paths, credentials, and troubleshooting checks.

## 4. Redpanda separates collection from analysis

Redpanda is the Kafka-compatible message broker. It stores messages so producers and consumers do not have to run in lockstep. Consumers track offsets, meaning their position in each stream.

| Event type | Topic selected by the supplied shipper | Example consumer |
|---|---|---|
| `flow` | `suricata.flow.v1` | Behavioral and east-west detectors |
| `dns` | `suricata.dns.v1` | DNS and behavioral detectors |
| `tls`, `http`, `ssh` | `suricata.tls.v1`, `suricata.http.v1`, `suricata.ssh.v1` | Protocol detectors |
| `fileinfo` | `suricata.file.v1` | Optional file-threat service |
| `anomaly` | `suricata.anomaly.v1` | Anomaly detector |
| `stats` | `suricata.stats.v1` | Coverage detector |
| `alert`, `smb`, `krb5`, `dcerpc`, other unmatched types | `suricata.raw.v1` | IDS alert promotion and relevant protocol consumers |

Notice that alerts go to `suricata.raw.v1`, not an assumed `suricata.alert.v1`. The file name and the destination topic are different concepts.

## 5. Detectors ask questions across observations

A detector may ask whether one host repeatedly connects at regular intervals, whether a source reaches many internal targets, or whether multiple outgoing transfers add up to an unusual pattern. It emits a **candidate finding**, not a verdict from a human investigator.

The core services also promote existing Suricata signature alerts. That path adds lifecycle and consolidation; it must not be described as a new detection if the signature already identified the activity.

The reviewed central Compose file defaults detector state to `memory`. That state is process-local and does not survive a detector restart. Redis-backed implementations exist, but changing a variable is not a substitute for deploying Redis and passing the correct URL to every relevant service. Do not assume the basic deployment is a validated distributed cluster.

## 6. Findings have a lifecycle

`finding-service` receives candidates on `ndr.finding.candidate.v1`. Depending on the finding, it can score, suppress, finalize, or request extra evidence. Deliverable findings reach `ndr.finding.final.v1`.

A finding can be final for delivery while enrichment remains pending. A later revision may report a timeout. Neither state erases the original observation. The [signature evidence case](/proof/#signature) shows exactly this sequence.

Consolidation is scoped to finding identity and revision. A repeated behavior can still produce multiple identities or findings from different detectors, as the [beacon](/proof/#beacon) and [fan-out](/proof/#scan) examples show.

## 7. The forwarder delivers to the SIEM

The forwarder consumes final findings, excludes suppressed findings from analyst delivery, and applies the selected adapter. JSON-based sinks preserve a richer document than the compact CEF mapping. Adapters and SIEM parsers determine what your search screen exposes.

Cernity does not automatically build your SIEM dashboards, configure its index mappings, or retain every raw flow there. For a full investigation, decide where the original telemetry is retained and how analysts pivot to it. See [SIEM delivery and record formats](/docs/siem-integrations/).

## Where Zeek fits

The optional packet-forensics path is separate from normal telemetry collection. It requires capture orchestration centrally, an agent able to access the sensor's Suricata control socket and capture output, reachable object storage, and a central Zeek worker.

The intended sequence is a scoped capture request, sensor-side capture, upload, offline Zeek analysis, and an update to the finding. This is not continuous Zeek packet inspection on every sensor. It also cannot recover packets from the past unless a configured retention or buffering mechanism actually holds them.

The reviewed optional Compose wiring has unresolved secure-bus and permissions dependencies described in [sensor dependencies](/docs/sensor-dependencies/#optional-packet-forensics). Treat the overlay as a separate integration project, not a prerequisite for understanding or evaluating basic findings.

## What the basic deployment does not install

The central core includes Redpanda, the detector services, finding-service, and findings-forwarder. It does not include a SIEM UI, a deployed ClickHouse store, Redis, or the full optional forensics stack. These require additional deployment and verification.

Source availability does not make every optional capability active. A service must be running, subscribed to the appropriate input, supplied with the fields it needs, and able to deliver its output.

## Implementation references

This walkthrough was checked against Cernity revision `18174b8`. Inspect the [central Compose file](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/deploy/central/docker-compose.yml), [sensor bundle](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/deploy/sensor/docker-compose.yml), and [routing function](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/deploy/fluent-bit/route.lua). Historical proof records are from their saved runs, not a fresh benchmark of this revision.
