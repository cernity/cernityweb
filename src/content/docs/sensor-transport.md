---
title: "How data gets off the sensor"
nav: "Sensor → Cernity transport"
order: 2.1
---

# How data gets off the sensor

**Fluent Bit is the missing connection between Suricata and central Cernity.** It reads local files on the sensor and publishes each parsed event to Redpanda on the central host.

Suricata does not need the central broker password. Fluent Bit does. Your SIEM credentials belong on the central forwarder, not on the sensor.

## The concrete example

These are illustrative private addresses, not addresses to copy into your own installation:

| Host | Example address | What runs there |
|---|---|---|
| Sensor management interface | `192.168.50.20` | Suricata plus Fluent Bit |
| Central Cernity host | `192.168.50.30` | Redpanda, detectors, finding-service, findings-forwarder |
| Your SIEM | Your own ingestion endpoint | A collector or API that accepts findings |

On this sensor, the shipper's `REDPANDA_BOOTSTRAP` is `192.168.50.30:19092`. Inside the central Docker network, the detectors use `redpanda:9092`. These are two listeners on the same broker.

A remote sensor cannot normally resolve the Docker service name `redpanda`. `127.0.0.1` on the sensor refers to the sensor, not the central machine.

## The files and mounts must agree

```text
Sensor host path                    Inside Fluent Bit container
/var/log/suricata/              →    /var/log/suricata/   (read-only)
  eve-alerts.json                       eve-alerts.json
  eve-nsm.json                          eve-nsm.json

/etc/cernity/ca.crt             →    /certs/ca.crt        (read-only)
Docker named state volume      →    /var/lib/cernity/    (read/write)
```

`SURICATA_LOG_DIR` is the host directory to mount. `SURICATA_EVE_ALERTS` and `SURICATA_EVE_NSM` are paths **inside the container**. If the host stores logs under `/srv/suricata`, set `SURICATA_LOG_DIR=/srv/suricata`, while retaining the container paths shown above unless you intentionally change the mount.

The shipper needs read access to the directory and files. An appliance-managed Suricata or remote log mount may require a different supported installation mechanism; do not assume Docker can be installed on every firewall.

## What happens to each line

1. Suricata appends a JSON object to an EVE file.
2. Fluent Bit's `tail` input reads it using the `eve_json` parser.
3. The Lua filter stamps trusted configured sensor identity, selects `_topic`, and sets `_pkey` from `src_ip` when available.
4. The Kafka output connects to the broker and publishes the event.
5. A central consumer reads it from its topic and advances its consumer offset after its processing policy allows.

The two tail inputs store read positions in SQLite databases on the named state volume. This is a record of where file reading reached, not an unlimited durable copy of every undelivered event.

The supplied tail configuration sets `Read_from_Head false`. With no saved offset, existing file contents are not a reliable installation test: generate fresh observed traffic after the shipper starts. Do not delete the offset database to troubleshoot casually; doing so changes replay behavior.

## The network connection and trust

| Item | What it does | Where it belongs |
|---|---|---|
| `CERNITY_ADVERTISE_HOST` | Address the broker gives clients after the initial connection. It must be reachable from sensors and match the certificate. | Central `.env` |
| `REDPANDA_BOOTSTRAP` | Initial broker address. | Remote sensor: central address and port 19092; central services: internal broker address |
| `CERNITY_BUS_USER`, `CERNITY_BUS_PASSWORD` | Sensor's SCRAM authentication identity. | Sensor and central broker bootstrap configuration |
| `CERNITY_BUS_CA` | Host path to the public CA certificate to mount. | Sensor environment file |
| `CERNITY_BUS_TLS_CA` | Container path used by Fluent Bit; supplied Compose sets `/certs/ca.crt`. | Container configuration |
| Central/admin credentials | Privileged pipeline and bootstrap access. | Central host only |

TLS protects the remote connection and verifies the broker. SCRAM authenticates the client. ACLs limit what that client can do. The supplied sensor identity can produce telemetry to `suricata.*`; it is not a general-purpose central consumer credential.

The normal telemetry path needs outbound TCP 19092 from sensor to central, with return traffic permitted. It does not require central-to-sensor SSH or an inbound collector port on the sensor. Optional packet capture has additional broker and object-store requirements.

## Set a unique sensor identity explicitly

The reviewed `route.lua` reads `NDR_TENANT` and `NDR_SENSOR`, but the reviewed sensor Compose file does not pass them into Fluent Bit. Putting those names in `.env` alone is insufficient. The [sensor installation guide](/docs/deploy-sensor/) supplies a small Compose override that passes them through.

A correct display label does not itself prove tenant isolation. The shipped broker ACL is a shared telemetry prefix; assess separate credentials, topic namespaces, and consumer scoping before deploying multiple security boundaries.

## Find the broken hop

| Symptom | First check | What a successful check actually proves |
|---|---|---|
| EVE files are empty | Capture interface, mirrored traffic, logger configuration, service logs. | The sensor is producing observations. |
| Files grow but shipper reads nothing | Mounted host directory, container filenames, read permissions, tail offsets. | Fluent Bit can see and follow the intended files. |
| Connection refused or timeout | Routing and firewall to the central advertised address on 19092. | TCP reachability only. |
| Certificate failure | Correct CA file, certificate name/address, readable mount. | Broker identity can be validated; not yet topic access. |
| Authentication failure | SCRAM mechanism, sensor username and password. | Client authentication works; not necessarily ACL authorization. |
| Authorization failure | Topic name and telemetry-prefix permissions. | The principal can publish to that topic. |
| Broker has records but no findings | Event types, expected fields, detector state, thresholds, suppression. | Telemetry delivery does not imply every event should become a finding. |
| File sink has findings but SIEM does not | Forwarder adapter, credentials, parser, failed-delivery queue. | The detection path and SIEM delivery path are separate. |

On the sensor, inspect `docker logs --tail 100 cernity-fluent-bit`. On central, inspect the relevant detector and forwarder logs. Do not publish credentials while sharing diagnostic output.

## Understand interruption and recovery

The broker's persistent volume retains broker data. The shipper's state volume retains file offsets. Suricata log rotation, Fluent Bit buffering, broker retention, detector state, and SIEM delivery retry each have independent limits.

The reviewed Fluent Bit file does not configure an explicit disk-backed output buffer. Do not advertise lossless delivery through arbitrary outages based solely on saved tail offsets. Validate outage behavior and log retention for your deployment.

Implementation: [Fluent Bit configuration](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/deploy/fluent-bit/fluent-bit.conf), [sensor Compose](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/deploy/sensor/docker-compose.yml), and the [Fluent Bit tail reference](https://docs.fluentbit.io/manual/data-pipeline/inputs/tail).
