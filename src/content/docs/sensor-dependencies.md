---
title: "Capability dependencies: sensor, central services, and SIEM"
nav: "Capability dependencies"
order: 6.1
---

# Capability dependencies: sensor, central services, and SIEM

Use this page to answer three separate questions: **can the sensor observe it, can the central service analyze it, and does the output reach the SIEM?** A “yes” at one stage does not imply a “yes” at the next.

The matrix describes source-visible implementation at Cernity revision `18174b8`, not a claim that every optional path has a captured successful deployment. The [evidence section](/proof/#optional-integrations) distinguishes recorded delivery from implementation support.

## Core telemetry and findings

| Capability | Sensor dependency | Central dependency | What the analyst receives or must verify |
|---|---|---|---|
| Signature promotion | Working rules and `alert` EVE output. | `ids-alerts`, finding-service, forwarder. | Finding retaining signature identity where provided. See the actual [signature records](/proof/#signature). |
| Beacon / transfer analysis | Canonical `flow` records with usable connection bounds and byte counters. | Behavioral detectors and their rolling state. | Pattern measurements for a scoped lead. This does not prove intent. |
| Internal fan-out | Visibility of internal connections and flow destinations/ports. | East-west detectors and internal-network interpretation. | Aggregate counts; authentication or execution evidence may still be needed. |
| DNS tunnel / domain beacon | Visible DNS queries and, for domain-IP association, answers; compatible record format. | DNS/behavioral consumers. | A DNS lead. Raw queried names are not necessarily copied into the finding. |
| HTTP analysis | Parsed HTTP metadata. | HTTP/protocol detectors. | Relevant entities or explanation, not all raw HTTP fields. Encrypted HTTP is not automatically visible. |
| TLS client/server rarity | TLS handshake visibility plus supported JA3/JA4 or server fields. | Protocol detector state and warm-up. | Fingerprint entities on relevant findings, subject to final delivery policy. |
| Coverage degradation | `stats` events with the required capture/parser counters. | Coverage detector. | A coverage lead when supported counters satisfy its checks. Missing stats are not themselves proof of safety. |

## Optional detection and context

| Capability | What must be enabled | Configuration location | Evidence boundary |
|---|---|---|---|
| nDPI risk | Compatible sensor integration emitting the expected `ndpi` object. | Sensor build/logger integration. | Source contains a risk-consumption path; no nDPI finding was present in the reviewed saved exports. |
| Reverse DNS | Resolver access and `INTEL_RDNS=1`. | Central finding-service. | Successful PTR lookups can populate `intel.rdns`; no such delivered field was found in the saved exports. |
| Domain registration age | Domain/SNI entity, RDAP access, `INTEL_RDAP=1`. | Central finding-service. | Best-effort `intel.domains`; parser limitations and missing registry data matter. |
| GeoIP / ASN | Compatible local databases, mounts, environment variables. | Central finding-service. | `geo` for eligible global IPs only if a lookup succeeds. Private and documentation addresses are not suitable positive tests. |
| Fingerprint naming | JA3/JA4 entity and an operator-supplied map. | `INTEL_FP_MAP` plus a central file mount. | `intel.fingerprints` is your map's label, not an independently established malware identity. |
| Reputation | Credentials and network access for enabled providers. | Central finding-service. | Provider-specific fields, restricted to global IP lookups in reviewed code. |
| SLIPS | EVE bridge, compatible SLIPS runtime, its Redis, alerts file, adapter, broker authentication. | Central optional overlay. | Candidate mappings exist; no SLIPS finding was found in the saved SIEM exports. |
| File hash / YARA | Complete file metadata or accessible extracted bytes; file services and transfer path. | Sensor plus optional central forensics services. | File metadata alone is not a YARA scan or successful delivery proof. |
| Correlation | The correlation service, state/storage prerequisites, relevant findings. | Central additional deployment. | A derived correlation candidate; optional overlay startup alone does not establish SIEM delivery. |

An environment variable written in `.env` does not automatically enter every container. Confirm the service's `environment` mapping and the actual mounted files.

## Optional packet forensics

Core detection can run without Zeek or packet capture. The optional path requires:

1. A sensor able to actuate the expected Suricata capture mechanism and access its control socket.
2. Capture-agent access to its instructions, scoped broker permissions, and writeable capture storage.
3. A reachable object-store endpoint with restricted upload credentials.
4. Central capture orchestration and a Zeek worker that can authenticate and read the uploaded object.
5. A finding update that preserves usable evidence references and a SIEM adapter that transmits them.

The reviewed sensor Compose passes the same produce-only telemetry credential to capture-agent. The broker bootstrap ACL grants writes to `suricata.*`, not reads of capture instructions. The forensics overlay also omits central SASL wiring for several services, and the reviewed Zeek worker directly creates Kafka clients without the shared authentication helper. These must be resolved and tested for a secured deployment; merely enabling the profile is insufficient.

The default object-store name `minio` is a Docker service name, not a reachable remote sensor address. The overlay does not by itself publish a protected sensor-facing object-store endpoint.

**Delivery detail:** the reviewed Zeek worker builds `summary` and `iocs`, but `apply_enrichment_result` merges evidence references and status, not those full objects, into the finding. Do not promise JA4H, JA4S, JA4SSH, or all Zeek log details in SIEM findings without verifying an additional delivery path or implementation change.

## Boundaries of visibility

A mirror can omit entire VLANs or one direction of a connection. A protocol logger can be enabled while an encrypted session prevents the desired detail. A fingerprint can be absent because the handshake was missed. A detector can be subscribed while its needed fields never arrive.

Document each capability as observed and tested, configured but unverified, or unavailable in this deployment. “No findings” is not a substitute for a coverage check.

## Verify one feature from end to end

Retain one allowed test's source EVE record, broker identity, detector candidate, final finding and revision, and retrieved SIEM document. Compare field values at each hop. Record the exact build and configuration, including which optional components were enabled. Use a benign control alongside the positive test.

See [how to collect comparable SIEM evidence](/docs/evidence-capture/) for the acceptance checklist.

Implementation references: [central services](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/deploy/central/docker-compose.yml), [forensics overlay](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/deploy/overlays/forensics.yml), [Zeek worker](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/services/zeek-central/enrich.py), and [finding lifecycle](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/services/finding-service/state_machine.py).
