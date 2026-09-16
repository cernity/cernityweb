---
title: "What Cernity adds, and where its boundaries are"
nav: "Coverage & boundaries"
order: 3
---

# What Cernity adds, and where its boundaries are

Cernity is a central analytics and finding-delivery layer built around Suricata telemetry. Its source includes behavioral detectors, signature promotion, finding lifecycle, optional enrichment, and SIEM adapters. Which capabilities work in your deployment depends on the collected fields, running services, configuration, and delivery path.

## What Suricata already provides

Suricata tracks state, parses protocols, applies signatures and other rule conditions, and emits useful telemetry. It can provide meaningful classifications, priorities, connection metadata, and flow correlation identifiers. It is incorrect to describe it as having no state or producing only unclassified packets.

Its saved baseline records in this website are raw EVE documents ingested into a test SIEM. That comparison does not include every analytic a production SIEM could run over those records.

## What the saved evidence demonstrates

| Function | Observed example | Qualification |
|---|---|---|
| Cross-flow regularity | A five-second beacon pattern over twenty connections. | Three findings were emitted as the observed window developed; this is not one universally deduplicated incident. |
| Signature consolidation | Forty-five alerts, two document revisions, one finding ID. | The signature was already a Suricata detection; enrichment timed out. |
| Internal destination aggregation | Forty-eight flows to twelve internal targets. | Label-file problems prevent an attack-recall claim. |
| Transfer aggregation | Eleven flows and 5,933,840 outgoing bytes. | An investigation lead, not proof of theft; run reconciliation was incomplete. |
| Unfavorable output | Beacon findings on a declared benign transfer. | A real false lead in that scenario, not a population false-positive rate. |

Read the [original records and case explanations](/proof/) before using these findings in product evaluation.

## Implementation is broader than the captured proof

The repository includes protocol fingerprint analysis, nDPI risk handling, DNS analysis, optional GeoIP and reputation, an optional SLIPS integration, packet forensics, file inspection, and correlation components. Source-visible functions are not interchangeable with exported successful SIEM records.

The [capability matrix](/docs/sensor-dependencies/) lists prerequisites. The [optional integration evidence](/proof/#optional-integrations) states which delivered fields were found and which remain unverified.

Core behavior is predominantly heuristic/statistical. The SLIPS overlay is an optional integration, not a guarantee that every SLIPS alert originates from a trained model. The adapter separates known lookup modules, but its label alone does not establish model provenance.

## What your existing stack still owns

- The physical or virtual traffic mirror and its coverage.
- Suricata operation, parser configuration, rules, and packet-loss monitoring.
- SIEM ingestion, retention, field parsing, analyst searches, dashboards, and case management.
- Asset ownership, identity, endpoint evidence, and the business context needed to assess intent.
- Validation of optional components, storage, delivery, and recovery in your environment.

Cernity does not make TLS contents visible without the necessary observation or decryption arrangement, prove that every absence is benign, or establish compromise from a category label.

## Source availability and deployment scope

The product documentation identifies the project as source available under PolyForm Perimeter. Review the repository's license for the applicable permissions. The architecture is self hosted; optional reputation, registration, threat-intelligence, and upstream image retrieval can require external services.

The basic central Compose uses in-memory detector state and does not deploy every optional datastore. A production architecture needs its own measured capacity, persistence, isolation, and recovery validation.

## How to evaluate it fairly

Compare identical source input with explicit rules, settings, and SIEM parsing. Count raw records, alerts, documents, revisions, and finding identities separately. Include benign controls, missing enrichment, suppression, delivery failures, and resources consumed.

The practical question is whether the added findings and context improve your analysts' decisions at an acceptable operating cost. The currently published records demonstrate mechanisms and limitations; they do not settle that question for every SOC.
