---
title: "Events, alerts, findings: how to read the records"
nav: "Read the records"
order: 0
---

# Events, alerts, findings: how to read the records

Start with a simple question: **does this record describe something observed, or does it make an assessment about that observation?** That distinction prevents a busy log from looking like a network full of attacks.

This guide introduces the vocabulary. Next, open the [five evidence case studies](/proof/) to read actual exported records with explanations beside them.

## The words describe different things

| Term | Plain-language meaning | What it does not establish |
|---|---|---|
| Packet | A unit of network traffic visible at the capture point. | The full conversation, a user's intent, or a threat. |
| Flow | A tracked conversation, usually identified by addresses, ports, and protocol. | A single packet, a single file, or necessarily a completed connection. |
| Event | A structured observation, such as a DNS answer, TLS handshake, flow summary, or rule match. | That someone needs to investigate it. |
| Record | One serialized entry representing an event or finding, often one JSON object. | A unique incident. Multiple records can describe the same activity. |
| Log | A collection of records. Suricata's EVE log contains several event types. | A list containing only alerts. |
| Alert | A detection engine's rule match or flagged condition. Suricata marks these `event_type: alert`. | Verified malicious intent or successful compromise. |
| Finding | Cernity's assessment of activity, with a detector, category, score, entities, and lifecycle. | An analyst-confirmed incident. |
| SIEM document | The record stored by your SIEM, possibly with ingestion fields or renamed fields. | A new detection simply because it was indexed. |
| Incident | An investigation or case defined by your organization. | Automatically the same thing as one finding or one alert. |

**Suricata is stateful.** It tracks connections and protocols and can use sophisticated rules. Cernity's role is additional central analysis across telemetry, not to give an otherwise stateless sensor its first memory.

## Read an EVE record in this order

1. **`event_type`** tells you which kind of record you have. A `flow` record and an `alert` record deserve different interpretations.
2. **Addresses and ports** identify the observed endpoints. `src_ip` is not automatically “attacker” and `dest_ip` is not automatically “victim.” Check direction and network placement.
3. **`proto` and `app_proto`**, when available, distinguish a transport such as TCP from a parsed application protocol. Port 443 alone does not prove HTTPS.
4. **The event-specific object** contains the useful detail: `flow`, `alert`, `dns`, `tls`, or `http`.
5. **Identifiers and observation bounds** let you connect this record to other evidence.

A field that is absent is not the same as a field that says `false` or zero. An absent TLS certificate may mean the handshake was not observed, not that the connection had no certificate.

## Flow fields: what actually crossed the sensor

| Field | How to interpret it |
|---|---|
| `flow_id` | Suricata's identifier for the tracked flow. Pivot within the relevant sensor and capture context; do not assume global uniqueness across all sensors and runs. |
| `community_id` | A standardized flow hash for cross-tool correlation. Matching requires compatible inputs and the same seed. NAT or a different observation point can change the tuple. |
| `flow.start`, `flow.end` | Connection bounds reported by the sensor. Use the appropriate event fields when analyzing connection spacing. |
| `flow.bytes_toserver`, `flow.bytes_toclient` | Directional counters. They are not proof of file contents or sensitive-data volume. Server direction is a flow role, not always “outside the company.” |
| `flow.pkts_toserver`, `flow.pkts_toclient` | Packet counts in each direction. Very asymmetric counts can suggest an unanswered attempt or missing visibility. |
| `flow.state` | Suricata's connection-state assessment. It does not describe user authorization. |
| `flow.reason` | Why a flow record was emitted or ended, such as shutdown. It is not a threat verdict. |
| `flow.alerted` | Whether the flow was associated with alerting. `false` does not mean the traffic was proven safe. |

For an outgoing-byte total, aggregate the relevant `event_type: flow` records once. Alert records may repeat flow counters. Adding both counts the same underlying traffic again.

## Alert fields: what matched a rule

`alert.signature` names the matched rule; `alert.signature_id` identifies it. Inspect the rule conditions, revision, and deployment context before treating its name as a conclusion.

`alert.category` is a classification label. `alert.severity` is a rule-priority value, not a measured probability. `alert.action: allowed` does not certify that the activity is benign; it says this alert's action was not blocking. Other rules or devices can still affect the traffic.

The [signature case](/proof/#signature) preserves a custom benchmark rule. It is useful for explaining consolidation but is not evidence that a normal ruleset would independently identify that test traffic.

## Cernity fields: what the detector inferred

| Field | Analyst meaning |
|---|---|
| `finding_id` | Identity used to track the finding. Group it with the tenant, not in isolation across customers. |
| `revision` | An update to that identity. Two revisions are not automatically two incidents. |
| `detector_id` | Which analytic produced the lead, such as `beacon` or `low_slow_exfil`. |
| `category` | The system's interpretation, such as `c2`, `lateral`, or `exfil`. Test this interpretation against evidence. |
| `severity` | Cernity's severity score. Its schema uses 1–10. Do not compare it numerically to Suricata's rule priority. |
| `confidence` | The emitted detector score between 0 and 1. The saved examples do not demonstrate probability calibration. |
| `entities` | Involved hosts and measurements. The exported wire value may be a JSON string requiring a second parse. |
| `mitre` | ATT&CK classification. A `T` identifier is a technique; a `TA` identifier is a tactic. Neither confirms attack success. |
| `state` | Processing lifecycle, not the analyst's case disposition. `FINAL` does not mean “confirmed malicious.” |
| `enrichment_state` | Whether extra evidence was required, pending, attached, failed, or timed out. |
| `evidence_refs` | Attached evidence references. An empty array means no references are present in this record. |

## Three clocks can appear in one investigation

Keep the original event clock, the processing clock, and the SIEM ingestion clock separate. An old capture replayed now can have old source records, re-anchored Cernity observations, and new ingestion values. A large gap between them is not automatically a long-running attack.

The evidence downloads include the saved replay offset. The [methodology](/proof/#methodology) explains how to compare those examples. In a live deployment, inspect the adapter and SIEM mapping rather than assuming every `@timestamp` means ingestion: the Cernity Elasticsearch adapter sets it from `last_seen`, falling back to `first_seen`.

## From reading to investigation

Read the [beacon case](/proof/#beacon), then answer: Which facts came from Suricata? Which pattern did Cernity calculate? What evidence would distinguish malware from a legitimate monitoring agent?

Continue with [an analyst's investigation workflow](/docs/analyst-workflow/) and [how records arrive in your SIEM](/docs/siem-integrations/).

## Sources and scope

Field definitions are grounded in the [Suricata EVE format reference](https://docs.suricata.io/en/suricata-8.0.3/output/eve/eve-json-format.html), Cernity's [finding contract](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/contracts/finding.schema.json), and its [SIEM adapters](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/services/findings-forwarder/adapters.py). The historical records can contain fields beyond the current contract; they are preserved as exported, not rewritten to fit it.
