---
title: "Collect exact SIEM evidence for a comparison"
nav: "Collect SIEM evidence"
order: 10.1
---

# Collect exact SIEM evidence for a comparison

A complete demonstration must show **what the receiving SIEM actually stored**, not just what a detector function could return. Use a controlled test deployment and approved test traffic. Keep real customer traffic and credentials out of public artifacts.

The existing [record comparisons](/proof/) retain original exported document bodies. Optional integrations without captured output are explicitly marked rather than represented by invented JSON.

## Define the two paths

**A: Suricata → baseline shipper → SIEM.** Retain raw EVE events, including non-alert types. Record whether the baseline SIEM adds enrichment or analytics of its own.

**B: the same Suricata EVE → Cernity → SIEM.** Retain the final findings, every revision, and any relevant delivery failures. Use the same original traffic and rules. If replay re-anchors observations, save the mapping.

If nDPI or JA3/JA4 is enabled on the sensor, retain that same enriched EVE input for both arms. Otherwise the comparison changes sensor instrumentation as well as Cernity processing.

## Preserve the boundaries

For each scoped test, save:

1. Source EVE JSON Lines and event-type counts.
2. Raw baseline SIEM documents, with index/table and document identifiers when the platform exposes them.
3. Candidate findings where needed to diagnose suppression or lost fields.
4. Final Cernity findings and revisions before delivery.
5. Actual received Cernity SIEM documents, preserving the original field types.
6. Input and output hashes, source commit and image digests, configuration with secrets removed, and completion accounting.
7. A benign control and the expected interpretation established independently of the detector.

Do not rewrite a string-valued `entities` field into an array in the original artifact. A decoded teaching view is useful as a second representation with the transformation disclosed.

## Scope and count correctly

Count raw events by `event_type`, then count alert records separately. Count delivered documents, unique finding IDs, and revisions separately. Preserve tenant identity.

A query's first page is not a complete export. Check hit counts and pagination. In a busy SIEM, use a dedicated test index or a reliable run marker so unrelated activity cannot silently enter the totals.

Do not compare the entire baseline run with one selected Cernity finding. Label pair-level, detector-level, and full-run totals distinctly.

## Acceptance evidence for optional capabilities

| Capability | Source-side evidence | Required received-side evidence |
|---|---|---|
| nDPI | Real EVE `ndpi` metadata and its integration version. | Delivered risk finding, matched risk values, and lifecycle result. |
| JA3/JA4 | TLS event with the actual fingerprint and handshake context. | Relevant fingerprint entities or intelligence output, plus any suppression decision. |
| DNS | Query and answer records and the client identity. | DNS finding and an explicit list of what query context is retained or omitted. |
| Reverse DNS | Controlled resolver/PTR result and enabled configuration. | `intel.rdns` in the actual stored JSON. |
| GeoIP / ASN | Database identity/version and eligible address. | `geo` values in the stored record, without fabricated labels for test-only IP space. |
| Domain age | Original domain and registry response provenance. | `intel.domains` with the actual age calculation and threshold setting. |
| Fingerprint naming | Versioned local map and observed fingerprint. | `intel.fingerprints` with the actual operator-supplied label. |
| Reputation | Provider response provenance, excluding credentials. | Separate provider fields and the original lookup context. |
| SLIPS | Original SLIPS alert and module/model provenance. | Final `slips_ml` or `slips_intel` record and any correlated revision. |
| Zeek / JA4+ | Successful capture, Zeek logs, enrichment result. | Actual fields that survived the finding merge and adapter, plus working evidence references. |
| File / YARA | File hash, completeness, permitted artifact, rule version. | Final finding with the actual matched rule and evidence linkage. |
| Response | Approved playbook trigger and execution audit. | Separate proof of receiver ingestion and successful action; a finding alone is insufficient. |

## Track failures as results

A capability may be configured but produce no candidate, generate a suppressed candidate, fail enrichment, be omitted by the merge function, be dropped by a compact adapter, or fail receiving-side parsing. These are different outcomes.

For each missing field, compare source, candidate, final, emitted payload, and retrieved document. This isolates a visibility problem from an implementation or ingestion problem.

## Publication standard

Publish only reviewed test records and disclose redactions and formatting transformations. Keep stable identifiers where safe so the two arms can be linked. Describe the test scope and completion state beside the examples, not in a distant disclaimer.

Hashes identify artifacts; they do not establish that a detector was correct. A successful delivery test establishes that fields arrived; it does not establish general accuracy, throughput, or analyst benefit.
