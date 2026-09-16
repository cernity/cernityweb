# Claude handoff: complete Cernity's SIEM evidence campaign

## 1. Assignment and required outcome

Review the current implementation, correct the specific integration or field propagation defects necessary for these demonstrations, and rerun the controlled tests. Produce a reproducible evidence package showing exactly what a SOC analyst receives in the SIEM:

**Arm A: Suricata → existing baseline ingestion → SIEM.**

**Arm B: the identical Suricata observations → Cernity with the declared integrations enabled → SIEM.**

The immediate objective is to close these evidence gaps:

> The available historical exports contain no nDPI, JA3/JA4, reverse DNS, or SLIPS findings. The reviewed Zeek result merge omits detailed summaries and indicators from the final finding. The reviewed CEF mapping omits enrichment fields.

Do not treat that statement as a conclusion about a newer checkout. Revalidate each issue, record the exact product revision and deployed images, and demonstrate the actual current behavior. If a gap is already fixed, prove it through the complete delivery path. If it remains, make the smallest necessary implementation correction in an isolated development/test environment and show its effect.

The deliverable is actual received evidence plus an explanation that a person with basic Suricata, Zeek, and SIEM knowledge can follow. A feature inventory, source walkthrough, unit test result, screenshot alone, generated example, or sender log is insufficient.

Carry the work through implementation, deployment verification, record retrieval, integrity checks, and the final handoff. Do not stop after producing a plan or a list of suggested commands. If an external dependency prevents a scenario, finish the independent work and identify precisely what is still required. Never turn a blocked or failed case into a passing demonstration.

## 2. Workspace and starting evidence

These paths were present when this handoff was prepared:

| Resource | Location |
|---|---|
| Product repository | `/Users/carterfields/Documents/git/cernityndr` |
| Website repository | `/Users/carterfields/Documents/git/cernityweb` |
| Historical evidence | `/Users/carterfields/Documents/git/cernity-forge/evidence/siem-comparison-results` |
| Historical raw bundles | `pipeline-evidence/` inside that evidence directory |
| Existing test harness | `/Users/carterfields/Documents/git/cernity-forge/workbench/benchmarks` |
| Website selected records | `cernityweb/public/evidence/` |
| Website record importer | `cernityweb/scripts/import-evidence.py` |
| Website validation | `cernityweb/scripts/check-site.py` |
| Website case explanations | `cernityweb/src/content/proof/cases.ts` |
| Website integration audit | `cernityweb/src/content/proof/integrations.ts` |
| Website maintenance notes | `cernityweb/docs/content-validation.md` |
| Evidence collection guide | `cernityweb/src/content/docs/evidence-capture.md` |

The product revision inspected for the website was:

```text
18174b8c2d8e29e2312d4f27064a2baa3456d9e3
```

The prior inventory covered 15 saved bundles. None of their `cernity-findings.jsonl` exports contained a nonempty top-level `geo`, `intel`, `iocs`, or `summary` object. No `ndpi_risk`, fingerprint-rarity, `slips_ml`, or `slips_intel` findings appeared in that inventory. DNS and domain-beacon findings exist in older bundles, but those lack the newer export manifests and qualified completion metadata.

This is a scoped observation about those artifacts, not a claim that Cernity can never produce these fields. Rebuild the inventory if additional evidence is available.

Preserve historical artifacts unchanged. Place new runs in a separate campaign directory. Inspect each repository's instructions and working tree before editing; the website already has substantial uncommitted work that must be preserved. Do not overwrite unrelated changes or publish/deploy the website as part of this evidence task.

## 3. Establish the test environment before execution

Discover the existing authorized test deployment and receiving SIEM. If the necessary information cannot be obtained from repository configuration or the connected environment, ask once for the missing SIEM endpoint, destination index/table, approved test hosts, and access mechanism. Do not ask the user to paste secrets into the report or public artifacts.

Record:

1. Sensor host and capture point, management route, Suricata version/build options, ruleset identity, parser settings, EVE outputs, and plugin versions.
2. Cernity source commit, clean or dirty state, patch digest if dirty, container image IDs/digests, Compose or orchestration configuration, and active profiles.
3. Broker listeners, authentication method, topic names, partitions, ACL scope, consumer groups, and state backend.
4. nDPI integration source/version, fingerprint packages, Zeek packages/scripts, SLIPS image and enabled modules/model artifacts.
5. Optional data sources: GeoIP/ASN database versions, fingerprint map version, threat intelligence snapshots, configured resolver, and reputation/RDAP access.
6. The receiving SIEM product/version, adapter, index or table, parser, ingest transformations, and any existing SIEM analytics/enrichment in the baseline.
7. Resource allocation, retention, queues, and the intended replay/capture mechanism.

Run tests only in the authorized isolated lab or test destinations. Use synthetic or approved traffic and controlled services. Do not contact live malware infrastructure, scan unrelated systems, execute real malware, or change production detection and collection settings to make a demonstration pass.

Pin the actual tested artifacts. An image tag such as `latest` is not enough to reproduce the run.

## 4. Revalidate and address the known implementation boundaries

Inspect implementation behavior rather than trusting comments. Preserve a failing observation or focused regression test before making a correction.

| Boundary to inspect | Starting implementation | Required assessment |
|---|---|---|
| Sensor identity | `deploy/fluent-bit/route.lua`, `deploy/sensor/docker-compose.yml` | Confirm `NDR_TENANT` and `NDR_SENSOR` reach the shipper container and the received records retain correct identity. |
| Replay authentication | `tools/eve-feeder/feeder.py`, `deploy/quickstart/docker-compose.yml` | Confirm the feeder authenticates to the actual secured listener and that it does not masquerade as a live sensor transport test. |
| SLIPS authentication | `deploy/overlays/slips.yml`, `services/eve-bridge/app.py`, `services/slips-adapter/app.py` | Confirm the bridge consumes and adapter publishes with appropriate central credentials and required topic permissions. |
| Capture permissions | Sensor capture profile and broker bootstrap ACLs | A produce-only telemetry credential cannot automatically consume capture instructions. Define narrowly scoped capture permissions; do not solve this by handing sensors a central superuser credential. |
| Zeek broker connection | `services/zeek-central/enrich.py` | The reviewed worker constructs direct Kafka clients without shared auth wiring. Verify and correct the secured connection path if still necessary. |
| Remote object storage | Forensics overlay and capture-agent configuration | Verify an actual sensor-reachable endpoint, TLS/trust where configured, least-privilege upload access, central read access, and evidence retrieval. A Docker service name is not a remote endpoint. |
| Zeek field propagation | `services/finding-service/state_machine.py: apply_enrichment_result` | The reviewed function copies status and evidence references, not the worker's `summary` or `iocs`. Trace all downstream boundaries before selecting a fix. |
| Schema and persistence | Finding contract, finding-service persistence/recovery, adapters, SIEM mappings | New enrichment fields must survive validation, serialization, persistence, restart recovery, and delivery. Do not fix only the in-memory merge. |
| CEF context loss | `services/findings-forwarder/cef.py` and receiving parser | Document every retained and omitted field. Its reviewed IP extraction expects `src`/`dst`, while SLIPS uses `attacker`/`victim`. |
| Optional variable pass-through | Central and overlay Compose service environments | Verify actual container settings and mounts. An entry in `.env` is not proof that a service receives it. |
| State assumptions | Detector state and optional Redis/ClickHouse configuration | Core Compose used memory-backed detector state. Do not claim persistent or distributed operation unless actually configured and tested. |

### Requirements for a Zeek propagation correction

Choose and document a stable, bounded schema for the useful Zeek summary and indicators. Preserve provenance, finding identity, tenant, revision, source evidence references, and the originating worker result. Do not overwrite unrelated prior enrichment or accept arbitrary unbounded result objects.

Test valid results, missing fields, failed results, duplicate results, late results, tenant isolation, oversized content, and restart recovery as applicable. Any truncation must be explicit and the original evidence must remain retrievable through authorized access. Verify that failed enrichment does not erase or indefinitely withhold an otherwise deliverable finding.

### Requirements for CEF

CEF is a compact transport, not inherently a full-fidelity JSON container. Do not promise that arbitrary nested JSON can be copied losslessly into it.

Produce an explicit field mapping that works with the actual receiving parser and its size limits. For supported contextual fields, test escaping, Unicode, backslashes, separators, equals signs, newlines, role mapping, message framing, and truncation behavior. Preserve existing mappings unless a documented migration is necessary.

If full context needs a companion JSON event or an authenticated evidence link, implement and test the chosen linkage rather than claiming CEF itself contains the omitted fields. Show exactly what the analyst sees in each record and how they reach the richer data. A documented remaining CEF limitation is preferable to an unsupported lossless-delivery claim.

## 5. Fair comparison design

Use identical observed input for both arms. When a sensor plugin or fingerprint logger changes EVE, that enriched EVE must be available to the baseline arm too. Do not compare a poorly configured baseline with a richly instrumented Cernity arm and attribute the sensor difference to Cernity.

Maintain a separate ablation where useful:

| Run | Purpose |
|---|---|
| A | Raw Suricata output through the declared baseline SIEM pipeline. |
| B0 | Same input through core Cernity without the optional capability. |
| B1 | Same input through Cernity with one optional capability enabled. |
| B2 | Same input through the declared combined integration configuration. |

Use B0/B1 to establish what the add-on changed and B2 to validate coexistence. Do not require every scenario to have an unnecessary fourth arm, but disclose exactly which contrasts were run.

For stateful detectors, control warm-up, retained state, replay ordering, concurrency, topic offsets, and input boundaries. Avoid cross-scenario state contamination. A benign and a positive stimulus should not share an aggregate key unless their interaction is the declared test.

If timestamps are shifted, save the exact transformation and replay offset. Use original event fields for behavioral calculations. Do not use ingestion timestamps as connection timing or silently rewrite historical source events.

Count these independently:

1. Source packets where a packet capture is used.
2. Source events by `event_type`.
3. Baseline SIEM documents and baseline alert records.
4. Candidate findings, including suppressed candidates.
5. Final finding documents.
6. Unique tenant/finding identities and their revisions.
7. Actual received documents per destination.
8. Failed, retried, dead-lettered, withheld, duplicated, and unresolved items.

Show pair-level, scenario-level, and complete-run totals distinctly. Do not call telemetry rows alerts, finding revisions separate incidents, or repeated detector IDs separate attacks.

## 6. Required scenario matrix

For every capability below, include a positive feature exercise, a realistic benign control, and an unavailable/failure case where applicable. Expected outcomes must be declared before examining detector results.

A positive feature exercise is not necessarily a malicious incident. Distinguish a transport/mapping success from a correctly detected attack, especially when using a controlled test rule or indicator.

### 6.1 nDPI risk and application metadata

1. Use a verified compatible Suricata/nDPI integration. Record its exact version, build, configuration, and actual emitted field shape.
2. Generate approved traffic that causes a known supported nDPI observation or risk indication. Include authorized traffic that can also carry a risk indication.
3. Preserve the complete source EVE record with the `ndpi` object and the exact baseline SIEM record retaining it.
4. Trace the actual matched risk values through the Cernity candidate, lifecycle decision, final revision, adapter, and retrieved SIEM document.
5. Explain which nDPI fields are carried forward, summarized, omitted, or available only in raw telemetry.
6. Test the integration absent and the expected input fields absent. Do not inject a fabricated `ndpi` object and call that a sensor-plugin demonstration.
7. Do not force a standalone risk flag into confirmed malware or successful packet forensics. Preserve the actual policy decision.

Required output: actual paired records, nDPI provenance, matched-risk explanation, delivery/suppression accounting, and benign-control outcome.

### 6.2 JA3 and JA4 client fingerprints

1. Capture real TLS handshakes with supported fingerprint generation. Save the packet input where permitted, full TLS EVE output, and build configuration.
2. Exercise JA3-only, JA4-available, and missing-handshake/fingerprint cases. Confirm whether JA4 is preferred and whether the JA3 fallback actually works.
3. Establish the rarity baseline/warm-up explicitly. Use a controlled client variation and an expected/common client without fabricating a known-malware attribution.
4. Preserve the raw fingerprint, its field type, any SNI and Community ID, candidate measurements, final decision, and stored SIEM body.
5. If the detector is named `ja4_rarity` but used JA3, make that distinction visible.
6. Record suppressed output as suppressed; do not secretly lower policy thresholds until a desired record appears. If a test-specific threshold is necessary, disclose it and also report the production-default outcome.
7. Verify that a high rarity score does not get described as calibrated compromise probability.

Required output: exact paired raw TLS and received Cernity records, warm-up evidence, fingerprint provenance, field retention map, and default versus test-specific configuration if different.

### 6.3 Server fingerprints and JA4+

Test the server fingerprints that the deployed tools genuinely support: JA3S, JA4S, and relevant Zeek-derived JA4H, JA4X, and JA4SSH fields. Do not claim stock Suricata emits every variant. A consumer accepting a JARM field does not itself produce JARM; identify and validate any real collector before claiming that capability.

For each variant, identify the generating component, original log and field, calculation/package version, central representation, final finding path, and actual received SIEM field. Record unavailable variants individually rather than declaring the entire suite supported from one client JA4 value.

Required output: one actual source-to-SIEM field lineage per demonstrated variant and explicit limitations for the others.

### 6.4 DNS tunnel and domain-level beacon

1. Rerun the older DNS and FQDN demonstrations with current export manifests, valid labels, replay mapping, and qualified completion.
2. Include normal DNS/CDN activity, approved long labels or telemetry names, an intentionally unusual controlled query pattern, and domain-to-address rotation where applicable.
3. Preserve requests and answers, client versus resolver versus authoritative-domain roles, query names, returned addresses, response codes, and source identifiers.
4. Show which of those fields actually reach the finding. If the finding contains only a client address and classification, expose that omission rather than filling the missing fields by hand.
5. Use authorized controlled domains and services. Do not send encoded sensitive data to external resolvers.

Required output: exact baseline DNS records, resulting received findings, reproducible domain/IP association, benign controls, and a clear distinction between passive DNS and reverse DNS.

### 6.5 Reverse DNS / PTR

1. Use a controlled resolver and test address with a known PTR result.
2. Verify `INTEL_RDNS` is enabled in the running service, not only in an environment template.
3. Exercise a successful PTR, no PTR/NXDOMAIN, resolver failure, and repeated lookup/cache behavior. Include internal address behavior if supported by the current implementation.
4. Save the source finding before enrichment, lookup provenance, final enriched revision, and retrieved SIEM document containing the actual `intel.rdns` value.
5. Preserve resolver and privacy context without exposing sensitive internal names in public artifacts.
6. Test actual resolver failure behavior; do not assume an HTTP timeout setting also bounds socket-based DNS resolution.

Required output: original baseline IP-bearing event beside the actual Cernity SIEM record, plus lookup provenance and the no-result/failure behavior. A manually performed lookup pasted into an old finding is not evidence.

### 6.6 GeoIP, ASN, domain age, fingerprint naming, and reputation

Exercise each as a separately attributable enrichment:

| Integration | Required provenance and output |
|---|---|
| GeoIP/ASN | Database version/hash, eligible global address, actual `geo` fields in the received document, and missing-database/lookup controls. |
| RDAP/domain age | Original domain/SNI, registry response provenance, parsed registration data, actual `intel.domains`, and missing-date/multi-label-suffix controls. |
| JA3/JA4 naming | Versioned operator map, observed fingerprint, actual `intel.fingerprints`, and an unmapped/common fingerprint control. |
| GreyNoise | Provider-backed result, provider identity, actual `intel.reputation`, and failure/unknown behavior. |
| VirusTotal | Provider-backed result, actual `intel.virustotal`, and missing/failed response behavior. |

Do not assign fake geographic or reputation results to private or documentation-only addresses. A fixture-backed adapter test is permitted as an additional engineering test, but label it clearly and do not use it as the live provider demonstration.

Use only authorized API access. If a key/database/account is unavailable, state which case is blocked and supply the exact prerequisite. Do not advertise invented provider results or current subscription terms.

The reviewed RDAP helper used the last two domain labels rather than a public-suffix-aware calculation. Revalidate and test this boundary. A fingerprint naming map is an operator assertion, not independent malware attribution.

### 6.7 SLIPS

1. Run the actual compatible SLIPS runtime with declared image digest, module configuration, Redis, bridge inputs, output path, and broker authentication.
2. Confirm real EVE reaches SLIPS and that newly generated alerts reach the adapter. Existing pre-start alert-file contents may be skipped by tailing behavior.
3. Exercise a genuine behavioral/model-originated result, a threat-intelligence lookup result, and a benign control. Retain the actual originating module and, for a model claim, the model identity/version and evidence that it executed.
4. Preserve the original SLIPS alert, mapped candidate, lifecycle decision, final finding, and stored SIEM document.
5. Inspect `slips_ml` versus `slips_intel` classification. The reviewed mapper defaults unknown/missing module names to `slips_ml`; do not call unknown provenance proof of machine learning. Correct misleading classification if necessary and test the fix.
6. Verify `attacker`/`victim` entity roles through JSON and the actual CEF parser, not just the adapter's Python return value.
7. If corroboration is claimed, retain the actual contributing heuristic and SLIPS findings, correlation output, and received record. Explain whether the evidence sources are independent; two copies of one blocklist result are not independent confirmation.
8. Measure startup/resource behavior rather than repeating a generic capacity estimate.

Required output: actual SLIPS alert-to-SIEM lineage, module/model provenance, benign and lookup controls, and an explicit account of mapped versus retained fields.

### 6.8 Zeek packet enrichment and final-finding propagation

1. Reproduce and document the current behavior before a fix: compare the worker's result to the final finding and received SIEM body.
2. Verify that a real capture is created by the claimed path and is readable centrally. A manually supplied PCAP tests offline analysis but not sensor capture orchestration; label these separately.
3. Run Zeek over the capture with pinned packages and preserve original logs: relevant connection, TLS, certificate, HTTP, SSH, file, SMB, and Kerberos output as actually available.
4. Preserve the complete enrichment request, worker result, summary, indicators, evidence references, and finding revisions.
5. Correct field propagation and all affected contract/persistence/adapter paths if still needed.
6. Retrieve the revised document from the SIEM and show exactly which summary and indicator fields arrived.
7. Test successful enrichment, empty/invalid/unavailable capture, permission failure, worker failure, delayed result, duplicate result, timeout, and recovery/restart.
8. Verify evidence references are usable by the intended analyst access path. An object URI is not necessarily an accessible user-facing link.
9. Do not claim capture can recover arbitrary past packets. Show the actual configured buffer/retention capability and what happens when the relevant bytes are unavailable.

Required output: before-and-after original SIEM records, original Zeek logs and worker results, field-by-field propagation diff, revision history, and explicit failed-case records.

### 6.9 JSON versus CEF, through the actual receiver

Deliver the same finalized findings to a full JSON sink and the configured CEF receiver, using actual independent sink receipts.

For each sink preserve:

1. The final finding before adapter formatting.
2. The exact application payload generated by the adapter.
3. The message captured at a controlled receiving collector before parsing, where supported.
4. The retrieved raw and parsed SIEM record after ingestion.
5. Receiver/parser configuration and version.
6. A machine-readable field retention/loss comparison.

Include reverse DNS, fingerprints, reputation, Zeek context, evidence references, tenant, finding ID, revision, lifecycle, and SLIPS roles in this comparison when those features are demonstrated.

If fields remain intentionally absent from CEF, list them explicitly and demonstrate the chosen companion JSON/evidence-access path. Exercise parser rejection, oversized values, escape characters, multibyte text, delivery failure, retry, and recovery. Do not declare success from a socket write or HTTP status alone.

Required output: exact JSON body, exact CEF text including framing where captured, raw received SIEM events, parsed fields, and an explicit supported mapping contract.

### 6.10 Additional optional capabilities

Inventory the actual available overlays and classify every advertised capability. Cover file hashes/YARA, threat intelligence, coverage degradation, assets, reconstruction, correlation, and response where implemented and deployable.

Use benign approved test artifacts for file inspection and controlled indicators for intelligence tests. Retain completeness/gap status, hashes, rule versions, match output, and received findings. A partial-file hash is not proof of a complete malware artifact.

Storage, reconstruction, and asset services may expose separate investigation results rather than embedding them in findings. Demonstrate the actual SOC access/linkage path if claimed. Do not invent a finding attachment.

A response finding does not prove a response action occurred. If testing response, use an approved harmless test action and preserve its independent execution audit.

## 7. Capture every relevant boundary

For every positive and negative scenario, collect enough information to identify the first point where a field disappears:

```text
Observed packets or declared fixture input
    → original Suricata EVE
    → shipped broker records
    → detector candidate or explicit no-candidate result
    → enrichment request/result where applicable
    → final finding, suppression, or terminal failure
    → adapter payload
    → collector receipt where available
    → stored SIEM raw document
    → parsed SIEM fields and analyst query
```

Distinguish a real sensor observation from synthetic EVE injection, a candidate from a delivered finding, and a generated adapter payload from a retrieved SIEM document. Label each artifact's evidence class.

Preserve original field types. If `entities` is an escaped JSON string, keep that string in the original. A decoded view must be a separate explicitly transformed file. Preserve large numeric IDs without floating-point precision loss.

Retain the receiving SIEM's document IDs, index/table, raw payload, query range, pagination details, total-hit count, and extraction command. For Elasticsearch/OpenSearch, preserve `_index`, `_id`, and `_source` when returned. For another platform, preserve its actual equivalents; do not fabricate Elasticsearch wrappers.

Do not stop after the first search page. Prove that retrieval is complete for the declared scope, or report the scope as partial.

## 8. Completion and reconciliation

A run is not complete merely because its feeder exited or its input topic has no lag. Define completion checks appropriate to the actual harness and retain evidence for them:

1. Source production ended with a documented expected input count and identity inventory.
2. Both arms consumed the declared source scope without unaccounted loss or duplication.
3. Required consumer groups reached their target offsets.
4. Candidate/lifecycle work reached final, suppressed, failed, or another explicitly documented terminal disposition.
5. Pending enrichment was settled, failed, or timed out with an explicit outcome.
6. Every deliverable tenant/finding/revision had a per-sink disposition and corresponding receiver evidence when marked delivered.
7. SIEM retrieval completed and the export was frozen before hashing.

Reconcile canonical event identities as a multiset, not counts alone. Equal totals can hide a dropped record plus a duplicate. List every permitted normalization, such as an ingestion timestamp excluded from source/baseline equality. Keep the unmodified originals as well.

A run may complete with failed deliveries or incorrect detections; that is a completed experiment with a negative product result. Conversely, `inputs_drained` is not proof of full reconciliation. Do not use partial snapshots to claim complete-run absence, final workload reduction, or recall.

## 9. Evidence package and machine-readable results

Return a campaign directory with an index and per-scenario artifacts. The following is the requested layout, not a claim that these files already exist:

```text
campaign/
  README.md
  capability-matrix.csv
  run-index.json
  environment.json
  changes.md
  known-limitations.md
  verification.json
  SHA256SUMS
  scripts/
    run-campaign.*
    export-siem.*
    verify-evidence.*
    build-comparisons.*
  scenarios/
    <scenario-id>/
      run-spec.json
      ground-truth.json
      config-redacted/
      source/
        capture.pcap                 # only where actually captured
        source-eve.jsonl
        source-manifest.json
        replay.json                  # only where replay applies
      arm-a/
        siem-query.json
        siem-raw-documents.jsonl
        parsed-fields.jsonl
        export-receipt.json
      arm-b/
        broker-observations.jsonl
        candidates.jsonl
        enrichment-requests.jsonl
        enrichment-results.jsonl
        final-findings.jsonl
        suppressed-findings.jsonl
        adapter-payloads/
        siem-json/
        siem-cef/
        delivery-ledger.jsonl
        failures.jsonl
      addon-native-output/
      comparisons/
        counts.json
        record-links.json
        field-lineage.json
        field-retention.json
        side-by-side.md
      completion.json
      verification.json
      export-manifest.json
      SHA256SUMS
  website-ready/
    manifest.json
    cases/
    explanations/
    downloads/
    publication-review.md
```

Use equivalent names if the existing harness has a better established structure, but supply a complete mapping. Do not create empty placeholder evidence files that imply a stage executed. Mark a missing or inapplicable artifact with a reason in the manifest.

### Required run metadata

Include campaign/scenario IDs, evidence class, source commit and patch status, image digests, enabled integrations, exact invocation, redacted configuration, stimulus provenance, declared expected behavior, actual detector and sink outcomes, state initialization/warm-up, replay transformation, baseline analytics, and completeness.

Keep three results separate:

1. **Execution outcome:** completed, partial, or blocked.
2. **Technical delivery outcome:** delivered, suppressed, failed, unavailable, or unverified for each relevant record/feature.
3. **Detection outcome:** expected lead, unexpected lead, missed expected lead, benign no-lead, or not an effectiveness test.

Do not collapse those axes into one reassuring “PASS.”

### Required field lineage

For each feature-bearing field, identify the source file, record identity, JSON path, source value, transformation, candidate/final path, emitted payload representation, received SIEM path/value, retention result, and first loss point if applicable.

Differentiate `preserved`, `derived`, `renamed`, `decoded`, `truncated`, `omitted`, `not observed`, `not applicable`, and `unverified`. Use actual observed field paths rather than paths from an assumed schema.

### Required record links

Link source event identities to baseline SIEM IDs and to the Cernity tenant/finding/revision and received SIEM IDs. Aggregate findings may involve many source records; retain the contributing set or disclose that the implementation cannot recover it. Do not imply a one-to-one link where the evidence supports only a scoped association.

## 10. Website-ready teaching material

For each demonstrated capability, produce a case containing:

1. **Scenario:** what the test client did, why it was chosen, and whether its intent was benign, simulated adverse behavior, or a transport-only exercise.
2. **Configuration:** exactly which sensor logger/plugin and central services are necessary.
3. **Arm A original record:** a real, complete, representative document retrieved from the baseline SIEM.
4. **Arm B original record:** the associated real, complete document retrieved from the Cernity destination, including revisions where relevant.
5. **Why these belong together:** identifiers and supporting source observations, with aggregation/replay qualifications.
6. **Decoded teaching view:** optional, clearly distinguished from the original.
7. **Field-by-field reading:** what each important value means and which tool created it.
8. **Added value:** what Cernity calculated or attached that is not already present in the baseline.
9. **Lost or missing context:** useful fields absent from the delivered finding or reduced transport.
10. **Investigation:** next evidence an analyst needs to separate the adverse and benign explanations.
11. **Limits:** false leads, suppression, missing evidence, incomplete enrichment, and what the records cannot establish.
12. **Downloads and provenance:** selected JSON/text, source references, hashes, test configuration, and exact assurance level.

Keep full record bodies available. Do not replace them with screenshots, selected metrics, or prose summaries. Screenshots can supplement the package only if taken from the actual test SIEM, with the query and source record IDs supplied.

The website's historical importer understands specific old bundles; it is not a generic loader for this new campaign. Provide a documented adapter or versioned data schema for the new package. Do not overwrite existing cases or feed new formats through the old importer without validation.

Keep the complete private evidence package separate from the reviewed public subset. Public artifacts must omit credentials and unauthorized private data. Record every redaction and preserve a restricted original for verification. Do not silently replace real addresses or identifiers and continue calling the result an unmodified record.

## 11. Verification and regression requirements

1. Run relevant product unit/contract tests for changed detector, mapping, lifecycle, authentication, persistence, and adapter behavior.
2. Test the actual secure deployment path; passing unit tests does not verify startup or end-to-end delivery.
3. Validate every evidence JSON/JSONL artifact and applicable contract. If a historical/runtime record differs from the declared contract, report the mismatch rather than rewriting the artifact to pass.
4. Recompute export hashes and compare source/baseline multisets with the declared normalization only.
5. Reconcile source scope, final identity/revisions, suppression, failures, and receiving-side document counts.
6. Verify original selected records in the website-ready package are byte-identical to their retained export slices where possible, or semantically identical with serialization differences declared. Do not normalize field types or lose integer precision.
7. Verify field-retention reports against the retrieved documents, not adapter expectations.
8. Confirm baseline controls and previously published beacon, fan-out, signature, transfer, and benign cases still behave as documented after relevant changes.
9. Preserve failed attempts and subsequent corrected runs under separate IDs. Do not delete negative results to clean up the report.
10. Supply the exact reproducible verification commands and their complete result logs.

If website integration is prepared locally, run its production build and `python3 scripts/check-site.py`, extending the checks for new records and schemas. Do not deploy the public site without a separate publication instruction.

## 12. Interpret results conservatively and precisely

A successful feature demonstration proves the stated pipeline behavior for the stated test. It does not establish general precision, recall, calibrated confidence, production scale, or operating return on investment.

Specific distinctions that must remain visible:

1. A flow is telemetry, not necessarily an alert.
2. A signature match is an engine assessment, not confirmed compromise.
3. `FINAL` is a lifecycle state, not an analyst verdict.
4. `TIMEOUT` is an enrichment outcome, not evidence that the original finding was dropped.
5. A PTR name, ASN, fingerprint label, or reputation score is context, not attribution.
6. A JA4 or SLIPS label does not establish which upstream algorithm produced the evidence without provenance.
7. A CEF transport acknowledgment is not confirmation of successful SIEM parsing or field preservation.
8. A receiver record is stronger delivery evidence than a sender's `QUEUED` field.
9. A synthetic positive and one benign control do not establish population accuracy.
10. An equivalent SIEM analytic may derive the same behavior from the raw baseline; disclose what analytics the baseline actually ran.

## 13. Final report required from Claude

Return the document/package paths and a concise factual report followed by detailed results:

1. What was actually executed, on which revision and deployment.
2. Every code/configuration change, why it was required, and its tests.
3. Capability matrix distinguishing demonstrated delivery, intentional suppression, failed delivery, missing input, unsupported capability, and external blockers.
4. Actual side-by-side records for every successful demonstration, with traceable original SIEM document identities.
5. Before-and-after Zeek propagation evidence and JSON-versus-CEF field retention results.
6. Negative and benign controls, false leads, timeouts, parser losses, recovery outcomes, and incomplete runs.
7. Exact claims the website may now make, with the corresponding evidence paths.
8. Exact claims the website must still avoid, and why.
9. Reproduction/verification commands and package integrity results.
10. Any remaining dependency that requires user input, stated specifically rather than as a generic “more testing needed.”

The acceptance question is:

**Can a SOC analyst open the original SIEM records for both arms, trace each claimed added field to its real origin, understand what Cernity added or omitted, and reproduce the comparison without trusting the report's narrative?**

If the answer is no for any capability, mark that capability incomplete and explain the missing evidence. Do not claim the overall optional-integration demonstration is complete until the required received records and verifications exist.
