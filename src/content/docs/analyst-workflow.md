---
title: "From a finding to a defensible investigation"
nav: "Analyst investigation workflow"
order: 0.5
---

# From a finding to a defensible investigation

A detector gives you a lead. An analyst establishes what happened, how reliable the evidence is, whether the activity was authorized, and what action is justified.

Use the [actual side-by-side cases](/proof/) alongside this guide. The workflow applies whether the first lead comes from a Suricata alert, Cernity, Zeek, or a SIEM analytic.

## 1. Identify the record before interpreting it

Read the event type or detector ID, tenant, sensor, endpoints, and observation bounds. Preserve the original record, its SIEM document ID if available, and its finding revision.

Ask whether you are looking at raw telemetry, a rule match, a derived finding, or a later enrichment update. In the signature case, `FINAL` and `TIMEOUT` describe different parts of processing; neither is an analyst disposition.

## 2. Separate observations from interpretation

| Observation you can report | Interpretation still needing evidence |
|---|---|
| Twenty connections show a measured five-second interval. | The host is communicating with command-and-control infrastructure. |
| One host contacted twelve internal destinations. | It successfully moved laterally into twelve machines. |
| Eleven flows total 5,933,840 counted bytes toward a destination. | Sensitive data was stolen. |
| A rule with a specific SID matched. | The named malware successfully executed. |
| A PTR lookup returned a hostname. | That hostname establishes ownership or trust. |
| A fingerprint matches an operator-maintained label. | Only that named software could have created the connection. |

Write the supported observation first. Keep the working hypothesis separate so another analyst can challenge it.

## 3. Verify coverage and data quality

Was the sensor watching the relevant segment? Did it see both directions? Were there drops, truncation, or parser errors? Are timestamps comparable, or was this a replay? Does `evidence_refs` actually point to accessible data?

An absence claim needs a defined search scope and a functioning collection path. “I see no DNS records” can mean encrypted DNS, unobserved DNS, disabled logging, transport loss, or simply no DNS in the selected window.

## 4. Add host and business context

Determine the asset owner, normal role, user or service account, expected destinations, and change history. Correlate with endpoint process telemetry, authentication logs, application logs, and change records where available.

A vulnerability scanner, management server, backup agent, and workstation can produce similar network patterns for very different reasons. Cernity's category cannot supply missing business authorization.

## 5. Pivot through identifiers carefully

Use flow ID within the correct sensor/capture context. Use Community ID across compatible observation points and seeds. For a finding with aggregate counts but no individual flow references, retrieve the underlying flows using the endpoints and observation scope.

For DNS, distinguish the recursive resolver from the authoritative infrastructure behind the queried name. For TLS, distinguish SNI, a certificate name, and a PTR name; they come from different sources and can disagree.

For finding updates, group by tenant and finding ID, then compare revisions. An enrichment update may add context without changing the original detection.

## 6. Test a benign explanation and an adverse explanation

For a beacon lead, check whether an approved agent is responsible, while also checking for an unexpected process, unfamiliar destination, or related endpoint alerts.

For fan-out, check authorized administration or scanning, while looking for unusual accounts, successful logons, or remote process execution.

For transfer leads, check approved backup or synchronization, while investigating data sensitivity, destination authorization, and activity around the transfer.

A plausible benign explanation is not proof. A plausible attack story is not proof either. Seek independent observations that discriminate between them.

## 7. Record a disposition with its basis

Use your organization's categories, such as confirmed malicious, authorized activity, unresolved, or collection issue. Record the supporting evidence and what remains unknown. A false lead in a test is useful evidence about tuning, not something to delete from the evaluation.

Do not globally allowlist an address from a synthetic case study. Tune against validated deployment context, with a defined scope and a way to review the effect on later detections.

## Practice with the records

1. In the [beacon case](/proof/#beacon), identify the measured regularity and two legitimate processes that could produce it. Which independent host evidence would distinguish them?
2. In the [signature case](/proof/#signature), explain why 45 alerts become two documents but one identity. What did the timeout prevent you from concluding?
3. In the [DNS case](/proof/#dns), list the useful raw fields that the delivered finding omits. Where would you retain them for investigation?
4. In the [benign control](/proof/#benign), explain why confidence 0.907 does not override the scenario label.
5. In the [optional integration audit](/proof/#optional-integrations), distinguish an implemented adapter from a captured SIEM result.

## A compact investigation record

For each case, retain: the observed behavior; original record references; affected assets; working hypothesis; competing explanation; independent corroboration; visibility limitations; disposition; and any follow-up owner.

This practice makes your conclusion reviewable. A detector's label becomes one input to the investigation rather than its conclusion.
