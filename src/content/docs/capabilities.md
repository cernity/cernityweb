---
title: "Everything Cernity does: the capability catalog"
nav: "Capability catalog"
order: 3.05
---

# Everything Cernity does: the capability catalog

A complete, source-verified list of what Cernity adds on top of Suricata — every detection layer,
enrichment, evidence step, and reasoning capability. This is a catalog, not a claim that every path
has a captured live deployment: see [capability dependencies](/docs/sensor-dependencies/) for what
each needs and [the evidence section](/proof/#optional-integrations) for what has been recorded end to
end. Detection, enrichment, and evidence are **additive** — the originating Suricata event is
preserved on the finding, so nothing Suricata observed is lost.

## Detection layers

Each row is a distinct finding class produced by a named service in the pipeline.

| Layer | What it finds | Example ATT&CK | Service |
|---|---|---|---|
| Behavioral / statistical | C2 beaconing (interval, jitter, connection count), low-and-slow exfil, nDPI risk promotion | T1071, TA0010 | `behavioral-detectors` |
| Encrypted-traffic & protocol | JA4/JA3 client & server fingerprint rarity, DoH to non-approved resolver, cloud-staging exfil SNI, self-signed / short-lived TLS cert, domain-fronting / ECH, suspicious tooling user-agent, SSH brute-force, ICMP exfil, app-protocol / port mismatch | T1071, T1090.004, T1571, T1110 | `protocol-detectors` |
| DNS | DGA-scored domains, NXDOMAIN bursts, DNS tunnelling, domain-level (FQDN) beaconing | T1071.004, T1568 | `dns-detector` |
| HTTP request shapes | Webshell / backdoor URI, SQL injection, command injection, path traversal / LFI, credentials in URL, risky methods (PUT/PROPFIND) | T1190, T1505.003 | `http-detector` |
| East-west / Active Directory | Lateral movement, RDP fan-out, internal scan, kerberoasting, AS-REP roasting, password spraying, LLMNR/mDNS poisoning, DCERPC lateral, ransomware-over-SMB, lateral-exec (named pipe) | T1021, T1558.003, T1558.004, T1110.003, T1557.001, T1486 | `east-west-detectors` |
| OT / ICS (Modbus) | Unauthorized write/control from a non-authorized master, new master→outstation pairing, function-code / unit-id enumeration, illegal-function bursts, Modbus off-502, program/operating-mode transfer | T0855, T0831, T0842, T0846, T0885, T0858 | `ot-detectors` |
| File & malware | Known-bad file hash (MalwareBazaar / EICAR / operator list), risky executable delivery, and YARA content match on carved files | T1105, T1204 | `file-threat`, `file-yara` |
| Threat intelligence | Curated-feed matches: abuse.ch Feodo C2 IPs, SSLBL certificate SHA-1, SSLBL JA3 (distinct from IP-reputation enrichment) | T1071 | `threat-intel` |
| ML behavioral | SLIPS behavioral / model verdicts, mapped by provenance to `slips_ml` / `slips_intel` / `slips_alert` | — | `slips-adapter` (← SLIPS) |
| Coverage & health | Capture-loss (kernel drops) and app-layer-blind (lossy/half-duplex mirror) — tells the SOC when the sensor is going blind | — | `coverage-detector` |
| Protocol-integrity anomalies | Promotes Suricata evasion-class stream and app-layer anomalies | — | `anomaly-detector` |
| Signature & notice promotion | Suricata ET signature alerts and Zeek notices become first-class findings | (as tagged) | `ids-alerts`, `zeek-notice` |

## Finding lifecycle (what raw Suricata does not do)

| Capability | What it gives the analyst | Service |
|---|---|---|
| Consolidation & dedup | A chatty rule (e.g. 45 alerts) collapses to one stable finding identity with revisions, instead of flooding the SIEM | `finding-service` |
| Severity / threat gate | Low-value, non-threat findings are suppressed from the analyst plane (kept for correlation/audit) so the SIEM queue is signal, not noise | `finding-service` |
| Lifecycle & audit trail | Explicit states — `CANDIDATE → FINAL`, `enrichment_state` PENDING / TIMEOUT / ENRICHED, delivery state, monotonic revisions | `finding-service` |
| ATT&CK tagging | Precise technique IDs where defensible, category-mapped otherwise | `finding-service` |
| Detection math on the finding | The measurements that fired it — e.g. beacon interval, jitter, connection count; enumeration breadth; distinct-account count | each detector |

## Enrichment — context attached to a finding

Added by `finding-service` (intel) and GeoIP enrichment. Real values require the corresponding
provider/database to be configured.

| Enrichment | Field | Requires |
|---|---|---|
| GeoIP / ASN | `intel.geo` | MaxMind GeoLite2 database |
| Reverse DNS (PTR) | `intel.rdns` | `INTEL_RDNS` + a resolver |
| Domain age / newly-registered-domain | `intel.domains` | `INTEL_RDAP` |
| JA3/JA4 → known-tool naming | `intel.fingerprints` | `INTEL_FP_MAP` (operator map) |
| GreyNoise reputation | `intel.reputation` | `GREYNOISE_API_KEY` |
| VirusTotal reputation | `intel.virustotal` | `VIRUSTOTAL_API_KEY` |
| community_id | on every finding | Suricata `community-id: yes` |

## Evidence — proof on demand, not just an assertion

When a finding is worth proving, Cernity arms a bounded packet capture and deep-parses it — gated by a
per-sensor safety budget, no standing full-packet capture.

| Step | What it produces | Service |
|---|---|---|
| On-demand PCAP | A bounded packet capture of the flow, stored in object storage; `evidence_refs` on the finding | `capture-agent`, `capture-orchestrator` |
| Zeek deep-parse | `summary` (conn/tls/x509/http/ssh/file/smb/kerberos) + `iocs` (JA3, JA4, JA4S, JA4H, JA4SSH, file hashes, self-signed certs) merged onto the finding | `zeek-central` |
| File carving + YARA | Carved files scanned with a maintained YARA ruleset → malware findings with rule/match | `file-yara` |

## Reasoning & entity spine

| Capability | What it gives the analyst | Service |
|---|---|---|
| Cross-detector correlation | Links related findings on an entity into one kill-chain incident (e.g. scan → beacon → C2), with ML×heuristic corroboration | `correlation-service` |
| Asset resolution | A stable `asset_key` + role that survives IP / DHCP / NAT change, tying findings to an entity | `asset-service` |
| Session reconstruction | A per-source timeline and entity graph retrievable for investigation | `reconstruction` |
| Response hand-off | Findings drive a playbook and an assertable action record; optional hand-off to a real SOAR | `soar-forwarder` |

## Provenance — the original Suricata event is preserved

Every finding carries (inline, or linked by `community_id`) the originating Suricata EVE — its native
fields intact (nDPI, JA3/JA4, community_id, protocol block) — so the finding is self-describing and a
SOC analyst never loses what Suricata observed. See the
[record-by-record proof](/proof/) and the [detection-coverage captures](/proof/detection/).

## Honest boundaries

- A capability appearing here is source-verified; whether it is **delivered in your deployment**
  depends on collected fields, running services, configuration, and provider credentials — see
  [capability dependencies](/docs/sensor-dependencies/).
- Enrichment values (GeoIP, reverse DNS, domain age, reputation) are populated only with the relevant
  database/API key present.
- Evidence (PCAP, Zeek, YARA) requires the forensics overlay and a satisfied capture budget.
- nDPI, JA3/JA4, and community_id are Suricata-native — they appear only if the sensor build and
  configuration emit them.
