// PUBLISHED live-SIEM enrichment cases — rendered by EnrichedCase.astro on
// src/pages/proof/index.astro.
//
// PROVENANCE: each `data` record is a REAL, verbatim `_source` pulled from the
// live Elasticsearch SIEM (ndr-findings-* on 192.168.222.141) — the actual
// findings Cernity delivered from the real .16 sensor path. No values were
// synthesized. See public/evidence/enriched-siem/*.json for the raw documents
// (with _index/_id so any value can be traced back to the exact SIEM record).
//
// WHAT THESE SHOW (distinct from the detector-stage captures in cases.pending.ts
// and the seven live cases in cases.ts): the ENRICHMENT Cernity adds on top of
// the raw detection once a finding reaches the SIEM. Suricata alone emits the
// flow/nDPI event with two bare IPs and nothing else. Cernity's delivered
// finding carries the same detection PLUS GeoIP/ASN/org, reverse-DNS, and a
// VirusTotal reputation lookup — keyed by the endpoint IP.
//
// HONESTY (verified against live ES — keep these true if edited):
//   - Every VirusTotal result currently in the SIEM is BENIGN (malicious:0). The
//     value shown is the automated reputation lookup, not a caught-bad example.
//   - intel.reputation (GreyNoise), intel.domains (RDAP age), and
//     intel.fingerprints returned ZERO docs on this traffic — do NOT claim them.
//   - source_events (originating Suricata EVE threaded onto the finding) is a
//     separate provenance track and is NOT in these records yet.
import longConnection from "../../../public/evidence/enriched-siem/long-connection-c2.json";
import ndpiRisk from "../../../public/evidence/enriched-siem/ndpi-risk-dns.json";

// Every entry carries stage:"enriched-siem" so the ProofCase renderer can badge
// these as live-SIEM enrichment captures, honestly distinct from detector-stage
// and from the full lifecycle cases.
export const enrichedCases = [
  {
    id: "enriched-long-connection",
    stage: "enriched-siem",
    label: "See enrichment on a real C2-category finding",
    title: "Suricata gives you two IPs. Cernity hands the SIEM who, where, and reputation.",
    data: longConnection,
    scenario:
      "A real long-lived beacon-shaped flow from the homelab: 163 connections over 20,879s from 192.168.222.15 to 44.231.237.105. Suricata logged the flow. This is the finding Cernity delivered to the live SIEM for it.",
    left: "Raw Suricata: src 192.168.222.15 · dst 44.231.237.105 · nothing else",
    right: "Cernity finding: + GeoIP/ASN · + reverse-DNS · + VirusTotal reputation",
    read: [
      ["detector_id: long_connection_cumulative / category: c2 / mitre: T1071", "The base detection — a persistent connection pattern. This much is the detector's call; the label is a lead, not a verdict."],
      ["geo.44.231.237.105 = US / asn 16509 / Amazon.com, Inc.", "Cernity-added. Suricata emits no GeoIP. An analyst instantly sees this is AWS-hosted, not a residential or hostile-country endpoint."],
      ["intel.rdns.44.231.237.105 = ec2-44-231-237-105.us-west-2.compute.amazonaws.com", "Cernity-added reverse-DNS. Names the EC2 host without the analyst pivoting to a separate tool."],
      ["intel.virustotal.44.231.237.105 = malicious 0 / suspicious 0 / harmless 53", "Cernity-added reputation lookup. Here it comes back clean — which is itself signal: it lets the analyst deprioritize a benign AWS destination instead of chasing it."],
    ],
    investigation: [
      "Confirm the destination against the geo/ASN + rdns: US/AWS EC2, VT clean — consistent with an SaaS/cloud backend, not an obvious C2.",
      "If still suspicious, pivot on the endpoint IP; the enrichment gives the ASN and hostname to correlate other flows.",
      "The long-connection pattern is the reason it fired — validate whether 163 conns/20,879s is expected for this internal host.",
    ],
    limit:
      "Enrichment does not change the detection — it contextualizes it. A clean VirusTotal result (as here) is not proof of innocence, only that no engine has flagged the IP. Enrichment values are point-in-time lookups cached at delivery.",
    question: "Does the enrichment prove this flow is malicious?",
    answer:
      "No. The detector flagged a long-connection pattern; the geo/rdns/VT enrichment actually points the other way here (US/AWS, VT clean). The value is that the analyst sees all of that in the finding instead of running three separate lookups.",
  },
  {
    id: "enriched-ndpi-risk",
    stage: "enriched-siem",
    label: "See enrichment on an nDPI-risk finding (IPv6)",
    title: "An nDPI risk flag, enriched with who owns the far end.",
    data: ndpiRisk,
    scenario:
      "A real nDPI-risk finding: Suricata's nDPI engine flagged 'Susp DNS Traffic' (risk score 460, Medium) toward an IPv6 endpoint. This is the finding Cernity delivered to the live SIEM.",
    left: "Raw Suricata/nDPI: an IPv6 address + a risk flag",
    right: "Cernity finding: + GeoIP/ASN/org · + reverse-DNS (IPv6)",
    read: [
      ["detector_id: ndpi_risk / category: malware / ndpi_risk: 'Susp DNS Traffic' (total 460, Medium)", "The base detection promotes Suricata's own nDPI flow-risk into a finding. Confidence 0.6 — a lead, deliberately not a high-certainty verdict."],
      ["geo.<ipv6> = US / asn 20001 / Charter Communications Inc", "Cernity-added. Resolves the IPv6 endpoint to a US residential ISP (Charter/Spectrum) — very different triage than a datacenter or foreign ASN."],
      ["intel.rdns.<ipv6> = syn-...res6.spectrum.com", "Cernity-added reverse-DNS on an IPv6 address — a Spectrum residential PTR, consistent with the ASN."],
    ],
    investigation: [
      "The geo + rdns say residential Charter/Spectrum — weigh 'Susp DNS Traffic' against a consumer endpoint (could be a home device, DoH, or a misclassification).",
      "Pull the DNS flow that nDPI flagged to see the actual query behavior behind the risk score.",
    ],
    limit:
      "This finding carries no VirusTotal block (not all findings trigger every enrichment). nDPI risk is a heuristic score, not a confirmed threat — the enrichment tells you where the endpoint lives, not whether the traffic was malicious.",
    question: "Does the nDPI 'Susp DNS Traffic' flag plus enrichment confirm malware?",
    answer:
      "No. nDPI raised a medium-severity DNS risk; the enrichment resolves the far end to a residential Spectrum IPv6 host. That reframes triage — it does not confirm compromise. Investigation of the DNS flow is still required.",
  },
];
