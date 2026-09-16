import beacon from "../../../public/evidence/beacon.json";
import signature from "../../../public/evidence/signature.json";
import scan from "../../../public/evidence/scan.json";
import transfer from "../../../public/evidence/transfer.json";
import benign from "../../../public/evidence/benign-transfer.json";
import dns from "../../../public/evidence/dns.json";
import fqdn from "../../../public/evidence/fqdn.json";
export const cases = [
  {
    id: "beacon",
    label: "Recognize a repeating connection",
    title: "A connection is a fact. A beacon is an interpretation.",
    data: beacon,
    scenario:
      "A test host repeatedly contacts the same destination. A single connection looks ordinary; the regular spacing across connections is the behavior being evaluated.",
    left: "20 flow records · 0 alerts for this pair",
    right: "3 beacon documents · 3 finding IDs",
    change:
      "Cernity calculated the pattern across flows. The selected finding describes 20 connections with a five-second interval and zero measured jitter. It is one of three beacon findings as the window developed, not the only finding in this run.",
    read: [
      [
        "event_type: flow",
        "Suricata is describing a connection, not raising an alert. A stored flow record is still useful evidence.",
      ],
      [
        "src_ip / dest_ip / dest_port",
        "10.0.0.5 contacted 203.0.113.66 on port 443. The port alone does not establish HTTPS, benign traffic, or encryption.",
      ],
      [
        "flow.bytes_toserver: 253",
        "This selected connection sent 253 counted bytes toward the server. This is not the byte total for all 20 connections.",
      ],
      [
        "interval_s: 5 / jitter_s: 0",
        "Cernity measured regularity across connections. Jitter describes variation in spacing; zero means the measured intervals were uniform.",
      ],
      [
        "category: c2 / mitre: T1071",
        "The detector categorized the behavior as a command-and-control lead and mapped it to Application Layer Protocol. A label is not proof of an attacker.",
      ],
      [
        "confidence: 1 / evidence_refs: []",
        "This is an emitted detector score, not a calibrated 100% probability. No packet evidence references are attached to this finding.",
      ],
    ],
    investigation: [
      "Identify the source host and the process making the connections using endpoint logs or EDR.",
      "Check whether the destination belongs to an approved agent, monitoring service, or scheduled task.",
      "Reconstruct connection spacing from flow.start, then compare domain, certificate, and other host activity before escalating.",
    ],
    limit:
      "The complete baseline has 17 engine-liveness control alerts on other activity, so “zero alerts” applies to this IP pair only. The complete Cernity export contains eight documents, including five background suspicious-user-agent findings. Replay shifted the capture clock; compare flow.start using the recorded replay offset, not SIEM ingestion timestamps. The selected source record’s top-level timestamp differs from flow.start; both are preserved rather than silently corrected.",
    question: "Does confidence 1.0 establish that the host is compromised?",
    answer:
      "No. It reports the detector’s score for a pattern. Regular callbacks also occur in legitimate software. Host ownership, the responsible process, and destination context are needed to assess compromise.",
  },
  {
    id: "signature",
    label: "Separate alerts from finding identities",
    title: "45 alerts. Two documents. One finding identity.",
    data: signature,
    scenario:
      "This test deliberately installed a custom Suricata signature, SID 9000003. Suricata already recognized the test traffic. The question is whether Cernity preserves the evidence and consolidates repeated detections.",
    left: "45 matching signature alerts",
    right: "2 revisions · 1 finding ID",
    change:
      "The selected alert and finding retain the same signature, flow ID, and Community ID. Cernity adds a stable finding identity and lifecycle. This is consolidation of an existing detection, not a threat that Suricata missed.",
    read: [
      [
        "alert.signature_id: 9000003",
        "The identifier of the custom benchmark rule. It is not a count of alerts or a generally deployed detection rule.",
      ],
      [
        "alert.action: allowed",
        "This alert does not say that this rule blocked the traffic. It does not mean the activity was approved or safe.",
      ],
      [
        "flow_id / community_id",
        "These match across the selected records, providing a concrete connection-level pivot back to Suricata. The destination port is present in Suricata but absent from the selected Cernity entities.",
      ],
      [
        "finding_id / revision: 2",
        "Both Cernity documents share the same identity. Revision 2 is an update, not a second incident. An append-only search can display both documents.",
      ],
      [
        "state: FINAL / enrichment_state: TIMEOUT",
        "The finding was finalized for delivery, but the requested enrichment did not complete. FINAL does not mean a threat was confirmed by an analyst.",
      ],
      [
        "severity: 1 versus 9",
        "These values use different scoring conventions. Suricata rule priority and Cernity’s 1–10 severity are not directly comparable.",
      ],
    ],
    investigation: [
      "Read the signature and its rule conditions before accepting its classification.",
      "Pivot using the retained flow ID and Community ID, scoped to the sensor and observation window.",
      "Group by tenant and finding ID, keep the latest revision for triage, and retain earlier revisions as evidence. Investigate the enrichment timeout separately.",
    ],
    limit:
      "The actual document reduction for this signature is 45 to 2. A latest-revision view could show one finding, but that UI behavior was not measured. The whole Cernity run contains six documents. Revision 1 has PENDING enrichment; revision 2 has TIMEOUT and empty evidence_refs. Successful packet, GeoIP, or reputation enrichment is not demonstrated.",
    question:
      "Would a SIEM search returning two Cernity rows mean two attacks?",
    answer:
      "No. Compare finding_id and revision. Here the two rows are successive versions of one finding. Other detectors can also raise different findings about the same underlying activity.",
  },
  {
    id: "scan",
    label: "Read a cross-host pattern",
    title: "One host reaches twelve internal destinations.",
    data: scan,
    scenario:
      "The saved traffic shows 172.31.0.5 contacting twelve internal hosts. An individual Suricata record describes one connection attempt; the behavior becomes visible when you group those records by source.",
    left: "48 flows · 12 destinations · 0 alerts",
    right: "2 documents · 2 detector findings",
    change:
      "Cernity emits lateral_movement and rdp_fanout leads. The displayed lateral_movement record summarizes internal_targets: 12. It does not include a list of all twelve target addresses.",
    read: [
      [
        "dest_port: 3389",
        "The selected flow targets the usual Remote Desktop port. A port number is a useful clue, not proof of successful RDP authentication.",
      ],
      [
        "flow.state / packet counters",
        "Read these to distinguish attempted connections from more developed sessions. Contacting a host is not the same as logging into it.",
      ],
      [
        "internal_targets: 12",
        "This is a count of distinct internal destinations, not twelve confirmed compromised machines.",
      ],
      [
        "detector_id: lateral_movement",
        "This is the detector’s name. The exported evidence supports a fan-out lead, not a demonstrated remote execution chain.",
      ],
      [
        "mitre: T1021",
        "Remote Services is an investigation category. Validate it against protocol and endpoint evidence.",
      ],
    ],
    investigation: [
      "Check whether the source is an approved scanner, jump host, or management server.",
      "Recover the actual destination list from the underlying flow records.",
      "Look for successful logons and process execution on the destinations before calling this lateral compromise.",
    ],
    limit:
      "The saved run is reconciled, but its frozen label file incorrectly describes a benign-control scenario. The records establish observed fan-out and detector output; they do not establish attack recall. The two findings can describe overlapping behavior, not two separate attacks.",
    question:
      "Does internal_targets: 12 prove that twelve machines were compromised?",
    answer:
      "No. It counts destinations contacted. Authentication outcomes, execution evidence, and business context are necessary to establish successful lateral movement.",
  },
  {
    id: "exfil",
    label: "Separate volume from data theft",
    title: "Eleven transfers become one aggregate lead.",
    data: transfer,
    scenario:
      "The test host sends data to the same destination over several connections. Suricata records the individual transfers and stream anomalies. Cernity aggregates the transferred bytes and labels the pattern for investigation.",
    left: "11 flows · 44 stream-anomaly alerts",
    right: "1 low_slow_exfil document",
    change:
      "The eleven flows total 5,933,840 bytes to the server, matching the Cernity finding. The extra value is the cross-flow aggregation and interpretation. Cernity has not discovered new packet facts or demonstrated that sensitive data was stolen.",
    read: [
      [
        "flow.bytes_toserver",
        "A per-flow directional byte counter. Sum matching flow records once; do not also add flow counters embedded in alert records.",
      ],
      [
        "entities: bytes = 5933840",
        "The aggregate is approximately 5.93 MB in decimal units. It is not a verified file size or a measure of sensitive content.",
      ],
      [
        "connections: 11",
        "The number of connections included in this finding, not the number of users, files, or incidents.",
      ],
      [
        "category: exfil / confidence: 0.22",
        "The detector produced an exfiltration lead with this score. Neither the label nor the score establishes unauthorized transfer.",
      ],
      [
        "mitre: TA0010",
        "This is the Exfiltration tactic, a broad goal. It is not a specific ATT&CK technique identifier.",
      ],
    ],
    investigation: [
      "Establish the source host’s normal role and whether this is an authorized backup, upload, or synchronization job.",
      "Verify the destination owner and total outgoing bytes from the same scoped flows.",
      "Use endpoint, application, proxy, or DLP evidence to establish which data moved and whether the transfer was authorized.",
    ],
    limit:
      "The run ended at inputs_drained, not full reconciliation. These positive records are present, but final queue size and complete-run absence claims are not supported. The 44 alerts on this pair are stream anomalies; baseline alerting was not silent. Empty evidence_refs does not provide direct links to every contributing flow.",
    question: "Can you report “5.93 MB of data stolen” from this finding?",
    answer:
      "No. You can report the measured outgoing byte total and a detector-generated exfiltration lead. Theft requires evidence about the data, destination, and authorization.",
  },
  {
    id: "benign",
    label: "Study a false lead",
    title: "A benign transfer can still look like C2.",
    data: benign,
    scenario:
      "The same transfer experiment includes a pair declared benign in the test scenario: an authorized concentrated transfer with callbacks to 198.51.100.50. It provides a counterexample to treating detector labels as ground truth.",
    left: "13 flows · 5 stream-anomaly alerts",
    right: "2 beacon documents for the benign pair",
    change:
      "Cernity produced two C2 beacon leads for this benign control. The selected finding reports an interval of 6.7 seconds, jitter of 2.2 seconds, and confidence 0.907. Additional analysis can produce misleading leads as well as useful ones.",
    read: [
      [
        "category: c2",
        "The detector’s interpretation conflicts with the scenario’s declared benign activity. Preserve both facts.",
      ],
      [
        "interval_s: 6.7 / jitter_s: 2.2",
        "Regularity can occur in authorized software and transfer retries as well as malicious callbacks.",
      ],
      [
        "confidence: 0.907",
        "A high detector score is not equivalent to a 90.7% chance of compromise.",
      ],
      [
        "13 connections",
        "The selected beacon includes thirteen connections. It does not mean thirteen separate alerts or thirteen attackers.",
      ],
      [
        "No low_slow_exfil record in this snapshot",
        "One detector staying quiet does not prevent another detector from raising a false lead on the same traffic.",
      ],
    ],
    investigation: [
      "Confirm the owner, process, and approved destination using records independent of the detector.",
      "Document why the behavior is expected before making a narrowly scoped tuning change.",
      "Retain the detection and its disposition so future tuning can be evaluated against both malicious and benign traffic.",
    ],
    limit:
      "This is an observed unfavorable result from a declared benign control, not a measured population false-positive rate. The run is only inputs_drained. The absence of a low_slow_exfil record applies to the saved snapshot.",
    question:
      "Should this destination be globally allowlisted solely because this example is benign?",
    answer:
      "No. This is a synthetic test address and a single scenario. In a deployment, validate asset ownership, process, scope, and expected behavior before tuning a specific detection.",
  },
  {
    id: "dns",
    label: "Inspect a DNS detection",
    title: "The DNS query is visible. The finding is much narrower.",
    data: dns,
    scenario:
      "A historical synthetic DNS-tunnel test generated long query names. The baseline export retained DNS requests and flow records; Cernity emitted one dns_tunnel finding for the client.",
    left: "200 baseline records · 0 alerts in this export",
    right: "1 dns_tunnel finding document",
    change:
      "Cernity adds a DNS-tunnel interpretation with ATT&CK T1071.004. The delivered finding contains the client IP but not the queried names, entropy measurements, resolver address, or the selected Community ID. The raw DNS record therefore remains necessary for detailed investigation.",
    read: [
      [
        "dns.queries[].rrname",
        "The actual queried name is visible on the Suricata side. Its unusual appearance is a clue, not by itself proof of encoded stolen data.",
      ],
      [
        "dest_ip: 8.8.8.8 / dest_port: 53",
        "This selected request targets a DNS resolver. Do not label the resolver as the attacker-controlled authoritative server.",
      ],
      [
        "dns.type: request / dns.version: 3",
        "This is a request in the DNS v3 format, not proof that the lookup received a successful answer.",
      ],
      [
        "entities: role client",
        "The Cernity document scopes its lead to the client. There is no destination entity or query-level evidence list here.",
      ],
      [
        "mitre: T1071.004",
        "The detector mapped the lead to DNS as an application-layer command-and-control technique. That classification still needs validation.",
      ],
    ],
    investigation: [
      "Retrieve the client’s full DNS queries and responses in the source observation window.",
      "Group queries by domain and inspect repetition, lengths, response behavior, and the responsible process.",
      "Check for legitimate telemetry, security products, or application-generated names before escalating.",
    ],
    limit:
      "This is a legacy export without the newer hash manifest or qualified completion metadata. The baseline/source records were rechecked for equality apart from ingestion timestamps, but its assurance is lower than the primary cases. The 200 records are 100 DNS events and 100 flow records, not 200 alerts. No complete-run recall or precise cross-clock alignment claim is made.",
    question:
      "Can an analyst reconstruct every suspicious query from this Cernity finding alone?",
    answer:
      "No. This document contains the client and classification but omits the individual query names and measurements. Retained raw DNS telemetry is needed for that investigation.",
  },
  {
    id: "fqdn",
    label: "Follow a domain across addresses",
    title: "A domain-level lead across rotating IP addresses.",
    data: fqdn,
    scenario:
      "A historical test combined DNS and flow activity. The selected Suricata request asks for cdn.evil.example; Cernity produced a domain-level beacon finding for 10.0.0.5, naming evil.example and four rotating IP addresses.",
    left: "124 baseline records · 0 alerts in this export",
    right: "1 beacon_fqdn finding document",
    change:
      "Cernity supplies a domain-level interpretation that can connect activity across addresses. The finding reports the parent-domain value evil.example and rotating_ips: 4; it does not include the four addresses or the individual supporting DNS answers.",
    read: [
      [
        "dns.queries[].rrname: cdn.evil.example",
        "This is the observed query in the selected baseline record. The name belongs to a synthetic example, not a live malicious domain claim.",
      ],
      [
        "entities: domain / role c2",
        "Cernity reports evil.example as its domain entity. This differs from the complete queried hostname; preserve that distinction when pivoting.",
      ],
      [
        "rotating_ips: 4",
        "The finding summarizes a count. It does not enumerate the addresses or prove they are all controlled by an attacker.",
      ],
      [
        "evidence_refs: []",
        "There are no attached references to the contributing DNS or flow records in this document.",
      ],
    ],
    investigation: [
      "Recover the DNS answer records that map the hostname to observed addresses.",
      "Match the source host’s flows against those mappings and their observation windows.",
      "Check whether expected CDN, failover, or load balancing explains the rotation and regularity.",
    ],
    limit:
      "This legacy bundle has no newer export manifest or qualified completion/replay metadata. The baseline contains 72 DNS and 52 flow records; counts describe the whole saved baseline, not just this hostname. Domain rotation can be normal. The record demonstrates emitted output, not general detection accuracy or complete attribution.",
    question: "Does rotating_ips: 4 establish four attacker servers?",
    answer:
      "No. It is a count in a domain-associated finding. Inspect the actual answers, infrastructure ownership, and client behavior before attributing the servers.",
  },
];
