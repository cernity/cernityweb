// STAGING — NOT PUBLISHED. This file is intentionally not imported by
// src/pages/proof/index.astro, so nothing here renders on the site. It holds the
// proposed proof-section additions for review. Each case's `data` is a REAL capture
// produced by running the detector's actual code over a fixture
// (tools/proof-capture/capture.py in cernityndr) — see public/evidence/detector-stage/.
//
// IMPORTANT LABEL: these are DETECTOR-STAGE captures — the real candidate findings the
// detector emits from the source EVE. They are NOT the full finding-service lifecycle
// (FINAL state, revisions) + SIEM delivery that the seven live cases in cases.ts show.
// Before publishing: (1) decide detector-stage vs upgrading to full-pipeline captures,
// (2) move approved entries into cases.ts + move the JSON out of the /detector-stage/
// staging folder, (3) add the disclaimer to the proof page intro.

import ot from "../../../public/evidence/detector-stage/ot-detectors.json";
import protocol from "../../../public/evidence/detector-stage/protocol-detectors.json";
import http from "../../../public/evidence/detector-stage/http-detector.json";
import dns from "../../../public/evidence/detector-stage/dns-detector.json";
import eastwest from "../../../public/evidence/detector-stage/east-west-detectors.json";
import coverage from "../../../public/evidence/detector-stage/coverage-detector.json";
import anomaly from "../../../public/evidence/detector-stage/anomaly-detector.json";

// Every entry carries stage:"detector" so the ProofCase renderer (or a wrapper) can show
// the "detector-stage capture" badge and keep it honestly distinct from the live cases.
export const pendingCases = [
  {
    id: "ot-modbus",
    stage: "detector",
    label: "See OT/ICS control abuse",
    title: "Suricata parses Modbus. It does not judge who may write to a PLC.",
    data: ot,
    scenario:
      "A replayed Modbus session on an OT segment: a normal read-only master baseline, then an unknown master issues writes, a program/mode transfer, function-code sweeps, illegal-function bursts, and Modbus on the wrong port.",
    left: "21 Modbus EVE records · 0 alerts",
    right: "12 ICS findings · 6 detectors · ATT&CK for ICS",
    change:
      "Suricata natively decodes Modbus to EVE but raises no alert on protocol misuse — there is no signature for 'a master that should not be writing.' Cernity learns the authorized masters per outstation and flags unauthorized write/control (T0855/T0831), a never-seen master→outstation pairing (T0842), function-code/unit enumeration (T0846), illegal-function bursts, program/mode transfer (T0858/T0843), and Modbus off :502 (T0885).",
    read: [
      ["event_type: modbus", "Suricata decoded the Modbus transaction into EVE. A decoded transaction is telemetry, not an alert."],
      ["detector_id: unauthorized_write", "A write function code (fc 5/6/15/16) from a source not in the learned authorized-masters set for that outstation."],
      ["category: ics_control / mitre: T0855,T0831", "Mapped to ATT&CK for ICS. A label is a lead, not confirmation the write was malicious."],
      ["entities: src (master) / dst (outstation)", "The two endpoints an OT analyst pivots on. Cernity carries them as first-class entities."],
    ],
    investigation: [
      "Confirm whether the flagged source is a sanctioned EWS/HMI; if so, pin it via OT_AUTHORIZED_MASTERS.",
      "Check the outstation's process context for the written registers/coils.",
      "Correlate the program/mode transfer with a change-management window.",
    ],
    limit:
      "Detector-stage capture: these are candidate findings computed by ot-detectors, not yet delivered through the finding-service lifecycle to a SIEM. The authorized-masters baseline is learn-on-observe, so a novel master's first control op is the alertable moment. Requires a sensor tapped on an OT segment with the Suricata Modbus parser enabled.",
    question: "Does an unauthorized_write finding prove sabotage?",
    answer:
      "No. It proves a write came from a source outside the learned/authorized master set for that outstation. Ownership of the source and the intent of the write still require investigation.",
  },
  {
    id: "protocol-encrypted",
    stage: "detector",
    label: "Read encrypted-traffic behavior",
    title: "Eight leads from traffic Suricata logged without a single alert.",
    data: protocol,
    scenario:
      "A mix of TLS, HTTP, SSH, and flow records: a warm-up of common TLS clients, then a never-seen JA4 client, a cloud-staging SNI, DoH, a self-signed cert, a curl user-agent, an SSH brute-force burst, ICMP with a large payload, and SSH offered on :443.",
    left: "27 EVE records · 0 alerts",
    right: "8 findings · 8 detectors",
    change:
      "None of these trip a signature. Cernity scores behavior across the encrypted-traffic metadata Suricata already emits: JA4 client rarity (fleet-wide), cloud-staging exfil SNI, DoH to a non-approved resolver, self-signed/short-lived certs, tooling user-agents, SSH brute-force volume, ICMP exfil bytes, and app-protocol/port mismatch.",
    read: [
      ["ja4_rarity", "A TLS client fingerprint the whole fleet has not seen before, past a warm-up. Rarity is a lead, not attribution."],
      ["cloud_staging / doh_detect", "SNI to a data-sharing host, or DNS-over-HTTPS to a resolver not on the approved list — both defense-evasion tells."],
      ["port_proto_mismatch", "Suricata detected SSH on port 443; the app protocol contradicts the well-known service for the port."],
      ["confidence", "An emitted detector score, not a calibrated probability of compromise."],
    ],
    investigation: [
      "For ja4_rarity, identify the client software and whether it is sanctioned.",
      "For cloud_staging/DoH, check whether the destination is an approved service for this host.",
      "Correlate the SSH brute-force source with authentication logs on the target.",
    ],
    limit:
      "Detector-stage capture (candidate findings). Rarity depends on a warm-up window; a rare fingerprint is not inherently malicious. Server-side fingerprint rarity and ECH/domain-fronting are additional protocol detectors not exercised by this fixture.",
    question: "Does ja4_rarity mean malware?",
    answer:
      "No. It means the client fingerprint is new to the fleet. New legitimate software also produces new fingerprints; the process and destination decide.",
  },
  {
    id: "http-attacks",
    stage: "detector",
    label: "Flag web-attack request shapes",
    title: "Six request URIs. Suricata stored them. Cernity named the attacks.",
    data: http,
    scenario:
      "Six HTTP requests — a webshell access, SQL injection, command injection, path traversal, credentials in the URL, and a risky WebDAV method — plus one benign request as a control.",
    left: "7 HTTP EVE records · 0 alerts",
    right: "6 findings · 6 detectors · benign request clean",
    change:
      "Without a matching rule, Suricata logs these as ordinary HTTP. Cernity's request-shape detectors name webshell, SQLi, command injection, path traversal, credential-in-URL, and suspicious-method — and leave the benign request alone.",
    read: [
      ["http_webshell", "GET to /uploads/shell.php?cmd=id — a request shape consistent with webshell interaction."],
      ["http_sqli / http_cmd_injection", "Injection syntax in the query string. A matched shape is an engine assessment, not proof the backend was vulnerable."],
      ["benign request", "/index.html produced no finding — the detectors are shape-specific, not blanket."],
    ],
    investigation: [
      "Check the server's response code and body size for the flagged requests.",
      "Confirm whether the target path exists and is reachable.",
      "Correlate the source IP across other request findings.",
    ],
    limit:
      "Detector-stage capture (candidate findings). A matched request shape does not establish successful exploitation — only that the request looked like an attack.",
    question: "Does http_sqli mean the database was breached?",
    answer:
      "No. It means the request contained SQL-injection syntax. Whether the backend was vulnerable or the query executed requires the server-side evidence.",
  },
  {
    id: "dns-behavior",
    stage: "detector",
    label: "Catch DGA and NXDOMAIN bursts",
    title: "One algorithmic domain and a wall of failures Suricata logged as normal DNS.",
    data: dns,
    scenario:
      "A query to an algorithmic-looking domain, followed by one host generating twenty distinct NXDOMAIN responses in a short window.",
    left: "21 DNS EVE records · 0 alerts",
    right: "2 findings: dga_domain + nxdomain_burst",
    change:
      "Suricata logs each DNS query/response. Cernity scores the domain string for DGA characteristics and aggregates NXDOMAIN failures per host into a burst lead — behavior that no single DNS record reveals.",
    read: [
      ["dga_domain", "The queried name scored high on algorithmic-generation heuristics. A high score is a lead; CDNs and cloud hosts can also look random."],
      ["nxdomain_count: 20", "Twenty distinct non-existent-domain answers from one host in the window — a common C2/DGA-resolution tell."],
      ["confidence = dga_score", "The confidence is the DGA score itself, surfaced honestly rather than as a fixed number."],
    ],
    investigation: [
      "Resolve whether the DGA-scored domain belongs to a known CDN/cloud provider.",
      "Identify the process on the source host generating the NXDOMAIN burst.",
      "Correlate with any beaconing to a domain that did resolve.",
    ],
    limit:
      "Detector-stage capture (candidate findings). DGA scoring is a heuristic; long random-looking CDN subdomains can score high. dns_tunnel and domain-level beacon are shown in the live DNS cases.",
    question: "Does a DGA score confirm malware?",
    answer:
      "No. It flags an algorithmically-generated-looking name. Confirmation needs the resolving process and whether the domain is attacker-controlled.",
  },
  {
    id: "east-west-ad",
    stage: "detector",
    label: "Surface Windows/AD lateral attacks",
    title: "Kerberoasting, spraying, lateral exec, and LLMNR poisoning — from logs, not alerts.",
    data: eastwest,
    scenario:
      "A synthetic internal Windows/AD burst: TGS requests for many SPNs with RC4, failed logons across many accounts, remote-exec named-pipe access, and a host answering many LLMNR name queries it does not own.",
    left: "25 EVE records · 0 alerts",
    right: "4 findings across four ATT&CK techniques",
    change:
      "A flat network never generates this, and Suricata raises no alert on it. Cernity's east-west detectors aggregate the Kerberos/SMB/LLMNR metadata into kerberoasting (T1558.003), password spraying (T1110.003), lateral exec (T1021.002), and LLMNR poisoning (T1557.001).",
    read: [
      ["kerberoasting: distinct_spns=8, rc4=true", "Many service-ticket requests with weak encryption from one source — the kerberoasting pattern."],
      ["password_spraying: distinct_accounts=10", "One source failing authentication across many accounts, not one account many times."],
      ["llmnr_poison: answered_names=6", "A host answering LLMNR queries for names it does not own — Responder-style poisoning."],
    ],
    investigation: [
      "Map the source IP to a host and account; confirm whether the SPN requests are expected.",
      "Check the sprayed accounts for any successful logon.",
      "Isolate the LLMNR responder and confirm it is not a legitimate service.",
    ],
    limit:
      "Detector-stage capture (candidate findings). These fire only on internal Windows/AD traffic reaching the sensor; a flat network correctly produces nothing. lateral_movement / rdp_fanout / internal_scan are shown in the live scan case.",
    question: "Does a kerberoasting finding mean an account was compromised?",
    answer:
      "No. It means service tickets were requested in a pattern consistent with offline cracking. Whether a ticket was cracked and used is a separate, later event.",
  },
  {
    id: "coverage-health",
    stage: "detector",
    label: "Know when the sensor is going blind",
    title: "A dropping sensor still looks 'up.' Cernity says it is losing packets.",
    data: coverage,
    scenario:
      "Two Suricata stats snapshots: one sensor dropping ~10% of packets at the kernel, and one seeing packets but reassembling almost no application-layer flows (a lossy/half-duplex mirror).",
    left: "2 stats EVE records · 0 alerts",
    right: "2 coverage_degraded findings",
    change:
      "Suricata reports counters; it does not decide that the counters mean blind spots. Cernity turns kernel drop ratio and an app-layer-blind ratio into explicit coverage-degradation leads, so a SOC learns detection quality is falling rather than assuming silence means safety.",
    read: [
      ["kind: capture_loss, value: 0.09", "~9% of packets dropped at the kernel — detection over that traffic is incomplete."],
      ["kind: applayer_blind", "Packets flowed but almost no HTTP/TLS/DNS flows were reassembled — a mirror/tap problem, not a quiet network."],
      ["category (collection fault)", "This is a collection-health lead, explicitly separated from a malicious-traffic claim."],
    ],
    investigation: [
      "Check the sensor's CPU/ring-buffer sizing for the dropping interface.",
      "Verify the SPAN/tap is delivering both directions of the mirrored traffic.",
      "Re-baseline once the fault is fixed to confirm coverage recovered.",
    ],
    limit:
      "Detector-stage capture (candidate findings). A missing stats stream is not itself proof of health; packet-capture APIs expose different counters.",
    question: "Is coverage_degraded a security incident?",
    answer:
      "No. It is a detection-quality warning: the sensor is losing visibility. It changes how much you can trust an absence of other findings.",
  },
  {
    id: "protocol-anomaly",
    stage: "detector",
    label: "Promote protocol-integrity anomalies",
    title: "Suricata's own anomaly events, promoted to leads instead of buried.",
    data: anomaly,
    scenario:
      "Two Suricata anomaly events: unexpected application-layer data, and a stream reassembly overlap carrying different data (a classic evasion tell).",
    left: "2 anomaly EVE records · 0 alerts",
    right: "2 protocol_anomaly findings",
    change:
      "Suricata emits anomaly events into a stream most pipelines ignore. Cernity promotes the security-relevant ones (app-layer and evasion-class stream anomalies) into findings, while deliberately ignoring benign decoder noise.",
    read: [
      ["anomaly.type: applayer", "The application-layer parser saw data it did not expect — protocol misuse or tunneling."],
      ["stream reassembly_overlap_different_data", "Overlapping TCP segments carrying different bytes — an IDS-evasion technique."],
      ["selective promotion", "Only threat-relevant anomaly classes are promoted; decoder checksum noise is not."],
    ],
    investigation: [
      "Pull the flow around the anomaly to see which endpoints and protocol are involved.",
      "Determine whether the overlap is a middlebox artifact or deliberate evasion.",
    ],
    limit:
      "Detector-stage capture (candidate findings). Anomaly events depend on Suricata's anomaly logging being enabled; classification here is by anomaly class, not deep analysis.",
    question: "Does a stream-overlap anomaly prove evasion?",
    answer:
      "No. Overlapping segments with different data can indicate evasion or a broken middlebox; the surrounding flow decides which.",
  },
];
