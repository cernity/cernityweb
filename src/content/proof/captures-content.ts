// Interpretation layer for the detector-stage proof captures — meaning and investigation prompts
// per detector, and framing per service. This is INTERPRETATION of the real captured data (in
// captures.json); it adds no facts, numbers, or records. The build fails if a captured detector
// has no entry here (see captures.ts), so nothing renders unexplained.

export const serviceContent: Record<string, { title: string; blurb: string; limit: string }> = {
  "ot-detectors": {
    title: "OT / ICS — Modbus control abuse",
    blurb:
      "Suricata natively decodes Modbus to EVE but raises no alert on protocol misuse — there is no signature for “a master that should not be writing.” Cernity learns the authorized masters per outstation and scores the behavior.",
    limit:
      "Requires a sensor tapped on an OT segment with the Modbus parser enabled. The authorized-masters baseline is learn-on-observe, so a novel master’s first control op is the alertable moment.",
  },
  "protocol-detectors": {
    title: "Encrypted-traffic & protocol behavior",
    blurb:
      "None of these trip a signature. Cernity scores behavior across the TLS/HTTP/SSH/flow metadata Suricata already emits — fingerprint rarity, evasion, and exfil tells.",
    limit:
      "Rarity depends on a warm-up window; a rare fingerprint or new client is a lead, not attribution. Server-side fingerprint and ECH/domain-fronting are additional detectors not exercised by this fixture.",
  },
  "http-detector": {
    title: "Web-attack request shapes",
    blurb:
      "Without a matching rule, Suricata logs these as ordinary HTTP. Cernity names the request shape — and leaves the benign request alone.",
    limit:
      "A matched request shape does not establish successful exploitation, only that the request looked like an attack. Response code and reachability decide.",
  },
  "dns-detector": {
    title: "DNS behavior — DGA & NXDOMAIN bursts",
    blurb:
      "Suricata logs each DNS query/response. Cernity scores the domain string for algorithmic generation and aggregates failures per host — behavior no single record reveals.",
    limit:
      "DGA scoring is a heuristic; long random-looking CDN subdomains can score high. Confirmation needs the resolving process and whether the domain is attacker-controlled.",
  },
  "east-west-detectors": {
    title: "Windows / AD lateral movement",
    blurb:
      "A flat network never generates this, and Suricata raises no alert on it. Cernity aggregates the Kerberos/SMB/LLMNR metadata into named ATT&CK techniques.",
    limit:
      "These fire only on internal Windows/AD traffic reaching the sensor; a flat network correctly produces nothing. A pattern match is not a confirmed compromise.",
  },
  "coverage-detector": {
    title: "Sensor coverage health",
    blurb:
      "Suricata reports counters; it does not decide that the counters mean blind spots. Cernity turns drop and app-layer ratios into explicit coverage-degradation leads.",
    limit:
      "A collection-health warning, explicitly separated from a malicious-traffic claim. A missing stats stream is not itself proof of health.",
  },
  "anomaly-detector": {
    title: "Protocol-integrity anomalies",
    blurb:
      "Suricata emits anomaly events into a stream most pipelines ignore. Cernity promotes the security-relevant classes (app-layer, evasion-class stream) and ignores decoder noise.",
    limit:
      "Depends on Suricata’s anomaly logging being enabled; classification is by anomaly class, not deep analysis.",
  },
};

export const detectorContent: Record<string, { meaning: string; investigation: string[] }> = {
  // OT
  unauthorized_write: { meaning: "A write/control function code from a source not in the learned authorized-masters set for that outstation.", investigation: ["Confirm whether the source is a sanctioned EWS/HMI; if so, pin it.", "Check the outstation process context for the written registers/coils."] },
  program_download: { meaning: "A program-download / operating-mode-change code a normal polling loop never issues, from a non-EWS source.", investigation: ["Correlate with a change-management window.", "Verify the source is authorized to reprogram the PLC."] },
  new_master_pairing: { meaning: "A master that has never before spoken Modbus to this outstation — a novel control relationship.", investigation: ["Determine whether the pairing is a newly commissioned device.", "Check what function codes the new master issued."] },
  fc_enumeration: { meaning: "One source touching an abnormal breadth of function codes / unit IDs — reconnaissance of the outstation.", investigation: ["Identify the source host and process.", "Confirm whether a legitimate scan/inventory job is running."] },
  error_flag_spike: { meaning: "A burst of Modbus exceptions (illegal function / illegal data address) — probing or misconfiguration.", investigation: ["Check whether the source is mis-scoped polling or deliberate probing.", "Review the outstation for configuration drift."] },
  modbus_port_anomaly: { meaning: "A Modbus transaction on a port other than 502 — the protocol where it is not expected.", investigation: ["Confirm whether a non-standard Modbus port is sanctioned here.", "Inspect the endpoint offering Modbus off-port."] },
  // protocol
  ja4_rarity: { meaning: "A TLS client fingerprint the whole fleet has not seen before, past a warm-up.", investigation: ["Identify the client software and whether it is sanctioned.", "Check the destination and SNI for the rare client."] },
  cloud_staging: { meaning: "TLS SNI to a data-sharing / cloud-storage host — a common exfil staging destination.", investigation: ["Check whether the destination is an approved service for this host.", "Review volume and direction of the transfer."] },
  doh_detect: { meaning: "DNS-over-HTTPS/TLS to a resolver not on the approved list — DNS visibility evasion.", investigation: ["Confirm whether DoH is sanctioned for this host.", "Check what the host resolved before switching to DoH."] },
  tls_cert_anomaly: { meaning: "A self-signed or very short-lived certificate — a frequent C2/malware tell.", investigation: ["Inspect the certificate subject/issuer and the destination.", "Correlate with fingerprint rarity on the same flow."] },
  suspicious_ua: { meaning: "A non-browser tooling user-agent (curl, python-requests, powershell…) to an external host.", investigation: ["Identify the process generating the request.", "Check whether the destination is an approved API/CDN."] },
  ssh_bruteforce: { meaning: "Many short SSH sessions from one source to one destination — credential guessing.", investigation: ["Check the target’s auth logs for any success.", "Confirm the source is not a sanctioned automation host."] },
  icmp_exfil: { meaning: "Large ICMP volume to an external destination — tunneling / covert exfil.", investigation: ["Inspect ICMP payload sizes and periodicity.", "Confirm the destination is not a monitoring endpoint."] },
  port_proto_mismatch: { meaning: "Suricata detected an application protocol that contradicts the well-known service for the port.", investigation: ["Confirm whether tunneling on this port is sanctioned.", "Inspect the flow’s true application protocol."] },
  // http
  http_webshell: { meaning: "A request shape consistent with webshell / backdoor interaction.", investigation: ["Check the server response code and body size.", "Confirm whether the target path exists."] },
  http_sqli: { meaning: "SQL-injection syntax in the request — an injection attempt against the backend.", investigation: ["Check whether the query executed or errored server-side.", "Confirm the parameter reaches a database."] },
  http_cmd_injection: { meaning: "Shell-command syntax in the request — OS command injection attempt.", investigation: ["Check the server response for command output.", "Confirm the endpoint shells out to the OS."] },
  http_path_traversal: { meaning: "Directory-traversal / LFI syntax targeting files outside the web root.", investigation: ["Check whether the traversal returned file contents.", "Confirm the path handler sanitizes input."] },
  http_cred_in_url: { meaning: "Credentials passed in the URL query string — exposure and a weak-auth signal.", investigation: ["Confirm whether the endpoint accepts query-string auth.", "Rotate any exposed credential."] },
  http_suspicious_method: { meaning: "An uncommon/risky HTTP method (PUT, PROPFIND, WebDAV) — often used to plant files.", investigation: ["Check whether the method is enabled on the target.", "Confirm no file was written."] },
  // dns
  dga_domain: { meaning: "A queried name scoring high on algorithmic-generation heuristics — possible C2 rendezvous.", investigation: ["Resolve whether the domain belongs to a known CDN/cloud provider.", "Identify the process making the query."] },
  nxdomain_burst: { meaning: "One host generating many non-existent-domain answers in a window — DGA resolution / C2 discovery.", investigation: ["Identify the process generating the burst.", "Correlate with any domain that did resolve."] },
  // east-west
  kerberoasting: { meaning: "Many service-ticket requests with weak (RC4) encryption from one source — offline-crackable tickets.", investigation: ["Map the source to a host/account; confirm the SPN requests are expected.", "Review the targeted service accounts for weak passwords."] },
  password_spraying: { meaning: "One source failing authentication across many distinct accounts — low-and-slow credential attack.", investigation: ["Check the sprayed accounts for any successful logon.", "Confirm the source is not a misconfigured service."] },
  llmnr_poison: { meaning: "A host answering LLMNR/mDNS name queries it does not own — Responder-style credential capture.", investigation: ["Isolate the responder; confirm it is not a legitimate service.", "Check which names it answered and who queried."] },
  lateral_exec: { meaning: "Access to a remote-exec named pipe (svcctl / atsvc / winreg) — PsExec-style lateral movement.", investigation: ["Map source and destination hosts and the invoking account.", "Confirm whether remote administration is expected between them."] },
  // coverage / anomaly
  coverage_degraded: { meaning: "The sensor is losing visibility — dropping packets at capture, or reassembling almost no app-layer flows.", investigation: ["Check the sensor’s CPU / ring-buffer sizing.", "Verify the SPAN/tap delivers both directions."] },
  protocol_anomaly: { meaning: "A security-relevant Suricata protocol anomaly — unexpected app-layer data or an evasion-class stream overlap.", investigation: ["Pull the flow to see the endpoints and protocol.", "Determine whether it is a middlebox artifact or deliberate evasion."] },
};
