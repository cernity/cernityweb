const revision = "18174b8c2d8e29e2312d4f27064a2baa3456d9e3";
const source = (path: string) =>
  `https://github.com/cernity/cernityndr/blob/${revision}/${path}`;
export const integrations = [
  {
    id: "ndpi",
    name: "nDPI application and risk metadata",
    status: "No captured SIEM finding",
    baseline:
      "A compatible sensor integration can add ndpi metadata to its EVE flow. Baseline ingestion must retain that object to expose it in the SIEM.",
    output:
      "The behavioral source builds detector_id: ndpi_risk, category: malware, and an entities entry with type: ndpi_risk and the matched risk values. This is a separate analytic, not automatic copying of the complete ndpi object into every finding.",
    requirements:
      "A compatible Suricata/nDPI integration; real EVE output in the expected shape; the behavioral consumer; a candidate that passes lifecycle and delivery policy.",
    caveat:
      "The reviewed lifecycle treats standalone nDPI risk as metadata rather than automatic packet-capture confirmation. No ndpi_risk document appears in the available saved exports.",
    acceptance:
      "Capture a source flow containing ndpi, the resulting candidate and final revision, and the stored SIEM body. Include an authorized application with a risk flag to demonstrate how false leads are handled.",
    href: source("services/behavioral-detectors/app.py"),
  },
  {
    id: "ja3-ja4",
    name: "JA3 and JA4 client fingerprints",
    status: "No captured SIEM finding",
    baseline:
      "With supported fingerprint generation and handshake visibility, raw TLS events can contain tls.ja3 and tls.ja4. Those fields are useful in a baseline SIEM without Cernity too.",
    output:
      "The protocol detector prefers JA4 and falls back to JA3 for its ja4_rarity path. Relevant candidate entities can include a ja3 or ja4 value, the source IP, SNI, and Community ID. The detector name alone does not prove the underlying fingerprint was JA4.",
    requirements:
      "TLS logger, enabled supported fingerprint computation, captured handshake, protocol-detector state and warm-up, and delivery rather than suppression.",
    caveat:
      "Fingerprint rarity is not malware identification. An output field can exist in a candidate yet never reach the analyst if the finding is suppressed. No corresponding delivered fingerprint record was present in the available bundles.",
    acceptance:
      "Retain a real TLS input, the observed fingerprint, the preceding warm-up context, the final lifecycle decision, and the retrieved SIEM record. Test both expected software and a declared anomalous client.",
    href: source("services/protocol-detectors/app.py"),
  },
  {
    id: "dns-addon",
    name: "DNS observations and domain-level analysis",
    status: "Recorded output · legacy assurance",
    baseline:
      "The two legacy examples retain actual DNS v3 request bodies, queried names, resolver addresses, flow IDs, and Community IDs.",
    output:
      "The saved dns_tunnel finding includes a client IP and T1071.004; the saved beacon_fqdn finding includes a domain and rotating_ips. Neither preserves all raw DNS evidence inside the finding.",
    requirements:
      "Visible queries and relevant answers; compatible EVE format; DNS/behavioral consumers and state. Encrypted DNS contents are not automatically visible.",
    caveat:
      "These older bundles lack the newer export manifests and qualified completion metadata. Their source/baseline equality was checked locally. Passive DNS observations are not reverse-DNS enrichment.",
    acceptance:
      "Read the actual records above. For a new benchmark, retain paired answers, input manifests, replay mapping, completion accounting, and original SIEM documents.",
    href: "/proof/#dns",
  },
  {
    id: "reverse-dns",
    name: "Reverse DNS / PTR context",
    status: "No captured intel.rdns field",
    baseline:
      "An ordinary flow records an IP address. Passive DNS query logs may show names previously observed, but they are not a PTR lookup of that IP.",
    output:
      "On a successful lookup, finding-service can add intel.rdns keyed by the IP address. The returned hostname is the resolver result, not proof that the named service or organization owns the traffic.",
    requirements:
      "INTEL_RDNS enabled in the actual container, resolver access, an IP entity, and a successful PTR result. The reviewed code allows internal-address lookups through its configured resolver too.",
    caveat:
      "A missing field can mean disabled enrichment, no PTR result, a lookup failure, or downstream field loss. The saved SIEM exports contain no nonempty intel block.",
    acceptance:
      "Use a permitted address with a controlled PTR record and retrieve the resulting SIEM document. Also record a no-PTR case. Do not append a manually looked-up hostname to a historical finding and call it original output.",
    href: source("services/finding-service/intel.py"),
  },
  {
    id: "geoip",
    name: "GeoIP and ASN",
    status: "No captured geo field",
    baseline:
      "A flow carries addresses; location or network-owner enrichment in the baseline would depend on that SIEM’s own ingest pipeline.",
    output:
      "The source can add geo keyed by global IP, with country, asn, and as_org when the corresponding database lookup succeeds.",
    requirements:
      "Compatible local MaxMind-format databases, actual file mounts, GEOIP_DB and GEOIP_ASN_DB passed into finding-service, and an eligible globally routable IP entity.",
    caveat:
      "The synthetic documentation addresses in the primary cases are unsuitable positive tests for global-address GeoIP enrichment. Location is not attribution, and ASN ownership is not proof of malicious operation.",
    acceptance:
      "Capture the database version, eligible address, successful lookup, and received SIEM body. Do not invent a country or ASN for a documentation address.",
    href: source("services/finding-service/geoenrich.py"),
  },
  {
    id: "rdap",
    name: "Domain registration age",
    status: "No captured intel.domains field",
    baseline:
      "A DNS or SNI observation reports a name, not its registration date.",
    output:
      "Successful RDAP enrichment can attach intel.domains entries with age_days and nrd. This is distinct from how recently your sensor first saw a domain.",
    requirements:
      "A domain or SNI entity, INTEL_RDAP passed to finding-service, registry data and outbound access. INTEL_NRD_DAYS controls the classification threshold when passed through.",
    caveat:
      "The reviewed registrable-domain helper takes the last two labels; it is not a public-suffix-aware parser. Multi-label suffixes can produce the wrong lookup target. A young domain is not itself malicious.",
    acceptance:
      "Retain the queried domain, registry response provenance, configuration, and the exact SIEM field. Include a multi-label-suffix and missing-registration-date control.",
    href: source("services/finding-service/intel.py"),
  },
  {
    id: "fingerprint-names",
    name: "Fingerprint-to-tool naming",
    status: "No captured intel.fingerprints field",
    baseline:
      "Raw JA3/JA4 values can be searched directly. A human-readable label is a separate lookup.",
    output:
      "intel.fingerprints maps a JA3/JA4 entity value to an operator-supplied label when the local map matches. The bundled map is not a maintained guarantee of malware attribution.",
    requirements:
      "INTEL_FP_MAP, a readable mounted JSON map, the exact matching entity value, and final JSON delivery.",
    caveat:
      "The operator’s label may be wrong, stale, or shared by benign clients. Generic fingerprint entities and all JA4+ variants are not automatically handled by this JA3/JA4-specific function.",
    acceptance:
      "Record the map version and source, the exact fingerprint and label, and the received SIEM document. Keep the label’s origin visible.",
    href: source("services/finding-service/intel.py"),
  },
  {
    id: "reputation",
    name: "GreyNoise and VirusTotal context",
    status: "No captured reputation fields",
    baseline:
      "Your baseline SIEM may already have reputation enrichment. That must be disclosed in any comparison.",
    output:
      "The reviewed code can add intel.reputation for GreyNoise fields and intel.virustotal for vendor-count statistics. Those are separate provider outputs, not a single Cernity verdict.",
    requirements:
      "The corresponding API credentials passed into finding-service, allowed external access, a global IP entity, and a successful provider response.",
    caveat:
      "Provider absence or failure can leave the fields absent. A count of vendors is not calibrated certainty. Current subscriptions and rate limits are external dependencies.",
    acceptance:
      "Retrieve actual provider-backed fields from the SIEM, preserving provider identity and observation context while excluding credentials from exported evidence.",
    href: source("services/finding-service/intel.py"),
  },
  {
    id: "slips",
    name: "SLIPS behavioral / ML integration",
    status: "No captured SLIPS finding",
    baseline:
      "Suricata flow and other selected EVE topics feed the central eve-bridge, which writes input for SLIPS. There is no SLIPS output in the baseline unless separately installed there.",
    output:
      "The adapter maps a SLIPS alert into slips_ml or slips_intel, with entities describing the originating module, threat level, and description. The IP roles are attacker/victim in this adapter, unlike src/dst in many other detectors.",
    requirements:
      "Compatible upstream runtime and command, Redis, input/output volumes, enabled bridge topics, broker authentication, the adapter, and a finalized finding delivered to the SIEM.",
    caveat:
      "The reviewed overlay omits secure-bus credentials for its bridge and adapter. Unknown or missing module names fall through to slips_ml, so the label alone does not establish that a trained model generated the original evidence. The overlay is not a verified all-in-one installation.",
    acceptance:
      "Capture the actual SLIPS alert, module/model provenance, mapped candidate, final finding and original SIEM body. Include a threat-intelligence lookup control to distinguish lookup agreement from model evidence.",
    href: source("services/slips-adapter/slips_map.py"),
  },
  {
    id: "zeek",
    name: "Zeek packet forensics and JA4+",
    status: "SIEM field propagation gap",
    baseline:
      "Suricata EVE contains the fields its own parsers emitted. Optional central Zeek operates on a captured packet slice rather than inventing missing packets.",
    output:
      "The Zeek worker constructs conn, TLS, certificate, HTTP, SSH, file, SMB, and Kerberos summaries when those logs exist. It can extract JA3, JA4, JA4S, JA4H, and JA4SSH indicators; JA4X is present only in certificate details in the reviewed summary code.",
    requirements:
      "Working capture, object-store access, authenticated broker paths, compatible Zeek packages, valid packet evidence, and a finding delivery path that explicitly retains the desired fields.",
    caveat:
      "The reviewed apply_enrichment_result function merges evidence_refs and enrichment status, but not the worker’s summary or iocs objects into the final finding. The saved signature example instead shows TIMEOUT. It would be incorrect to display a fabricated fully enriched SIEM finding.",
    acceptance:
      "After resolving the delivery gap, retrieve a successful enriched revision from the SIEM and compare its actual fields against the Zeek result and referenced capture. Until then, source capability is not delivered-field proof.",
    href: source("services/finding-service/state_machine.py"),
  },
  {
    id: "files",
    name: "File hashes and YARA inspection",
    status: "No captured file finding",
    baseline:
      "Suricata fileinfo may contain file state, gaps, size, and hashes if logging and visibility permit. That is not the same as a central scan of the file bytes.",
    output:
      "Optional services can create file-related findings from hash matching or content rules. The exact detector, hash, match, completeness, and evidence reference must be inspected in a delivered record.",
    requirements:
      "Completeness-aware file metadata for whole-file matching; extracted bytes, transport, object access, rules, and running services for YARA.",
    caveat:
      "A partial file hash cannot establish identity of a complete malware artifact. No file/YARA finding was present in the available historical SIEM exports.",
    acceptance:
      "Use approved benign test artifacts and an explicit test rule. Retain file completeness, hash, rule version, scan output, and stored SIEM document; include a truncated-file control.",
    href: source("services/file-yara/scan.py"),
  },
  {
    id: "correlation",
    name: "Cross-detector correlation and response",
    status: "No captured correlated SIEM record",
    baseline:
      "Separate raw events or alerts remain separate unless the baseline SIEM correlates them. Existing SIEM analytics must be included in a fair evaluation.",
    output:
      "The source includes derived incident/corroboration candidates that reference contributing detections. SOAR integration is another output path, not evidence that containment took place.",
    requirements:
      "Running correlation/response services, their state and storage dependencies, authenticated inputs, compatible entity identities, and configured delivery or playbooks.",
    caveat:
      "A generated correlation label does not prove independent evidence, attack success, or response execution. A SIEM finding and a successfully executed response need separate receipts.",
    acceptance:
      "Show the contributing findings, correlation candidate, final SIEM document, and a separately captured response audit when response is claimed.",
    href: source("services/correlation-service/correlate.py"),
  },
  {
    id: "threat-intelligence",
    name: "Threat-intelligence matching and server fingerprints",
    status: "No captured threat_intel finding",
    baseline:
      "Suricata can expose IPs, certificate hashes, and client/server fingerprints when available. Rules or existing SIEM intelligence may already match some indicators.",
    output:
      "The threat-intel service builds threat_intel candidates from configured indicator matches. Its source also supports an operator-supplied C2 server-fingerprint list for observed JA3S, JA4S, or JARM values.",
    requirements:
      "Successfully loaded feeds or local lists, actual observable input values, authenticated consumers, and a finalized delivered finding.",
    caveat:
      "A consumer for a JARM value is not an active JARM scanner and does not mean stock Suricata produces JARM. Feed matching is distinct from reverse DNS and reputation enrichment. No threat_intel finding was present in the saved exports.",
    acceptance:
      "Use controlled indicators with documented provenance and retain the matched source field, list version, candidate, final finding, and original stored SIEM record. Disclose equivalent baseline matching.",
    href: source("services/threat-intel/app.py"),
  },
  {
    id: "coverage",
    name: "Capture coverage and protocol anomalies",
    status: "No captured coverage finding",
    baseline:
      "Suricata stats report counters where supported; anomaly events and stream-anomaly alerts report parser or protocol conditions. These are distinct event types.",
    output:
      "The coverage detector can produce coverage_degraded candidates from supported loss or parser-visibility counters. The anomaly detector can promote selected anomaly conditions.",
    requirements:
      "Stats and anomaly loggers, required fields, correctly routed topics, running consumers, and final delivery.",
    caveat:
      "A missing stats stream does not itself demonstrate healthy collection. Packet-capture APIs differ in their available counters. Stream anomalies are shown in the transfer examples, but no delivered coverage finding appears in these saved exports.",
    acceptance:
      "Retain original counters and known test visibility conditions, the resulting finding, and the received SIEM record. Separate a collection fault from a malicious-traffic claim.",
    href: source("services/coverage-detector/coverage.py"),
  },
  {
    id: "storage",
    name: "Telemetry retention, assets, and reconstruction",
    status: "Separate investigation outputs",
    baseline:
      "A SIEM can retain raw events and support searches over them. Retention scope and query capability are part of the baseline configuration.",
    output:
      "Optional central storage, asset resolution, and reconstruction services support retained telemetry and investigation views. A timeline or asset-store result is not automatically embedded in every SIEM finding.",
    requirements:
      "Deployed storage, authenticated consumers, schema initialization, retention policy, available identity observations, and an explicit analyst access path.",
    caveat:
      "Installing ClickHouse or MinIO does not prove that every source event is retained or that reconstructed context reaches the SOC. No complete asset/timeline SIEM attachment is demonstrated by the saved finding exports.",
    acceptance:
      "Retrieve the retained records and a scoped reconstruction result, then show the actual SIEM linkage if one is claimed. Verify missing data and access boundaries separately.",
    href: source("services/reconstruction/app.py"),
  },
];
