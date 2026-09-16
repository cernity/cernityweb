export const guideGroups = [
  {
    title: "Learn to read the evidence",
    label: "01 / ANALYST FOUNDATIONS",
    description:
      "Understand the vocabulary, inspect the records, and build a defensible investigation.",
    guides: [
      {
        slug: "reading-records",
        description:
          "Packets, flows, alerts, findings, revisions, scores, and the fields that connect them.",
      },
      {
        slug: "analyst-workflow",
        description:
          "Separate observations from interpretations and test competing explanations.",
      },
      {
        slug: "how-it-works",
        description:
          "Follow one observation from a mirrored packet to a stored SIEM finding.",
      },
      {
        slug: "ndr-coverage",
        description:
          "What is demonstrated, what is implemented, and what your deployment must supply.",
      },
      {
        slug: "capabilities",
        description:
          "The complete, source-verified catalog of every Cernity detection, enrichment, evidence, and reasoning capability.",
      },
    ],
  },
  {
    title: "Install and connect your sensor",
    label: "02 / FIRST DEPLOYMENT",
    description:
      "Each step identifies the machine, configuration, and checkpoint you need.",
    guides: [
      {
        slug: "getting-started",
        description:
          "Start central Cernity, configure the sensor, verify the pipeline, and connect a SIEM.",
      },
      {
        slug: "sensor-transport",
        description:
          "How Fluent Bit reads EVE files and sends authenticated telemetry to Redpanda.",
      },
      {
        slug: "deploy-sensor",
        description:
          "Set file mounts, credentials, CA trust, sensor identity, and the shipper service.",
      },
      {
        slug: "suricata-config",
        description:
          "Configure EVE event types, fingerprints, statistics, and file metadata.",
      },
      {
        slug: "sensor-dependencies",
        description:
          "Map every capability to its sensor input, central service, and delivery prerequisites.",
      },
      {
        slug: "placement",
        description:
          "Understand service boundaries, in-memory state, and the requirements for scaling.",
      },
    ],
  },
  {
    title: "Add context and verify delivery",
    label: "03 / INTEGRATIONS",
    description:
      "Understand where optional fields originate and verify what reaches your SOC.",
    guides: [
      {
        slug: "siem-integrations",
        description:
          "JSON versus CEF, receiving-side parsing, finding revisions, and exact document retrieval.",
      },
      {
        slug: "enrichment",
        description:
          "Reverse DNS, registration age, GeoIP, ASN, fingerprint naming, and reputation.",
      },
      {
        slug: "ml-detection",
        description:
          "SLIPS data flow, secure-bus wiring, module provenance, and integration limitations.",
      },
      {
        slug: "suricata-zeek-parity",
        description:
          "Overlapping protocol visibility and the optional Zeek evidence delivery boundary.",
      },
      {
        slug: "evidence-capture",
        description:
          "Collect comparable raw and enriched SIEM records with identifiers and provenance.",
      },
    ],
  },
  {
    title: "Operate and extend",
    label: "04 / OPERATIONS",
    description: "Maintain the pipeline and work with the implementation.",
    guides: [
      {
        slug: "logging",
        description:
          "Inspect service health, operational logs, and delivery failures.",
      },
      {
        slug: "development",
        description:
          "Find the implementation, contracts, and development workflow.",
      },
    ],
  },
];
export const orderedGuides = guideGroups.flatMap((group) => group.guides);
