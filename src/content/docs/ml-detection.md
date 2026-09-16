---
title: "SLIPS: integration, provenance, and delivery checks"
nav: "SLIPS integration"
order: 9
---

# SLIPS: integration, provenance, and delivery checks

Cernity includes an optional central integration for SLIPS. It bridges existing EVE telemetry into SLIPS and maps SLIPS alerts into Cernity candidates. **No `slips_ml` or `slips_intel` finding was present in the saved SIEM exports reviewed for this website.** Configuration and mapping support are not a substitute for a captured successful result.

## The data path

```text
Suricata EVE topics
    ↓ eve-bridge (central)
Shared growing eve.json
    ↓ SLIPS plus its own Redis (central)
SLIPS alerts.json
    ↓ slips-adapter (central)
ndr.finding.candidate.v1
    ↓ finding-service → findings-forwarder
Your SIEM's stored finding
```

No additional SLIPS process runs on the sensor in this design. However, the sensor must supply the observations that SLIPS needs. The default bridge topics are flow and raw; DNS, TLS, and other dedicated topics are not included simply because they exist on the bus.

## Required pieces

| Component | What to verify |
|---|---|
| `eve-bridge` | Authenticated topic consumption, selected topic list, input-file growth, and rotation behavior. |
| SLIPS runtime | The chosen image's invocation, input format support, Redis connection, enabled modules, and output path. |
| `slips-redis` | Actual connectivity and persistence requirements for the intended evaluation. |
| Shared volumes | SLIPS reads the bridge output and the adapter sees the actual alerts file. |
| `slips-adapter` | Successfully parsed new alerts and authenticated candidate publication. |
| Finding lifecycle | Final delivery versus suppression or enrichment routing. |
| SIEM | Original retrieved document, not merely a producer log line. |

The supplied overlay uses an upstream `latest` image and explicitly describes its command as version-sensitive. Pin and validate the actual runtime before calling it a repeatable deployment.

## Secure-bus wiring

The reviewed `deploy/overlays/slips.yml` does not pass central SASL credentials into the bridge and adapter. Both use Cernity's shared runtime, so add a local override such as `deploy/overlays/slips-auth.local.yml`:

```yaml
services:
  eve-bridge:
    environment:
      NDR_BUS_SASL_MECHANISM: SCRAM-SHA-512
      NDR_BUS_SASL_USER: ${CERNITY_BUS_CENTRAL_USER}
      NDR_BUS_SASL_PASSWORD: ${CERNITY_BUS_CENTRAL_PASSWORD}
  slips-adapter:
    environment:
      NDR_BUS_SASL_MECHANISM: SCRAM-SHA-512
      NDR_BUS_SASL_USER: ${CERNITY_BUS_CENTRAL_USER}
      NDR_BUS_SASL_PASSWORD: ${CERNITY_BUS_CENTRAL_PASSWORD}
```

This addresses that specific internal-listener configuration gap. It does not verify the upstream SLIPS command, input/output behavior, or end-to-end delivery.

After those prerequisites are validated, the Compose invocation uses all files explicitly:

```bash
docker compose --project-name cernity --env-file .env \
  -f deploy/central/docker-compose.yml \
  -f deploy/overlays/slips.yml \
  -f deploy/overlays/slips-auth.local.yml config --quiet
```

Use the same files with your normal `up -d --build` workflow for the controlled integration deployment. Keep the credentials central.

## What the adapter actually maps

The source maps an IDEA-style alert into a candidate using its source/target IPs, category, confidence, threat level, and description. Its entities use `attacker` and `victim` roles rather than the `src` and `dst` roles used by several other detectors.

Known blocklist or threat-intelligence module names map to `slips_intel`. Other modules, including missing or unknown module names, fall through to `slips_ml`. Therefore **the `slips_ml` label alone does not prove a trained model generated the evidence**. Preserve the original module and model provenance in your test.

The mapping's category and MITRE fields are translations, not independent confirmations. Unknown categories can become `anomaly` without a technique mapping.

## Things that can hide a result

The adapter tails from the end of an existing alert file, so an old pre-existing alert is not a reliable startup test. Input rotation, output framing, module thresholds, missing topic types, authentication, and lifecycle suppression can each affect the outcome.

The CEF formatter looks for `src` and `dst` roles and sends only a reduced set of fields. A full JSON path is more appropriate for verifying the original SLIPS module, description, and entity roles.

## A defensible demonstration

Retain a real SLIPS alert with its module/model identity, the mapped candidate, the final revision, and the retrieved SIEM document. Include a lookup-based control, a benign behavior control, and any suppressed or failed output. A mocked adapter unit test proves mapping logic, not the behavior of the complete system.

Correlation with a heuristic is a separate service and requires its own deployment and evidence. Two detectors agreeing does not automatically establish independent information or a calibrated probability.

References: [overlay](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/deploy/overlays/slips.yml), [mapping implementation](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/services/slips-adapter/slips_map.py), and [evidence requirements](/docs/evidence-capture/).
