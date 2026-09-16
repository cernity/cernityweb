---
title: "Suricata and Zeek: overlapping visibility, different records"
nav: "Suricata & Zeek"
order: 7
---

# Suricata and Zeek: overlapping visibility, different records

Suricata and Zeek can both describe network activity, but their record formats, parsers, scripts, and field availability differ. Cernity's architecture does not require claiming complete parity between them.

## Compare the concepts, not just the field names

| Investigation question | Suricata source | Zeek source when configured and observed |
|---|---|---|
| Who connected to whom? | EVE flow endpoints and counters. | Connection logs and identifiers. |
| What name was queried? | EVE DNS records. | DNS logs. |
| What TLS metadata was visible? | EVE TLS records and enabled fingerprints. | TLS/certificate logs and installed fingerprint packages. |
| What HTTP request was observed? | EVE HTTP metadata. | HTTP logs. |
| What file was reconstructed? | File metadata and optional file store. | File-analysis logs and configured extraction/hashing. |
| What condition was flagged? | Signature alerts and anomaly events. | Notices and script-specific output. |

A Zeek connection record is not automatically an alert, just as a Suricata flow record is not an alert. A logger may be enabled but still lack the data if the capture missed a handshake or the content was encrypted.

## Cernity's core path uses EVE

The normal pipeline ships Suricata EVE to central detectors. It can produce behavioral leads without running Zeek continuously on the sensor. This keeps the basic input path explicit: Suricata → files → Fluent Bit → broker → analytics.

## The optional Zeek path uses captured packets

Cernity's optional worker runs Zeek over a packet slice and builds summaries from the logs that were produced. Richer parser output is conditional on the captured bytes, enabled scripts, packages, and successful execution.

The reviewed worker computes summaries and indicators, but the finding lifecycle currently merges evidence references and status rather than copying all those details to the final finding. The [integration audit](/proof/#integration-zeek) describes this propagation gap. Do not infer that a Zeek field is available to the SOC merely because it exists inside the worker.

## Pivot using supported evidence

Community ID can help connect records from tools observing compatible flow tuples with the same seed. It does not recover a missing capture or remove NAT and observation-point differences. Preserve source identifiers and observation bounds alongside it.

For a claimed capability, compare actual records from your deployed builds. A source implementation or a unit test is useful engineering evidence, but is different from a successful SIEM ingestion record.

Continue with [reading records](/docs/reading-records/) and [sensor dependencies](/docs/sensor-dependencies/).
