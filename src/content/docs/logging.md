---
title: "Operational logs, health, and delivery failures"
nav: "Logging & health"
order: 11
---

# Operational logs, health, and delivery failures

A service log explains what a process is doing. A Suricata event describes observed traffic. A Cernity finding is a security assessment. These are different streams, even if you store all three in a SIEM.

## Start with the component owning the failed hop

| Question | Component to inspect |
|---|---|
| Are packets being observed and parsed? | Suricata capture statistics, parser output, and service logs. |
| Are EVE files being read and shipped? | Fluent Bit input and Kafka-output errors. |
| Can the broker accept and retain messages? | Redpanda health, authentication, ACLs, storage, and topics. |
| Are consumers processing the required events? | Detector startup, consumer lag, errors, and input event types. |
| Did a candidate finalize, suppress, or await evidence? | finding-service and the finding's lifecycle fields. |
| Did the selected sink accept the finding? | findings-forwarder, delivery ledger, failed-delivery records, and the actual receiving SIEM. |

## Inspect service logs

On the sensor:

```bash
docker logs --tail 100 cernity-fluent-bit
```

On central:

```bash
docker compose --project-name cernity --env-file .env \
  -f deploy/central/docker-compose.yml logs --tail 100 \
  behavioral-detectors finding-service findings-forwarder
```

Look for the specific error before changing thresholds. File-not-found, TLS failure, authentication failure, missing topic authorization, and a rejected SIEM document are different faults.

## Shared logging settings

Services using `ndr_runtime.setup_logging` support `LOG_LEVEL`, `LOG_FORMAT`, and a heartbeat controlled by `HEARTBEAT_SECS`. The reviewed defaults are INFO, JSON, and a periodic heartbeat. Third-party containers and services with their own logger can differ.

An INFO heartbeat proves that process code is running, not that new sensor events reached it or that a SIEM accepted findings. Enable DEBUG only when the additional detail is needed and handle any exposed event data appropriately.

Compose must pass each environment variable into the target service. Changing a central `.env` entry that the service never receives has no effect.

## Liveness is not readiness or end-to-end success

Services using the metrics helper can expose `/healthz`, `/readyz`, and `/metrics`, commonly on container port 9108. Verify the specific service and its bindings; the central Compose does not publish every metrics endpoint on the host.

Liveness indicates the process is responding. Readiness reflects the checks that service actually implements. Neither alone establishes traffic coverage, detector effectiveness, or a successfully parsed SIEM event.

## Retention and failure artifacts

The Compose files cap container stdout logs. That does not cap every data volume: Suricata EVE retention, broker storage, shipper offsets, captures, file-sink output, and delivery ledgers have independent policies.

The reviewed forwarder can write exhausted deliveries to its configured dead-letter directory. Treat those records as failed delivery, preserve them for diagnosis, and follow a tested reprocessing procedure. Restarting a service is not a guarantee that every terminal dead-letter obligation will automatically retry.

## A useful success check

Trace one known test observation through collection and a relevant finding through delivery. Retrieve the actual SIEM document, match its identity and revision, and inspect its fields. Keep the source record so a later field mismatch can be located at the right boundary.

See [transport troubleshooting](/docs/sensor-transport/#find-the-broken-hop), [SIEM formats](/docs/siem-integrations/), and [evidence collection](/docs/evidence-capture/).
