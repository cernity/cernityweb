---
title: "Where the services run and what scaling changes"
nav: "Placement & state"
order: 4
---

# Where the services run and what scaling changes

Start with one sensor and one central host to understand the boundaries. Moving services to multiple machines introduces network, authentication, state, storage, and partitioning requirements; it is not simply a matter of running more identical containers.

## The initial topology

| Location | Responsibilities | State to retain |
|---|---|---|
| Sensor | Suricata capture and EVE logging; Fluent Bit shipping. | Logger retention and shipper offsets. |
| Central core | Broker, detectors, finding lifecycle, delivery. | Broker data; configured detector state; delivery ledger and failed records. |
| SIEM | Ingestion, search, dashboards, case workflow. | Original documents and intended retention. |
| Optional storage/forensics hosts | Raw telemetry retention, captures, files, offline analysis. | Store-specific persistence and access controls. |

The core Compose defaults detector state to memory. Those services are not all stateless: a process restart can lose its rolling analysis window. Broker persistence and detector-state persistence solve different problems.

## What changes when workers move off-host

A remote worker needs a reachable advertised broker listener, suitable authentication, and trust for TLS. It must also reach any shared state or storage service it uses. A Docker service name on one machine is not automatically resolvable from another machine.

Do not reuse a produce-only sensor credential for a central consumer. Keep central pipeline credentials restricted to trusted central services or define appropriately scoped worker principals.

## Replicas require partition and state planning

Kafka consumer groups assign partitions among consumers. More replicas than useful partitions do not create more independent input lanes. Per-host analysis also depends on consistent keys and state ownership.

Shared Redis implementations exist, but every participating service must actually receive its backend and endpoint configuration. Merely placing `NDR_REDIS_URL` in a file does not prove the container receives it. Review the selected Compose environment mappings.

The repository includes `deploy/scale` and Helm resources as starting points. Their existence does not establish measured throughput, fault tolerance, or secure compatibility with every overlay.

## What to measure before expanding

Track source event production, shipper delivery failures, broker consumer lag, detector state growth, finding lifecycle backlog, SIEM delivery outcomes, and packet drops. Test a restart and an outage with traceable input before depending on a recovery claim.

A successful single-host replay demonstrates that specific path. It does not validate a clustered deployment or an analyst workload reduction.

Continue with [sensor transport](/docs/sensor-transport/), [capability dependencies](/docs/sensor-dependencies/), and [recorded evidence](/proof/).
