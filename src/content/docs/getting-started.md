---
title: "Install Cernity: central host, sensor, and SIEM"
nav: "First installation"
order: 1
---

# Install Cernity: central host, sensor, and SIEM

This path starts with **one existing Suricata sensor and one separate Linux Docker host**. You will start the central services, configure the sensor's EVE logs, install its shipper, and verify output before connecting a SIEM.

Commands below were checked against Cernity source revision `18174b8`. They are configuration guidance, not a claim that a fresh deployment was executed for this website. Image tags in the repository include `latest`; record your resolved image digests and validate compatibility for a repeatable deployment.

## Know which machine you are using

| Label used below | Where to run the command |
|---|---|
| **CENTRAL** | The host that will run the broker, detectors, and forwarder. |
| **SENSOR** | The host where Suricata writes its EVE files. |
| **MONITORED CLIENT** | A test machine whose traffic is actually visible to the sensor. |
| **SIEM** | Your existing log platform and its ingestion configuration. |

The sensor sends JSON telemetry to central. It does not send a continuous packet capture. Read [how data gets off the sensor](/docs/sensor-transport/) if this boundary is unclear.

## Before you install

You need a working Suricata capture point, permission to edit its logger configuration, Docker with Compose v2 on the central host and sensor, Git, and OpenSSL on central. The checks below also use `jq` on the sensor. The replay option uses Compose `include`, which requires a Compose release supporting that feature.

Confirm the central host has a stable address reachable from the sensor on TCP 19092. The certificate and the broker's advertised address must use that address. A hostname is preferable when you manage matching DNS and certificates; an IP address also works with a certificate containing its IP SAN.

There is no measured production sizing guarantee in these instructions. The core, optional storage, and SLIPS have different resource needs. Begin with the core and measure memory, consumer lag, packet loss, and delivery before adding overlays.

## 1. CENTRAL: prepare the checkout and settings

```bash
git clone https://github.com/cernity/cernityndr.git
cd cernityndr
cp cernity.env.example .env
chmod 600 .env
docker compose version
```

Edit `.env`. This example uses the illustrative central address `192.168.50.30`; replace it with your own reachable address:

```dotenv
CERNITY_ADVERTISE_HOST=192.168.50.30
REDPANDA_BOOTSTRAP=redpanda:9092
CERNITY_SINK=file
NDR_STATE_BACKEND=memory
NDR_TENANT=default
NDR_SENSOR=sensor-1
CLICKHOUSE_PASSWORD=
```

Keep the internal `redpanda:9092` address for central containers. Do not copy the sensor's external listener address into this setting unless you deliberately redesign the network path. Leave the ClickHouse password empty when no ClickHouse deployment is configured.

## 2. CENTRAL: generate the broker certificate and credentials

Run the repository helper with the **same address** as `CERNITY_ADVERTISE_HOST`:

```bash
CERNITY_ADVERTISE_HOST=192.168.50.30 ./deploy/security/gen-bus-certs.sh
```

The helper creates `deploy/security/secrets/` and prints settings for three separate principals. Add the generated values to central `.env`:

- `CERNITY_BUS_USER` and `CERNITY_BUS_PASSWORD`: the sensor publisher.
- `CERNITY_BUS_CENTRAL_USER` and `CERNITY_BUS_CENTRAL_PASSWORD`: central pipeline access.
- `CERNITY_BUS_ADMIN_USER` and `CERNITY_BUS_ADMIN_PASSWORD`: broker administration.

Keep the central and admin passwords on central. Sensors receive only their publisher credential and the public `ca.crt`. Do not distribute `ca.key` or `broker.key`.

The helper may report that it could not set the broker key's ownership. The reviewed image configuration expects UID/GID 101; confirm your chosen image, then apply the ownership specified by the helper. For that UID/GID:

```bash
sudo chown 101:101 deploy/security/secrets/broker.key deploy/security/secrets/broker.crt
```

The helper does not silently rotate existing certificates. If it reports they already exist, retain the matching credentials or follow an intentional rotation procedure; rerunning is not a password recovery mechanism.

## 3. CENTRAL: start and inspect the core

Use a stable project name and an explicit environment file throughout this guide:

```bash
docker compose --project-name cernity --env-file .env \
  -f deploy/central/docker-compose.yml config --quiet

docker compose --project-name cernity --env-file .env \
  -f deploy/central/docker-compose.yml up -d --build

docker compose --project-name cernity --env-file .env \
  -f deploy/central/docker-compose.yml ps
```

`config --quiet` checks Compose interpolation and structure without printing the expanded secrets. It does not test network access, certificate permissions, or application behavior.

Inspect startup errors if any service restarts:

```bash
docker compose --project-name cernity --env-file .env \
  -f deploy/central/docker-compose.yml logs --tail 100 redpanda finding-service findings-forwarder
```

**Checkpoint:** broker healthy; detector, lifecycle, and forwarder processes running without authentication errors. An empty file sink is expected until a deliverable finding exists. “Container running” is not an end-to-end success result.

## 4. SENSOR: make Suricata produce the right inputs

Follow [Suricata configuration](/docs/suricata-config/) to merge the EVE output blocks into the existing configuration. Keep the existing interfaces, rules, network variables, and other outputs that your deployment needs.

The supplied shipper expects:

```text
/var/log/suricata/eve-alerts.json
/var/log/suricata/eve-nsm.json
```

Validate before restarting on a typical Linux package installation:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
sudo tail -n 5 /var/log/suricata/eve-nsm.json | jq .
```

Appliance and container deployments may use other paths or service controls. Apply the equivalent validation through that deployment's supported mechanism.

**Checkpoint:** valid JSON observations are written for traffic crossing the capture point. Alerts are not guaranteed for ordinary traffic. The [dependency matrix](/docs/sensor-dependencies/) explains which capabilities remain unavailable when an event type is missing.

## 5. SENSOR: install the shipper

Follow [install the sensor shipper](/docs/deploy-sensor/) for the exact environment file, public CA placement, identity override, and startup command. This step is required even though central is already running.

The sensor initiates an authenticated TLS connection to the central host on TCP 19092. A local EVE file that grows but is not being shipped will never reach a central detector.

## 6. Verify fresh telemetry separately from detection

On a **MONITORED CLIENT**, make a normal request to an approved test destination. For example, if permitted by your network policy:

```bash
curl -I https://example.com
```

On the **SENSOR**, inspect new EVE records and Fluent Bit logs. Use the client address and the actual request to identify the records. Running the request on central proves nothing about sensor visibility unless that path is mirrored.

This checks observation and shipping. A harmless web request is not expected to guarantee a threat finding. Use [pipeline troubleshooting](/docs/sensor-transport/#find-the-broken-hop) to work through each hop before changing detection thresholds.

## 7. Optional CENTRAL-only replay: verify a known test input

The bundled feeder bypasses the sensor and ships saved EVE directly to the broker. It can exercise central processing, but **cannot validate your live capture, Suricata configuration, file mounts, or Fluent Bit transport**.

The reviewed quickstart service omits authentication variables even though the central broker enables authentication. Create `deploy/quickstart/auth.local.yml` with this explicit override:

```yaml
services:
  eve-feeder:
    environment:
      NDR_BUS_SASL_MECHANISM: SCRAM-SHA-512
      NDR_BUS_SASL_USER: ${CERNITY_BUS_USER}
      NDR_BUS_SASL_PASSWORD: ${CERNITY_BUS_PASSWORD}
```

After the core is healthy, run the feeder in the **same project**:

```bash
docker compose --project-name cernity --env-file .env \
  -f deploy/quickstart/docker-compose.yml \
  -f deploy/quickstart/auth.local.yml run --rm --no-deps eve-feeder
```

It uses the private internal broker listener, which authenticates with SASL but does not use TLS. The external sensor connection continues to use TLS. The feeder must report successful publication without an authentication error; a nonzero exit is a failed replay.

Read central output:

```bash
docker compose --project-name cernity --env-file .env \
  -f deploy/central/docker-compose.yml exec findings-forwarder \
  sh -c 'tail -n 5 /out/findings.jsonl'
```

Look for a relevant `detector_id`, `finding_id`, lifecycle, and entities. If no file exists, inspect detector and forwarder logs rather than assuming installation succeeded. A fixture finding is a functional test, not an independent accuracy measurement.

## 8. CENTRAL and SIEM: configure delivery

Once you have a readable file finding, configure one adapter using [SIEM delivery and record formats](/docs/siem-integrations/). Ensure the receiving endpoint, token, index or table, and parser are ready on the SIEM side.

Recreate the forwarder after editing `.env`:

```bash
docker compose --project-name cernity --env-file .env \
  -f deploy/central/docker-compose.yml up -d findings-forwarder
```

**Final checkpoint:** find the same `finding_id` in the SIEM, inspect the document body, and verify that its entities and lifecycle fields survived parsing. A sender log reporting a POST is weaker evidence than retrieving the stored SIEM record.

## What to save from your first successful deployment

Record the Cernity commit, image digests, Suricata version, enabled event types, sensor identity, and one verified finding ID. Retain source and received records with appropriate access controls. That gives you a baseline for upgrades and for diagnosing whether a missing field was never observed, lost in transport, or omitted by the SIEM adapter.

Continue with [reading records](/docs/reading-records/) and the [analyst workflow](/docs/analyst-workflow/).
