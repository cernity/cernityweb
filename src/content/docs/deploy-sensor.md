---
title: "Install the sensor shipper"
nav: "Install the sensor shipper"
order: 5
---

# Install the sensor shipper

Run these steps on the machine where Suricata writes its EVE files. Central Cernity must already be configured using the [installation guide](/docs/getting-started/).

This installs **Fluent Bit**, not another packet inspection engine. Its job is to read Suricata's JSON and send it to central. The optional capture agent is a separate component.

## 1. Prepare the checkout and public CA

```bash
git clone https://github.com/cernity/cernityndr.git
cd cernityndr
sudo install -d -m 0755 /etc/cernity
```

Transfer `deploy/security/secrets/ca.crt` from central through your normal trusted administration channel. If it has been placed in the current directory as `ca.crt`:

```bash
sudo install -m 0644 ca.crt /etc/cernity/ca.crt
```

This is a public verification certificate. It is not the CA private signing key. The separate sensor username and password authenticate the publisher.

## 2. Create the sensor environment file

Create `sensor.env` in the checkout root. Replace the illustrative address, identity, and password:

```dotenv
REDPANDA_BOOTSTRAP=192.168.50.30:19092
SURICATA_LOG_DIR=/var/log/suricata
SURICATA_EVE_ALERTS=/var/log/suricata/eve-alerts.json
SURICATA_EVE_NSM=/var/log/suricata/eve-nsm.json
CERNITY_BUS_CA=/etc/cernity/ca.crt
CERNITY_BUS_USER=cernity-sensor
CERNITY_BUS_PASSWORD=REPLACE_WITH_GENERATED_SENSOR_PASSWORD
NDR_TENANT=default
NDR_SENSOR=sensor-1
LOG_LEVEL=info
```

```bash
chmod 600 sensor.env
```

Keep this file out of version control. Use a unique `NDR_SENSOR` for each sensor. For an initial single-sensor setup, the names above match the central defaults.

`SURICATA_LOG_DIR` refers to the host directory. The two EVE variables refer to container paths. See the [mount diagram](/docs/sensor-transport/#the-files-and-mounts-must-agree) if your logs live elsewhere.

## 3. Pass identity into the container

In the reviewed Cernity revision, `route.lua` uses identity environment variables but the sensor Compose service does not pass them through. Create `deploy/sensor/identity.local.yml`:

```yaml
services:
  fluent-bit:
    environment:
      NDR_TENANT: ${NDR_TENANT:-default}
      NDR_SENSOR: ${NDR_SENSOR:-sensor-1}
```

This is an explicit correction in your local deployment configuration. An `.env` value affects a container only if Compose passes it into the service or a mounted configuration uses it.

## 4. Start Fluent Bit

```bash
docker compose --project-name cernity-sensor --env-file sensor.env \
  -f deploy/sensor/docker-compose.yml \
  -f deploy/sensor/identity.local.yml config --quiet

docker compose --project-name cernity-sensor --env-file sensor.env \
  -f deploy/sensor/docker-compose.yml \
  -f deploy/sensor/identity.local.yml up -d fluent-bit

docker logs --tail 100 cernity-fluent-bit
```

Look for file-open, TLS, SASL, authorization, or broker connection errors. A lack of obvious errors is not proof that the intended event reached its consumer.

The named `cernity-fluentbit-state` volume keeps file offsets. Retain the same Compose project name so later commands operate on the same deployment and volumes.

## 5. Verify the actual path

Generate fresh permitted traffic from a monitored client. Confirm a corresponding event in the host EVE file. Confirm the shipper is reading the correct mounted file and is not reporting output errors. Then inspect the central consumer behavior and a resulting known test finding when you intentionally exercise detection.

New file readers start at the tail by default. Existing historical lines may not be replayed. Do not assume an idle detector means transport is broken, or that an active shipper means every required protocol field is present.

## Restart after a configuration change

Run the same `up -d fluent-bit` command with both Compose files after editing `sensor.env`. A plain container restart may retain its old environment. Confirm that the resulting events carry the intended identity.

If you change Suricata filenames, update the shipper paths too. If you rotate the CA or broker certificate, coordinate the trust update before expecting sensors to reconnect.

## What about packet capture and Zeek?

The `capture-agent` profile is not required to send EVE telemetry. It needs write access to capture output, access to the Suricata control socket, broker permissions to receive capture instructions, and an object-store upload credential.

The reviewed default publisher credential cannot read capture instructions, and the optional central overlay does not consistently pass secure-bus credentials. These are separate integration dependencies, not steps to skip silently. Read [optional packet forensics](/docs/sensor-dependencies/#optional-packet-forensics) before enabling the profile.

Sources: [sensor Compose](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/deploy/sensor/docker-compose.yml), [Fluent Bit configuration](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/deploy/fluent-bit/fluent-bit.conf), and [routing function](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/deploy/fluent-bit/route.lua).
