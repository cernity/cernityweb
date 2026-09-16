---
title: "Configure Suricata: the inputs each capability needs"
nav: "Configure Suricata"
order: 6
---

# Configure Suricata: the inputs each capability needs

Cernity cannot recover a field that your sensor did not observe or log. Configure capture visibility first, event output second, and optional fields third. Then check a real record before enabling a dependent analytic.

This guide uses the **Suricata 8 DNS version 3 format**. Check `suricata --build-info` and the documentation matching your installed build. A configuration fragment is not a complete `suricata.yaml` and must be merged into the appropriate existing sections.

## 1. Keep the capture and rule configuration working

Retain your existing interfaces, capture mode, rules, `HOME_NET`, and other deployment settings. `HOME_NET` influences rules that reference it; it is not automatically synchronized to every Cernity detector's internal-network logic.

A sensor watching only internet egress will not see every internal SMB or RDP connection. Bidirectional visibility matters for protocol parsing. Capture drops, packet truncation, and encryption can make fields unavailable even when a logger is enabled.

## 2. Enable the EVE inputs used by the supplied shipper

Merge these entries into the existing `outputs` list. Do not create a second top-level `outputs` key. The filenames below assume your Suricata log directory is `/var/log/suricata`.

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve-alerts.json
      community-id: true
      community-id-seed: 0
      types:
        - alert

  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve-nsm.json
      community-id: true
      community-id-seed: 0
      types:
        - flow
        - dns:
            version: 3
        - tls:
            extended: yes
        - http:
            extended: yes
        - ssh
        - files:
            force-hash: [sha256]
        - anomaly
        - stats:
            totals: yes
            threads: no
        - smb
        - krb5
        - dcerpc
```

`files` is the logger name in configuration; the emitted `event_type` is `fileinfo`. `stats` supplies coverage monitoring. SMB, Kerberos, and DCE/RPC records need the corresponding visible protocols and supported parsers; adding them does not create missing traffic.

If you retain a separate existing `eve.json` for another consumer, ensure the Cernity shipper does not also read it and duplicate these observations.

## 3. Understand required versus optional inputs

| Input or setting | What it contributes | What happens without it |
|---|---|---|
| `flow` events | Connection bounds, addresses, ports, directional counts. | Flow-based beacon, transfer, and fan-out analysis lacks its main input. |
| `alert` events and a loaded ruleset | Existing Suricata detections for promotion and consolidation. | No signature hits can be promoted from an empty alert stream. |
| DNS events | Query names, answers, response codes, DNS-derived context. | DNS-specific analytics and observed domain-to-IP association lose visibility. |
| TLS events with fingerprints | Handshake metadata for rarity or intelligence matching. | A detector cannot invent a fingerprint from a plain TCP flow. |
| `community-id` | A cross-tool flow pivot when retained on the finding. | Some correlations become harder; it is not a universal prerequisite for every detector. |
| `stats` | Capture-drop and parser-visibility counters used by coverage-detector. | No stats-based coverage assessment from this input. Silence is not proof of healthy visibility. |
| File hashes | Hash matching when a file is actually observed and completeness criteria are met. | No whole-file hash conclusion from an absent hash. |
| File bytes and packet captures | Optional offline forensics and content inspection. | Logging metadata alone does not provide file contents. |

See the [full capability dependency matrix](/docs/sensor-dependencies/) for central services and output limitations.

## 4. Enable JA3 and JA4 only with supported builds

Merge these keys into the existing TLS parser section:

```yaml
app-layer:
  protocols:
    tls:
      ja3-fingerprints: yes
      ja4-fingerprints: yes
```

JA3 and JA4 characterize handshake behavior. They can be shared by legitimate and malicious software, and can change with implementation or configuration. They do not uniquely identify a person, device, or malware family.

Observe a new TLS handshake and inspect the actual TLS record. Fingerprints may be absent when the relevant handshake was missed. Extended TLS logging and enabled fingerprint generation serve different purposes: one exposes metadata, the other enables the fingerprint computation.

Suricata's [JA3/JA4 reference](https://docs.suricata.io/en/suricata-8.0.3/rules/ja-keywords.html) and [EVE format reference](https://docs.suricata.io/en/suricata-8.0.3/output/eve/eve-json-format.html) describe the supported fields. Cernity's reviewed protocol detector prefers JA4 for client rarity and falls back to JA3; server fingerprint handling is a separate path.

## 5. nDPI is an optional sensor integration

Cernity's behavioral detector contains consumers for `ndpi.flow_risk` and related nDPI metadata. That does not mean a stock Suricata package emits those fields.

Use a compatible nDPI integration for your exact Suricata build and verify its field shape in EVE. A guessed plugin path or compiler flag is not a portable installation instruction. Do not add an arbitrary `/usr/lib/suricata/ndpi.so` path to a working sensor.

A useful acceptance check is a real `flow` record containing the expected `ndpi` object, followed by a scoped detector finding and the retrieved SIEM document. The [optional integration evidence](/proof/#optional-integrations) explains what has and has not been captured. An nDPI risk classification is evidence to assess, not automatic proof of compromise.

## 6. Hashing is not file extraction

The `files.force-hash` setting requests a hash for logged files. It does not provide a central file object for YARA to scan. Whole-file matching also needs completeness: a partial or gapped file is not the same artifact as the complete original.

If you intentionally deploy file extraction, the file-store block is another entry **under `outputs`**, not a separate top-level key:

```yaml
outputs:
  # Retain the EVE entries above in this same list.
  - file-store:
      version: 2
      enabled: yes
      dir: filestore
      force-filestore: yes
```

This stores eligible observed files on the sensor. It can use substantial storage and can capture sensitive content. Central inspection additionally needs a supported upload path, credentials, retention, the file inspection services, and retrievable evidence. Encrypted payloads are not extracted merely by enabling this output.

## 7. Validate configuration before service restart

For a typical Linux package installation:

```bash
suricata --build-info
sudo suricata -T -c /etc/suricata/suricata.yaml
```

If validation fails, fix the configuration or unsupported logger option before restarting. Use the service controls appropriate to your deployment; for a systemd installation:

```bash
sudo systemctl restart suricata
sudo journalctl -u suricata -n 50 --no-pager
```

## 8. Inspect real output

After fresh traffic crosses the mirror, sample the files. These commands use `jq`:

```bash
sudo tail -n 200 /var/log/suricata/eve-nsm.json \
  | jq -r '.event_type' | sort | uniq -c

sudo tail -n 500 /var/log/suricata/eve-nsm.json \
  | jq 'select(.event_type == "tls") | {src_ip, dest_ip, tls}'

sudo tail -n 500 /var/log/suricata/eve-nsm.json \
  | jq 'select(.event_type == "stats") | .stats'
```

These inspect only the sampled lines. A missing event type in a small sample does not prove it never occurs. Generate known permitted traffic of the relevant type and verify it specifically.

A TLS record without JA4 is a sensor or visibility question before it is a SIEM question. A TLS record with JA4 on disk but no such field in the final finding may be expected: Cernity does not copy every raw field into every finding.

Next: [install the shipper](/docs/deploy-sensor/) and [trace transport](/docs/sensor-transport/).
