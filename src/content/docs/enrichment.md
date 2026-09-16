---
title: "Configure enrichment and verify the received fields"
nav: "Enrichment & context"
order: 8
---

# Configure enrichment and verify the received fields

Enrichment adds context to a finding: a PTR hostname, network owner, registration age, or reputation result. It is separate from the original observed event and from proof of compromise.

**No nonempty `geo` or `intel` object appears in the 15 saved finding exports reviewed for the website.** The paths below are source-supported configuration guidance, not claims that the published benchmarks exercised them. See [the integration evidence audit](/proof/#optional-integrations).

## Where each field comes from

| Received JSON path | Source | Important limitation |
|---|---|---|
| `community_id` | An entity retained from the originating detection. | Not every aggregate finding has a single flow key. |
| `geo[IP].country` | Local GeoIP database. | Network geolocation is not a person's location. |
| `geo[IP].asn`, `as_org` | Local ASN database. | Network ownership is not attribution. |
| `intel.rdns[IP]` | PTR lookup using the container's resolver. | A hostname is not an authorization or trust assertion. |
| `intel.domains[domain].age_days`, `nrd` | RDAP registration lookup. | Domain age is not the same as first-seen age. |
| `intel.fingerprints[fingerprint]` | Operator-maintained local mapping. | A label can be stale or shared by unrelated software. |
| `intel.reputation[IP]` | GreyNoise adapter. | Provider-specific context, not a definitive Cernity verdict. |
| `intel.virustotal[IP]` | VirusTotal analysis counts. | Vendor counts are not calibrated probabilities. |

The IP-indexed notation above describes a JSON map key, not a literal field named `IP`. Fields are added only when the corresponding input and lookup produce a result.

## Pass configuration into finding-service

The reviewed central Compose passes some enrichment variables, but not every variable listed in `cernity.env.example`. For explicit wiring, create `deploy/central/enrichment.local.yml`:

```yaml
services:
  finding-service:
    environment:
      INTEL_RDNS: ${INTEL_RDNS:-}
      INTEL_RDAP: ${INTEL_RDAP:-}
      INTEL_NRD_DAYS: ${INTEL_NRD_DAYS:-30}
      INTEL_HTTP_TIMEOUT: ${INTEL_HTTP_TIMEOUT:-3}
      INTEL_FP_MAP: ${INTEL_FP_MAP:-}
      GREYNOISE_API_KEY: ${GREYNOISE_API_KEY:-}
      VIRUSTOTAL_API_KEY: ${VIRUSTOTAL_API_KEY:-}
      GEOIP_DB: ${GEOIP_DB:-}
      GEOIP_ASN_DB: ${GEOIP_ASN_DB:-}
```

Set only the adapters you intend to use in central `.env`. For reverse DNS through the configured resolver:

```dotenv
INTEL_RDNS=1
```

Recreate the service with the override:

```bash
docker compose --project-name cernity --env-file .env \
  -f deploy/central/docker-compose.yml \
  -f deploy/central/enrichment.local.yml up -d finding-service
```

Retain this override in later deployment commands; omitting it can recreate the service without your added configuration.

## GeoIP and ASN databases

Obtain compatible databases from the provider under its applicable terms and keep them updated. The code can use a GeoLite2 Country or City database and an ASN database. Store them on central, for example under `/srv/cernity/geoip`.

Add this mount under the same finding-service override:

```yaml
    volumes:
      - /srv/cernity/geoip:/geoip:ro
```

Set the corresponding **container** paths in central `.env`:

```dotenv
GEOIP_DB=/geoip/GeoLite2-Country.mmdb
GEOIP_ASN_DB=/geoip/GeoLite2-ASN.mmdb
```

The code skips non-global addresses and tolerates absent/unreadable databases. An empty `geo` result can therefore mean the feature did not run successfully. The documentation IP ranges used in the historical examples should not be assigned made-up countries or ASNs.

## Reverse DNS and registration age are different

Reverse DNS maps an IP to a PTR name. The reviewed code can look up internal IPs through its configured resolver too. Whether a lookup stays local depends on that resolver's configuration.

Registration lookup starts from a domain or SNI entity and queries RDAP when `INTEL_RDAP=1`. The source computes a registrable candidate using the last two labels, which is not correct for every public suffix. Validate multi-label suffixes and missing registry dates before relying on `nrd` for decisions.

The HTTP timeout setting applies to HTTP lookups; the socket-based reverse-DNS lookup uses resolver behavior and is not bounded by that HTTP setting.

## Fingerprint labels

Supply a JSON map whose keys are exact observed JA3/JA4 values and whose values are your reviewed labels. Mount the file read-only and pass `INTEL_FP_MAP` to its container path. Record the map's provenance and version.

The shipped map does not establish a maintained malware attribution service. The enrichment function handles `ja3` and `ja4` entity types; a generic fingerprint string elsewhere in a record does not automatically get labeled.

## External reputation

Configure the relevant provider key in the central secret-managed environment and pass it through. The reviewed adapters restrict reputation lookups to globally routable IPs. Availability, provider terms, quotas, and results depend on the configured account and service.

GreyNoise and VirusTotal results have separate fields. A failure or missing response can leave the corresponding field absent. Do not rewrite absence as a benign reputation result.

## Verify a field at the SIEM boundary

Use permitted test inputs with a known expected lookup result. Retrieve the final finding from your JSON sink and then retrieve its actual SIEM document. Match the tenant, finding ID, and revision, then compare the exact field and value.

CEF is a reduced mapping and omits this detailed context in the reviewed implementation. For full enrichment inspection, use a JSON-preserving delivery path and verify receiving-side parsing. See [SIEM formats](/docs/siem-integrations/).

## Packet forensics is a separate enrichment path

The optional Zeek worker creates summaries and indicators, but the reviewed lifecycle merge retains evidence references and status rather than copying all those objects into the finding. Do not expect every Zeek JA4+ or file detail in the SIEM without an explicitly verified propagation path.

References: [enrichment implementation](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/services/finding-service/intel.py), [GeoIP implementation](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/services/finding-service/geoenrich.py), and [field-delivery acceptance checks](/docs/evidence-capture/).
