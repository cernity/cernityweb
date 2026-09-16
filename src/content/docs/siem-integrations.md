---
title: "SIEM delivery: what gets stored and how to read it"
nav: "SIEM delivery & formats"
order: 10
---

# SIEM delivery: what gets stored and how to read it

**Cernity's forwarder sends findings, not the entire raw Suricata log.** If your SOC needs both, configure and retain a separate raw EVE ingestion path or another queryable raw-telemetry store.

The [proof page](/proof/) shows actual selected document bodies from saved exports. It preserves the escaped `entities` string because that is what those records contain. An attractive decoded array is easier to read, but is not the original field representation.

## One finding can have several stored documents

The signature example has one `finding_id` and two revisions. In the reviewed Elasticsearch adapter, document IDs incorporate tenant, finding ID, and revision. Each revision can therefore be retained separately rather than overwriting its predecessor.

For triage, group by tenant and finding ID and choose the latest revision. Preserve the original documents for audit. Do not assume two rows mean two incidents or that every SIEM automatically displays only the current version.

## Choose the adapter by the fields your SOC needs

| Adapter | Transport and payload | Field preservation |
|---|---|---|
| `file` | JSON Lines in the configured file. | Writes the finding object. Useful as a local boundary check, but not proof of SIEM ingestion. |
| `elasticsearch` / `opensearch` | HTTP bulk API, daily index. | Stores the finding body; sets `@timestamp` from observation bounds. |
| `splunk` | HTTP Event Collector wrapper with `event` and `sourcetype`. | Places the finding inside `event`; SIEM extraction must expose its fields. |
| `webhook` | JSON object containing a `findings` array. | Preserves the objects sent; receiving application determines persistence. |
| `devo` with JSON | Tagged JSON via the configured supported transport. | Sends the finding JSON; receiving table and parser determine searchable fields. |
| `syslog` / `cef` | TCP syslog, optional TLS, compact CEF payload. | Maps only selected fields. It does **not** preserve all enrichment objects or entities. |

**For deep enrichment analysis, the current CEF mapping is materially different from full JSON.** It includes the detector/category/severity, finding ID, MITRE, tenant, and source/destination when extracted. It omits full `geo`, `intel`, entities, evidence references, and other detailed fields. The reviewed CEF extraction looks for `src`/`dst` roles, while SLIPS uses `attacker`/`victim`; do not assume those IPs appear in CEF without adapting and verifying the mapping.

## Configure a JSON sink on CENTRAL

Edit central `.env`, then recreate the forwarder using the same project and Compose file as the installation guide.

For Elasticsearch or OpenSearch:

```dotenv
CERNITY_SINK=elasticsearch
ES_ENDPOINT=https://YOUR_SIEM_ENDPOINT:9200
ES_USER=YOUR_INGEST_USER
ES_PASSWORD=YOUR_INGEST_PASSWORD
ES_INDEX_PREFIX=ndr-findings
ES_TLS_VERIFY=true
```

For Splunk HEC:

```dotenv
CERNITY_SINK=splunk
SPLUNK_HEC_URL=https://YOUR_SPLUNK_ENDPOINT:8088/services/collector
SPLUNK_HEC_TOKEN=YOUR_HEC_TOKEN
SPLUNK_SOURCETYPE=cernity:finding
SPLUNK_TLS_VERIFY=true
```

For a JSON webhook:

```dotenv
CERNITY_SINK=webhook
WEBHOOK_URL=https://YOUR_RECEIVER/ingest
WEBHOOK_AUTH=Bearer YOUR_TOKEN
WEBHOOK_TLS_VERIFY=true
```

The placeholders must be replaced with your own endpoint and credentials. A webhook receiver must support the adapter's JSON shape; an arbitrary chat webhook is not automatically compatible.

```bash
docker compose --project-name cernity --env-file .env \
  -f deploy/central/docker-compose.yml up -d findings-forwarder

docker logs --tail 100 cernity-findings-forwarder
```

For an ingest comparison you may temporarily configure `CERNITY_SINK=file,elasticsearch` to retain both boundaries. The two sinks have separate delivery outcomes; presence in the file does not prove successful indexing.

## Receiving-side preparation

Create or select the destination index/table, allow the ingestion identity to write there, and configure the expected parser. Ensure your UI has an appropriate time field and search range. A record can be present but invisible in the current UI filter.

Preserve original JSON. If you decode the `entities` JSON string into searchable objects, retain the source field or raw document as well. Large numeric flow identifiers should not be round-tripped through a client that silently loses integer precision.

Decide whether your dashboard shows every revision or a current-state projection. Make that choice explicit when reporting document counts or queue reduction.

## Retrieve the actual stored document

In Elasticsearch/OpenSearch Dev Tools, this query searches the preserved signature example's identity. Use your actual index prefix and finding ID for your deployment:

```json
GET ndr-findings-*/_search
{
  "size": 100,
  "query": {
    "match_phrase": {
      "finding_id": "idsig-9000003-6264501210"
    }
  }
}
```

The query is an example, not a claim that the historical test record exists in your SIEM. Scope tenant and observation range for real investigations. Check the response's total-hit count and pagination before treating the first page as a complete export. Preserve `_index`, `_id`, and `_source` when available; the historical website exports did not retain those search wrappers.

In Splunk, after JSON extraction is configured, a starting search is:

```text
sourcetype="cernity:finding" "idsig-9000003-6264501210"
| spath
| table _time finding_id revision detector_id category state enrichment_state entities
```

Use your actual index constraints. To work with a string-valued `entities` field, a second `spath input=entities` step may be needed, depending on your extraction. Inspect `_raw` before assuming the field paths used by a dashboard are identical to the original payload.

## Interpret delivery status correctly

The reviewed forwarder retries failures and records exhausted delivery attempts in its configured dead-letter directory. A dead-lettered item has not successfully reached that destination. Its presence is a failure receipt, not a delivery receipt.

`devo_delivery_state: QUEUED` can remain in a document found in a SIEM export. That field is not an independent receipt from the receiving SIEM. Retrieve the actual stored record to establish ingestion.

Transport guarantees differ by sink. A successful TCP write to a syslog endpoint is weaker than confirmation that the SIEM indexed and parsed the event. Even an API acknowledgment should be checked against the retrieved document when validating field fidelity.

## Optional fields must survive every hop

To demonstrate reverse DNS, verify `intel.rdns` in the final retrieved JSON. To demonstrate SLIPS, retain its original alert, module provenance, candidate, final finding, and stored record. To demonstrate Zeek details, verify field propagation rather than assuming every worker result is merged into the finding.

The [optional integration evidence audit](/proof/#optional-integrations) documents current gaps. Use the [evidence capture procedure](/docs/evidence-capture/) to close them with real records.

Source: [reviewed adapters](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/services/findings-forwarder/adapters.py) and [CEF mapping](https://github.com/cernity/cernityndr/blob/18174b8c2d8e29e2312d4f27064a2baa3456d9e3/services/findings-forwarder/cef.py).
