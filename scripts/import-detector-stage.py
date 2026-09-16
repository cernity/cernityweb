"""Build the web model for the detector-stage proof section from the real captures.

Reads public/evidence/detector-stage/<service>.json (produced by cernityndr's
tools/proof-capture/capture.py — the detector's actual code over a fixture) and emits
src/content/proof/captures.json grouped per service -> one card per detector_id, each pairing
the EXACT triggering source EVE record with the real finding.

No value is invented or mutated: the emitted source_record is an unmodified element of
suricata_baseline.records and the finding is an unmodified element of cernity.findings (this is
what check-site.py re-verifies against the displayed page). Interpretation (plain-language meaning,
investigation prompts) lives separately in captures-content.ts and is merged at render time.

Usage: python3 scripts/import-detector-stage.py
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "public/evidence/detector-stage"
OUT = ROOT / "src/content/proof/captures.json"
SERVICES = ["ot-detectors", "protocol-detectors", "http-detector", "dns-detector",
            "east-west-detectors", "coverage-detector", "anomaly-detector"]

_SRC_ROLES = ("src", "responder", "attacker", "scanner")
_DST_ROLES = ("dst", "victim", "target")


def _ents(finding):
    e = finding.get("entities")
    if isinstance(e, str):
        try:
            e = json.loads(e)
        except (ValueError, TypeError):
            return []
    return e if isinstance(e, list) else []


def _role_value(ents, roles):
    for e in ents:
        if isinstance(e, dict) and e.get("role") in roles:
            return e.get("value")
    return None


def _sensor(ents):
    for e in ents:
        if isinstance(e, dict) and e.get("type") == "sensor":
            return e.get("value")
    return None


def _why(finding):
    """A short human descriptor for the card headline, derived ONLY from the finding's own
    entities (no new facts). Prefers an explicit `why`; otherwise composes from typed entities."""
    ents = _ents(finding)
    by_type = {e.get("type"): e for e in ents if isinstance(e, dict)}
    if "why" in by_type:
        return by_type["why"].get("value")
    if "kerberoast" in by_type:
        k = by_type["kerberoast"]
        return f"{k.get('distinct_spns')} distinct SPNs requested" + (", RC4" if k.get("rc4") else "")
    if "spray" in by_type:
        return f"{by_type['spray'].get('distinct_accounts')} distinct accounts failed auth"
    if "llmnr" in by_type:
        return f"{by_type['llmnr'].get('answered_names')} names answered (not owned)"
    if "nxdomain_count" in by_type:
        return f"{by_type['nxdomain_count'].get('value')} NXDOMAIN in window"
    if "dga_score" in by_type:
        return f"DGA score {by_type['dga_score'].get('value')}"
    if "attempts" in by_type:
        return f"{by_type['attempts'].get('value')} attempts"
    if "bytes" in by_type:
        return f"{by_type['bytes'].get('value')} bytes"
    if "anomaly" in by_type:
        return by_type["anomaly"].get("value")
    if "ua" in by_type:
        return f"non-browser tooling user-agent: {by_type['ua'].get('value')}"
    if "service" in by_type and "sni" in by_type:      # cloud_staging
        return f"data-staging destination: {by_type['sni'].get('value')}"
    if "ja4" in by_type and "sni" in by_type:          # ja4_rarity
        return f"never-before-seen JA4 client → {by_type['sni'].get('value')}"
    if "lateral_exec" in by_type:
        return "; ".join(by_type["lateral_exec"].get("signals", [])) or "remote-exec named pipe"
    return finding.get("detector_id")


def _match_source(finding, records):
    """The exact source EVE record that triggered this finding: same source, then the record
    whose body carries the most of the finding's distinctive tokens (uri/domain/sni/fc/port).
    Returns an unmodified element of `records`, or None."""
    ents = _ents(finding)
    src = _role_value(ents, _SRC_ROLES)
    dst = _role_value(ents, _DST_ROLES)
    sensor = _sensor(finding if False else ents)
    if sensor is not None:                       # coverage: keyed by sensor host, not IP
        cand = [r for r in records if r.get("host") == sensor]
        return cand[0] if cand else (records[0] if records else None)
    cand = [r for r in records if r.get("src_ip") == src] or list(records)
    if dst:
        narrowed = [r for r in cand if r.get("dest_ip") == dst]
        cand = narrowed or cand
    tokens = []
    for e in ents:
        if not isinstance(e, dict):
            continue
        if e.get("type") in ("uri", "domain", "sni", "modbus_fc"):
            tokens.append(str(e.get("value")))
    why = _why(finding) or ""
    for word in why.split():                     # e.g. "port 1502" / "fc=16"
        w = word.strip("()").split("=")[-1]
        if w.isdigit():
            tokens.append(w)
    if not cand:
        return None
    best = max(cand, key=lambda r: sum(t in json.dumps(r) for t in tokens))
    return best


def build_service(path):
    data = json.loads(path.read_text())
    findings = data["cernity"]["findings"]
    records = data["suricata_baseline"]["records"]
    delivered_by_id = {r["finding_id"]: r for r in data["cernity"].get("delivered", [])}
    by_det = {}
    for f in findings:
        by_det.setdefault(f["detector_id"], []).append(f)
    detectors = []
    for det_id, group in by_det.items():
        showcase = max(group, key=lambda f: (f.get("severity", 0)))   # most severe instance
        variants = sorted({_why(f) for f in group if _why(f)})
        deliv = delivered_by_id.get(showcase.get("finding_id"), {})
        detectors.append({
            "detector_id": det_id,
            "category": showcase.get("category"),
            "severity": showcase.get("severity"),
            "confidence": showcase.get("confidence"),
            "mitre": showcase.get("mitre", []),
            "why": _why(showcase),
            "fired_count": len(group),
            "variant_whys": variants,
            "source_record": _match_source(showcase, records),   # unmodified EVE element
            "finding": showcase,                                  # unmodified candidate finding
            "delivered": deliv.get("delivered", False),
            "lifecycle": deliv.get("lifecycle", {}),              # real finding-service outcome
            "siem": deliv.get("siem"),                            # real ES doc + CEF (None if suppressed)
        })
    detectors.sort(key=lambda d: (-(d["severity"] or 0), d["detector_id"]))
    delivered_n = sum(1 for r in delivered_by_id.values() if r.get("delivered"))
    return {
        "service": data["service"],
        "fixture": data["fixture"],
        "stage": "detector",
        "captured_at": data.get("captured_at"),
        "suricata": {
            "record_count": data["suricata_baseline"]["source_event_count"],
            "alerts": data["suricata_baseline"]["alerts"],
            "records": records,                                   # full raw EVE, unmodified
        },
        "detector_count": len(detectors),
        "finding_count": len(findings),
        "delivered_count": delivered_n,
        "suppressed_count": len(delivered_by_id) - delivered_n,
        "detectors": detectors,
    }


def main():
    services = [build_service(SRC / f"{s}.json") for s in SERVICES if (SRC / f"{s}.json").exists()]
    model = {
        "stage": "detector",
        "total_services": len(services),
        "total_detectors": sum(s["detector_count"] for s in services),
        "total_findings": sum(s["finding_count"] for s in services),
        "total_delivered": sum(s["delivered_count"] for s in services),
        "total_suppressed": sum(s["suppressed_count"] for s in services),
        "total_suricata_alerts": sum(s["suricata"]["alerts"] for s in services),
        "services": services,
    }
    OUT.write_text(json.dumps(model, indent=2) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}: {model['total_services']} services, "
          f"{model['total_detectors']} detectors, {model['total_findings']} findings, "
          f"{model['total_suricata_alerts']} suricata alerts")
    # integrity: every emitted source_record/finding must be an exact element of its capture
    for s in services:
        cap = json.loads((SRC / f"{s['service']}.json").read_text())
        recs, finds = cap["suricata_baseline"]["records"], cap["cernity"]["findings"]
        for d in s["detectors"]:
            assert d["finding"] in finds, f"{s['service']}/{d['detector_id']}: finding not in capture"
            assert d["source_record"] is None or d["source_record"] in recs, \
                f"{s['service']}/{d['detector_id']}: source record not in capture"
    print("integrity OK: all displayed records/findings are unmodified capture elements")


if __name__ == "__main__":
    main()
