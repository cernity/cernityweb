# Documentation and evidence maintenance

The guide content was checked against the local Cernity implementation at commit
`18174b8c2d8e29e2312d4f27064a2baa3456d9e3`. Links pin that revision. The website build
and static checks do not establish a successful fresh Cernity deployment.

## Regenerate selected historical evidence

```sh
python3 scripts/import-evidence.py /path/to/siem-comparison-results
npm run build
python3 scripts/check-site.py
```

The importer reads the private evidence directory but copies only selected synthetic
record bodies, scoped summaries, original matching findings, and provenance metadata.
It never publishes the full private captures or evidence packages. Do not copy the
private directory into `public/`.

The primary five cases require all export hashes to match and verify source/baseline
multiset equivalence excluding only ingestion timestamps. The two DNS cases lack the
newer manifest/completion metadata and retain their explicit lower-assurance label.
The import checks source record selection and key count/byte totals.

`check-site.py` checks generated links and anchors, parses the syntax-highlighted JSON
back out of the proof HTML, and compares it with the original selected record bodies.
It also verifies downloadable evidence, inventory claims, and shell-block syntax.
Deployment commands in the docs are never executed by that script.

## Optional integration evidence

No optional output is fabricated. The inventory covers all fifteen available historical
finding exports. Current integration descriptions distinguish implementation from
successful SIEM delivery and link the reviewed code. A new successful run must include
retrieved SIEM documents, original inputs, configuration/version provenance, and a
benign control before changing an integration to demonstrated status.

The source review found these material boundaries:

- Sensor Compose does not pass tenant/sensor identity into Fluent Bit; the docs include
  an explicit override.
- Quickstart feeder authentication and SLIPS bridge/adapter authentication need explicit
  overrides with the default secured broker.
- The forensics path has additional broker authentication/ACL and remote object-store
  prerequisites; the Zeek worker's direct Kafka clients do not use the shared auth helper.
- Zeek's result contains summaries and indicators, but the reviewed finding merge copies
  evidence references and state, not those full result objects.
- CEF intentionally emits only selected fields and does not retain full enrichment. Its
  source/destination role extraction also differs from SLIPS's attacker/victim roles.
- The core Compose defaults detector state to memory. Optional storage and distributed
  state are not implied by starting the basic stack.

Recheck these facts against the product revision before changing documentation or
presenting a new deployment recipe as validated. None of these product implementation
files were modified as part of the website task.
