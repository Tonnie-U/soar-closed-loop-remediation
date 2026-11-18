# Architecture

## Hosts

| Host | Role |
|---|---|
| `siem-endpoint` (Ubuntu 26.04 ARM64) | Monitored host, Elastic stack, SOAR daemon |
| `kali-attack` | Attack emulation (optional; scenarios also run locally) |

Elasticsearch and Kibana 9.5.1 run under Docker Compose on `siem-endpoint`.
Kibana reaches the daemon across the Docker bridge at `172.18.0.1:8088`.

## Data flow

```
publisher (systemd timer)
    │  writes one document per check
    ▼
Elasticsearch index
    │  Kibana Elasticsearch-query rule, 1-minute interval
    ▼
alert raised (status change)
    │  Webhook connector, POST with secret header
    ▼
SOAR daemon  /webhook/alert
    │  authenticate → select playbook → execute under sudo
    ▼
playbook (root, three fixed paths)
    │  restore / revoke, validate, reload
    ▼
re-audit → annotate soar-actions
```

## Indices

| Index | Written by | Key fields |
|---|---|---|
| `drift-events` | `publish-drift-check.sh` | `drift.status` (`CLEAN`/`DRIFTED`), `drift.files`, `drift.file_count` |
| `cert-events` | `ssh-cert-expiry-check.sh` | `ssh_cert.key_id`, `ssh_cert.principal`, `ssh_cert.status`, `ssh_cert.days_remaining` |
| `lynis-metrics` | `publish-lynis-score.sh` | `lynis.hardening_index`, `lynis.baseline` |
| `soar-actions` | SOAR daemon | `soar.status`, `soar.verification_criterion`, `soar.remediation`, `soar.end_to_end_seconds` |

Dynamic mapping gives the string fields a `.keyword` subfield, which is what
the rule queries use — a `term` query against the analysed field would not
match.

## Why two detection paths

The brief names `lynis.hardening_index < 85` as the drift trigger. A Lynis
audit takes 60–90 seconds to complete, so it cannot sit on a detection path
with a 60-second response target: the measurement alone exceeds the budget.

The design therefore splits the concern:

- **`publish-drift-check.sh`** compares live security configuration against the
  golden baseline by content. It completes in well under a second and runs
  every 30 seconds. This is the detection control.
- **`publish-lynis-score.sh`** remains the compliance measure, on a slower
  cadence. It answers "is this host hardened?", not "has this file changed?".

Both feed rules; both route to the same daemon. The verification model
distinguishes them (see below).

## Verification model

`verification_passed()` in the daemon selects the criterion from the alert:

| Alert | Criterion | Rationale |
|---|---|---|
| Configuration drift | Every deviating file restored, zero failures | The alert fired on file content; the index measures something else |
| Hardening index below baseline | Lynis index ≥ 85 | The index is the condition that fired |
| Certificate expired | Playbook exited 0 after revoking | Revocation is binary; there is no score to recover |

The incident record in `soar-actions` carries `verification_criterion`
alongside the status, so an auditor can see which test was applied rather than
inferring it.

## Privilege boundary

```
soar (unprivileged)  ──sudo, 3 absolute paths, 5 env vars──▶  root
```

The daemon never writes to `/etc` itself and never updates a golden baseline.
If remediation could rewrite its own source of truth, an attacker would alter a
file, wait one cycle, and have the drift adopted as the approved state.

## Latency budget

| Stage | Time |
|---|---|
| Integrity check cycle | 0–30 s |
| Kibana rule interval | 0–60 s |
| Webhook delivery + authentication | < 0.1 s |
| Playbook execution | < 0.1 s |
| Re-audit (Lynis) | ~44 s, off the critical path |

Detection dominates. Remediation is effectively instantaneous, so tuning the
daemon cannot improve the figure — only removing a polling cycle can.
