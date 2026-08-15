# Governed Agent Memory

This is a compiling scaffold; it makes no implemented capability claim.

## Planned build

The following capabilities are planned and are not implemented in this scaffold:

- CockroachDB persistent memory
- CockroachDB Distributed Vector Indexing
- an agent-used read-only `ccloud` cluster-info adapter
- deterministic four-valued evaluation
- human decisions
- one typed append-only demo effect
- consequence feedback
- AWS Lambda
- a public fixed demonstration route

## Development status

All planned capabilities remain unimplemented in this scaffold.

## Original-work disclosure

> All submitted source code was written during the submission period. The
> project applies concepts from the cited prior publications. No pre-existing
> source code or protected implementation was incorporated.

## Theory sources

| Role | Source | Author | Date | License/status |
|---|---|---|---|---|
| verdict tokens and ordering | [Your Loop Has Two States. It Needs Four.](https://metacortexdynamics.substack.com/p/your-loop-has-two-states-it-needs) | Devon Generally / MetaCortex Dynamics | 2026-07-09 | citation-only unless separately granted |
| fifteen public operator-family names | [The Operator Completeness Theorem: The 15 Invariant Operators as Constitutive Conditions of Projection](https://doi.org/10.5281/zenodo.20370848) | Devon A. Generally | 2026-05-25 | CC BY-NC-ND 4.0 |
| pre-numeric thesis | [Operators, Not Numbers: 0 and 1 as Pre-Numeric Structure](https://doi.org/10.5281/zenodo.21499659) | Devon A. Generally | 2026-07-22 | CC BY 4.0 |
| seven witness names | [The Universal Interrogative Theorem: The Constitutive Grammar of Appearing-Being](https://doi.org/10.5281/zenodo.21465420) | Devon A. Generally | 2026-07-21 | CC BY-ND 4.0 |

## License boundary

Apache-2.0 applies only to original repository work. It does not relicense any
cited material. External publications remain under the licenses or status shown
above.

## Local scaffold check

```bash
python -m pip install --requirement requirements-dev.txt
python -m compileall -q src lambda scripts tests
bash -n lambda/deploy.sh scripts/clean_clone_smoke.sh
python scripts/verify_release.py --initial-exact
python scripts/check_boundary.py .
python scripts/check_secrets.py --worktree
python scripts/check_secrets.py --history
python scripts/check_license_boundary.py
ruff check .
ruff format --check .
mypy
pytest -q
bandit -q -r src lambda scripts
pip-audit --requirement requirements-dev.txt
git status --short
```

## License

See [LICENSE](LICENSE) and [NOTICE](NOTICE).
