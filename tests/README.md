# Tests

Two test surfaces ship in this repo:

1. **Framework unit tests** at `tests/test_*.py` — mock-based, no Neo4j required.
2. **Per-check fixture tests** at `tests/checks/test_*.py` — load Cypher fixtures into a real Neo4j and run a single check against the resulting graph. Marked `@pytest.mark.neo4j`.

Both suites run on every PR via CI. Framework tests run across the Python 3.9/3.13 matrix; fixture tests run on 3.13 only against a `neo4j:5-community` service container.

## Running the fast suite (no Docker)

```bash
pip install -e ".[test]"
pytest tests/ -m "not neo4j and not integration" -v
```

This runs every framework test and skips anything Neo4j-backed. CI runs the same selector on Python 3.9 and 3.13.

## Running the Neo4j fixture suite

The fixture suite wipes the target Neo4j database before and after every test. Two guards prevent this from hitting a real BloodHound instance:

1. `ADPF_TEST_ALLOW_WIPE=1` must be set explicitly.
2. The default `NEO4J_URI` is `bolt://localhost:17687`, not the BloodHound-standard `7687`. Even with `ADPF_TEST_ALLOW_WIPE=1`, the harness refuses to wipe `localhost:7687` unless `GITHUB_ACTIONS=true` or `ADPF_TEST_FORCE_DEFAULT_PORT=1` is set.

Start a disposable container:

```bash
docker run -d --name adpf-test-neo4j \
  -p 17474:7474 -p 17687:7687 \
  -e NEO4J_AUTH=neo4j/testpassword \
  neo4j:5-community

# Wait for Bolt:
until docker exec adpf-test-neo4j cypher-shell -u neo4j -p testpassword "RETURN 1" >/dev/null 2>&1; do sleep 2; done
```

Run the suite:

```bash
ADPF_TEST_ALLOW_WIPE=1 \
NEO4J_URI=bolt://localhost:17687 \
NEO4J_USER=neo4j NEO4J_PASSWORD=testpassword \
pytest tests/checks -m "neo4j and not integration" -v
```

Tear down:

```bash
docker rm -f adpf-test-neo4j
```

## Adding a test for a new check

1. Create `tests/fixtures/<your_check>.cypher` with a minimal graph that triggers your check. Look at `tests/fixtures/esc3_enrollment_agent.cypher` for the pattern.
2. Create `tests/checks/test_<your_check>.py` starting with `import pytest` and `pytestmark = pytest.mark.neo4j` at module top, then load the fixture, run the check via `run_check(YourCheck, clean_neo4j)`, and assert the findings. The marker is mandatory — without it the test runs in the fast lane and trips the wipe guard.
3. Optionally add a negative fixture (`<your_check>_negative.cypher`) and assert the check stays silent.
4. Run locally as shown above.

See [`CHECK_FIXTURE_PLAN.md`](../CHECK_FIXTURE_PLAN.md) for the per-check migration plan.

## CI integration tests

All 6 cross-domain checks under `checks/cross_domain/` are covered: 3 NTDS-only checks run without Neo4j, and 3 Neo4j checks (`domain_trusts`, `cross_domain_escalation_path`, `cross_domain_computer_escalation_path`) use fixtures. The inventory test verifies coverage for both `CheckRegistry` and `CrossDomainRegistry`.
