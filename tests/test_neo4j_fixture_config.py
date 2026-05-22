import importlib.util
from pathlib import Path


def _load_test_conftest():
    path = Path(__file__).with_name("conftest.py")
    spec = importlib.util.spec_from_file_location("adpf_test_conftest", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


conftest = _load_test_conftest()


def test_neo4j_fixture_defaults_to_disposable_test_container():
    assert conftest.DEFAULT_NEO4J_TEST_URI == "bolt://localhost:17687"
    assert conftest.DEFAULT_NEO4J_TEST_PASSWORD == "testpassword"


def test_bloodhound_default_port_guard_detects_common_local_uris():
    assert conftest._bloodhound_default_port("neo4j://localhost:7687")
    assert conftest._bloodhound_default_port("bolt://127.0.0.1")
    assert not conftest._bloodhound_default_port(conftest.DEFAULT_NEO4J_TEST_URI)
    assert not conftest._bloodhound_default_port("bolt://localhost:17687")
