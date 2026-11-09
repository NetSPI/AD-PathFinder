from argparse import Namespace

import pytest

from modules.config_loader import load
from modules.main import _apply_uri_overrides


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    monkeypatch.delenv("ADPF_NEO4J_URI", raising=False)
    monkeypatch.delenv("ADPF_BLOODHOUND_URL", raising=False)
    path = tmp_path / "config.ini"
    path.write_text("[NEO4J]\nuri = neo4j://cfg:7687\n[BLOODHOUND]\nurl = http://cfg:8080\n")
    return str(path)


def test_flags_beat_env_and_config(config_file, monkeypatch):
    monkeypatch.setenv("ADPF_NEO4J_URI", "neo4j://env:7687")
    monkeypatch.setenv("ADPF_BLOODHOUND_URL", "http://env:8080")

    _apply_uri_overrides(Namespace(neo4j_uri="bolt://flag:17687", bloodhound_url="http://flag:18080/"))
    resolved = load(config_file)

    assert resolved.neo4j_uri == "bolt://flag:17687"
    assert resolved.bh_url == "http://flag:18080"


def test_unset_flags_leave_config_alone(config_file):
    _apply_uri_overrides(Namespace(neo4j_uri=None, bloodhound_url=None))
    resolved = load(config_file)

    assert resolved.neo4j_uri == "neo4j://cfg:7687"
    assert resolved.bh_url == "http://cfg:8080"
