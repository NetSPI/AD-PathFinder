import configparser
import os
import stat
from unittest import mock

import pytest

from modules.config_loader import ResolvedConfig
from modules.config_manager import (
    connect_neo4j_and_load_bloodhound,
    disable_bloodhound,
    get_valid_bloodhound_credentials,
    get_valid_neo4j_credentials,
    save_config,
)
from modules.secret import Secret


class FakeNeo4jConn:
    def __init__(self, connected=True):
        self._connected = connected

    def is_connected(self):
        return self._connected

    def close(self):
        pass


def make_neo4j_factory(scenarios):
    iterator = iter(scenarios)
    calls = []

    def factory(uri, user, pwd):
        calls.append((uri, user, pwd))
        spec = next(iterator)
        if "raise" in spec:
            raise spec["raise"]
        return FakeNeo4jConn(connected=spec["connected"])

    factory.calls = calls
    return factory


class FakeBHImporter:
    def __init__(self, auth_succeeds):
        self._auth = auth_succeeds

    def _authenticate(self):
        if not self._auth:
            raise RuntimeError("authentication failed")


def make_bh_factory(auth_results):
    iterator = iter(auth_results)
    calls = []

    def factory(*args, **kwargs):
        calls.append((args, kwargs))
        return FakeBHImporter(next(iterator))

    factory.calls = calls
    return factory


def make_input_fn(responses):
    iterator = iter(responses)
    return lambda _prompt: next(iterator)


def no_input(_prompt):
    raise AssertionError("input must not be called")


def base_resolved(**overrides):
    kwargs = dict(
        neo4j_uri="neo4j://localhost:7687",
        neo4j_username=None,
        neo4j_password=None,
        bh_url="http://localhost:8080",
        bh_username=None,
        bh_password=None,
        bh_enabled=False,
        bh_configured=False,
        hashcat_file_path=None,
    )
    kwargs.update(overrides)
    return ResolvedConfig(**kwargs)


def reload_ini(ini):
    cfg = configparser.ConfigParser()
    cfg.read(ini)
    return cfg


@pytest.fixture
def ini(tmp_path):
    return str(tmp_path / "config.ini")


def test_neo4j_default_creds_connect_without_prompting(ini):
    cfg = configparser.ConfigParser()
    factory = make_neo4j_factory([{"connected": True}])

    creds = get_valid_neo4j_credentials(base_resolved(), cfg, ini, input_fn=no_input, neo4j_factory=factory)

    assert creds == ("neo4j", "bloodhoundcommunityedition")
    assert factory.calls == [("neo4j://localhost:7687", "neo4j", "bloodhoundcommunityedition")]
    assert dict(cfg["NEO4J"]) == {
        "uri": "neo4j://localhost:7687", "username": "neo4j", "password": "bloodhoundcommunityedition",
    }
    assert dict(cfg["BLOODHOUND"]) == {"username": "admin", "enabled": "True", "url": "http://localhost:8080"}


def test_neo4j_default_creds_disconnected_falls_through_silently(ini, capsys):
    creds = get_valid_neo4j_credentials(
        base_resolved(), configparser.ConfigParser(), ini,
        input_fn=make_input_fn(["jdoe", "pw"]),
        neo4j_factory=make_neo4j_factory([{"connected": False}, {"connected": True}]),
    )

    assert creds == ("jdoe", "pw")
    out = capsys.readouterr().out
    assert "Default credentials failed" not in out
    assert "Please enter your Neo4j credentials" not in out


def test_neo4j_default_creds_exception_prompts_manual_entry(ini, capsys):
    factory = make_neo4j_factory([{"raise": RuntimeError("auth fail")}, {"connected": True}])

    creds = get_valid_neo4j_credentials(
        base_resolved(), configparser.ConfigParser(), ini,
        input_fn=make_input_fn(["alice", "secret"]),
        neo4j_factory=factory,
    )

    assert creds == ("alice", "secret")
    assert [c[1:] for c in factory.calls] == [("neo4j", "bloodhoundcommunityedition"), ("alice", "secret")]
    out = capsys.readouterr().out
    assert "Default credentials failed" in out
    assert "Please enter your Neo4j credentials" in out


def test_neo4j_manual_entry_retries_until_connected(ini):
    creds = get_valid_neo4j_credentials(
        base_resolved(), configparser.ConfigParser(), ini,
        input_fn=make_input_fn(["bad", "bad", "good", "good"]),
        neo4j_factory=make_neo4j_factory([
            {"raise": RuntimeError("default fail")},
            {"connected": False},
            {"connected": True},
        ]),
    )

    assert creds == ("good", "good")


def test_save_config_first_write_is_owner_only(ini):
    save_config(configparser.ConfigParser(), ini)

    assert stat.S_IMODE(os.stat(ini).st_mode) == 0o600


def test_save_config_preserves_existing_permissions(ini):
    cfg = configparser.ConfigParser()
    save_config(cfg, ini)
    os.chmod(ini, 0o644)

    save_config(cfg, ini)

    assert stat.S_IMODE(os.stat(ini).st_mode) == 0o644


def test_save_config_still_writes_when_chmod_fails(ini):
    with mock.patch("modules.config_manager.os.chmod", side_effect=OSError("nope")):
        save_config(configparser.ConfigParser(), ini)

    assert os.path.isfile(ini)


def test_disable_bloodhound_persists_disabled_state(ini):
    disable_bloodhound(configparser.ConfigParser(), ini, "http://bh.example:8080")

    assert dict(reload_ini(ini)["BLOODHOUND"]) == {"enabled": "False", "url": "http://bh.example:8080"}


def test_bloodhound_stored_creds_authenticate_without_prompting(ini):
    factory = make_bh_factory([True])

    creds = get_valid_bloodhound_credentials(
        base_resolved(bh_enabled=True, bh_url="http://bh.example:8080",
                      bh_username="admin", bh_password=Secret("stored")),
        configparser.ConfigParser(), ini,
        input_fn=no_input,
        bh_factory=factory,
    )

    assert creds == ("admin", "stored")
    assert factory.calls == [((None,), {
        "bloodhound_username": "admin",
        "bloodhound_password": "stored",
        "base_url": "http://bh.example:8080",
    })]


@pytest.mark.parametrize("resolved,inputs,auth_results", [
    (base_resolved(bh_enabled=True, bh_username="admin", bh_password=Secret("stale")), [""], [False]),
    (base_resolved(bh_enabled=True), ["u1", "p1", "u2", "p2", "u3", "p3"], [False, False, False]),
], ids=["user_skips_after_stored_fail", "three_failed_attempts"])
def test_bloodhound_auth_failure_disables_bloodhound(ini, resolved, inputs, auth_results):
    creds = get_valid_bloodhound_credentials(
        resolved, configparser.ConfigParser(), ini,
        input_fn=make_input_fn(inputs),
        bh_factory=make_bh_factory(auth_results),
    )

    assert creds == (None, None)
    assert reload_ini(ini)["BLOODHOUND"]["enabled"] == "False"


def test_bloodhound_force_re_enables_disabled(ini):
    cfg = configparser.ConfigParser()
    cfg["BLOODHOUND"] = {"enabled": "False"}
    save_config(cfg, ini)

    creds = get_valid_bloodhound_credentials(
        base_resolved(bh_username="admin", bh_password=Secret("pw")), cfg, ini,
        force=True,
        input_fn=no_input,
        bh_factory=make_bh_factory([True]),
    )

    assert creds == ("admin", "pw")
    assert reload_ini(ini)["BLOODHOUND"]["enabled"] == "True"


def test_bloodhound_disabled_without_force_returns_immediately(ini):
    creds = get_valid_bloodhound_credentials(
        base_resolved(), configparser.ConfigParser(), ini,
        input_fn=no_input,
        bh_factory=make_bh_factory([]),
    )

    assert creds == (None, None)


@pytest.fixture
def no_adpf_env(monkeypatch):
    for key in list(os.environ):
        if key.startswith("ADPF_"):
            monkeypatch.delenv(key)


def test_stored_neo4j_creds_skip_bootstrap(ini, no_adpf_env):
    resolved = base_resolved(
        neo4j_uri="neo4j+s://neo.example:7687",
        neo4j_username="stored",
        neo4j_password=Secret("storedpw"),
        bh_username="bh_user",
        bh_password=Secret("bh_pw"),
        bh_enabled=True,
    )
    factory = make_neo4j_factory([{"connected": True}])

    with mock.patch("modules.config_manager.load_resolved_config") as reload_mock:
        conn, bh_username, bh_password, bh_enabled = connect_neo4j_and_load_bloodhound(
            resolved, configparser.ConfigParser(), ini,
            input_fn=no_input,
            neo4j_factory=factory,
        )

    reload_mock.assert_not_called()
    assert conn.is_connected()
    assert factory.calls == [("neo4j+s://neo.example:7687", "stored", "storedpw")]
    assert (bh_username, bh_password, bh_enabled) == ("bh_user", "bh_pw", True)


STALE_NEO4J = base_resolved(neo4j_username="stale", neo4j_password=Secret("stalepw"))


@pytest.mark.parametrize("resolved,ini_text,inputs,scenarios", [
    (STALE_NEO4J, None, ["u", "p"], [
        {"raise": RuntimeError("stored fail")}, {"raise": RuntimeError("default fail")},
        {"connected": True}, {"connected": True},
    ]),
    (STALE_NEO4J, None, ["u", "p"], [
        {"connected": False}, {"raise": RuntimeError("default fail")},
        {"connected": True}, {"connected": True},
    ]),
    (base_resolved(), None, [], [{"connected": True}, {"connected": True}]),
    (base_resolved(), "[OTHER]\nfoo=bar\n", [], [{"connected": True}, {"connected": True}]),
], ids=["stored_creds_raise", "stored_creds_disconnected", "missing_config", "config_without_neo4j_section"])
def test_bootstrap_reloads_config(ini, no_adpf_env, resolved, ini_text, inputs, scenarios):
    cfg = configparser.ConfigParser()
    if ini_text:
        with open(ini, "w") as fh:
            fh.write(ini_text)
        cfg.read(ini)
    reloaded = base_resolved(bh_username="admin", bh_password=Secret("bh_pw"), bh_enabled=True)

    with mock.patch("modules.config_manager.load_resolved_config", return_value=reloaded) as reload_mock:
        _, bh_username, bh_password, bh_enabled = connect_neo4j_and_load_bloodhound(
            resolved, cfg, ini,
            input_fn=make_input_fn(inputs),
            neo4j_factory=make_neo4j_factory(scenarios),
        )

    reload_mock.assert_called_once_with(ini)
    assert (bh_username, bh_password, bh_enabled) == ("admin", "bh_pw", True)
