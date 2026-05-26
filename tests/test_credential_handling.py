import configparser
import io
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

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
        self.closed = False

    def is_connected(self):
        return self._connected

    def close(self):
        self.closed = True

def make_neo4j_factory(scenarios):
    """scenarios: list of {'connected': bool} or {'raise': Exception}. Records calls on factory.calls."""
    iterator = iter(scenarios)
    calls = []

    def factory(uri, user, pwd):
        calls.append((uri, user, pwd))
        spec = next(iterator)
        if "raise" in spec:
            raise spec["raise"]
        return FakeNeo4jConn(connected=spec.get("connected", True))

    factory.calls = calls
    return factory

class FakeBHImporter:
    def __init__(self, auth_succeeds=True, **kwargs):
        self._auth = auth_succeeds

    def _authenticate(self):
        if not self._auth:
            raise RuntimeError("authentication failed")

def make_bh_factory(auth_results):
    """auth_results: list of bools (True = _authenticate succeeds, False = raises). Records calls on factory.calls."""
    iterator = iter(auth_results)
    calls = []

    def factory(*args, **kwargs):
        calls.append((args, kwargs))
        return FakeBHImporter(auth_succeeds=next(iterator))

    factory.calls = calls
    return factory

def make_input_fn(responses):
    iterator = iter(responses)
    return lambda _prompt: next(iterator)

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

def silent(fn, *args, **kwargs):
    """Run fn with stdout suppressed; return result + captured text."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = fn(*args, **kwargs)
    return result, buf.getvalue()

class TestGetValidNeo4jCredentials(unittest.TestCase):

    def test_default_creds_connect_without_prompting(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()

            def fail_on_input(_):
                raise AssertionError("input must not be called when default creds connect")

            factory = make_neo4j_factory([{"connected": True}])
            (user, pwd), _ = silent(
                get_valid_neo4j_credentials,
                base_resolved(), cfg, ini,
                input_fn=fail_on_input,
                neo4j_factory=factory,
            )
            self.assertEqual((user, pwd), ("neo4j", "bloodhoundcommunityedition"))
            self.assertEqual(factory.calls, [("neo4j://localhost:7687", "neo4j", "bloodhoundcommunityedition")])
            self.assertEqual(cfg["NEO4J"]["username"], "neo4j")
            self.assertEqual(cfg["NEO4J"]["password"], "bloodhoundcommunityedition")
            self.assertEqual(cfg["BLOODHOUND"]["username"], "admin")
            self.assertNotIn("password", cfg["BLOODHOUND"])
            self.assertEqual(cfg["BLOODHOUND"]["enabled"], "True")
            self.assertEqual(cfg["BLOODHOUND"]["url"], "http://localhost:8080")

    def test_default_creds_disconnected_falls_through_to_manual(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()
            (user, pwd), captured = silent(
                get_valid_neo4j_credentials,
                base_resolved(), cfg, ini,
                input_fn=make_input_fn(["jdoe", "pw"]),
                neo4j_factory=make_neo4j_factory([
                    {"connected": False},
                    {"connected": True},
                ]),
            )
            self.assertEqual((user, pwd), ("jdoe", "pw"))
            self.assertNotIn("Default credentials failed", captured)
            self.assertNotIn("Please enter your Neo4j credentials", captured)

    def test_default_creds_exception_prompts_manual_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()
            factory = make_neo4j_factory([
                {"raise": RuntimeError("auth fail")},
                {"connected": True},
            ])
            (user, pwd), captured = silent(
                get_valid_neo4j_credentials,
                base_resolved(), cfg, ini,
                input_fn=make_input_fn(["alice", "secret"]),
                neo4j_factory=factory,
            )
            self.assertEqual((user, pwd), ("alice", "secret"))
            self.assertEqual(factory.calls, [
                ("neo4j://localhost:7687", "neo4j", "bloodhoundcommunityedition"),
                ("neo4j://localhost:7687", "alice", "secret"),
            ])
            self.assertIn("Default credentials failed", captured)
            self.assertIn("Please enter your Neo4j credentials", captured)

    def test_manual_entry_retries_until_connected(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()
            (user, pwd), _ = silent(
                get_valid_neo4j_credentials,
                base_resolved(), cfg, ini,
                input_fn=make_input_fn(["bad1", "bad1", "good", "good"]),
                neo4j_factory=make_neo4j_factory([
                    {"raise": RuntimeError("default fail")},
                    {"connected": False},
                    {"connected": True},
                ]),
            )
            self.assertEqual((user, pwd), ("good", "good"))

class TestSaveConfig(unittest.TestCase):

    def test_first_write_chmods_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()
            cfg.add_section("NEO4J")
            cfg["NEO4J"]["username"] = "x"
            save_config(cfg, ini)
            mode = stat.S_IMODE(os.stat(ini).st_mode)
            self.assertEqual(mode, 0o600)

    def test_subsequent_writes_preserve_existing_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()
            cfg.add_section("NEO4J")
            save_config(cfg, ini)
            os.chmod(ini, 0o644)
            cfg["NEO4J"]["username"] = "y"
            save_config(cfg, ini)
            mode = stat.S_IMODE(os.stat(ini).st_mode)
            self.assertEqual(mode, 0o644)

    def test_chmod_oserror_swallowed_file_still_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()
            cfg.add_section("NEO4J")
            with mock.patch("modules.config_manager.os.chmod", side_effect=OSError("nope")):
                save_config(cfg, ini)
            self.assertTrue(os.path.isfile(ini))

class TestDisableBloodhound(unittest.TestCase):

    def test_disable_writes_enabled_false_to_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()
            disable_bloodhound(cfg, ini, "http://bh.example:8080")
            reloaded = configparser.ConfigParser()
            reloaded.read(ini)
            self.assertEqual(reloaded["BLOODHOUND"]["enabled"], "False")
            self.assertEqual(reloaded["BLOODHOUND"]["url"], "http://bh.example:8080")

class TestGetValidBloodhoundCredentials(unittest.TestCase):

    def test_stored_creds_authenticate_without_prompting(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()

            def fail_on_input(_):
                raise AssertionError("input must not be called when stored creds authenticate")

            factory = make_bh_factory([True])
            (username, password), _ = silent(
                get_valid_bloodhound_credentials,
                base_resolved(bh_enabled=True, bh_url="http://bh.example:8080",
                              bh_username="admin", bh_password=Secret("stored")),
                cfg, ini,
                input_fn=fail_on_input,
                bh_factory=factory,
            )
            self.assertEqual((username, password), ("admin", "stored"))
            self.assertEqual(len(factory.calls), 1)
            args, kwargs = factory.calls[0]
            self.assertEqual(args, (None,))
            self.assertEqual(kwargs, {
                "bloodhound_username": "admin",
                "bloodhound_password": "stored",
                "base_url": "http://bh.example:8080",
            })

    def test_stored_creds_fail_user_skips_disables_bloodhound(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()
            (result, _) = silent(
                get_valid_bloodhound_credentials,
                base_resolved(bh_enabled=True, bh_username="admin", bh_password=Secret("stale")),
                cfg, ini,
                input_fn=make_input_fn([""]),
                bh_factory=make_bh_factory([False]),
            )
            self.assertEqual(result, (None, None))
            reloaded = configparser.ConfigParser()
            reloaded.read(ini)
            self.assertEqual(reloaded["BLOODHOUND"]["enabled"], "False")

    def test_three_failed_attempts_disables_bloodhound(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()
            (result, _) = silent(
                get_valid_bloodhound_credentials,
                base_resolved(bh_enabled=True),
                cfg, ini,
                input_fn=make_input_fn(["u1", "p1", "u2", "p2", "u3", "p3"]),
                bh_factory=make_bh_factory([False, False, False]),
            )
            self.assertEqual(result, (None, None))
            reloaded = configparser.ConfigParser()
            reloaded.read(ini)
            self.assertEqual(reloaded["BLOODHOUND"]["enabled"], "False")

    def test_force_flag_re_enables_disabled_bloodhound(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()
            cfg.add_section("BLOODHOUND")
            cfg["BLOODHOUND"]["enabled"] = "False"
            save_config(cfg, ini)

            (username, password), _ = silent(
                get_valid_bloodhound_credentials,
                base_resolved(bh_enabled=False, bh_username="admin", bh_password=Secret("pw")),
                cfg, ini,
                force=True,
                input_fn=make_input_fn([]),
                bh_factory=make_bh_factory([True]),
            )
            self.assertEqual((username, password), ("admin", "pw"))
            reloaded = configparser.ConfigParser()
            reloaded.read(ini)
            self.assertEqual(reloaded["BLOODHOUND"]["enabled"], "True")

    def test_disabled_without_force_returns_none_immediately(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()

            def fail_on_input(_):
                raise AssertionError("input must not be called on disabled-and-not-force path")

            (result, _) = silent(
                get_valid_bloodhound_credentials,
                base_resolved(bh_enabled=False),
                cfg, ini,
                input_fn=fail_on_input,
                bh_factory=make_bh_factory([]),
            )
            self.assertEqual(result, (None, None))

class TestConnectNeo4jAndLoadBloodhound(unittest.TestCase):

    def setUp(self):
        self._patcher = mock.patch.dict(os.environ, {}, clear=False)
        self._patcher.start()
        for key in list(os.environ):
            if key.startswith("ADPF_"):
                del os.environ[key]

    def tearDown(self):
        self._patcher.stop()

    def test_stored_neo4j_creds_skip_bootstrap(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            with open(ini, "w") as fh:
                fh.write("[NEO4J]\nusername=stored\npassword=storedpw\n")
            cfg = configparser.ConfigParser()
            cfg.read(ini)
            resolved = base_resolved(
                neo4j_uri="neo4j+s://neo.example:7687",
                neo4j_username="stored",
                neo4j_password=Secret("storedpw"),
                bh_url="http://bh:8080",
                bh_username="bh_user",
                bh_password=Secret("bh_pw"),
                bh_enabled=True,
            )

            factory = make_neo4j_factory([{"connected": True}])
            with mock.patch("modules.config_manager.load_resolved_config") as reload_mock:
                (out, _) = silent(
                    connect_neo4j_and_load_bloodhound,
                    resolved, cfg, ini,
                    input_fn=make_input_fn([]),
                    neo4j_factory=factory,
                )
                reload_mock.assert_not_called()

            conn, bh_username, bh_password, bh_enabled = out
            self.assertTrue(conn.is_connected())
            self.assertEqual(factory.calls, [("neo4j+s://neo.example:7687", "stored", "storedpw")])
            self.assertEqual(bh_username, "bh_user")
            self.assertEqual(bh_password, "bh_pw")
            self.assertTrue(bh_enabled)

    def test_stored_neo4j_creds_exception_triggers_bootstrap(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()
            resolved = base_resolved(
                neo4j_username="stale",
                neo4j_password=Secret("stalepw"),
            )

            reloaded = base_resolved(
                bh_url="http://localhost:8080",
                bh_username="admin",
                bh_password=Secret("This-Password1-Meets-Policy"),
                bh_enabled=True,
                bh_configured=True,
            )

            with mock.patch("modules.config_manager.load_resolved_config", return_value=reloaded) as reload_mock:
                (out, _) = silent(
                    connect_neo4j_and_load_bloodhound,
                    resolved, cfg, ini,
                    input_fn=make_input_fn(["u", "p"]),
                    neo4j_factory=make_neo4j_factory([
                        {"raise": RuntimeError("stored creds broken")},
                        {"raise": RuntimeError("default creds also fail")},
                        {"connected": True},
                        {"connected": True},
                    ]),
                )
                reload_mock.assert_called_once_with(ini)

            _, bh_username, bh_password, bh_enabled = out
            self.assertEqual(bh_username, "admin")
            self.assertEqual(bh_password, "This-Password1-Meets-Policy")
            self.assertTrue(bh_enabled)

    def test_stored_neo4j_creds_disconnected_triggers_bootstrap(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()
            resolved = base_resolved(
                neo4j_username="stale",
                neo4j_password=Secret("stalepw"),
            )

            reloaded = base_resolved(
                bh_url="http://localhost:8080",
                bh_username="admin",
                bh_password=Secret("This-Password1-Meets-Policy"),
                bh_enabled=True,
            )

            with mock.patch("modules.config_manager.load_resolved_config", return_value=reloaded) as reload_mock:
                (out, _) = silent(
                    connect_neo4j_and_load_bloodhound,
                    resolved, cfg, ini,
                    input_fn=make_input_fn(["u", "p"]),
                    neo4j_factory=make_neo4j_factory([
                        {"connected": False},
                        {"raise": RuntimeError("default fail")},
                        {"connected": True},
                        {"connected": True},
                    ]),
                )
                reload_mock.assert_called_once_with(ini)

            _, bh_username, _, bh_enabled = out
            self.assertEqual(bh_username, "admin")
            self.assertTrue(bh_enabled)

    def test_missing_config_file_bootstraps_and_resolves(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "nonexistent.ini")
            cfg = configparser.ConfigParser()
            resolved = base_resolved()

            reloaded = base_resolved(
                bh_username="admin",
                bh_password=Secret("This-Password1-Meets-Policy"),
                bh_enabled=True,
            )

            with mock.patch("modules.config_manager.load_resolved_config", return_value=reloaded) as reload_mock:
                (out, _) = silent(
                    connect_neo4j_and_load_bloodhound,
                    resolved, cfg, ini,
                    input_fn=make_input_fn([]),
                    neo4j_factory=make_neo4j_factory([
                        {"connected": True},
                        {"connected": True},
                    ]),
                )
                reload_mock.assert_called_once_with(ini)

            _, bh_username, _, bh_enabled = out
            self.assertEqual(bh_username, "admin")
            self.assertTrue(bh_enabled)

    def test_config_exists_without_neo4j_section_bootstraps(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            with open(ini, "w") as fh:
                fh.write("[OTHER]\nfoo=bar\n")
            cfg = configparser.ConfigParser()
            cfg.read(ini)
            resolved = base_resolved()

            reloaded = base_resolved(
                bh_username="admin",
                bh_password=Secret("This-Password1-Meets-Policy"),
                bh_enabled=True,
            )

            with mock.patch("modules.config_manager.load_resolved_config", return_value=reloaded) as reload_mock:
                (out, _) = silent(
                    connect_neo4j_and_load_bloodhound,
                    resolved, cfg, ini,
                    input_fn=make_input_fn([]),
                    neo4j_factory=make_neo4j_factory([
                        {"connected": True},
                        {"connected": True},
                    ]),
                )
                reload_mock.assert_called_once_with(ini)

            _, bh_username, _, bh_enabled = out
            self.assertEqual(bh_username, "admin")
            self.assertTrue(bh_enabled)

    def test_env_overrides_bootstrap_bloodhound_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "nonexistent.ini")
            cfg = configparser.ConfigParser()
            resolved = base_resolved()

            reloaded = base_resolved(
                bh_username="admin",
                bh_password=Secret("This-Password1-Meets-Policy"),
                bh_enabled=False,
            )

            with mock.patch.dict(os.environ, {"ADPF_BLOODHOUND_ENABLED": "false"}, clear=False), \
                 mock.patch("modules.config_manager.load_resolved_config", return_value=reloaded):
                (out, _) = silent(
                    connect_neo4j_and_load_bloodhound,
                    resolved, cfg, ini,
                    input_fn=make_input_fn([]),
                    neo4j_factory=make_neo4j_factory([
                        {"connected": True},
                        {"connected": True},
                    ]),
                )

            _, _, _, bh_enabled = out
            self.assertFalse(bh_enabled)

    def test_env_overrides_bootstrap_bloodhound_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "nonexistent.ini")
            cfg = configparser.ConfigParser()
            resolved = base_resolved()

            reloaded = base_resolved(
                bh_username="custom_user",
                bh_password=Secret("custom_pass"),
                bh_enabled=True,
            )

            env = {
                "ADPF_BLOODHOUND_USERNAME": "custom_user",
                "ADPF_BLOODHOUND_PASSWORD": "custom_pass",
            }
            with mock.patch.dict(os.environ, env, clear=False), \
                 mock.patch("modules.config_manager.load_resolved_config", return_value=reloaded):
                (out, _) = silent(
                    connect_neo4j_and_load_bloodhound,
                    resolved, cfg, ini,
                    input_fn=make_input_fn([]),
                    neo4j_factory=make_neo4j_factory([
                        {"connected": True},
                        {"connected": True},
                    ]),
                )

            _, bh_username, bh_password, _ = out
            self.assertEqual(bh_username, "custom_user")
            self.assertEqual(bh_password, "custom_pass")
