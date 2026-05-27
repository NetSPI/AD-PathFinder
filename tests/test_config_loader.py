import configparser
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from modules.config_loader import (
    BLOODHOUND_URL_DEFAULT,
    DEFAULT_EXCLUDED_RELATIONSHIPS,
    NEO4J_URI_DEFAULT,
    _env_bool,
    load,
)
from modules.secret import Secret

ADPF_ENV_VARS = (
    "ADPF_NEO4J_URI",
    "ADPF_NEO4J_USERNAME",
    "ADPF_NEO4J_PASSWORD",
    "ADPF_BLOODHOUND_URL",
    "ADPF_BLOODHOUND_USERNAME",
    "ADPF_BLOODHOUND_PASSWORD",
    "ADPF_BLOODHOUND_ENABLED",
    "ADPF_HASHCAT_FILE_PATH",
)

def _clean_env():
    env = os.environ.copy()
    for var in ADPF_ENV_VARS:
        env.pop(var, None)
    return env

def _write(path: str, body: str) -> None:
    with open(path, "w") as fh:
        fh.write(body)

class TestEnvBoolValidValues(unittest.TestCase):

    def test_truthy_values(self):
        for raw in ("1", "true", "TRUE", "True", "yes", "YES", "on", "ON"):
            with patch.dict(os.environ, {"ADPF_TEST_BOOL": raw}, clear=False):
                self.assertIs(_env_bool("ADPF_TEST_BOOL"), True, f"value={raw!r}")

    def test_falsy_values(self):
        for raw in ("0", "false", "FALSE", "False", "no", "NO", "off", "OFF"):
            with patch.dict(os.environ, {"ADPF_TEST_BOOL": raw}, clear=False):
                self.assertIs(_env_bool("ADPF_TEST_BOOL"), False, f"value={raw!r}")

    def test_unset_returns_none(self):
        env = _clean_env()
        with patch.dict(os.environ, env, clear=True):
            self.assertIsNone(_env_bool("ADPF_TEST_BOOL"))

    def test_whitespace_stripped(self):
        with patch.dict(os.environ, {"ADPF_TEST_BOOL": "  true  "}, clear=False):
            self.assertIs(_env_bool("ADPF_TEST_BOOL"), True)

class TestEnvBoolInvalidValueWarning(unittest.TestCase):

    def test_typo_returns_none_not_false(self):
        with patch.dict(os.environ, {"ADPF_TEST_BOOL": "treu"}, clear=False):
            buf = io.StringIO()
            with redirect_stdout(buf):
                result = _env_bool("ADPF_TEST_BOOL")
            self.assertIsNone(result)
            self.assertIn("ADPF_TEST_BOOL", buf.getvalue())
            self.assertIn("treu", buf.getvalue())

    def test_empty_string_returns_none(self):
        with patch.dict(os.environ, {"ADPF_TEST_BOOL": ""}, clear=False):
            self.assertIsNone(_env_bool("ADPF_TEST_BOOL"))

    def test_garbage_returns_none(self):
        for raw in ("maybe", "2", "enabled", "disabled"):
            with patch.dict(os.environ, {"ADPF_TEST_BOOL": raw}, clear=False):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    result = _env_bool("ADPF_TEST_BOOL")
                self.assertIsNone(result, f"value={raw!r}")
                self.assertIn("not a valid boolean", buf.getvalue())

class TestLoadDefaults(unittest.TestCase):

    def test_missing_file_returns_hard_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.ini")
            with patch.dict(os.environ, _clean_env(), clear=True):
                resolved = load(missing)
            self.assertEqual(resolved.neo4j_uri, NEO4J_URI_DEFAULT)
            self.assertEqual(resolved.bh_url, BLOODHOUND_URL_DEFAULT)
            self.assertIsNone(resolved.neo4j_username)
            self.assertIsNone(resolved.neo4j_password)
            self.assertIsNone(resolved.bh_username)
            self.assertIsNone(resolved.bh_password)
            self.assertFalse(resolved.bh_enabled)
            self.assertFalse(resolved.bh_configured)
            self.assertIsNone(resolved.hashcat_file_path)
            self.assertEqual(
                resolved.excluded_relationships,
                tuple(DEFAULT_EXCLUDED_RELATIONSHIPS),
            )

class TestLoadPrecedence(unittest.TestCase):

    def test_env_beats_config_for_neo4j_uri(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(ini, "[NEO4J]\nuri = neo4j://config-host:7687\n")
            env = _clean_env()
            env["ADPF_NEO4J_URI"] = "bolt+s://env-host:7687"
            with patch.dict(os.environ, env, clear=True):
                resolved = load(ini)
            self.assertEqual(resolved.neo4j_uri, "bolt+s://env-host:7687")

    def test_config_used_when_env_unset(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(ini, "[NEO4J]\nuri = neo4j://config-host:7687\nusername = neo4j\npassword = pw\n")
            with patch.dict(os.environ, _clean_env(), clear=True):
                resolved = load(ini)
            self.assertEqual(resolved.neo4j_uri, "neo4j://config-host:7687")
            self.assertEqual(resolved.neo4j_username, "neo4j")
            self.assertIsInstance(resolved.neo4j_password, Secret)
            self.assertEqual(resolved.neo4j_password.expose(), "pw")

    def test_passwords_wrapped_in_secret(self):
        env = _clean_env()
        env["ADPF_NEO4J_PASSWORD"] = "n4j-secret"
        env["ADPF_BLOODHOUND_PASSWORD"] = "bh-secret"
        with patch.dict(os.environ, env, clear=True):
            resolved = load("nonexistent.ini")
        self.assertIsInstance(resolved.neo4j_password, Secret)
        self.assertIsInstance(resolved.bh_password, Secret)
        self.assertEqual(resolved.neo4j_password.expose(), "n4j-secret")
        self.assertEqual(resolved.bh_password.expose(), "bh-secret")
        self.assertNotIn("n4j-secret", repr(resolved.neo4j_password))
        self.assertNotIn("bh-secret", repr(resolved.bh_password))

class TestBloodhoundUrlNormalisation(unittest.TestCase):

    def test_trailing_slash_stripped_from_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(ini, "[BLOODHOUND]\nurl = http://bh.example/\nenabled = True\n")
            with patch.dict(os.environ, _clean_env(), clear=True):
                resolved = load(ini)
            self.assertEqual(resolved.bh_url, "http://bh.example")

    def test_trailing_slash_stripped_from_env(self):
        env = _clean_env()
        env["ADPF_BLOODHOUND_URL"] = "https://bh.example:8443/"
        with patch.dict(os.environ, env, clear=True):
            resolved = load("nonexistent.ini")
        self.assertEqual(resolved.bh_url, "https://bh.example:8443")

class TestBhConfiguredAndEnabled(unittest.TestCase):

    def test_no_section_and_no_env_means_not_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(ini, "[NEO4J]\nuri = neo4j://localhost:7687\n")
            with patch.dict(os.environ, _clean_env(), clear=True):
                resolved = load(ini)
            self.assertFalse(resolved.bh_configured)
            self.assertFalse(resolved.bh_enabled)

    def test_section_present_means_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(ini, "[BLOODHOUND]\nenabled = False\n")
            with patch.dict(os.environ, _clean_env(), clear=True):
                resolved = load(ini)
            self.assertTrue(resolved.bh_configured)
            self.assertFalse(resolved.bh_enabled)

    def test_legacy_section_without_enabled_key_defaults_to_enabled(self):
        # regression: pre-refactor get_valid_bloodhound_credentials used fallback=True
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(ini, "[BLOODHOUND]\nurl = http://bh.example\nusername = admin\npassword = pw\n")
            with patch.dict(os.environ, _clean_env(), clear=True):
                resolved = load(ini)
            self.assertTrue(resolved.bh_configured)
            self.assertTrue(resolved.bh_enabled)

    def test_env_set_means_configured_even_without_section(self):
        env = _clean_env()
        env["ADPF_BLOODHOUND_ENABLED"] = "false"
        with patch.dict(os.environ, env, clear=True):
            resolved = load("nonexistent.ini")
        self.assertTrue(resolved.bh_configured)
        self.assertFalse(resolved.bh_enabled)

    def test_env_false_overrides_config_true(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(ini, "[BLOODHOUND]\nenabled = True\n")
            env = _clean_env()
            env["ADPF_BLOODHOUND_ENABLED"] = "false"
            with patch.dict(os.environ, env, clear=True):
                resolved = load(ini)
            self.assertTrue(resolved.bh_configured)
            self.assertFalse(resolved.bh_enabled)

    def test_env_true_overrides_config_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(ini, "[BLOODHOUND]\nenabled = False\n")
            env = _clean_env()
            env["ADPF_BLOODHOUND_ENABLED"] = "true"
            with patch.dict(os.environ, env, clear=True):
                resolved = load(ini)
            self.assertTrue(resolved.bh_configured)
            self.assertTrue(resolved.bh_enabled)

    def test_invalid_env_falls_through_to_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(ini, "[BLOODHOUND]\nenabled = True\n")
            env = _clean_env()
            env["ADPF_BLOODHOUND_ENABLED"] = "treu"
            with patch.dict(os.environ, env, clear=True):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    resolved = load(ini)
            self.assertTrue(resolved.bh_enabled)
            self.assertTrue(resolved.bh_configured)
            self.assertIn("treu", buf.getvalue())

class TestHashcatPathResolution(unittest.TestCase):

    def test_existing_file_resolves(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"")
            pot = fh.name
        try:
            env = _clean_env()
            env["ADPF_HASHCAT_FILE_PATH"] = pot
            with patch.dict(os.environ, env, clear=True):
                resolved = load("nonexistent.ini")
            self.assertEqual(resolved.hashcat_file_path, pot)
        finally:
            os.unlink(pot)

    def test_missing_file_drops_to_none(self):
        env = _clean_env()
        env["ADPF_HASHCAT_FILE_PATH"] = "/nonexistent/path/to/potfile.txt"
        with patch.dict(os.environ, env, clear=True):
            resolved = load("nonexistent.ini")
        self.assertIsNone(resolved.hashcat_file_path)

class TestExclusionsConfigWins(unittest.TestCase):

    def test_missing_section_falls_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(ini, "[NEO4J]\nuri = neo4j://localhost:7687\n")
            with patch.dict(os.environ, _clean_env(), clear=True):
                resolved = load(ini)
            self.assertEqual(
                resolved.excluded_relationships,
                tuple(DEFAULT_EXCLUDED_RELATIONSHIPS),
            )

    def test_present_but_empty_distinct_from_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(ini, "[EXCLUSIONS]\nexcluded_relationships =\n")
            with patch.dict(os.environ, _clean_env(), clear=True):
                resolved = load(ini)
            self.assertEqual(resolved.excluded_relationships, ())

    def test_explicit_list_replaces_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(ini, "[EXCLUSIONS]\nexcluded_relationships = OnlyThis, AndThat\n")
            with patch.dict(os.environ, _clean_env(), clear=True):
                resolved = load(ini)
            self.assertEqual(
                resolved.excluded_relationships,
                ("OnlyThis", "AndThat"),
            )
            for default in DEFAULT_EXCLUDED_RELATIONSHIPS:
                self.assertNotIn(default, resolved.excluded_relationships)

    def test_dedupe_case_insensitive(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(ini, "[EXCLUSIONS]\nexcluded_relationships = contains, Contains, CONTAINS, Enroll\n")
            with patch.dict(os.environ, _clean_env(), clear=True):
                resolved = load(ini)
            self.assertEqual(resolved.excluded_relationships, ("contains", "Enroll"))

    def test_multi_line_continuation_parses(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(
                ini,
                "[EXCLUSIONS]\nexcluded_relationships = First,\n    Second,\n    Third\n",
            )
            with patch.dict(os.environ, _clean_env(), clear=True):
                resolved = load(ini)
            self.assertEqual(resolved.excluded_relationships, ("First", "Second", "Third"))

    def test_default_list_contains_audited_45_entries(self):
        self.assertEqual(len(DEFAULT_EXCLUDED_RELATIONSHIPS), 45)
        self.assertIn("ADCSESC2", DEFAULT_EXCLUDED_RELATIONSHIPS)
        self.assertIn("ADCSESC7", DEFAULT_EXCLUDED_RELATIONSHIPS)
        self.assertIn("CoerceAndRelayNTLMToLDAP", DEFAULT_EXCLUDED_RELATIONSHIPS)
        self.assertIn("CoerceAndRelayNTLMToLDAPS", DEFAULT_EXCLUDED_RELATIONSHIPS)
        for absent in ("ADCSESC10a", "ADCSESC10b", "ADCSESC13"):
            self.assertNotIn(absent, DEFAULT_EXCLUDED_RELATIONSHIPS)

    def test_round_trip_bootstrap_serialization(self):
        from modules.config_manager import ensure_exclusions_section

        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            cfg = configparser.ConfigParser()
            ensure_exclusions_section(cfg)
            with open(ini, "w") as fh:
                cfg.write(fh)
            with patch.dict(os.environ, _clean_env(), clear=True):
                resolved = load(ini)
            self.assertEqual(
                resolved.excluded_relationships,
                tuple(DEFAULT_EXCLUDED_RELATIONSHIPS),
            )

class TestPermissionWarning(unittest.TestCase):

    def test_world_readable_config_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(ini, "[NEO4J]\nuri = neo4j://localhost:7687\n")
            os.chmod(ini, 0o644)
            buf = io.StringIO()
            with patch.dict(os.environ, _clean_env(), clear=True):
                with redirect_stdout(buf):
                    load(ini)
            self.assertIn("readable beyond owner", buf.getvalue())
            self.assertIn("chmod 600", buf.getvalue())

    def test_owner_only_config_does_not_warn(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "config.ini")
            _write(ini, "[NEO4J]\nuri = neo4j://localhost:7687\n")
            os.chmod(ini, 0o600)
            buf = io.StringIO()
            with patch.dict(os.environ, _clean_env(), clear=True):
                with redirect_stdout(buf):
                    load(ini)
            self.assertNotIn("readable beyond owner", buf.getvalue())
