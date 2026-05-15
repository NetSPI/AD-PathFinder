import configparser
import os
import tempfile
import unittest

from modules.config_loader import DEFAULT_EXCLUDED_RELATIONSHIPS, _resolve_excluded_relationships
from modules.config_manager import ensure_exclusions_section

class TestEnsureExclusionsSection(unittest.TestCase):

    def test_section_absent_adds_section_with_defaults(self):
        cfg = configparser.ConfigParser()
        ensure_exclusions_section(cfg)
        self.assertTrue(cfg.has_section("EXCLUSIONS"))
        self.assertTrue(cfg.has_option("EXCLUSIONS", "excluded_relationships"))
        self.assertEqual(
            _resolve_excluded_relationships(cfg),
            tuple(DEFAULT_EXCLUDED_RELATIONSHIPS),
        )

    def test_section_present_but_key_absent_adds_only_the_key(self):
        cfg = configparser.ConfigParser()
        cfg.add_section("EXCLUSIONS")
        ensure_exclusions_section(cfg)
        self.assertEqual(
            _resolve_excluded_relationships(cfg),
            tuple(DEFAULT_EXCLUDED_RELATIONSHIPS),
        )

    def test_key_present_and_empty_left_alone(self):
        cfg = configparser.ConfigParser()
        cfg.add_section("EXCLUSIONS")
        cfg.set("EXCLUSIONS", "excluded_relationships", "")
        ensure_exclusions_section(cfg)
        self.assertEqual(cfg.get("EXCLUSIONS", "excluded_relationships"), "")
        self.assertEqual(_resolve_excluded_relationships(cfg), ())

    def test_key_present_and_populated_left_alone(self):
        cfg = configparser.ConfigParser()
        cfg.add_section("EXCLUSIONS")
        cfg.set("EXCLUSIONS", "excluded_relationships", "OnlyA, OnlyB")
        ensure_exclusions_section(cfg)
        self.assertEqual(
            _resolve_excluded_relationships(cfg),
            ("OnlyA", "OnlyB"),
        )

class TestEnsureExclusionsRoundTrip(unittest.TestCase):

    def test_save_then_reload_preserves_four_states(self):
        with tempfile.TemporaryDirectory() as tmp:
            for label, build in (
                ("section_absent", lambda c: None),
                ("section_only", lambda c: c.add_section("EXCLUSIONS")),
                ("key_empty", lambda c: (c.add_section("EXCLUSIONS"),
                                          c.set("EXCLUSIONS", "excluded_relationships", ""))),
                ("key_populated", lambda c: (c.add_section("EXCLUSIONS"),
                                              c.set("EXCLUSIONS", "excluded_relationships", "Foo, Bar"))),
            ):
                with self.subTest(label=label):
                    cfg = configparser.ConfigParser()
                    build(cfg)
                    ensure_exclusions_section(cfg)
                    path = os.path.join(tmp, f"{label}.ini")
                    with open(path, "w") as fh:
                        cfg.write(fh)
                    reloaded = configparser.ConfigParser()
                    reloaded.read(path)
                    self.assertEqual(
                        _resolve_excluded_relationships(reloaded),
                        _resolve_excluded_relationships(cfg),
                    )
