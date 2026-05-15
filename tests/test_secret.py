import unittest

from modules.secret import Secret

class TestSecretMasking(unittest.TestCase):

    def test_repr_masks_real_value(self):
        s = Secret("hunter2")
        self.assertEqual(repr(s), "Secret('***')")
        self.assertNotIn("hunter2", repr(s))

    def test_str_masks_real_value(self):
        s = Secret("hunter2")
        self.assertEqual(str(s), "***")
        self.assertNotIn("hunter2", str(s))

    def test_repr_empty_distinguishable(self):
        self.assertEqual(repr(Secret("")), "Secret('')")
        self.assertEqual(repr(Secret(None)), "Secret('')")

    def test_str_empty_distinguishable(self):
        self.assertEqual(str(Secret("")), "")
        self.assertEqual(str(Secret(None)), "")

    def test_format_does_not_leak(self):
        s = Secret("hunter2")
        formatted = f"password={s}"
        self.assertNotIn("hunter2", formatted)
        self.assertEqual(formatted, "password=***")

class TestSecretExpose(unittest.TestCase):

    def test_expose_returns_value(self):
        self.assertEqual(Secret("hunter2").expose(), "hunter2")

    def test_expose_empty_returns_empty_string(self):
        self.assertEqual(Secret("").expose(), "")
        self.assertEqual(Secret(None).expose(), "")

class TestSecretBoolean(unittest.TestCase):

    def test_truthy_when_value_present(self):
        self.assertTrue(bool(Secret("hunter2")))
        self.assertTrue(Secret("x"))

    def test_falsy_when_empty(self):
        self.assertFalse(bool(Secret("")))
        self.assertFalse(bool(Secret(None)))

class TestSecretEquality(unittest.TestCase):

    def test_equal_secrets_compare_equal(self):
        self.assertEqual(Secret("a"), Secret("a"))

    def test_different_secrets_not_equal(self):
        self.assertNotEqual(Secret("a"), Secret("b"))

    def test_secret_not_equal_to_raw_string(self):
        self.assertNotEqual(Secret("a"), "a")

    def test_hash_matches_for_equal_secrets(self):
        self.assertEqual(hash(Secret("a")), hash(Secret("a")))

    def test_hash_derived_from_value(self):
        self.assertEqual(hash(Secret("a")), hash("a"))
