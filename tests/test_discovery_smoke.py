import unittest

class TestCheckDiscoverySmoke(unittest.TestCase):
    def test_importing_check_packages_registers_expected_checks(self):
        import checks
        import checks.cross_domain
        from checks.core.registry import CheckRegistry

        registered = {check_class.__name__ for check_class in CheckRegistry.get_all_checks()}

        self.assertEqual(len(registered), 50)
        self.assertIn("MSSQLLoginsCheck", registered)
        self.assertIn("MSSQLNTLMRelayCheck", registered)
        self.assertIn("SCCMTakeover1Check", registered)

    def test_runtime_imports_needed_by_installed_console_are_available(self):
        import checks
        import datasources
        import modules.main

        self.assertIsNotNone(checks)
        self.assertIsNotNone(datasources)
        self.assertTrue(callable(modules.main.main))

    def test_check_packages_expose_import_errors_collector(self):
        import checks
        import checks.cross_domain

        self.assertIsInstance(checks.IMPORT_ERRORS, list)
        self.assertIsInstance(checks.cross_domain.IMPORT_ERRORS, list)
        self.assertEqual(checks.IMPORT_ERRORS, [],
                         "checks/ has unexpected import errors in healthy state")
        self.assertEqual(checks.cross_domain.IMPORT_ERRORS, [],
                         "checks/cross_domain/ has unexpected import errors in healthy state")
