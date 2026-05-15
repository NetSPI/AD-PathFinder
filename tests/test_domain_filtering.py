import unittest

from checks.core.dependencies import CheckDependencies
from checks.core.platform_mixins import MSSQLDomainMixin, SCCMDomainMixin

class FakeNeo4jData:
    def __init__(self, domain_filter=None):
        self.conn = None
        self._domain_filter = domain_filter
        self.computer_sids = set()

class MSSQLHarness(MSSQLDomainMixin):
    def __init__(self, domain_filter=None):
        self._domain_filter = domain_filter

    def _domain_condition(self, var_name):
        if not self._domain_filter:
            return ""
        d = self._domain_filter.upper()
        return f' AND {var_name}.domain IN ["{d}", ["{d}"]]'

class SCCMHarness(SCCMDomainMixin):
    def __init__(self, domain_filter=None):
        self._domain_filter = domain_filter

class TestPlatformDomainFiltering(unittest.TestCase):
    def test_mssql_server_condition_scopes_fqdn_to_domain_filter(self):
        condition = MSSQLHarness("training.local")._server_domain_condition("server.name")

        self.assertIn("server.name", condition)
        self.assertIn('= "TRAINING.LOCAL"', condition)

    def test_mssql_default_group_condition_scopes_domain_relative_groups(self):
        condition = MSSQLHarness("training.local")._default_group_condition("g")
        compact = " ".join(condition.split())

        for suffix in ["-513", "-515", "S-1-5-11", "S-1-1-0"]:
            self.assertIn(f'g.objectid ENDS WITH "{suffix}"', compact)
            self.assertIn(f'g.objectid ENDS WITH "{suffix}" AND g.domain IN ["TRAINING.LOCAL", ["TRAINING.LOCAL"]]', compact)

    def test_mssql_builtin_users_fallback_is_scoped_when_domain_filter_is_set(self):
        condition = MSSQLHarness("training.local")._default_group_condition("g")
        compact = " ".join(condition.split())

        self.assertIn(
            'g.objectid ENDS WITH "S-1-5-32-545" AND g.domain IN ["TRAINING.LOCAL", ["TRAINING.LOCAL"]]',
            compact,
        )

    def test_sccm_site_condition_scopes_source_forest(self):
        condition = SCCMHarness("training.local")._site_domain_condition("site")

        self.assertEqual(condition, ' AND toUpper(site.sourceForest) = "TRAINING.LOCAL"')

    def test_domain_mixins_emit_no_condition_without_filter(self):
        self.assertEqual(MSSQLHarness()._server_domain_condition("server.name"), "")
        self.assertEqual(SCCMHarness()._site_domain_condition("site"), "")

class TestRealMSSQLChecksUseDomainPredicates(unittest.TestCase):
    def _make_check(self, check_class, domain_filter="training.local"):
        neo4j_data = FakeNeo4jData(domain_filter)
        return check_class(CheckDependencies(neo4j_data=neo4j_data))

    def test_mssql_logins_group_query_uses_default_group_condition(self):
        from checks.mssql_logins import MSSQLLoginsCheck

        check = self._make_check(MSSQLLoginsCheck)
        condition = check._default_group_condition()

        self.assertIn('g.domain IN ["TRAINING.LOCAL", ["TRAINING.LOCAL"]]', condition)

    def test_mssql_ntlm_relay_targets_are_domain_filtered(self):
        from checks.mssql_ntlm_relay import MSSQLNTLMRelayCheck

        check = self._make_check(MSSQLNTLMRelayCheck)
        condition = check._domain_condition("c")

        self.assertEqual(condition, ' AND c.domain IN ["TRAINING.LOCAL", ["TRAINING.LOCAL"]]')
