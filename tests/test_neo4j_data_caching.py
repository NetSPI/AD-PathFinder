import inspect
import unittest
from unittest.mock import MagicMock

from modules.neo4j_data import Neo4jData

def _make_conn(return_value=None):
    conn = MagicMock()
    if return_value is None:
        conn.query.return_value = []
    else:
        conn.query.return_value = return_value
    return conn

class TestCheckBhVersionPerInstanceCache(unittest.TestCase):

    def test_second_call_returns_cached_no_extra_query(self):
        conn = _make_conn([{"is_v2": True}])
        nd = Neo4jData(conn, domain_filter="A.LOCAL")
        self.assertEqual(nd.check_bh_version(), "v2")
        self.assertEqual(nd.check_bh_version(), "v2")
        self.assertEqual(conn.query.call_count, 1)

    def test_v1_path_also_cached(self):
        conn = _make_conn([{"is_v2": False}])
        nd = Neo4jData(conn, domain_filter="A.LOCAL")
        self.assertEqual(nd.check_bh_version(), "v1")
        self.assertEqual(nd.check_bh_version(), "v1")
        self.assertEqual(conn.query.call_count, 1)

    def test_empty_result_treated_as_v1_and_cached(self):
        conn = _make_conn([])
        nd = Neo4jData(conn, domain_filter="A.LOCAL")
        self.assertEqual(nd.check_bh_version(), "v1")
        self.assertEqual(nd.check_bh_version(), "v1")
        self.assertEqual(conn.query.call_count, 1)

class TestGetAllComputersCacheUnderDomainFilter(unittest.TestCase):

    def test_second_call_returns_same_object_one_query(self):
        conn = _make_conn([{"name": "DC01.A.LOCAL", "samaccountname": "DC01$"}])
        nd = Neo4jData(conn, domain_filter="A.LOCAL")
        first = nd.get_all_computers_with_attributes()
        second = nd.get_all_computers_with_attributes()
        self.assertIs(first, second)
        self.assertEqual(conn.query.call_count, 1)

    def test_force_refresh_re_runs_query(self):
        conn = _make_conn([{"name": "DC01.A.LOCAL"}])
        nd = Neo4jData(conn, domain_filter="A.LOCAL")
        nd.get_all_computers_with_attributes()
        nd.get_all_computers_with_attributes(force_refresh=True)
        self.assertEqual(conn.query.call_count, 2)

class TestGetAllEnterpriseCasCacheUnderDomainFilter(unittest.TestCase):

    def test_second_call_one_query(self):
        conn = _make_conn([{"name": "CA1", "dnshostname": "ca.a.local"}])
        nd = Neo4jData(conn, domain_filter="A.LOCAL")
        nd.get_all_enterprise_cas_with_attributes()
        nd.get_all_enterprise_cas_with_attributes()
        self.assertEqual(conn.query.call_count, 1)

    def test_empty_result_cached(self):
        conn = _make_conn([])
        nd = Neo4jData(conn, domain_filter="A.LOCAL")
        first = nd.get_all_enterprise_cas_with_attributes()
        second = nd.get_all_enterprise_cas_with_attributes()
        self.assertEqual(first, [])
        self.assertEqual(second, [])
        self.assertEqual(conn.query.call_count, 1)

class TestGetComputerAdminPathsCacheUnderDomainFilter(unittest.TestCase):

    def test_second_call_one_query(self):
        conn = _make_conn([{"SourceSID": "S-1", "TargetSID": "S-2"}])
        nd = Neo4jData(conn, domain_filter="A.LOCAL")
        first = nd.get_computer_admin_paths()
        second = nd.get_computer_admin_paths()
        self.assertIs(first, second)
        self.assertEqual(conn.query.call_count, 1)

class TestGetUserToComputerAdminPathsCacheUnderDomainFilter(unittest.TestCase):

    def test_second_call_one_query(self):
        conn = _make_conn([{"SourceSID": "S-1", "TargetSID": "S-2"}])
        nd = Neo4jData(conn, domain_filter="A.LOCAL")
        first = nd.get_user_to_computer_admin_paths()
        second = nd.get_user_to_computer_admin_paths()
        self.assertIs(first, second)
        self.assertEqual(conn.query.call_count, 1)

class TestCacheShortCircuitsForComplexMethods(unittest.TestCase):
    """Methods whose first call runs many internal queries: pre-prime the cache and
    verify the second call short-circuits without touching conn.query."""

    def test_get_all_users_with_attributes_short_circuits_when_primed(self):
        conn = MagicMock()
        nd = Neo4jData(conn, domain_filter="A.LOCAL")
        primed = [{"username": "alice"}]
        nd.all_users_data_cache = primed
        result = nd.get_all_users_with_attributes()
        self.assertIs(result, primed)
        self.assertEqual(conn.query.call_count, 0)

    def test_get_builtin_groups_analysis_short_circuits_when_primed(self):
        conn = MagicMock()
        nd = Neo4jData(conn, domain_filter="A.LOCAL")
        primed = [{"groupFriendlyName": "Domain Users"}]
        nd.builtin_groups_paths_cache = primed
        result = nd.get_builtin_groups_analysis()
        self.assertIs(result, primed)
        self.assertEqual(conn.query.call_count, 0)

    def test_get_common_groups_analysis_short_circuits_when_primed(self):
        conn = MagicMock()
        nd = Neo4jData(conn, domain_filter="A.LOCAL")
        primed = [{"groupFriendlyName": "IT Staff"}]
        nd.common_groups_paths_cache = primed
        result = nd.get_common_groups_analysis(threshold_count=10, total_user_count=100)
        self.assertIs(result, primed)
        self.assertEqual(conn.query.call_count, 0)

class TestDistinctDomainFilterInstancesIsolated(unittest.TestCase):
    """Two Neo4jData(domain_filter=...) instances must not share cache state."""

    def test_users_cache_not_shared_across_instances(self):
        conn_a = MagicMock()
        conn_b = MagicMock()
        nd_a = Neo4jData(conn_a, domain_filter="A.LOCAL")
        nd_b = Neo4jData(conn_b, domain_filter="B.LOCAL")
        nd_a.all_users_data_cache = [{"username": "alice@A.LOCAL"}]
        self.assertIsNone(nd_b.all_users_data_cache)

    def test_computers_cache_not_shared_across_instances(self):
        conn_a = MagicMock()
        conn_b = MagicMock()
        nd_a = Neo4jData(conn_a, domain_filter="A.LOCAL")
        nd_b = Neo4jData(conn_b, domain_filter="B.LOCAL")
        nd_a.all_computers_cache = [{"name": "DC01.A.LOCAL"}]
        self.assertFalse(hasattr(nd_b, "all_computers_cache"))

    def test_admin_paths_cache_not_shared_across_instances(self):
        conn_a = MagicMock()
        conn_b = MagicMock()
        nd_a = Neo4jData(conn_a, domain_filter="A.LOCAL")
        nd_b = Neo4jData(conn_b, domain_filter="B.LOCAL")
        nd_a.admin_paths_cache["admin_paths"] = ["a-only"]
        self.assertEqual(nd_b.admin_paths_cache, {})

    def test_bh_version_cache_not_shared_across_instances(self):
        conn_a = _make_conn([{"is_v2": True}])
        conn_b = _make_conn([{"is_v2": False}])
        nd_a = Neo4jData(conn_a, domain_filter="A.LOCAL")
        nd_b = Neo4jData(conn_b, domain_filter="B.LOCAL")
        self.assertEqual(nd_a.check_bh_version(), "v2")
        self.assertEqual(nd_b.check_bh_version(), "v1")
        self.assertEqual(conn_a.query.call_count, 1)
        self.assertEqual(conn_b.query.call_count, 1)

class TestGetAllUsersSignatureMatchesLiveCallers(unittest.TestCase):
    """After dropping the dead domain_filter parameter the function must still accept
    every kwarg that today's callers pass:
      - analysis.py:18           -> skip_high_value=...
      - account_analysis.py:187  -> skip_high_value=..., force_refresh=...
      - user_query.py:27         -> username=...
    Preload at checks/core/manager.py invokes via getattr() with no args."""

    def test_signature_accepts_known_caller_kwargs(self):
        sig = inspect.signature(Neo4jData.get_all_users_with_attributes)
        params = sig.parameters
        for kw in ("username", "force_refresh", "skip_high_value"):
            self.assertIn(kw, params, f"{kw} kwarg removed — caller compatibility broken")

    def test_signature_no_longer_advertises_domain_filter(self):
        sig = inspect.signature(Neo4jData.get_all_users_with_attributes)
        self.assertNotIn("domain_filter", sig.parameters,
                         "domain_filter parameter should have been dropped in the cache refactor")

    def test_no_args_invocation_is_valid_signature(self):
        nd = Neo4jData(MagicMock(), domain_filter="A.LOCAL")
        nd.all_users_data_cache = [{"username": "alice"}]
        result = nd.get_all_users_with_attributes()
        self.assertEqual(result, [{"username": "alice"}])

    def test_account_analysis_kwarg_shape_works(self):
        nd = Neo4jData(MagicMock(), domain_filter="A.LOCAL")
        nd.all_users_data_cache = [{"username": "alice"}]
        result = nd.get_all_users_with_attributes(skip_high_value=True, force_refresh=False)
        self.assertEqual(result, [{"username": "alice"}])


class TestGetDomainNameCache(unittest.TestCase):

    def test_unscoped_caches_after_first_query(self):
        conn = MagicMock()
        conn.query.return_value = [{'domain': 'TRAINING.LOCAL'}]
        nd = Neo4jData(conn)

        self.assertEqual(nd.get_domain_name(), 'TRAINING.LOCAL')
        self.assertEqual(nd.get_domain_name(), 'TRAINING.LOCAL')
        self.assertEqual(conn.query.call_count, 1)

    def test_unknown_domain_result_is_cached(self):
        conn = MagicMock()
        conn.query.return_value = []
        nd = Neo4jData(conn)

        self.assertEqual(nd.get_domain_name(), 'Unknown Domain')
        self.assertEqual(nd.get_domain_name(), 'Unknown Domain')
        self.assertEqual(conn.query.call_count, 1)

    def test_domain_filter_short_circuit_skips_cache_entirely(self):
        conn = MagicMock()
        nd = Neo4jData(conn, domain_filter='TRAINING.LOCAL')
        self.assertEqual(nd.get_domain_name(), 'TRAINING.LOCAL')
        self.assertEqual(nd.get_domain_name(), 'TRAINING.LOCAL')
        conn.query.assert_not_called()

    def test_force_refresh_requeries_and_replaces_cache(self):
        conn = MagicMock()
        conn.query.side_effect = [[{'domain': 'TRAINING.LOCAL'}], []]
        nd = Neo4jData(conn)

        self.assertEqual(nd.get_domain_name(), 'TRAINING.LOCAL')
        self.assertEqual(conn.query.call_count, 1)

        self.assertEqual(nd.get_domain_name(force_refresh=True), 'Unknown Domain')
        self.assertEqual(conn.query.call_count, 2)

        self.assertEqual(nd.get_domain_name(), 'Unknown Domain')
        self.assertEqual(conn.query.call_count, 2)

    def test_force_refresh_still_short_circuits_on_scoped_instance(self):
        conn = MagicMock()
        nd = Neo4jData(conn, domain_filter='TRAINING.LOCAL')
        self.assertEqual(nd.get_domain_name(force_refresh=True), 'TRAINING.LOCAL')
        conn.query.assert_not_called()


class TestGetEnterpriseCaStatusCache(unittest.TestCase):

    def test_second_call_returns_cached_dict_without_querying(self):
        conn = MagicMock()
        conn.query.return_value = [
            {'sid': 'S-1-5-21-EnterpriseCA-1', 'hostEnabled': True, 'ntAuth': True, 'tplCount': 3},
        ]
        nd = Neo4jData(conn)

        first = nd.get_enterprise_ca_status()
        second = nd.get_enterprise_ca_status()

        self.assertEqual(first, second)
        self.assertEqual(conn.query.call_count, 1)
        self.assertTrue(first['S-1-5-21-EnterpriseCA-1']['active'])

    def test_empty_result_cached(self):
        conn = MagicMock()
        conn.query.return_value = []
        nd = Neo4jData(conn)

        self.assertEqual(nd.get_enterprise_ca_status(), {})
        self.assertEqual(nd.get_enterprise_ca_status(), {})
        self.assertEqual(conn.query.call_count, 1)


class TestGetKrbtgtPasswordLastChangedCache(unittest.TestCase):

    def test_value_result_cached(self):
        conn = MagicMock()
        conn.query.return_value = [{'pwdLastSet': 1700000000}]
        nd = Neo4jData(conn, domain_filter='TRAINING.LOCAL')

        self.assertEqual(nd.get_krbtgt_password_last_changed(), 1700000000)
        self.assertEqual(nd.get_krbtgt_password_last_changed(), 1700000000)
        self.assertEqual(conn.query.call_count, 1)

    def test_none_result_cached(self):
        conn = MagicMock()
        conn.query.return_value = []
        nd = Neo4jData(conn, domain_filter='TRAINING.LOCAL')

        self.assertIsNone(nd.get_krbtgt_password_last_changed())
        self.assertIsNone(nd.get_krbtgt_password_last_changed())
        self.assertEqual(conn.query.call_count, 1)

    def test_query_exception_caches_none(self):
        conn = MagicMock()
        conn.query.side_effect = RuntimeError('neo4j down')
        nd = Neo4jData(conn, domain_filter='TRAINING.LOCAL')

        self.assertIsNone(nd.get_krbtgt_password_last_changed())
        conn.query.side_effect = None
        conn.query.return_value = [{'pwdLastSet': 999}]
        self.assertIsNone(nd.get_krbtgt_password_last_changed())
        self.assertEqual(conn.query.call_count, 1)


class TestGetDomainPropertiesFiltered(unittest.TestCase):

    def test_second_call_returns_cached_value_without_querying(self):
        conn = MagicMock()
        conn.query.return_value = [{'domainProperties': {'minpwdlength': 7, 'maxpwdage': -36000000000}}]
        nd = Neo4jData(conn, domain_filter='TRAINING.LOCAL')

        first = nd.get_domain_properties_filtered()
        second = nd.get_domain_properties_filtered()

        self.assertEqual(first, second)
        self.assertEqual(conn.query.call_count, 1)

    def test_returns_distinct_dict_each_call(self):
        conn = MagicMock()
        conn.query.return_value = [{'domainProperties': {'minpwdlength': 7}}]
        nd = Neo4jData(conn, domain_filter='TRAINING.LOCAL')

        first = nd.get_domain_properties_filtered()
        first['minpwdlength'] = 99
        second = nd.get_domain_properties_filtered()

        self.assertEqual(second, {'minpwdlength': 7})
        self.assertIsNot(first, second)

    def test_filters_none_values_and_giant_magnitudes(self):
        conn = MagicMock()
        conn.query.return_value = [{
            'domainProperties': {
                'minpwdlength': 7,
                'pwdhistorylength': None,
                'maxpwdage': -10_000_000_000_000,
                'lockoutthreshold': 0,
            }
        }]
        nd = Neo4jData(conn, domain_filter='TRAINING.LOCAL')

        result = nd.get_domain_properties_filtered()

        self.assertIn('minpwdlength', result)
        self.assertIn('lockoutthreshold', result)
        self.assertNotIn('pwdhistorylength', result)
        self.assertNotIn('maxpwdage', result)

    def test_uses_domain_filter_for_cypher_param(self):
        conn = MagicMock()
        conn.query.return_value = [{'domainProperties': {}}]
        nd = Neo4jData(conn, domain_filter='SECRET.TRAINING.LOCAL')

        nd.get_domain_properties_filtered()
        kwargs = conn.query.call_args.kwargs
        self.assertEqual(kwargs['parameters'], {'domain': 'SECRET.TRAINING.LOCAL'})
