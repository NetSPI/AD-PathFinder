import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from modules.audit_context import MultiDomainAuditContext

def _make_unscoped_mock(domains, relationship_pattern="MemberOf|AdminTo"):
    m = MagicMock()
    m.get_all_domain_names.return_value = list(domains)
    m.get_all_relationships.return_value = relationship_pattern
    m.build_rid_to_domain_map.return_value = ({}, {})
    return m

class TestContextLazyAndCached(unittest.TestCase):

    def test_all_domains_queried_once(self):
        unscoped = _make_unscoped_mock(["A.LOCAL", "B.LOCAL"])
        ctx = MultiDomainAuditContext(
            conn=MagicMock(), unscoped_neo4j_data=unscoped,
            excluded_relationships=[], hashcat_file_path=None,
            ntds_file_path=None, diagnostics=None,
        )
        self.assertEqual(ctx.all_domains, ["A.LOCAL", "B.LOCAL"])
        self.assertEqual(ctx.all_domains, ["A.LOCAL", "B.LOCAL"])
        self.assertEqual(unscoped.get_all_domain_names.call_count, 1)

    def test_relationship_pattern_cached(self):
        unscoped = _make_unscoped_mock(["A.LOCAL"], "MemberOf|AdminTo|GenericAll")
        ctx = MultiDomainAuditContext(
            conn=MagicMock(), unscoped_neo4j_data=unscoped,
            excluded_relationships=[], hashcat_file_path=None,
            ntds_file_path=None, diagnostics=None,
        )
        ctx.relationship_pattern
        ctx.relationship_pattern
        self.assertEqual(unscoped.get_all_relationships.call_count, 1)

    @patch("modules.audit_context.Neo4jData")
    def test_per_domain_neo4j_data_cached(self, neo4j_data_cls):
        neo4j_data_cls.side_effect = lambda *a, **kw: MagicMock(domain=kw.get("domain_filter"))
        unscoped = _make_unscoped_mock(["A.LOCAL", "B.LOCAL"])
        ctx = MultiDomainAuditContext(
            conn=MagicMock(), unscoped_neo4j_data=unscoped,
            excluded_relationships=["X"], hashcat_file_path=None,
            ntds_file_path=None, diagnostics=None,
        )
        a1 = ctx.get_domain_neo4j_data("A.LOCAL")
        a2 = ctx.get_domain_neo4j_data("A.LOCAL")
        b = ctx.get_domain_neo4j_data("B.LOCAL")
        self.assertIs(a1, a2)
        self.assertIsNot(a1, b)
        self.assertEqual(neo4j_data_cls.call_count, 2)

class TestPotfileParsedOnce(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".pot", delete=False)
        self.tmp.write("aabbccdd:hunter2\n"
                       "user1::TRAINING:abc:def:blob:ntlmv2pass\n"
                       "user2::SECRET:abc:def:blob:secretpass\n")
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_parse_once_across_multiple_accesses(self):
        unscoped = _make_unscoped_mock(["TRAINING.LOCAL", "SECRET.TRAINING.LOCAL"])
        ctx = MultiDomainAuditContext(
            conn=MagicMock(), unscoped_neo4j_data=unscoped,
            excluded_relationships=[], hashcat_file_path=self.tmp.name,
            ntds_file_path=None, diagnostics=None,
        )
        with patch("modules.audit_context.parse_potfile_partitioned",
                   wraps=__import__("modules.utils", fromlist=["parse_potfile_partitioned"]).parse_potfile_partitioned) as parser:
            ctx.cracked_passwords_global
            ctx.get_ntlmv2_hashes_for_domain("TRAINING.LOCAL")
            ctx.get_ntlmv2_hashes_for_domain("SECRET.TRAINING.LOCAL")
            ctx.cracked_passwords_global
            self.assertEqual(parser.call_count, 1)

    def test_ntlmv2_partitioned_by_netbios(self):
        unscoped = _make_unscoped_mock(["TRAINING.LOCAL", "SECRET.TRAINING.LOCAL"])
        ctx = MultiDomainAuditContext(
            conn=MagicMock(), unscoped_neo4j_data=unscoped,
            excluded_relationships=[], hashcat_file_path=self.tmp.name,
            ntds_file_path=None, diagnostics=None,
        )
        self.assertEqual(ctx.get_ntlmv2_hashes_for_domain("TRAINING.LOCAL"),
                         {"user1": "ntlmv2pass"})
        self.assertEqual(ctx.get_ntlmv2_hashes_for_domain("SECRET.TRAINING.LOCAL"),
                         {"user2": "secretpass"})
        self.assertEqual(ctx.cracked_passwords_global, {"aabbccdd": "hunter2"})

class TestCrossDomainManagerInvokedOnce(unittest.TestCase):

    @patch("modules.audit_context.Neo4jData")
    def test_run_all_checks_called_once(self, neo4j_data_cls):
        neo4j_data_cls.return_value = MagicMock()
        neo4j_data_cls.return_value.get_admin_users_and_computers.return_value = ([], [])

        unscoped = _make_unscoped_mock(["A.LOCAL", "B.LOCAL"])
        ctx = MultiDomainAuditContext(
            conn=MagicMock(), unscoped_neo4j_data=unscoped,
            excluded_relationships=[], hashcat_file_path=None,
            ntds_file_path=None, diagnostics=None,
        )
        manager_cls = MagicMock()
        manager = manager_cls.return_value
        manager.run_all_checks.return_value = {"X": {"count": 1}}
        ctx._cd_manager_cls = manager_cls
        ctx._cd_deps_cls = MagicMock()

        first = ctx.cross_domain_results
        second = ctx.cross_domain_results
        self.assertIs(first, second)
        self.assertEqual(manager.run_all_checks.call_count, 1)

class TestNtdsErrorPaths(unittest.TestCase):

    def test_ntds_path_not_set(self):
        unscoped = _make_unscoped_mock(["A.LOCAL"])
        ctx = MultiDomainAuditContext(
            conn=MagicMock(), unscoped_neo4j_data=unscoped,
            excluded_relationships=[], hashcat_file_path=None,
            ntds_file_path=None, diagnostics=None,
        )
        self.assertEqual(ctx.domain_hashes, {})
        self.assertFalse(ctx.ntds_entries_loaded)

    def test_ntds_path_set_but_empty(self):
        unscoped = _make_unscoped_mock(["A.LOCAL"])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            empty_path = f.name
        try:
            ctx = MultiDomainAuditContext(
                conn=MagicMock(), unscoped_neo4j_data=unscoped,
                excluded_relationships=[], hashcat_file_path=None,
                ntds_file_path=empty_path, diagnostics=None,
            )
            self.assertEqual(ctx.domain_hashes, {})
            self.assertFalse(ctx.ntds_entries_loaded)
        finally:
            os.unlink(empty_path)

class TestHashcatFileMissingHandled(unittest.TestCase):

    def test_missing_hashcat_file_treated_as_none(self):
        unscoped = _make_unscoped_mock(["A.LOCAL"])
        ctx = MultiDomainAuditContext(
            conn=MagicMock(), unscoped_neo4j_data=unscoped,
            excluded_relationships=[], hashcat_file_path="/nonexistent/path/file.pot",
            ntds_file_path=None, diagnostics=None,
        )
        self.assertIsNone(ctx.hashcat_file_path)
        self.assertEqual(ctx.cracked_passwords_global, {})
        self.assertEqual(ctx.get_ntlmv2_hashes_for_domain("A.LOCAL"), {})
