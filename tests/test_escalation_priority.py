"""Tests for escalation path target priority logic."""
import unittest
from unittest.mock import MagicMock, patch

class TestEscalationTargetPriority(unittest.TestCase):
    """Test the _escalation_target_priority static method used by v1/v2 single-entity queries."""

    @staticmethod
    def _get_cls():
        from modules.neo4j_data import Neo4jData
        return Neo4jData

    def _priority(self, result):
        return self._get_cls()._escalation_target_priority(result)

    # -- tier 0: key groups (DA/DC/EA/Administrators), high-value Users and Computers --

    def test_domain_admins_group_is_tier0(self):
        result = {'fullPath': [
            {'name': 'user1', 'labels': ['User']},
            'MemberOf',
            {'name': 'DOMAIN ADMINS@CORP.LOCAL', 'labels': ['Group']},
        ]}
        self.assertEqual(self._priority(result)[0], 0)

    def test_domain_controllers_group_is_tier0(self):
        result = {'fullPath': [
            {'name': 'user1', 'labels': ['User']},
            'MemberOf',
            {'name': 'DOMAIN CONTROLLERS@CORP.LOCAL', 'labels': ['Group']},
        ]}
        self.assertEqual(self._priority(result)[0], 0)

    def test_enterprise_admins_group_is_tier0(self):
        result = {'fullPath': [
            {'name': 'user1', 'labels': ['User']},
            'MemberOf',
            {'name': 'ENTERPRISE ADMINS@CORP.LOCAL', 'labels': ['Group']},
        ]}
        self.assertEqual(self._priority(result)[0], 0)

    def test_administrator_user_is_tier0(self):
        result = {'fullPath': [
            {'name': 'user1', 'labels': ['User']},
            'GenericAll',
            {'name': 'ADMINISTRATOR@CORP.LOCAL', 'labels': ['User']},
        ]}
        self.assertEqual(self._priority(result)[0], 0)

    def test_administrators_group_is_tier0(self):
        result = {'fullPath': [
            {'name': 'user1', 'labels': ['User']},
            'MemberOf',
            {'name': 'ADMINISTRATORS@CORP.LOCAL', 'labels': ['Group']},
        ]}
        self.assertEqual(self._priority(result)[0], 0)

    def test_highvalue_computer_is_tier0(self):
        result = {'fullPath': [
            {'name': 'user1', 'labels': ['User']},
            'GenericAll',
            {'name': 'DC01.CORP.LOCAL', 'labels': ['Computer']},
        ]}
        self.assertEqual(self._priority(result)[0], 0)

    # -- tier 1: other high-value targets (OUs, GPOs, other groups, etc.) --

    def test_domain_controllers_ou_is_tier1(self):
        """OU named 'DOMAIN CONTROLLERS' should NOT get tier 0 (it's an OU, not a Group)."""
        result = {'fullPath': [
            {'name': 'user1', 'labels': ['User']},
            'GenericAll',
            {'name': 'DOMAIN CONTROLLERS@CORP.LOCAL', 'labels': ['OU']},
        ]}
        self.assertEqual(self._priority(result)[0], 1)

    # -- empty path --

    def test_empty_path_returns_tier1(self):
        result = {'fullPath': []}
        self.assertEqual(self._priority(result)[0], 1)

    # -- shorter paths sort before longer ones within same tier --

    def test_shorter_path_sorts_first(self):
        short = {'fullPath': [
            {'name': 'u', 'labels': ['User']}, 'MemberOf',
            {'name': 'DOMAIN ADMINS@CORP.LOCAL', 'labels': ['Group']},
        ]}
        long = {'fullPath': [
            {'name': 'u', 'labels': ['User']}, 'MemberOf',
            {'name': 'g', 'labels': ['Group']}, 'MemberOf',
            {'name': 'DOMAIN ADMINS@CORP.LOCAL', 'labels': ['Group']},
        ]}
        self.assertLess(self._priority(short), self._priority(long))

    # -- v1 string paths (no labels, just flat name strings) --

    def test_v1_domain_admins_string_is_tier0(self):
        result = {'fullPath': ['user1', 'MemberOf', 'DOMAIN ADMINS@CORP.LOCAL']}
        self.assertEqual(self._priority(result)[0], 0)

    def test_v1_enterprise_admins_string_is_tier0(self):
        result = {'fullPath': ['user1', 'MemberOf', 'ENTERPRISE ADMINS@CORP.LOCAL']}
        self.assertEqual(self._priority(result)[0], 0)

    def test_v1_administrator_string_is_tier0(self):
        result = {'fullPath': ['user1', 'GenericAll', 'ADMINISTRATOR@CORP.LOCAL']}
        self.assertEqual(self._priority(result)[0], 0)

    def test_v1_administrators_string_is_tier0(self):
        result = {'fullPath': ['user1', 'MemberOf', 'ADMINISTRATORS@CORP.LOCAL']}
        self.assertEqual(self._priority(result)[0], 0)

    def test_v1_other_target_string_is_tier1(self):
        result = {'fullPath': ['user1', 'GenericAll', 'DC01.CORP.LOCAL']}
        self.assertEqual(self._priority(result)[0], 1)

class TestFindEscalationPathsV2Query(unittest.TestCase):
    """Test _find_escalation_paths_v2 query construction and result processing."""

    def _make_neo4j_data(self):
        from modules.neo4j_data import Neo4jData
        mock_conn = MagicMock()
        mock_conn.query = MagicMock(return_value=None)
        nd = Neo4jData(mock_conn)
        # Pre-cache relationships to avoid DB call
        nd._ad_only_relationships_pattern = 'MemberOf|GenericAll'
        nd._all_relationships_pattern = 'MemberOf|GenericAll|AdminTo'
        return nd, mock_conn

    def test_query_contains_tier0_targets_parameter(self):
        """The batch query should use $tier0_targets parameter, not hardcoded names."""
        nd, mock_conn = self._make_neo4j_data()
        mock_conn.query.return_value = []

        nd._find_escalation_paths_v2(['S-1-5-21-123'], interesting_rels_only=True)

        call_args = mock_conn.query.call_args
        query = call_args[0][0]
        params = call_args[1].get('parameters', call_args[0][1] if len(call_args[0]) > 1 else {})

        self.assertIn('$tier0_targets', query)
        self.assertIn('tier0_targets', params)
        self.assertIsInstance(params['tier0_targets'], list)
        self.assertIn('DOMAIN ADMINS', params['tier0_targets'])
        self.assertIn('ENTERPRISE ADMINS', params['tier0_targets'])
        self.assertIn('ADMINISTRATORS', params['tier0_targets'])

    def test_no_duplicate_query_branches(self):
        """Both interesting_rels_only=True and False should produce a single query call."""
        nd1, conn1 = self._make_neo4j_data()
        nd2, conn2 = self._make_neo4j_data()
        conn1.query.return_value = []
        conn2.query.return_value = []

        nd1._find_escalation_paths_v2(['S-1-5-21-123'], interesting_rels_only=True)
        nd2._find_escalation_paths_v2(['S-1-5-21-123'], interesting_rels_only=False)

        # Both should make exactly one query call
        self.assertEqual(conn1.query.call_count, 1)
        self.assertEqual(conn2.query.call_count, 1)

    def test_interesting_rels_uses_interesting_relationships(self):
        """interesting_rels_only=True should use get_interesting_relationships() rels."""
        nd, mock_conn = self._make_neo4j_data()
        mock_conn.query.return_value = []

        nd._find_escalation_paths_v2(['S-1-5-21-123'], interesting_rels_only=True)

        query = mock_conn.query.call_args[0][0]
        # Should contain interesting rels like MemberOf, GenericAll, AdminTo etc.
        self.assertIn('MemberOf', query)
        self.assertIn('GenericAll', query)
        self.assertIn('shortestPath((m)-[:', query)

    def test_all_rels_uses_all_relationships(self):
        """interesting_rels_only=False should use get_all_relationships(exclude_mssql=True) rels."""
        nd, mock_conn = self._make_neo4j_data()
        mock_conn.query.return_value = []

        nd._find_escalation_paths_v2(['S-1-5-21-123'], interesting_rels_only=False)

        query = mock_conn.query.call_args[0][0]
        # Should use the _ad_only_relationships_pattern cache (exclude_mssql=True)
        self.assertIn('MemberOf|GenericAll', query)
        self.assertIn('shortestPath((m)-[:', query)

    def test_query_has_two_tier_priority(self):
        """Query CASE should have 2 tiers: 0 for Users/Computers/key groups, 1 for other."""
        nd, mock_conn = self._make_neo4j_data()
        mock_conn.query.return_value = []

        nd._find_escalation_paths_v2(['S-1-5-21-123'], interesting_rels_only=True)

        query = mock_conn.query.call_args[0][0]
        # Tier 0: User/Computer labels and Group matching tier0_targets
        self.assertIn("'User', 'Computer'", query)
        self.assertIn('$tier0_targets', query)
        self.assertIn('THEN 0', query)
        self.assertIn('ELSE 1', query)

    def test_processes_da_group_result(self):
        """A result targeting DA group should be stored correctly."""
        nd, mock_conn = self._make_neo4j_data()
        mock_conn.query.return_value = [{
            'entity_id': 'S-1-5-21-123',
            'username': 'JDOE@CORP.LOCAL',
            'enabled': True,
            'isAdmin': False,
            'path_nodes': [
                {'name': 'JDOE@CORP.LOCAL', 'objectid': 'S-1-5-21-123',
                 'guid': None, 'distinguishedname': None, 'labels': ['User'], 'samaccountname': 'jdoe'},
                {'name': 'DOMAIN ADMINS@CORP.LOCAL', 'objectid': 'S-1-5-21-999',
                 'guid': None, 'distinguishedname': None, 'labels': ['Group'], 'samaccountname': None},
            ],
            'path_node_types': ['User', 'Group'],
            'relationship_types': ['MemberOf'],
            'sid': 'S-1-5-21-123',
            'path_length': 1,
        }]

        result = nd._find_escalation_paths_v2(['S-1-5-21-123'], interesting_rels_only=True)

        self.assertIn('S-1-5-21-123', result)
        path_result = result['S-1-5-21-123'][0]
        self.assertTrue(path_result['hasEscalationPath'])
        self.assertEqual(path_result['fullPath'][-1]['name'], 'DOMAIN ADMINS@CORP.LOCAL')

    def test_processes_highvalue_user_result(self):
        """A result targeting a high-value user (DA member) should be stored correctly."""
        nd, mock_conn = self._make_neo4j_data()
        mock_conn.query.return_value = [{
            'entity_id': 'S-1-5-21-123',
            'username': 'JDOE@CORP.LOCAL',
            'enabled': True,
            'isAdmin': False,
            'path_nodes': [
                {'name': 'JDOE@CORP.LOCAL', 'objectid': 'S-1-5-21-123',
                 'guid': None, 'distinguishedname': None, 'labels': ['User'], 'samaccountname': 'jdoe'},
                {'name': 'ADMIN.USER@CORP.LOCAL', 'objectid': 'S-1-5-21-500',
                 'guid': None, 'distinguishedname': None, 'labels': ['User'], 'samaccountname': 'admin.user'},
            ],
            'path_node_types': ['User', 'User'],
            'relationship_types': ['GenericAll'],
            'sid': 'S-1-5-21-123',
            'path_length': 1,
        }]

        result = nd._find_escalation_paths_v2(['S-1-5-21-123'], interesting_rels_only=True)

        self.assertIn('S-1-5-21-123', result)
        path_result = result['S-1-5-21-123'][0]
        self.assertTrue(path_result['hasEscalationPath'])
        # Path interleaves nodes and relationships
        self.assertEqual(len(path_result['fullPath']), 3)  # node, rel, node

    def test_entities_without_paths_get_default(self):
        """Entities with no paths should get a default no-path result."""
        nd, mock_conn = self._make_neo4j_data()
        mock_conn.query.return_value = []

        result = nd._find_escalation_paths_v2(
            ['S-1-5-21-123', 'S-1-5-21-456'], interesting_rels_only=True
        )

        for sid in ['S-1-5-21-123', 'S-1-5-21-456']:
            self.assertIn(sid, result)
            self.assertFalse(result[sid][0]['hasEscalationPath'])
