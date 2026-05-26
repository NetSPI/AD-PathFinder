import unittest
from unittest.mock import MagicMock, patch

from modules.neo4j_data import Neo4jData

def _build_neo4j_data():
    conn = MagicMock()
    # get_all_relationships query shape
    conn.query.return_value = [{'relationships': ['MemberOf', 'AdminTo', 'GenericAll']}]
    nd = Neo4jData(conn, domain_filter='TRAINING.LOCAL')
    return nd, conn

class TestPrewarmInBatchProcess(unittest.TestCase):
    """The pre-warm shifts `get_all_relationships(exclude_mssql=True)` from
    `_find_escalation_paths_v2`'s first invocation up to before the parallel
    launcher. Without this, every worker fires the query on entry because
    Neo4j's response is too slow for any worker to win the cache-populate
    race against the others reading `hasattr`."""

    def test_parallel_mode_prewarms_before_launcher(self):
        nd, _ = _build_neo4j_data()
        recorded = {}

        def parallel_stub(*args, **kwargs):
            recorded['cache_present_at_launch'] = hasattr(nd, '_ad_only_relationships_pattern')

        with patch.object(nd, '_process_batches_parallel', side_effect=parallel_stub) as plaunch, \
             patch.object(nd, '_process_batches_sequential') as slaunch:
            entities = [{'sid': f'S-1-5-{i}'} for i in range(250)]
            nd._batch_process_v2(entities)

            self.assertTrue(recorded.get('cache_present_at_launch'),
                            "cache must be populated before parallel workers launch")
            plaunch.assert_called_once()
            slaunch.assert_not_called()

    def test_sequential_mode_also_prewarms(self):
        nd, _ = _build_neo4j_data()
        recorded = {}

        def sequential_stub(*args, **kwargs):
            recorded['cache_present_at_launch'] = hasattr(nd, '_ad_only_relationships_pattern')

        with patch.object(nd, '_process_batches_parallel') as plaunch, \
             patch.object(nd, '_process_batches_sequential', side_effect=sequential_stub) as slaunch:
            entities = [{'sid': f'S-1-5-{i}'} for i in range(50)]
            nd._batch_process_v2(entities)

            self.assertTrue(recorded.get('cache_present_at_launch'))
            slaunch.assert_called_once()
            plaunch.assert_not_called()

    def test_prewarm_fires_get_all_relationships_with_exclude_mssql_true(self):
        nd, _ = _build_neo4j_data()
        with patch.object(nd, 'get_all_relationships', return_value='MemberOf|AdminTo') as gar, \
             patch.object(nd, '_process_batches_parallel'), \
             patch.object(nd, '_process_batches_sequential'):
            entities = [{'sid': f'S-1-5-{i}'} for i in range(250)]
            nd._batch_process_v2(entities)

            gar.assert_called_once_with(exclude_mssql=True)

    def test_no_extra_relationship_query_inside_first_sequential_batch(self):
        # Pre-warmed cache means _find_escalation_paths_v2 hits the cached attr;
        # the get_all_relationships call inside it must not re-query Neo4j.
        nd, conn = _build_neo4j_data()
        with patch.object(nd, '_process_batches_parallel'), \
             patch.object(nd, '_process_batches_sequential'):
            entities = [{'sid': f'S-1-5-{i}'} for i in range(50)]
            nd._batch_process_v2(entities)

        # one underlying conn.query for the pre-warm itself
        gar_calls = [c for c in conn.query.call_args_list if c.kwargs.get('name') == 'get_all_relationships']
        self.assertEqual(len(gar_calls), 1)

        # cache attr is set, so subsequent get_all_relationships(exclude_mssql=True) is a no-op
        self.assertTrue(hasattr(nd, '_ad_only_relationships_pattern'))
        nd.get_all_relationships(exclude_mssql=True)
        gar_calls = [c for c in conn.query.call_args_list if c.kwargs.get('name') == 'get_all_relationships']
        self.assertEqual(len(gar_calls), 1)
