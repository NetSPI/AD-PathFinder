import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock

from modules.neo4j_data import Neo4jData

def _make_neo4j_data_with_only_excluded_edges():
    conn = MagicMock()
    conn.query.return_value = [{"relationships": ["Contains", "LocalToComputer"]}]
    return Neo4jData(conn, excluded_relationships=["Contains", "LocalToComputer"])

class TestEmptyPatternShortCircuit(unittest.TestCase):

    def test_short_circuit_skips_cypher_and_emits_one_shot_notice(self):
        data = _make_neo4j_data_with_only_excluded_edges()
        buf = io.StringIO()
        with redirect_stdout(buf):
            results = data._get_escalation_paths_v2("S-1-5-21-XYZ")
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["hasEscalationPath"])

        calls = [c.args[0] for c in data.conn.query.call_args_list]
        for cypher in calls:
            self.assertNotIn("[:*1..6]", cypher)
            self.assertNotRegex(cypher, r"\[:\*")

        notice = buf.getvalue()
        self.assertIn("Empty relationship pattern", notice)
        self.assertEqual(notice.count("Empty relationship pattern"), 1)

    def test_notice_fires_once_across_repeat_calls(self):
        data = _make_neo4j_data_with_only_excluded_edges()
        buf = io.StringIO()
        with redirect_stdout(buf):
            data._get_escalation_paths_v2("S-1-5-21-XYZ")
            data._get_escalation_paths_v2("S-1-5-21-ABC")
        self.assertEqual(buf.getvalue().count("Empty relationship pattern"), 1)
