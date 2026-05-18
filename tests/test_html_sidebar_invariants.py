import re
import unittest
from unittest.mock import patch

from modules.client_report_generator import ClientReportGenerator
from modules.html_report_generator import _json_for_script

def _pg(path_string, count, entities=None):
    return {
        'path_string': path_string,
        'count': count,
        'entities': entities or [],
    }

def _step(edge, node, node_type):
    return {'edge': edge, 'node': node, 'node_type': node_type}

class TestSidebarMatchesCards(unittest.TestCase):

    def _make_generator(self):
        gen = ClientReportGenerator(json_data={
            'metadata': {'domain': 'TEST.LOCAL'},
            'destination_groups': {},
            'entities': [],
            'domain_summary': {},
        })
        gen._dest_cache = {}
        gen._client_report_data = {'pathGroups': {}}
        return gen

    def _render_category(self, cat_name, groups_with_steps):
        gen = self._make_generator()
        gen._visible_path_groups = {cat_name: groups_with_steps}

        # _build_path_card pulls in destination tooltips, SVG, mitigation prose etc.
        # The invariant we care about is that the same card_id appears in the
        # sidebar row and on the card, so stub the card builder to emit a marker
        # that reuses self._path_card_id — that proves both branches agree.
        def stub_card(pg, cat, sev, steps=None):
            cid = gen._path_card_id(cat, pg['path_string'])
            return f'<div class="card {sev} path-card" id="{cid}" data-path=""></div>'

        with patch.object(ClientReportGenerator, '_build_path_card', autospec=False,
                          side_effect=stub_card):
            return gen._build_category_section(cat_name, 'unused-sev', {'total_count': len(groups_with_steps)})

    def test_sidebar_rows_match_cards_one_to_one(self):
        groups = [
            (_pg('p-alpha', 12), [_step('MemberOf', 'GROUP-A', 'Group'),
                                  _step('GenericAll', 'TARGET-A', 'User')]),
            (_pg('p-beta', 5), [_step('MemberOf', 'GROUP-B', 'Group'),
                                _step('GenericAll', 'TARGET-B', 'Computer')]),
            (_pg('p-gamma', 1, entities=['lone-user@TEST.LOCAL']),
             [_step('GenericAll', 'TARGET-C', 'User')]),
        ]
        html = self._render_category('Non-admin Users with Escalation Paths', groups)

        card_ids = set(re.findall(r'class="card critical path-card" id="(p-[a-f0-9]+)"', html))
        sidebar_targets = set(re.findall(r'class="sidebar-row critical" data-target="(p-[a-f0-9]+)"', html))

        self.assertEqual(len(card_ids), 3, msg='expected exactly three rendered cards')
        self.assertEqual(card_ids, sidebar_targets,
                         msg='sidebar data-target set must equal card id set')

    def test_sidebar_uses_high_severity_for_computers(self):
        groups = [
            (_pg('p-1', 4), [_step('GenericAll', 'COMP-1.TEST.LOCAL', 'Computer')]),
            (_pg('p-2', 2), [_step('GenericAll', 'COMP-2.TEST.LOCAL', 'Computer')]),
        ]
        html = self._render_category('Computers with Escalation Paths', groups)

        # _CATEGORIES maps Computers -> 'high'; sidebar and card severity classes
        # must agree, otherwise the CSS dot colour drifts from the card border.
        self.assertEqual(len(re.findall(r'class="card high path-card"', html)), 2)
        self.assertEqual(len(re.findall(r'class="sidebar-row high"', html)), 2)
        self.assertEqual(html.count('class="card critical'), 0)
        self.assertEqual(html.count('class="sidebar-row critical'), 0)

    def test_sidebar_empty_state_when_no_paths(self):
        gen = self._make_generator()
        gen._visible_path_groups = {'Non-admin Users with Escalation Paths': []}

        html = gen._build_category_section(
            'Non-admin Users with Escalation Paths', 'unused-sev', {'total_count': 0}
        )

        self.assertIn('class="sidebar-empty"', html)
        self.assertNotIn('class="sidebar-row', html)
        self.assertNotIn('class="card', html)
        self.assertNotIn('class="sidebar-filter"', html,
                         msg='filter input is pointless when the list is empty')

    def test_filter_label_is_lowercased_but_visible_label_preserves_case(self):
        groups = [(_pg('p-1', 3),
                   [_step('GenericAll', 'MIXED.Case.Host', 'Computer')])]
        html = self._render_category('Computers with Escalation Paths', groups)

        # Filter matching is case-insensitive via lowercased data-label, but the
        # displayed text keeps the original casing.
        self.assertIn('data-label="mixed.case.host"', html)
        self.assertIn('>MIXED.Case.Host<', html)

    def test_sidebar_count_header_matches_path_count(self):
        groups = [
            (_pg(f'p-{i}', i + 1), [_step('GenericAll', f'TARGET-{i}', 'User')])
            for i in range(7)
        ]
        html = self._render_category('Non-admin Users with Escalation Paths', groups)
        self.assertIn('<h4>Paths (7)</h4>', html)


class TestScriptJsonEscaping(unittest.TestCase):

    def assertScriptSafeJson(self, rendered):
        self.assertNotIn("</script", rendered.lower())
        self.assertNotIn("<!--", rendered)
        self.assertNotIn("]]>", rendered)
        self.assertNotIn("&", rendered)
        self.assertNotIn("\u2028", rendered)
        self.assertNotIn("\u2029", rendered)
        self.assertIn("\\u003c", rendered)
        self.assertIn("\\u003e", rendered)
        self.assertIn("\\u0026", rendered)
        self.assertIn("\\u2028", rendered)
        self.assertIn("\\u2029", rendered)

    def test_json_for_script_escapes_html_breakout_sequences(self):
        payload = {"domain": "</script><!--x]]>&\u2028\u2029"}

        rendered = _json_for_script(payload)

        self.assertScriptSafeJson(rendered)

    def test_client_report_json_script_content_uses_same_escaping(self):
        payload = {"domain": "</script><!--x]]>&\u2028\u2029"}

        rendered = ClientReportGenerator._json_script_content(payload)

        self.assertScriptSafeJson(rendered)
