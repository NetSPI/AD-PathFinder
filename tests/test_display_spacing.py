from checks.core.constants import DataTypes
from checks.core.display.escalation import (
    EscalationPathDisplayHandler,
    GroupedEscalationDisplayHandler,
)
from checks.core.display.group_analysis import GroupAnalysisDisplayHandler
from checks.core.display.shared_graph_paths import SharedGraphPathDisplayHandler
from checks.core.display.simple import SimpleDisplayHandler
from checks.cross_domain.injector import _display_grouped_paths, _display_results


class FakeSidMapper:
    def __init__(self, mapping=None):
        self.mapping = mapping or {}

    def get_display_name(self, sid):
        return self.mapping.get(sid, sid)


class FakeCheck:
    ENTITY_TYPE = 'user'
    REQUIRED_DATA = []

    def __init__(self):
        self.data = {}
        self.neo4j_data = type('Neo4jData', (), {})()
        self.account_analysis = None


def test_simple_display_inserts_blank_line_between_multiple_items():
    handler = SimpleDisplayHandler(
        suppress_terminal_output=True,
        check_instance=FakeCheck(),
        sid_mapper=FakeSidMapper(),
    )

    content = []
    handler.display(
        {
            'ESC1 (TRAINING-DC01-CA ON DC01.TRAINING.LOCAL)': 'AUTHENTICATED USERS, DOMAIN USERS',
            'ESC2 (TRAINING-DC01-CA ON DC01.TRAINING.LOCAL)': 'AUTHENTICATED USERS, DOMAIN USERS',
        },
        '',
        'ESC1 - Enrollee Supplies Subject',
        content,
        2,
        '',
    )

    assert content == [
        '\n  ESC1 - Enrollee Supplies Subject: 2',
        '    ▶ ESC1 (TRAINING-DC01-CA ON DC01.TRAINING.LOCAL)',
        '        ▶ AUTHENTICATED USERS, DOMAIN USERS',
        '',
        '    ▶ ESC2 (TRAINING-DC01-CA ON DC01.TRAINING.LOCAL)',
        '        ▶ AUTHENTICATED USERS, DOMAIN USERS',
    ]


def test_escalation_path_display_inserts_blank_line_between_entities():
    handler = EscalationPathDisplayHandler(
        suppress_terminal_output=True,
        check_instance=FakeCheck(),
        sid_mapper=FakeSidMapper({'S-1-1': 'HOST1', 'S-1-2': 'HOST2'}),
    )

    content = []
    handler.display({'S-1-1': '', 'S-1-2': ''}, '', 'Escalation Paths', content, 2, '')

    assert content == [
        '\n  Escalation Paths: 2',
        '    ▶ HOST1',
        '',
        '    ▶ HOST2',
    ]


def test_grouped_escalation_display_separates_entities_from_common_path():
    check = FakeCheck()
    path = [
        {'name': 'ALICE@TEST.LOCAL', 'labels': ['User']},
        'MemberOf',
        {'name': 'DOMAIN ADMINS@TEST.LOCAL', 'labels': ['Group']},
    ]
    check.data = {
        DataTypes.FULL_ESCALATION_PATHS: {
            'S-1-1': [{'fullPath': path}],
            'S-1-2': [{'fullPath': path}],
        }
    }
    handler = GroupedEscalationDisplayHandler(
        suppress_terminal_output=True,
        check_instance=check,
        sid_mapper=FakeSidMapper({'S-1-1': 'ALICE', 'S-1-2': 'BOB'}),
    )

    content = []
    handler.display({'S-1-1': '', 'S-1-2': ''}, '', 'Non-admin Users with Escalation Paths', content, 2, '')

    summary_index = content.index('    Users with Shared Path (2): ALICE, BOB')
    assert content[summary_index + 1] == ''
    assert content[summary_index + 2].startswith('        Common Escalation Path: ')


def test_group_analysis_display_separates_multiple_paths_under_same_group():
    class AccountAnalysis:
        def _resolve_target_type(self, *_args):
            return 'User'

    check = FakeCheck()
    check.account_analysis = AccountAnalysis()
    handler = GroupAnalysisDisplayHandler(
        suppress_terminal_output=True,
        check_instance=check,
        sid_mapper=FakeSidMapper(),
    )

    content = []
    handler.display(
        {
            'DOMAIN USERS': [
                {'rel_type': 'GenericAll', 'target': 'TARGET1', 'targetSID': 'S-1-1'},
                {'rel_type': 'WriteDacl', 'target': 'TARGET2', 'targetSID': 'S-1-2'},
            ]
        },
        '',
        'Common Groups with Privilege Escalation Paths',
        content,
        1,
        '',
    )

    first_path = content.index('      ├─ GenericAll on TARGET1 (User)')
    assert content[first_path + 1] == ''
    assert content[first_path + 2] == '      └─ WriteDacl on TARGET2 (User)'


def test_shared_graph_paths_display_inserts_blank_line_between_entities():
    handler = SharedGraphPathDisplayHandler(
        suppress_terminal_output=True,
        check_instance=FakeCheck(),
        sid_mapper=FakeSidMapper({'S-1-1': 'USER1', 'S-1-2': 'USER2'}),
    )

    content = []
    handler.display(
        {
            'S-1-1': 'user1 -> MSSQL_Connect -> sql01',
            'S-1-2': 'user2 -> MSSQL_Connect -> sql01',
        },
        '',
        'MSSQL Privilege Escalation',
        content,
        2,
        '',
    )

    assert content == [
        '\n  MSSQL Privilege Escalation: 2',
        '    ▶ USER1',
        '        user1 > MSSQL_Connect > sql01',
        '',
        '    ▶ USER2',
        '        user2 > MSSQL_Connect > sql01',
    ]


def test_cross_domain_standard_display_inserts_blank_line_between_items():
    content = []
    _display_results({'ONE': '', 'TWO': ''}, '', 'Cross-Domain', content, 2, '')

    assert content == [
        '\n  Cross-Domain: 2',
        '    ▶ ONE',
        '',
        '    ▶ TWO',
    ]


def test_cross_domain_grouped_display_separates_summary_from_path():
    content = []
    _display_grouped_paths(
        {'Users with Shared Path (2): ALICE, BOB': 'Cross-Domain Path: MemberOf -> DOMAIN ADMINS'},
        '',
        'Cross-Domain Escalation Paths',
        content,
        2,
        '',
    )

    assert content == [
        '\n  Cross-Domain Escalation Paths: 2',
        '    Users with Shared Path (2): ALICE, BOB',
        '',
        '        Cross-Domain Path: MemberOf -> DOMAIN ADMINS',
    ]
