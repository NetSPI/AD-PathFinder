import unittest
from modules.policy_compliance import PolicyComplianceAnalyzer


def _make_analyzer(min_length, cracked):
    analyzer = PolicyComplianceAnalyzer(
        neo4j_data=None,
        cracked_accounts=cracked,
        user_details={},
        domain_name='example.local',
    )
    analyzer.domain_properties = {'minpwdlength': min_length}
    return analyzer


class TestCheckPasswordLength(unittest.TestCase):

    def test_below_min_length_is_flagged(self):
        analyzer = _make_analyzer(min_length=8, cracked={'alice': 'short'})
        self.assertEqual(
            analyzer._check_password_length('alice'),
            {'type': 'length', 'message': 'Below Min Length'},
        )

    def test_equal_to_min_length_is_compliant(self):
        analyzer = _make_analyzer(min_length=8, cracked={'alice': 'eightchr'})
        self.assertIsNone(analyzer._check_password_length('alice'))

    def test_above_min_length_is_not_flagged(self):
        analyzer = _make_analyzer(min_length=8, cracked={'alice': 'longerthanmin'})
        self.assertIsNone(analyzer._check_password_length('alice'))

    def test_min_length_zero_short_circuits(self):
        analyzer = _make_analyzer(min_length=0, cracked={'alice': 'whatever'})
        self.assertIsNone(analyzer._check_password_length('alice'))

    def test_missing_minpwdlength_returns_none(self):
        analyzer = _make_analyzer(min_length=8, cracked={'alice': 'short'})
        analyzer.domain_properties = {}
        self.assertIsNone(analyzer._check_password_length('alice'))

    def test_username_not_cracked_returns_none(self):
        analyzer = _make_analyzer(min_length=8, cracked={})
        self.assertIsNone(analyzer._check_password_length('alice'))


if __name__ == '__main__':
    unittest.main()
