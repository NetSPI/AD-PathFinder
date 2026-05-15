import unittest
from unittest.mock import MagicMock

from checks.common_group_escalation import CommonGroupEscalationCheck

def _build_check(enabled_user_count):
    check = CommonGroupEscalationCheck.__new__(CommonGroupEscalationCheck)
    users = [{'enabled': True, 'is_computer': False}] * enabled_user_count
    check.account_analysis = MagicMock()
    check.account_analysis.get_all_user_data.return_value = users
    check.neo4j_data = MagicMock()
    check.neo4j_data.get_common_groups_analysis.return_value = []
    return check

class TestCommonGroupThreshold(unittest.TestCase):
    """Pin the common-groups threshold to 35% of enabled users.

    History: was 50% pre-2026-05-08, lowered to 35% to surface partially-saturated
    common groups (e.g. role groups covering 1/3 of the user base) that were missed
    at the older bar. The platform JSON caption in shared_powershell.py is the
    user-facing copy of the same number; both must move together."""

    def test_threshold_is_thirty_five_percent_of_enabled_users(self):
        check = _build_check(enabled_user_count=1000)
        check.execute()
        kwargs = check.neo4j_data.get_common_groups_analysis.call_args.kwargs
        self.assertEqual(kwargs['threshold_count'], 350)
        self.assertEqual(kwargs['total_user_count'], 1000)

    def test_threshold_floors_at_one_for_small_populations(self):
        # 0.35 * 2 = 0.7 -> int -> 0; max(1, 0) keeps a single-member match possible.
        check = _build_check(enabled_user_count=2)
        check.execute()
        kwargs = check.neo4j_data.get_common_groups_analysis.call_args.kwargs
        self.assertEqual(kwargs['threshold_count'], 1)

    def test_threshold_truncates_not_rounds(self):
        # 0.35 * 10 = 3.5; int() truncates to 3 (we want to err toward surfacing,
        # not hiding, marginal groups).
        check = _build_check(enabled_user_count=10)
        check.execute()
        kwargs = check.neo4j_data.get_common_groups_analysis.call_args.kwargs
        self.assertEqual(kwargs['threshold_count'], 3)

    def test_zero_enabled_users_short_circuits(self):
        check = _build_check(enabled_user_count=0)
        result = check.execute()
        self.assertEqual(result, {})
        check.neo4j_data.get_common_groups_analysis.assert_not_called()

    def test_disabled_and_computer_accounts_excluded_from_count(self):
        check = CommonGroupEscalationCheck.__new__(CommonGroupEscalationCheck)
        users = (
            [{'enabled': True, 'is_computer': False}] * 100
            + [{'enabled': False, 'is_computer': False}] * 50
            + [{'enabled': True, 'is_computer': True}] * 25
        )
        check.account_analysis = MagicMock()
        check.account_analysis.get_all_user_data.return_value = users
        check.neo4j_data = MagicMock()
        check.neo4j_data.get_common_groups_analysis.return_value = []

        check.execute()
        kwargs = check.neo4j_data.get_common_groups_analysis.call_args.kwargs
        self.assertEqual(kwargs['threshold_count'], 35)
        self.assertEqual(kwargs['total_user_count'], 100)
