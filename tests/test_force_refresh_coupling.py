import unittest
from unittest.mock import MagicMock, patch

from modules.neo4j_data import Neo4jData

class TestForceRefreshNotPropagatedIntoHvt(unittest.TestCase):
    """Refreshing user attributes must not rebuild the high-value chain.

    Today's call sites never pass force_refresh=True into get_all_user_data, but
    the latent coupling at neo4j_data.py:642 would have propagated the flag into
    get_high_value_targets and discarded the HVT cache; this regression test pins
    that the propagation stays decoupled."""

    def test_force_refresh_user_attrs_does_not_force_hvt_rebuild(self):
        conn = MagicMock()
        conn.query.return_value = []
        nd = Neo4jData(conn, domain_filter="A.LOCAL")

        with patch.object(nd, "get_high_value_targets", return_value=([], [])) as hvt_mock:
            nd.get_all_users_with_attributes(force_refresh=True)
            hvt_mock.assert_called_once()
            args, kwargs = hvt_mock.call_args
            forwarded_value = (args[0] if args else kwargs.get("force_refresh", False))
            self.assertFalse(
                forwarded_value,
                "force_refresh=True must not propagate into get_high_value_targets",
            )

    def test_skip_high_value_avoids_hvt_call_entirely(self):
        conn = MagicMock()
        conn.query.return_value = []
        nd = Neo4jData(conn, domain_filter="A.LOCAL")

        with patch.object(nd, "get_high_value_targets") as hvt_mock:
            nd.get_all_users_with_attributes(force_refresh=True, skip_high_value=True)
            hvt_mock.assert_not_called()

    def test_default_invocation_calls_hvt_without_force_refresh(self):
        conn = MagicMock()
        conn.query.return_value = []
        nd = Neo4jData(conn, domain_filter="A.LOCAL")

        with patch.object(nd, "get_high_value_targets", return_value=([], [])) as hvt_mock:
            nd.get_all_users_with_attributes()
            hvt_mock.assert_called_once()
            args, kwargs = hvt_mock.call_args
            forwarded_value = (args[0] if args else kwargs.get("force_refresh", False))
            self.assertFalse(forwarded_value)
