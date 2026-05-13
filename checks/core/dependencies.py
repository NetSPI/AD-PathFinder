from __future__ import annotations

from typing import Any


class CheckDependencies:

    def __init__(self, neo4j_data: Any, shared_cache: dict[str, Any] | None = None,
                 account_analysis: Any = None) -> None:
        self.neo4j_data = neo4j_data
        self.shared_cache = shared_cache if shared_cache is not None else {}
        self.account_analysis = account_analysis

        from checks.core.sid_mapper import SidMapper
        from checks.core.data_access import DataAccessLayer

        self.sid_mapper = SidMapper(neo4j_data=neo4j_data, shared_cache=self.shared_cache, account_analysis=account_analysis)
        self.data_access = DataAccessLayer(neo4j_data, self.shared_cache)

        self.weak_password_handler = None
        self.admin_privileges_handler = None
        self.shared_password_handler = None

        if account_analysis:
            from checks.core.weak_password import WeakPasswordHandler
            from checks.core.admin_privileges import AdminPrivilegesHandler
            from checks.core.shared_password import SharedPasswordHandler
            self.weak_password_handler = WeakPasswordHandler(account_analysis, self.sid_mapper)
            self.admin_privileges_handler = AdminPrivilegesHandler(account_analysis, self.sid_mapper)
            self.shared_password_handler = SharedPasswordHandler(account_analysis, self.sid_mapper)

