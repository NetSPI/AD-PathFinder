from __future__ import annotations

from .constants import DataTypes


class CheckRegistry:
    checks: list[type] = []

    @classmethod
    def register(cls, check_class: type) -> type:
        cls._validate_check_metadata(check_class)
        cls.checks.append(check_class)
        return check_class

    @classmethod
    def _validate_check_metadata(cls, check_class):
        required_attrs = ['RISK_LEVEL', 'CATEGORY_NAME', 'REQUIRED_DATA']
        for attr in required_attrs:
            if not hasattr(check_class, attr):
                raise ValueError(f"Check {check_class.__name__} missing required attribute: {attr}")

        valid_data_types = {DataTypes.COMPUTERS, DataTypes.USERS,
                           DataTypes.ENTERPRISE_CAS, DataTypes.BAD_SUCCESSOR_OU_PRIVILEGES,
                           DataTypes.ESCALATION_PATHS, DataTypes.FULL_ESCALATION_PATHS,
                           DataTypes.WEAK_PASSWORD, DataTypes.ADMIN_PRIVILEGES}

        for data_type in check_class.REQUIRED_DATA:
            if data_type not in valid_data_types:
                raise ValueError(f"Check {check_class.__name__} requires invalid data type: {data_type}")

    @classmethod
    def get_all_checks(cls) -> list[type]:
        return cls.checks

