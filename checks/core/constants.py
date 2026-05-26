import sys
if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    from enum import Enum
    class StrEnum(str, Enum):
        __str__ = str.__str__


class DataTypes(StrEnum):
    COMPUTERS = 'computers'
    USERS = 'users'
    ENTERPRISE_CAS = 'enterprise_cas'
    BAD_SUCCESSOR_OU_PRIVILEGES = 'bad_successor_ou_privileges'
    ESCALATION_PATHS = 'escalation_paths'
    FULL_ESCALATION_PATHS = 'full_escalation_paths'
    WEAK_PASSWORD = 'weak_password'
    ADMIN_PRIVILEGES = 'admin_privileges'


class EntityTypes(StrEnum):
    COMPUTER = 'computer'
    USER = 'user'


class DisplayTypes(StrEnum):
    SIMPLE = 'simple'
    ESCALATION_PATHS = 'escalation_paths'
    GROUPED_ESCALATION_PATHS = 'grouped_escalation_paths'
    GROUP_ANALYSIS = 'group_analysis'
    SHARED_GRAPH_PATHS = 'shared_graph_paths'


class DisplaySymbols:
    MAIN_ITEM = '    ▶ '
    SUB_ITEM = '        ▶ '
    PATH_ARROW = ' -> '
    PATH_CONNECTOR = '└─'


class DataAccessConfig:
    METHOD_TEMPLATE = 'get_all_{}_with_attributes'
    SPECIAL_METHODS = {
        DataTypes.BAD_SUCCESSOR_OU_PRIVILEGES: 'get_bad_successor_ou_privileges'
    }


def is_sid(identifier):
    return identifier and str(identifier).upper().startswith('S-1-')
