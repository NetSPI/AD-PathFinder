from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .dependencies import CheckDependencies
from .constants import DataTypes, EntityTypes, DisplayTypes

class VulnerabilityCheck:
    RISK_LEVEL = "High"
    CATEGORY_NAME = None
    DISPLAY_TYPE = DisplayTypes.SIMPLE
    REQUIRED_DATA = [DataTypes.COMPUTERS]
    ENTITY_TYPE = EntityTypes.COMPUTER
    
    def __init__(self, dependencies: CheckDependencies) -> None:
        if not isinstance(dependencies, CheckDependencies):
            raise TypeError("VulnerabilityCheck requires CheckDependencies container")

        self.dependencies = dependencies
        self.neo4j_data = dependencies.neo4j_data
        self.data = dependencies.shared_cache

        self.data_access = dependencies.data_access
        self.sid_mapper = dependencies.sid_mapper

        self._domain_filter = getattr(dependencies.neo4j_data, '_domain_filter', None)

        self.weak_password_handler = self.dependencies.weak_password_handler
        self.admin_privileges_handler = self.dependencies.admin_privileges_handler
        self.shared_password_handler = self.dependencies.shared_password_handler
        self.account_analysis = self.dependencies.account_analysis
        
    def run(self) -> dict[str, Any]:
        return self.execute()

    def execute(self) -> dict[str, Any]:
        raise NotImplementedError

    def get_computers(self) -> list[dict[str, Any]]:
        return self.data_access.get_computers()

    def get_users(self) -> list[dict[str, Any]]:
        return self.data_access.get_users()

    def get_enterprise_cas(self) -> list[dict[str, Any]]:
        return self.data_access.get_enterprise_cas()

    def get_bad_successor_ou_privileges(self) -> list[dict[str, Any]]:
        return self.data_access.get_bad_successor_ou_privileges()
    
    def _filter_entities_by_type(self, entities):
        entity_type = getattr(self, 'ENTITY_TYPE', EntityTypes.COMPUTER)
        skip_computers = entity_type == EntityTypes.USER
        filtered_entities = []

        self._filter_stats = {"no_sid": 0, "disabled": 0, "domain_controller": 0, "wrong_entity_type": 0}

        for entity in entities:
            if not entity or not entity.get('sid'):
                self._filter_stats["no_sid"] += 1
                continue

            entity_sid = entity.get('sid')

            if skip_computers:
                if entity.get('is_computer', False):
                    self._filter_stats["wrong_entity_type"] += 1
                    continue
                if hasattr(self.neo4j_data, 'computer_sids') and entity_sid in self.neo4j_data.computer_sids:
                    self._filter_stats["wrong_entity_type"] += 1
                    continue

            if entity.get('enabled') is False:
                self._filter_stats["disabled"] += 1
                continue

            # DCs inherently need these privileges, flagging them is noise
            if entity_type == EntityTypes.COMPUTER and entity.get('isDomainController') is True:
                self._filter_stats["domain_controller"] += 1
                continue

            filtered_entities.append(entity)

        return filtered_entities
    
    def _apply_vulnerability_check(self, entity, check_function):
        entity_sid = entity.get('sid')
        vuln_info = check_function(entity)
        
        if vuln_info is not None:
            # SID as key — usernames aren't unique across domains
            return entity_sid, vuln_info
        return None, None
    
    def process_entity_results(self, entities: list[dict[str, Any]],
                                check_function: Callable[[dict[str, Any]], Any]) -> dict[str, Any]:
        self._entities_input = len(entities) if entities else 0
        results = {}
        filtered_entities = self._filter_entities_by_type(entities)
        self._entities_after_filter = len(filtered_entities)

        for entity in filtered_entities:
            entity_sid, vuln_info = self._apply_vulnerability_check(entity, check_function)
            if entity_sid and vuln_info is not None:
                results[entity_sid] = vuln_info

        return results
    
    def has_escalation_path(self, entity_identifier: Any) -> bool:
        return self.data_access.has_escalation_path(entity_identifier)

    def _extract_identifier(self, entity_identifier):
        return self.sid_mapper.extract_sid(entity_identifier)

    def has_weak_password(self, entity_identifier: Any) -> bool:
        if not self.weak_password_handler:
            return False
        identifier = self._extract_identifier(entity_identifier)
        if identifier:
            return self.weak_password_handler.has_weak_password(identifier)
        return False

    def get_password_display(self, entity_identifier: Any) -> str | None:
        if not self.weak_password_handler:
            return None
        identifier = self._extract_identifier(entity_identifier)
        if identifier:
            return self.weak_password_handler.get_password_display(identifier)
        return None

    def is_admin(self, entity_identifier: Any) -> bool:
        if not self.admin_privileges_handler:
            return False
        identifier = self._extract_identifier(entity_identifier)
        if identifier:
            return self.admin_privileges_handler.is_admin(identifier)
        return False

    def has_shared_password(self, entity_identifier: Any) -> bool:
        if not self.shared_password_handler:
            return False
        identifier = self._extract_identifier(entity_identifier)
        if identifier:
            return self.shared_password_handler.has_shared_password(identifier)
        return False

    def get_count(self, results: Any) -> int:
        return len(results) if isinstance(results, (dict, list)) else 0

    def finding(self, description: str = "", details: Any = None,
                inline: bool = False) -> str | dict[str, Any]:
        if inline:
            return {"inline_description": description}
        if details:
            return {"description": description, "details": details}
        return description

    def query(self, cypher: str, parameters: dict[str, Any] | None = None,
              name: str | None = None) -> list[dict[str, Any]]:
        results = self.neo4j_data.conn.query(cypher, parameters=parameters, name=name)
        return results if results else []

    def _domain_condition(self, var_name):
        # BH stores .domain as string or single-element list depending on version
        if not self._domain_filter:
            return ""
        d = self._domain_filter.upper()
        return f' AND {var_name}.domain IN ["{d}", ["{d}"]]'

    def host_name_expr(self, alias: str, *, lower: bool = True) -> str:
        expr = f"coalesce({alias}.DNSHostName, replace({alias}.name, '$', ''))"
        return f"toLower({expr})" if lower else expr

    def format_relay_finding(self, coerce_source: str | None, target: str, *,
                             site: str | None = None,
                             qualifier: str | None = None) -> str:
        if coerce_source:
            desc = f"Coerce {coerce_source} -> SMB relay to {target}"
        else:
            desc = f"SMB relay to {target}"
        if qualifier:
            desc += f" {qualifier}"
        if site:
            desc += f" (Site {site})"
        return desc

    def get_display_method(self) -> Callable[..., Any]:
        suppress = getattr(self, 'suppress_terminal_output', False)
        if self.DISPLAY_TYPE == DisplayTypes.GROUPED_ESCALATION_PATHS:
            from checks.core.display.escalation import GroupedEscalationDisplayHandler
            return GroupedEscalationDisplayHandler(suppress, self, self.sid_mapper).display
        elif DataTypes.ESCALATION_PATHS in self.REQUIRED_DATA and self.DISPLAY_TYPE == DisplayTypes.ESCALATION_PATHS:
            from checks.core.display.escalation import EscalationPathDisplayHandler
            return EscalationPathDisplayHandler(suppress, self, self.sid_mapper).display
        elif self.DISPLAY_TYPE == DisplayTypes.GROUP_ANALYSIS:
            from checks.core.display.group_analysis import GroupAnalysisDisplayHandler
            return GroupAnalysisDisplayHandler(suppress, self, self.sid_mapper).display
        else:
            from checks.core.display.simple import SimpleDisplayHandler
            return SimpleDisplayHandler(suppress, self, self.sid_mapper).display