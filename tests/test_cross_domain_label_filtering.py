from checks.cross_domain.base import CrossDomainDependencies
from checks.cross_domain.cross_domain_computer_escalation_path import (
    CrossDomainComputerEscalationPathCheck,
)
from checks.cross_domain.cross_domain_escalation_path import CrossDomainEscalationPathCheck


def _row():
    return {
        "source_user": "ALICE@A.LOCAL",
        "source_computer": "WS01.A.LOCAL",
        "source_domain": "A.LOCAL",
        "source_sid": "S-1-5-21-A-1105",
        "target_name": "DOMAIN ADMINS@B.LOCAL",
        "target_domain": "B.LOCAL",
        "path_nodes": [
            {
                "name": "ALICE@A.LOCAL",
                "domain": "A.LOCAL",
                "labels": ["Base", "User", "MSSQL_Login"],
                "objectid": "S-1-5-21-A-1105",
            },
            {
                "name": "DOMAIN ADMINS@B.LOCAL",
                "domain": "B.LOCAL",
                "labels": ["Base", "Group", "SCCM_Site"],
                "objectid": "S-1-5-21-B-512",
            },
        ],
        "path_rels": ["MemberOf"],
        "path_length": 1,
    }


def test_cross_domain_user_paths_store_reportable_labels_only():
    check = CrossDomainEscalationPathCheck(CrossDomainDependencies(None, []))

    findings = check._process_results([_row()], target_type="Domain Admin")

    nodes = findings[0]["fullPath"][::2]
    assert nodes[0]["labels"] == ["User"]
    assert nodes[1]["labels"] == ["Group"]


def test_cross_domain_computer_paths_store_reportable_labels_only():
    check = CrossDomainComputerEscalationPathCheck(CrossDomainDependencies(None, []))

    findings = check._process_results([_row()], target_type="Domain Admin")

    nodes = findings[0]["fullPath"][::2]
    assert nodes[0]["labels"] == ["User"]
    assert nodes[1]["labels"] == ["Group"]


def test_cross_domain_paths_drop_plugin_only_labels():
    row = _row()
    row["path_nodes"][1]["labels"] = ["Base", "SCCM_Site"]
    check = CrossDomainEscalationPathCheck(CrossDomainDependencies(None, []))

    findings = check._process_results([row], target_type="Domain Admin")

    nodes = findings[0]["fullPath"][::2]
    assert nodes[1]["labels"] == []
