from modules.neo4j_groups import GroupAnalysisMixin


def test_group_analysis_keeps_raw_plugin_labels_but_reports_ad_types():
    records = [
        {
            "Target Object Type": "MSSQL_Login",
            "Target Object Types": ["Base", "MSSQL_Login", "User"],
        },
        {
            "Target Object Type": "SCCM_Site",
            "Target Object Types": ["SCCM_Site"],
        },
    ]

    cleaned = GroupAnalysisMixin()._normalise_group_target_labels(records)

    assert cleaned[0]["Target Raw Object Types"] == ["Base", "MSSQL_Login", "User"]
    assert cleaned[0]["Target Object Type"] == "User"
    assert cleaned[0]["Target Object Types"] == ["User"]
    assert cleaned[1]["Target Raw Object Types"] == ["SCCM_Site"]
    assert cleaned[1]["Target Object Type"] == "Unknown"
    assert cleaned[1]["Target Object Types"] == []
