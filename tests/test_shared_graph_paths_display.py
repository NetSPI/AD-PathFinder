from checks.core.display.shared_graph_paths import SharedGraphPathDisplayHandler


class FakeSidMapper:
    def __init__(self, mapping):
        self.mapping = mapping

    def get_display_name(self, sid):
        return self.mapping.get(sid, sid)


class FakeCheck:
    ENTITY_TYPE = 'user'


def _run(results):
    handler = SharedGraphPathDisplayHandler(
        suppress_terminal_output=True,
        check_instance=FakeCheck(),
        sid_mapper=FakeSidMapper({
            'S-1-1': 'USER1',
            'S-1-2': 'USER2',
        }),
    )
    content = []
    handler.display(results, '', 'SCCM Privilege Escalation', content, len(results), '')
    return content


def test_graph_path_display_shows_only_node_chains():
    suffix = (
        "MSSQL_Connect -> lab-sql01.training.local -> MSSQL_LinkedAsAdmin "
        "-> sccmdb.training.local -> MSSQL_Contains -> sysadmin@sccmdb.training.local"
    )
    out = _run({
        'S-1-1': f"user1 -> {suffix}",
        'S-1-2': f"user2 -> {suffix}",
    })

    assert "    ▶ USER1" in out
    assert "    ▶ USER2" in out
    assert (
        "        user1 > MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin "
        "> sccmdb.training.local > MSSQL_Contains > sysadmin@sccmdb.training.local"
    ) in out
    assert (
        "        user2 > MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin "
        "> sccmdb.training.local > MSSQL_Contains > sysadmin@sccmdb.training.local"
    ) in out
    assert not any("Shared Graph Path" in line for line in out)
    assert not any("Path:" in line for line in out)


def test_shared_graph_path_splits_sccm_scope_from_path_template():
    path = (
        "user1 -> MSSQL_Connect -> lab-sql01.training.local -> MSSQL_LinkedAsAdmin "
        "-> sccmdb.training.local -> MSSQL_Contains -> MSSQL_Database(CM_TRN) "
        "-> MSSQL_Contains -> db_owner@CM_TRN"
    )
    scope = "MSSQL_Database(CM_TRN) -> SCCM_AssignAllPermissions -> SCCM_Site(TRN)"

    out = _run({'S-1-1': f"{path} | {scope}"})

    assert (
        "        user1 > MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin "
        "> sccmdb.training.local > MSSQL_Contains > MSSQL_Database(CM_TRN) "
        "> MSSQL_Contains > db_owner@CM_TRN > SCCM_Site(TRN)"
    ) in out
    assert not any("SCCM Scope:" in line for line in out)


def test_scope_node_with_platform_prefix_is_not_dropped():
    out = _run({
        'S-1-1': (
            "user1 -> MSSQL_Connect -> sql01 | "
            "SCCM_AssignAllPermissions -> MSSQL_login_stub"
        )
    })

    assert "        user1 > MSSQL_Connect > sql01 > MSSQL_login_stub" in out
