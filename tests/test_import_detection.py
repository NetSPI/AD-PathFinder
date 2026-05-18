import json
import zipfile
from types import SimpleNamespace

from modules.main import _is_supplementary_only_import, handle_import_with_check


BASELINE_REQUIRED_MESSAGE = (
    "[ERROR] OpenGraph plugin data requires existing BloodHound/SharpHound data. "
    "Import SharpHound first or include it in the same import command."
)


class RecordingImporter:
    def __init__(self, result=True):
        self.result = result
        self.import_calls = []

    def import_zip(self, import_file):
        self.import_calls.append(import_file)
        return self.result


def _write_zip(path, payloads):
    with zipfile.ZipFile(path, "w") as zf:
        for name, payload in payloads.items():
            zf.writestr(name, json.dumps(payload))
    return path


def test_single_opengraph_zip_is_supplementary_only(tmp_path):
    graph_zip = _write_zip(
        tmp_path / "supplementary.zip",
        {"data.json": {"graph": {"nodes": [], "edges": []}}},
    )

    assert _is_supplementary_only_import(str(graph_zip)) is True


def test_sharphound_zip_is_not_supplementary_only(tmp_path):
    sharphound_zip = _write_zip(
        tmp_path / "sharphound.zip",
        {"users.json": {"data": []}},
    )

    assert _is_supplementary_only_import(str(sharphound_zip)) is False


def test_mixed_import_is_not_supplementary_only(tmp_path):
    graph_zip = _write_zip(
        tmp_path / "supplementary.zip",
        {"data.json": {"graph": {"nodes": [], "edges": []}}},
    )
    sharphound_zip = _write_zip(
        tmp_path / "sharphound.zip",
        {"users.json": {"data": []}},
    )

    assert _is_supplementary_only_import([str(graph_zip), str(sharphound_zip)]) is False


def test_graph_null_zip_is_not_supplementary_only(tmp_path):
    graph_zip = _write_zip(
        tmp_path / "broken-supplementary.zip",
        {"data.json": {"graph": None}},
    )

    assert _is_supplementary_only_import(str(graph_zip)) is False


def test_corrupted_zip_is_not_supplementary_only(tmp_path):
    broken_zip = tmp_path / "broken.zip"
    broken_zip.write_bytes(b"not a zip")

    assert _is_supplementary_only_import(str(broken_zip)) is False


def test_zip_with_no_json_is_not_supplementary_only(tmp_path):
    empty_zip = tmp_path / "no-json.zip"
    with zipfile.ZipFile(empty_zip, "w") as zf:
        zf.writestr("README.txt", "not json")

    assert _is_supplementary_only_import(str(empty_zip)) is False


def test_zip_with_malformed_json_is_not_supplementary_only(tmp_path):
    broken_json_zip = tmp_path / "bad-json.zip"
    with zipfile.ZipFile(broken_json_zip, "w") as zf:
        zf.writestr("data.json", "{not json")

    assert _is_supplementary_only_import(str(broken_json_zip)) is False


def test_supplementary_only_import_into_empty_database_fails_before_import(
    tmp_path,
    monkeypatch,
    capsys,
):
    graph_zip = _write_zip(
        tmp_path / "supplementary.zip",
        {"data.json": {"graph": {"nodes": [], "edges": []}}},
    )
    importer = RecordingImporter()
    monkeypatch.setattr("modules.main.check_database_has_data", lambda conn: False)

    result = handle_import_with_check(
        SimpleNamespace(import_file=str(graph_zip)),
        importer,
        conn=object(),
    )

    assert result is False
    assert importer.import_calls == []
    assert BASELINE_REQUIRED_MESSAGE in capsys.readouterr().out


def test_supplementary_only_import_into_existing_database_imports_without_warning(
    tmp_path,
    monkeypatch,
    capsys,
):
    graph_zip = _write_zip(
        tmp_path / "supplementary.zip",
        {"data.json": {"graph": {"nodes": [], "edges": []}}},
    )
    importer = RecordingImporter()
    monkeypatch.setattr("modules.main.check_database_has_data", lambda conn: True)

    result = handle_import_with_check(
        SimpleNamespace(import_file=str(graph_zip)),
        importer,
        conn=object(),
    )

    output = capsys.readouterr().out
    assert result is True
    assert importer.import_calls == [str(graph_zip)]
    assert "[INFO] Importing supplementary OpenGraph data" in output
    assert "Importing supplementary data from 1 file(s)" in output
    assert "WARNING: BloodHound data already exists" not in output


def test_sharphound_only_import_into_empty_database_imports_as_bloodhound_data(
    tmp_path,
    monkeypatch,
    capsys,
):
    sharphound_zip = _write_zip(
        tmp_path / "sharphound.zip",
        {"users.json": {"data": []}},
    )
    importer = RecordingImporter()
    monkeypatch.setattr("modules.main.check_database_has_data", lambda conn: False)

    result = handle_import_with_check(
        SimpleNamespace(import_file=str(sharphound_zip)),
        importer,
        conn=object(),
    )

    output = capsys.readouterr().out
    assert result is True
    assert importer.import_calls == [str(sharphound_zip)]
    assert "Importing BloodHound data from 1 file(s)" in output
    assert BASELINE_REQUIRED_MESSAGE not in output


def test_mixed_sharphound_and_opengraph_import_into_empty_database_imports(
    tmp_path,
    monkeypatch,
    capsys,
):
    graph_zip = _write_zip(
        tmp_path / "supplementary.zip",
        {"data.json": {"graph": {"nodes": [], "edges": []}}},
    )
    sharphound_zip = _write_zip(
        tmp_path / "sharphound.zip",
        {"users.json": {"data": []}},
    )
    import_files = [str(sharphound_zip), str(graph_zip)]
    importer = RecordingImporter()
    monkeypatch.setattr("modules.main.check_database_has_data", lambda conn: False)

    result = handle_import_with_check(
        SimpleNamespace(import_file=import_files),
        importer,
        conn=object(),
    )

    output = capsys.readouterr().out
    assert result is True
    assert importer.import_calls == [import_files]
    assert "Importing BloodHound data from 2 file(s)" in output
    assert BASELINE_REQUIRED_MESSAGE not in output
