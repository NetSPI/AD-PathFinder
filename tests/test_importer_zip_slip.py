import json
import zipfile
from pathlib import Path

import pytest

from modules.BloodhoundImporter import BloodhoundImporter


def _write_zip(zip_path: Path, entries: dict) -> Path:
    with zipfile.ZipFile(zip_path, 'w') as zip_ref:
        for name, content in entries.items():
            zip_ref.writestr(name, content)
    return zip_path


def test_extract_zip_rejects_parent_directory_traversal(tmp_path):
    zip_path = _write_zip(tmp_path / "evil.zip", {
        "../escapee.json": json.dumps({"k": "v"}),
    })
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()

    importer = BloodhoundImporter(None)

    with pytest.raises(Exception, match="escapes extract directory"):
        importer._extract_zip(zip_path, extract_dir)

    assert not (tmp_path / "escapee.json").exists()


def test_extract_zip_rejects_absolute_path_member(tmp_path):
    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, 'w') as zip_ref:
        info = zipfile.ZipInfo(filename="/tmp/adpf_zipslip_canary.json")
        zip_ref.writestr(info, json.dumps({"k": "v"}))
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()

    importer = BloodhoundImporter(None)

    with pytest.raises(Exception, match="escapes extract directory"):
        importer._extract_zip(zip_path, extract_dir)

    assert not Path("/tmp/adpf_zipslip_canary.json").exists()


def test_extract_zip_accepts_well_formed_archive(tmp_path):
    zip_path = _write_zip(tmp_path / "good.zip", {
        "users.json": json.dumps({"users": []}),
        "nested/groups.json": json.dumps({"groups": []}),
    })
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()

    importer = BloodhoundImporter(None)

    json_files = importer._extract_zip(zip_path, extract_dir)

    assert sorted(p.name for p in json_files) == ["groups.json", "users.json"]
    assert (extract_dir / "users.json").exists()
    assert (extract_dir / "nested" / "groups.json").exists()
