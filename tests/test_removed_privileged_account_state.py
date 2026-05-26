from pathlib import Path


LEGACY_PRIVILEGED_ACCOUNT_TERMS = tuple(
    "".join(parts)
    for parts in (
        ("is", "Privileged"),
        ("Cracked ", "Privileged Accounts"),
        ("Privileged", " Accounts"),
        ("cracked_", "privileged"),
        ("cracked_enabled_", "privileged"),
        ("privileged", "_account"),
        ("Privileged", "_Account"),
        ("Privileged Account", " with Weak Password"),
        ("Privileged", ":"),
        ("privileged", "_violations"),
        ("Admin or ", "privileged account"),
    )
)


def test_legacy_indirect_access_state_not_reintroduced():
    repo_root = Path(__file__).resolve().parents[1]
    roots = ("assets", "checks", "modules", "sample_reports")
    suffixes = {".css", ".html", ".js", ".py", ".txt"}

    offenders = []
    for root_name in roots:
        root = repo_root / root_name
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in suffixes:
                continue
            text = path.read_text(encoding="utf-8")
            for term in LEGACY_PRIVILEGED_ACCOUNT_TERMS:
                if term in text:
                    offenders.append(f"{path.relative_to(repo_root)}: {term}")

    assert offenders == []
