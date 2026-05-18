from modules.account_analysis import AccountAnalysis
from modules.analysis import Analysis
from modules.utils import find_cracked_accounts, load_ntds_hashes


BLANK_NTLM = "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_find_cracked_accounts_detects_lowercase_blank_nt_hash():
    cracked = find_cracked_accounts({}, {}, ({"alice": BLANK_NTLM}, {}))

    assert cracked == {"alice": ""}


def test_load_ntds_hashes_normalizes_uppercase_blank_nt_hash(tmp_path):
    ntds_path = tmp_path / "ntds.txt"
    ntds_path.write_text(
        "TRAINING\\alice:1101:aad3b435b51404eeaad3b435b51404ee:"
        f"{BLANK_NTLM.upper()}:::\n",
        encoding="utf-8",
    )

    ntds_data = load_ntds_hashes(str(ntds_path))

    assert ntds_data[0] == {"alice": BLANK_NTLM}
    assert find_cracked_accounts({}, {}, ntds_data) == {"alice": ""}


def test_account_analysis_detects_blank_password_without_potfile_matches():
    analysis = AccountAnalysis(None, None, ({"alice": BLANK_NTLM}, {}), None)

    assert analysis.cracked_accounts == {"alice": ""}


def test_password_analysis_categorizes_blank_password_without_potfile_matches():
    analysis = Analysis(None, None, {}, ({"alice": BLANK_NTLM}, {}))

    total, categories, _, _, length_data, complexity_data = analysis._analyse_passwords(
        None,
        ({"alice": BLANK_NTLM}, {}),
        {"alice"},
        analysis._define_category_patterns(None),
        "safe",
        [{"username": "alice", "enabled": True}],
    )

    assert total == 1
    assert categories["blank password"]["users"] == ["alice"]
    assert length_data == {"0": ["alice"]}
    assert complexity_data == {0: ["alice"]}
