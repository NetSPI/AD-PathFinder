from checks.cross_domain.base import CrossDomainDependencies
from checks.cross_domain.cracked_password_reuse import CrackedPasswordReuseCheck


def test_fires_on_different_users_with_same_cracked_hash():
    deps = CrossDomainDependencies(
        conn=None,
        all_domains=["DOMAIN_A", "DOMAIN_B"],
        domain_hashes={
            "DOMAIN_A": ({"alice": "aabbccdd"}, {}),
            "DOMAIN_B": ({"bob": "aabbccdd"}, {}),
        },
        cracked_hashes={"aabbccdd": "Password1"},
    )
    findings = CrackedPasswordReuseCheck(deps).run()

    assert findings
    usernames = {f["username"] for f in findings}
    assert "alice" in usernames
    assert "bob" in usernames


def test_silent_when_hash_not_cracked():
    deps = CrossDomainDependencies(
        conn=None,
        all_domains=["DOMAIN_A", "DOMAIN_B"],
        domain_hashes={
            "DOMAIN_A": ({"alice": "aabbccdd"}, {}),
            "DOMAIN_B": ({"bob": "aabbccdd"}, {}),
        },
        cracked_hashes={},
    )
    findings = CrackedPasswordReuseCheck(deps).run()
    assert findings == []
