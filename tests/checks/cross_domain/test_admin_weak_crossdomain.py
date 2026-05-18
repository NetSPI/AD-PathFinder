from checks.cross_domain.admin_weak_crossdomain import AdminWeakCrossDomainCheck
from checks.cross_domain.base import CrossDomainDependencies


def test_fires_on_admin_with_cracked_hash_in_other_domain():
    deps = CrossDomainDependencies(
        conn=None,
        all_domains=["DOMAIN_A", "DOMAIN_B"],
        domain_hashes={
            "DOMAIN_B": ({"alice": "aabbccdd"}, {}),
        },
        cracked_hashes={"aabbccdd": "Password1"},
        per_domain_admin_users={"DOMAIN_A": ["alice"]},
    )
    assert AdminWeakCrossDomainCheck.RISK_LEVEL == "Critical"
    findings = AdminWeakCrossDomainCheck(deps).run()

    assert len(findings) == 1
    assert findings[0]["username"] == "alice"
    assert findings[0]["admin_domain"] == "DOMAIN_A"
    assert findings[0]["weak_password_domain"] == "DOMAIN_B"


def test_silent_when_hash_not_cracked():
    deps = CrossDomainDependencies(
        conn=None,
        all_domains=["DOMAIN_A", "DOMAIN_B"],
        domain_hashes={
            "DOMAIN_B": ({"alice": "aabbccdd"}, {}),
        },
        cracked_hashes={},
        per_domain_admin_users={"DOMAIN_A": ["alice"]},
    )
    findings = AdminWeakCrossDomainCheck(deps).run()
    assert findings == []
