from checks.cross_domain.base import CrossDomainDependencies
from checks.cross_domain.same_user_password import SameUserPasswordCheck


def test_fires_on_same_user_same_hash_across_domains():
    deps = CrossDomainDependencies(
        conn=None,
        all_domains=["DOMAIN_A", "DOMAIN_B"],
        domain_hashes={
            "DOMAIN_A": ({"alice": "aabbccdd"}, {}),
            "DOMAIN_B": ({"alice": "aabbccdd"}, {}),
        },
    )
    assert SameUserPasswordCheck.RISK_LEVEL == "High"
    findings = SameUserPasswordCheck(deps).run()

    assert len(findings) == 1
    assert findings[0]["username"] == "alice"
    assert set(findings[0]["domains"]) == {"DOMAIN_A", "DOMAIN_B"}


def test_silent_when_hashes_differ():
    deps = CrossDomainDependencies(
        conn=None,
        all_domains=["DOMAIN_A", "DOMAIN_B"],
        domain_hashes={
            "DOMAIN_A": ({"alice": "aabbccdd"}, {}),
            "DOMAIN_B": ({"alice": "11223344"}, {}),
        },
    )
    findings = SameUserPasswordCheck(deps).run()
    assert findings == []
