"""Tier-0 user sessions on non-Tier-0 hosts — credential-theft primitive."""

from checks.core import Check, check


@check(risk="Low", category="Tier-0 Session on Non-Tier-0 Host",
       entity="user", data=[])
class Tier0SessionExposureCheck(Check):

    def execute(self):
        if not self.neo4j_data:
            return {}

        try:
            rows = self.neo4j_data.conn.query("""
                MATCH (c:Computer)-[:HasSession]->(u:User)
                WHERE u.system_tags CONTAINS 'admin_tier_0'
                  AND (c.system_tags IS NULL OR NOT c.system_tags CONTAINS 'admin_tier_0')
                  AND u.enabled = true
                  AND c.enabled = true
                RETURN u.objectid AS sid,
                       collect(DISTINCT c.name) AS hosts
            """, name="tier0_session_exposure")

            findings = {}
            for row in rows:
                sid = row.get('sid')
                hosts = sorted(row.get('hosts') or [])
                if sid and hosts:
                    findings[sid] = self.finding(
                        f"Active session on: {', '.join(hosts)}",
                        details={"hosts": hosts},
                    )
            return findings
        except Exception:
            return {}
