from checks.core import Check, check
from datetime import datetime, timedelta


@check(risk="Medium", category="KRBTGT Password Older Than 6 Months",
       entity="user", data=["users"])
class KrbtgtPasswordAgeCheck(Check):

    def execute(self):
        if not hasattr(self, 'neo4j_data') or not self.neo4j_data:
            return {}

        password_last_changed = self.neo4j_data.get_krbtgt_password_last_changed()

        if not password_last_changed or password_last_changed in ['Unknown', 'Never', 0, -1]:
            return {}

        try:
            ts = float(password_last_changed)

            # Convert to datetime: Windows FILETIME or Unix timestamp
            if ts > 116444736000000000:
                unix_ts = (ts / 10_000_000) - (datetime(1970, 1, 1) - datetime(1601, 1, 1)).total_seconds()
                dt = datetime.fromtimestamp(unix_ts) if unix_ts > 0 else None
            elif ts > 946684800:
                dt = datetime.fromtimestamp(ts)
            else:
                return {}

            if dt and (datetime.now() - dt) > timedelta(days=180):
                return {'krbtgt': self.finding(f"Last Changed On: {dt.strftime('%m/%d/%Y')}")}

        except (ValueError, TypeError, OSError, OverflowError):
            pass

        return {}