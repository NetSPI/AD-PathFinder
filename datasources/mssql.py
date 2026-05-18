from checks.core import DataSource, datasource


@datasource("mssql")
class MSSQLAvailability(DataSource):

    def available(self):
        domain_filter = getattr(self.deps.neo4j_data, '_domain_filter', None)
        if domain_filter:
            result = self.query(
                f'MATCH (n:MSSQL_Server) WHERE toUpper(n.name) CONTAINS ".{domain_filter.upper()}:" RETURN count(n) AS c',
                name="mssql_availability")
        else:
            result = self.query("MATCH (n:MSSQL_Server) RETURN count(n) AS c", name="mssql_availability")
        return result[0]['c'] > 0 if result else False
