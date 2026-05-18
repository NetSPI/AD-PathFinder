from checks.core import DataSource, datasource


@datasource("sccm")
class SCCMAvailability(DataSource):

    def available(self):
        domain_filter = getattr(self.deps.neo4j_data, '_domain_filter', None)
        if domain_filter:
            result = self.query(
                f'MATCH (n:SCCM_Site) WHERE toUpper(n.sourceForest) = "{domain_filter.upper()}" RETURN count(n) AS c',
                name="sccm_availability")
        else:
            result = self.query("MATCH (n:SCCM_Site) RETURN count(n) AS c", name="sccm_availability")
        return result[0]['c'] > 0 if result else False
