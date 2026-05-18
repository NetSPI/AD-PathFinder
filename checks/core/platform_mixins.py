class MSSQLDomainMixin:

    def _server_domain_condition(self, server_field):
        if not self._domain_filter:
            return ""
        return (f' AND toUpper(split(substring({server_field}, size(split({server_field}, ".")[0]) + 1), ":")[0])'
                f' = "{self._domain_filter.upper()}"')

    def _default_group_condition(self, group_var="g"):
        gdf = self._domain_condition(group_var)
        return (f'({group_var}.name STARTS WITH "DOMAIN USERS" {gdf})'
                f' OR ({group_var}.name STARTS WITH "DOMAIN COMPUTERS" {gdf})'
                f' OR ({group_var}.name STARTS WITH "AUTHENTICATED USERS" {gdf})'
                f' OR ({group_var}.name STARTS WITH "EVERYONE" {gdf})'
                f' OR ({group_var}.name STARTS WITH "USERS" {gdf})'
                f' OR ({group_var}.objectid ENDS WITH "-513" {gdf})'
                f' OR ({group_var}.objectid ENDS WITH "-515" {gdf})'
                f' OR ({group_var}.objectid ENDS WITH "S-1-5-11" {gdf})'
                f' OR ({group_var}.objectid ENDS WITH "S-1-1-0" {gdf})'
                f' OR ({group_var}.objectid ENDS WITH "S-1-5-32-545" {gdf})')


class SCCMDomainMixin:

    def _site_domain_condition(self, site_var="site"):
        if not self._domain_filter:
            return ""
        return f' AND toUpper({site_var}.sourceForest) = "{self._domain_filter.upper()}"'
