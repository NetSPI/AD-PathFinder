class DomainFilterMixin:

    def _domain_condition(self, var_name):
        # IN handles domain stored as string or single-element list (BH CE quirk)

        if not self._domain_filter:
            return ""
        d = self._domain_filter.upper()
        return f' AND {var_name}.domain IN ["{d}", ["{d}"]]'
