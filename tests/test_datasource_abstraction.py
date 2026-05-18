import unittest
from checks.core.datasource import DataSource, datasource, DataSourceRegistry
from checks.core.dependencies import CheckDependencies
from checks.core import check, Check

class FakeConnection:
    def __init__(self, query_results=None):
        self._results = query_results or {}

    def query(self, cypher, parameters=None, name=None):
        return self._results.get(name, [])

class FakeNeo4jData:
    def __init__(self, conn, domain_filter=None):
        self.conn = conn
        self._domain_filter = domain_filter
        self.computer_sids = set()

    def populate_group_sid_mappings(self):
        pass

def make_deps(query_results=None, domain_filter=None):
    conn = FakeConnection(query_results)
    neo4j_data = FakeNeo4jData(conn, domain_filter)
    return CheckDependencies(neo4j_data=neo4j_data)

class TestDataSourceRegistry(unittest.TestCase):

    def setUp(self):
        self._orig = dict(DataSourceRegistry._datasources)

    def tearDown(self):
        DataSourceRegistry._datasources = self._orig

    def test_decorator_registers(self):
        @datasource("test_platform")
        class TestDS(DataSource):
            def available(self):
                return True

        self.assertIn("test_platform", DataSourceRegistry.get_all())
        self.assertIs(DataSourceRegistry.get_all()["test_platform"], TestDS)

    def test_available_true(self):
        @datasource("jenkins")
        class JenkinsAvailability(DataSource):
            def available(self):
                result = self.query("MATCH (n:JenkinsBuild) RETURN count(n) AS c",
                                    name="jenkins_avail")
                return result[0]['c'] > 0 if result else False

        deps = make_deps({"jenkins_avail": [{"c": 3}]})
        ds = JenkinsAvailability(deps)
        self.assertTrue(ds.available())

    def test_available_false_no_nodes(self):
        @datasource("jenkins2")
        class JenkinsAvailability(DataSource):
            def available(self):
                result = self.query("MATCH (n:JenkinsBuild) RETURN count(n) AS c",
                                    name="jenkins_avail")
                return result[0]['c'] > 0 if result else False

        deps = make_deps({"jenkins_avail": [{"c": 0}]})
        self.assertFalse(JenkinsAvailability(deps).available())

    def test_available_false_empty_result(self):
        @datasource("jenkins3")
        class JenkinsAvailability(DataSource):
            def available(self):
                result = self.query("MATCH (n:JenkinsBuild) RETURN count(n) AS c",
                                    name="jenkins_avail")
                return result[0]['c'] > 0 if result else False

        deps = make_deps({})
        self.assertFalse(JenkinsAvailability(deps).available())

class TestCheckWithDataSource(unittest.TestCase):

    def setUp(self):
        self._orig_ds = dict(DataSourceRegistry._datasources)
        from checks.core.registry import CheckRegistry
        self._orig_checks = list(CheckRegistry.checks)

    def tearDown(self):
        DataSourceRegistry._datasources = self._orig_ds
        from checks.core.registry import CheckRegistry
        CheckRegistry.checks = self._orig_checks

    def test_check_queries_own_data(self):
        """A check using self.query() gets results without an analyzer class."""

        @datasource("github")
        class GitHubAvailability(DataSource):
            def available(self):
                result = self.query("MATCH (n:GitHubRepo) RETURN count(n) AS c",
                                    name="github_avail")
                return result[0]['c'] > 0 if result else False

        @check(risk="High", category="GitHub Public Repos", data=[], requires=["github"])
        class GitHubPublicRepoCheck(Check):
            def execute(self):
                rows = self.query("MATCH (r:GitHubRepo) WHERE r.visibility = 'public' "
                                  "RETURN r.objectid AS id, r.name AS name",
                                  name="github_public")
                results = {}
                for row in rows:
                    results[row['id']] = self.finding(f"Public repo: {row['name']}")
                return results

        deps = make_deps({
            "github_avail": [{"c": 2}],
            "github_public": [
                {"id": "repo-001", "name": "internal-tools"},
                {"id": "repo-002", "name": "secret-config"},
            ]
        })

        ds = GitHubAvailability(deps)
        self.assertTrue(ds.available())

        c = GitHubPublicRepoCheck(deps)
        results = c.run()
        self.assertEqual(len(results), 2)
        self.assertEqual(results["repo-001"], "Public repo: internal-tools")
        self.assertEqual(results["repo-002"], "Public repo: secret-config")

    def test_check_skipped_when_datasource_unavailable(self):
        """Manager skips checks whose DataSource returns False."""
        from checks.core.manager import VulnerabilityFrameworkManager

        @datasource("empty_platform")
        class EmptyPlatform(DataSource):
            def available(self):
                return False

        @check(risk="Medium", category="Empty Platform Check", data=[], requires=["empty_platform"])
        class EmptyPlatformCheck(Check):
            def execute(self):
                return {"should-not-appear": self.finding("bug")}

        neo4j_data = FakeNeo4jData(FakeConnection(), None)
        neo4j_data.get_all_computers_with_attributes = lambda: []
        neo4j_data.get_all_users_with_attributes = lambda: []
        manager = VulnerabilityFrameworkManager(neo4j_data)
        display, stats = manager.run_all_checks()

        for risk_blocks in display.values():
            for block in risk_blocks:
                self.assertNotEqual(block['category'], "Empty Platform Check")
