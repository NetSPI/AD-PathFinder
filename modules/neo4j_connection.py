from neo4j import GraphDatabase, basic_auth
from neo4j.exceptions import ServiceUnavailable
import threading
import time

class Neo4jConnection:
    def __init__(self, uri, user, pwd):
        self.__uri = uri
        self.__user = user
        self.__pwd = pwd
        self.__driver = None
        self._connection_pool = []
        self._pool_lock = threading.Lock()
        try:
            self.__driver = GraphDatabase.driver(self.__uri, auth=basic_auth(self.__user, self.__pwd))
            with self.__driver.session() as session:
                session.run("RETURN 1")
        except Exception as e:
            print(f"Cannot establish connection to Neo4j ({type(e).__name__}: {e}). Please check your connection.")
            if self.__driver is not None:
                self.__driver.close()
            self.__driver = None

    def close(self):
        if self.__driver is not None:
            self.__driver.close()

    def is_connected(self):
        if self.__driver is None:
            return False
        try:
            with self.__driver.session() as session:
                session.run("RETURN 1")
            return True
        except ServiceUnavailable:
            return False

    def query(self, query, parameters=None, db=None, **kwargs):
        if not self.is_connected():
            print("Cannot execute query. No connection to Neo4j.")
            return None
        try:
            with self.__driver.session(database=db) if db is not None else self.__driver.session() as session:
                response = list(session.run(query, parameters))
            return response
        except ServiceUnavailable:
            print("Neo4j is not available. Please check your connection.")
            return None

    def get_connection_for_thread(self):
        with self._pool_lock:
            if len(self._connection_pool) > 0:
                return self._connection_pool.pop()
            else:
                new_conn = Neo4jConnection(self.__uri, self.__user, self.__pwd)
                return new_conn

    def return_connection_to_pool(self, conn):
        with self._pool_lock:
            if len(self._connection_pool) < 20:
                self._connection_pool.append(conn)
            else:
                conn.close()


class InstrumentedConnection:

    def __init__(self, conn, collector):
        if isinstance(conn, InstrumentedConnection):
            conn = conn._conn
        self._conn = conn
        self._collector = collector

    def query(self, query, parameters=None, db=None, name=None):
        start = time.time()
        try:
            results = self._conn.query(query, parameters, db)
        except Exception:
            if self._collector:
                duration_ms = (time.time() - start) * 1000
                self._collector.record_query(
                    name=name or "unnamed",
                    duration_ms=duration_ms,
                    result_count=0,
                    success=False,
                )
            raise

        if self._collector:
            duration_ms = (time.time() - start) * 1000
            success = results is not None
            self._collector.record_query(
                name=name or "unnamed",
                duration_ms=duration_ms,
                result_count=len(results) if success else 0,
                success=success,
            )
        return results

    def get_connection_for_thread(self):
        raw = self._conn.get_connection_for_thread()
        return InstrumentedConnection(raw, self._collector)

    def return_connection_to_pool(self, conn):
        if isinstance(conn, InstrumentedConnection):
            conn = conn._conn
        return self._conn.return_connection_to_pool(conn)

    def __getattr__(self, attr):
        return getattr(self._conn, attr)
