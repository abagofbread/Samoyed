from __future__ import annotations

import os
from typing import Any


def cartography_configured() -> bool:
    return bool(os.environ.get("CARTOGRAPHY_NEO4J_URI") or os.environ.get("NEO4J_URI"))


def cartography_connection_params(
    *,
    uri: str | None = None,
    user: str | None = None,
    password: str | None = None,
    database: str | None = None,
) -> dict[str, str]:
    return {
        "uri": uri or os.environ.get("CARTOGRAPHY_NEO4J_URI") or os.environ.get("NEO4J_URI", ""),
        "user": user or os.environ.get("CARTOGRAPHY_NEO4J_USER") or os.environ.get("NEO4J_USER", "neo4j"),
        "password": password
        or os.environ.get("CARTOGRAPHY_NEO4J_PASSWORD")
        or os.environ.get("NEO4J_PASSWORD", "samoyed-dev"),
        "database": database or os.environ.get("CARTOGRAPHY_NEO4J_DATABASE", "neo4j"),
    }


class CartographyClient:
    """Read-only Neo4j client for a Cartography-synced graph."""

    def __init__(
        self,
        *,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
        database: str | None = None,
    ) -> None:
        params = cartography_connection_params(
            uri=uri, user=user, password=password, database=database
        )
        if not params["uri"]:
            raise RuntimeError(
                "Cartography Neo4j URI not configured. Set CARTOGRAPHY_NEO4J_URI or NEO4J_URI."
            )
        self.uri = params["uri"]
        self.user = params["user"]
        self.password = params["password"]
        self.database = params["database"]
        self._driver: Any = None

    def _driver_instance(self) -> Any:
        if self._driver is None:
            from neo4j import GraphDatabase

            self._driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        return self._driver

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def __enter__(self) -> CartographyClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def run(self, query: str, **params: Any) -> list[dict[str, Any]]:
        driver = self._driver_instance()
        rows: list[dict[str, Any]] = []
        with driver.session(database=self.database) as session:
            result = session.run(query, **params)
            for record in result:
                row: dict[str, Any] = {}
                for key in record.keys():
                    value = record[key]
                    if hasattr(value, "items"):
                        row[key] = dict(value)
                    elif isinstance(value, (list, tuple)):
                        row[key] = list(value)
                    else:
                        row[key] = value
                rows.append(row)
        return rows

    def ping(self) -> bool:
        rows = self.run("RETURN 1 AS ok LIMIT 1")
        return bool(rows and rows[0].get("ok") == 1)

    def list_aws_accounts(self) -> list[dict[str, Any]]:
        return self.run(
            """
            MATCH (a:AWSAccount)
            RETURN a.id AS account_id, a.name AS name
            ORDER BY a.id
            """
        )

    def stats(self, *, account_id: str | None = None) -> dict[str, int]:
        rows = self.run(
            """
            MATCH (a:AWSAccount)
            WHERE $account_id IS NULL OR a.id = $account_id
            OPTIONAL MATCH (a)-[:RESOURCE]->(n)
            RETURN count(DISTINCT n) AS resources
            """,
            account_id=account_id,
        )
        principals = self.run(
            """
            MATCH (a:AWSAccount)
            WHERE $account_id IS NULL OR a.id = $account_id
            MATCH (a)-[:RESOURCE]->(p)
            WHERE p:AWSUser OR p:AWSRole OR p:AWSGroup
            RETURN count(DISTINCT p) AS principals
            """,
            account_id=account_id,
        )
        return {
            "resources": int((rows[0]["resources"] if rows else 0) or 0),
            "principals": int((principals[0]["principals"] if principals else 0) or 0),
        }
