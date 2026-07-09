"""OpenSearch-backed log search engine for CloudLogProject.

The engine uses a dual-mode architecture:
- Connected mode talks to OpenSearch for indexing and search.
- Fallback mode keeps documents in memory so the application still works during
  local development, offline testing, or temporary cluster outages.
"""

import os
import json

from opensearchpy import OpenSearch, RequestsHttpConnection


class LogSearchEngine:
    """Index and search structured log data with graceful offline fallback."""

    def __init__(self):
        """Initialize the OpenSearch client or fall back to in-memory storage.

        Environment variables control the remote endpoint so deployments can be
        reconfigured without code changes. If the client cannot be created or
        the cluster does not respond to a ping, the engine switches to fallback
        mode instead of raising an exception.
        """
        self.connected = False
        self.fallback_storage = []
        self.client = None
        self.index_name = "cloud-logs"

        opensearch_host = os.getenv("OPENSEARCH_HOST", "localhost")
        opensearch_port = int(os.getenv("OPENSEARCH_PORT", 9200))

        try:
            self.client = OpenSearch(
                hosts=[{"host": opensearch_host, "port": opensearch_port}],
                connection_class=RequestsHttpConnection,
                use_ssl=False,
                verify_certs=False,
                ssl_show_warn=False,
            )

            if self.client.ping():
                self.connected = True
            else:
                self.connected = False
                self.fallback_storage = []
                print(
                    f"Warning: OpenSearch at {opensearch_host}:{opensearch_port} did not respond to ping. "
                    "Using in-memory fallback storage."
                )
        except Exception as exc:
            self.connected = False
            self.client = None
            self.fallback_storage = []
            print(
                f"Warning: OpenSearch initialization failed for {opensearch_host}:{opensearch_port}. "
                f"Using in-memory fallback storage. Details: {exc}"
            )

    def _ensure_index_exists(self):
        """Create the default index if it does not already exist.

        The mapping is intentionally lightweight and flexible because the
        structured events produced by the parser may evolve over time.
        """
        if self.client is None:
            return False

        try:
            if not self.client.indices.exists(index=self.index_name):
                self.client.indices.create(
                    index=self.index_name,
                    body={
                        "settings": {
                            "number_of_shards": 1,
                            "number_of_replicas": 0,
                        },
                        "mappings": {
                            "properties": {
                                "job_id": {"type": "keyword"},
                                "timestamp": {"type": "keyword"},
                                "level": {"type": "keyword"},
                                "ip": {"type": "ip"},
                                "message": {"type": "text"},
                            }
                        },
                    },
                )
            return True
        except Exception as exc:
            print(f"Warning: Failed to ensure OpenSearch index '{self.index_name}': {exc}")
            return False

    def index_logs(self, job_id: str, structured_events: list) -> bool:
        """Index structured events into OpenSearch or fallback storage.

        Every document is enriched with the job ID before storage so queries can
        scope results to a specific job run.
        """
        enriched_events = []
        for event in structured_events:
            if not isinstance(event, dict):
                continue
            enriched_event = dict(event)
            enriched_event["job_id"] = job_id
            enriched_events.append(enriched_event)

        if self.connected and self.client is not None:
            try:
                if not self._ensure_index_exists():
                    return False

                for event in enriched_events:
                    self.client.index(index=self.index_name, body=event)
                self.client.indices.refresh(index=self.index_name)
                return True
            except Exception as exc:
                print(f"Warning: OpenSearch indexing failed for job_id={job_id}: {exc}")
                return False

        self.fallback_storage.extend(enriched_events)
        return True

    def search_logs(self, job_id: str, query_string: str = None, level_filter: str = None) -> list:
        """Search stored logs by job, optional free-text query, and level filter.

        In connected mode the method uses a bool query so the job scope is always
        enforced. In fallback mode it performs the equivalent filtering directly
        against the in-memory list of documents.
        """
        if self.connected and self.client is not None:
            try:
                must_clauses = [{"term": {"job_id": job_id}}]
                filter_clauses = []

                if query_string:
                    must_clauses.append(
                        {
                            "multi_match": {
                                "query": query_string,
                                "fields": ["message", "level", "timestamp", "ip"],
                            }
                        }
                    )

                if level_filter:
                    filter_clauses.append({"term": {"level": level_filter.upper()}})

                query_body = {
                    "query": {
                        "bool": {
                            "must": must_clauses,
                        }
                    }
                }

                if filter_clauses:
                    query_body["query"]["bool"]["filter"] = filter_clauses

                response = self.client.search(index=self.index_name, body=query_body)
                hits = response.get("hits", {}).get("hits", [])
                return [hit.get("_source", {}) for hit in hits]
            except Exception as exc:
                print(f"Warning: OpenSearch search failed for job_id={job_id}: {exc}")
                return []

        results = []
        normalized_query = query_string.lower() if query_string else None
        normalized_level = level_filter.upper() if level_filter else None

        for event in self.fallback_storage:
            if not isinstance(event, dict):
                continue
            if event.get("job_id") != job_id:
                continue

            if normalized_query:
                message = str(event.get("message", "")).lower()
                if normalized_query not in message:
                    continue

            if normalized_level:
                event_level = str(event.get("level", "")).upper()
                if event_level != normalized_level:
                    continue

            results.append(event)

        return results
