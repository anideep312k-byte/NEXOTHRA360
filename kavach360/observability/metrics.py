from prometheus_client import Counter, Gauge, Histogram

HTTP_REQUESTS = Counter("kavach360_http_requests_total", "Total HTTP requests",
                        ["method", "endpoint", "status"])
HTTP_LATENCY = Histogram("kavach360_http_request_duration_seconds", "Request latency",
                         ["method", "endpoint"])
EVENTS_INGESTED = Counter("kavach360_events_ingested_total", "Events ingested",
                          ["tenant", "source_type"])
DETECTIONS_FIRED = Counter("kavach360_detections_fired_total", "Detections fired",
                           ["tenant", "rule_id", "severity"])
BROKER_LAG = Gauge("kavach360_broker_lag", "Broker consumer lag", ["stream", "group"])
WORKER_HEARTBEAT = Gauge("kavach360_worker_heartbeat_seconds", "Worker heartbeat", ["worker"])
AUDIT_CHAIN_VERIFY = Counter("kavach360_audit_verify_total", "Audit chain verification",
                             ["result"])
ENRICHMENT_DURATION = Histogram("kavach360_enrichment_duration_seconds",
                                "Enrichment latency", ["provider"])
ENRICHMENT_QUEUE_DEPTH = Gauge("kavach360_enrichment_queue_depth",
                               "Enrichment queue depth")
ENRICHMENT_WORKER_ACTIVE = Gauge("kavach360_enrichment_worker_active",
                                 "Active enrichment workers")
AI_TRIAGE_REQUESTS = Counter("kavach360_ai_triage_total", "AI triage requests",
                             ["provider", "result"])
RLS_CONTEXT_ERRORS = Counter("kavach360_rls_context_errors_total",
                             "RLS context setup failures")
REDIS_DEGRADED = Counter("kavach360_redis_degraded_total",
                         "Redis degradation events (non-security-critical paths)",
                         ["component"])
GRAPH_NODES = Gauge("kavach360_graph_nodes", "Attacker path graph node count")
GRAPH_EDGES = Gauge("kavach360_graph_edges", "Attacker path graph edge count")
LOG_LINES_PARSED = Counter("kavach360_log_lines_parsed_total",
                           "Log lines parsed", ["format", "source"])
