CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    goal_artifact_id TEXT NOT NULL,
    goal_hash TEXT NOT NULL CHECK(length(goal_hash) = 64),
    mode TEXT NOT NULL CHECK(mode IN ('routine', 'coding', 'computer_use')),
    status TEXT NOT NULL,
    workspace TEXT,
    owner TEXT,
    cancellation_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancellation_requested IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX tasks_trace_idx ON tasks(trace_id);
CREATE INDEX tasks_status_idx ON tasks(status, updated_at);

CREATE TABLE plans (
    plan_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    trace_id TEXT NOT NULL,
    model_name TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    plan_artifact_id TEXT NOT NULL,
    plan_hash TEXT NOT NULL CHECK(length(plan_hash) = 64),
    user_acceptance TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY(plan_id, version)
) STRICT;

CREATE INDEX plans_task_idx ON plans(task_id, version);

CREATE TABLE steps (
    step_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    action_hash TEXT NOT NULL CHECK(length(action_hash) = 64),
    tool_name TEXT,
    arguments_artifact_id TEXT,
    normalized_arguments_hash TEXT,
    target_artifact_id TEXT,
    exact_target_hash TEXT,
    expected_result_hash TEXT NOT NULL CHECK(length(expected_result_hash) = 64),
    status TEXT NOT NULL,
    attempt_limit INTEGER NOT NULL CHECK(attempt_limit BETWEEN 1 AND 3),
    timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds BETWEEN 1 AND 3600),
    risk TEXT NOT NULL CHECK(risk IN ('R0', 'R1', 'R2', 'R3', 'R4')),
    capability_scope_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(plan_id, plan_version) REFERENCES plans(plan_id, version)
) STRICT;

CREATE INDEX steps_plan_idx ON steps(plan_id, plan_version);
CREATE INDEX steps_task_status_idx ON steps(task_id, status);

CREATE TABLE step_dependencies (
    step_id TEXT NOT NULL REFERENCES steps(step_id),
    depends_on_step_id TEXT NOT NULL REFERENCES steps(step_id),
    PRIMARY KEY(step_id, depends_on_step_id),
    CHECK(step_id <> depends_on_step_id)
) STRICT;

CREATE TABLE tool_invocations (
    invocation_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    step_id TEXT NOT NULL REFERENCES steps(step_id),
    attempt_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    tool_name TEXT NOT NULL,
    normalized_arguments_hash TEXT NOT NULL CHECK(length(normalized_arguments_hash) = 64),
    status TEXT NOT NULL,
    result_reference TEXT,
    error_code TEXT,
    side_effect_marker TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX tool_invocations_step_idx ON tool_invocations(step_id, created_at);

CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    step_id TEXT NOT NULL REFERENCES steps(step_id),
    plan_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL,
    risk TEXT NOT NULL CHECK(risk IN ('R0', 'R1', 'R2', 'R3', 'R4')),
    reason TEXT NOT NULL,
    scope_hash TEXT NOT NULL,
    decision TEXT NOT NULL,
    channel TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    approver TEXT,
    consumed_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(plan_id, plan_version) REFERENCES plans(plan_id, version)
) STRICT;

CREATE TABLE verifications (
    verification_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    step_id TEXT NOT NULL REFERENCES steps(step_id),
    invocation_id TEXT REFERENCES tool_invocations(invocation_id),
    verifier_type TEXT NOT NULL,
    evidence_references_json TEXT NOT NULL,
    result TEXT NOT NULL CHECK(result IN ('passed', 'failed')),
    confidence REAL,
    repair_count INTEGER NOT NULL DEFAULT 0 CHECK(repair_count BETWEEN 0 AND 2),
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE artifacts (
    artifact_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    step_id TEXT REFERENCES steps(step_id),
    kind TEXT NOT NULL,
    storage_reference TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    size_bytes INTEGER CHECK(size_bytes IS NULL OR size_bytes >= 0),
    sensitivity_class TEXT NOT NULL,
    retention_class TEXT NOT NULL,
    encrypted INTEGER NOT NULL CHECK(encrypted IN (0, 1)),
    encryption_key_reference TEXT,
    redaction_metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK(encrypted = 0 OR encryption_key_reference IS NOT NULL)
) STRICT;

CREATE TABLE events (
    event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    schema_version TEXT NOT NULL,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    severity TEXT NOT NULL,
    session_id TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    task_id TEXT REFERENCES tasks(task_id),
    plan_id TEXT,
    plan_version INTEGER,
    step_id TEXT,
    invocation_id TEXT,
    approval_id TEXT,
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL CHECK(length(event_hash) = 64),
    hash_algorithm TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX events_task_idx ON events(task_id, event_sequence);
CREATE INDEX events_trace_idx ON events(trace_id, event_sequence);
CREATE INDEX events_type_idx ON events(event_type, event_sequence);

CREATE TRIGGER events_no_update
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER events_no_delete
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TABLE outbox (
    outbox_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id),
    topic TEXT NOT NULL,
    partition_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    available_at TEXT NOT NULL,
    published_at TEXT,
    last_error_code TEXT,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX outbox_pending_idx ON outbox(published_at, available_at, created_at);

CREATE TABLE checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    step_id TEXT REFERENCES steps(step_id),
    workspace TEXT NOT NULL,
    state_hash TEXT NOT NULL CHECK(length(state_hash) = 64),
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER plans_no_update
BEFORE UPDATE ON plans
WHEN OLD.plan_id IS NOT NEW.plan_id
  OR OLD.version IS NOT NEW.version
  OR OLD.task_id IS NOT NEW.task_id
  OR OLD.trace_id IS NOT NEW.trace_id
  OR OLD.model_name IS NOT NEW.model_name
  OR OLD.prompt_version IS NOT NEW.prompt_version
  OR OLD.plan_artifact_id IS NOT NEW.plan_artifact_id
  OR OLD.plan_hash IS NOT NEW.plan_hash
  OR OLD.created_at IS NOT NEW.created_at
BEGIN
    SELECT RAISE(ABORT, 'plan version content is immutable');
END;

CREATE TRIGGER plans_no_delete
BEFORE DELETE ON plans
BEGIN
    SELECT RAISE(ABORT, 'plan versions are immutable');
END;

CREATE TRIGGER steps_no_update
BEFORE UPDATE ON steps
WHEN OLD.plan_id IS NOT NEW.plan_id
  OR OLD.plan_version IS NOT NEW.plan_version
  OR OLD.task_id IS NOT NEW.task_id
  OR OLD.action_hash IS NOT NEW.action_hash
  OR OLD.tool_name IS NOT NEW.tool_name
  OR OLD.arguments_artifact_id IS NOT NEW.arguments_artifact_id
  OR OLD.normalized_arguments_hash IS NOT NEW.normalized_arguments_hash
  OR OLD.target_artifact_id IS NOT NEW.target_artifact_id
  OR OLD.exact_target_hash IS NOT NEW.exact_target_hash
  OR OLD.expected_result_hash IS NOT NEW.expected_result_hash
  OR OLD.attempt_limit IS NOT NEW.attempt_limit
  OR OLD.timeout_seconds IS NOT NEW.timeout_seconds
  OR OLD.risk IS NOT NEW.risk
  OR OLD.capability_scope_json IS NOT NEW.capability_scope_json
  OR OLD.created_at IS NOT NEW.created_at
BEGIN
    SELECT RAISE(ABORT, 'plan step definitions are immutable');
END;

CREATE TRIGGER steps_no_delete
BEFORE DELETE ON steps
BEGIN
    SELECT RAISE(ABORT, 'plan steps are immutable');
END;

CREATE TRIGGER step_dependencies_no_update
BEFORE UPDATE ON step_dependencies
BEGIN
    SELECT RAISE(ABORT, 'plan dependencies are immutable');
END;

CREATE TRIGGER step_dependencies_no_delete
BEFORE DELETE ON step_dependencies
BEGIN
    SELECT RAISE(ABORT, 'plan dependencies are immutable');
END;

CREATE TRIGGER schema_migrations_no_update
BEFORE UPDATE ON schema_migrations
BEGIN
    SELECT RAISE(ABORT, 'migration history is append-only');
END;

CREATE TRIGGER schema_migrations_no_delete
BEFORE DELETE ON schema_migrations
BEGIN
    SELECT RAISE(ABORT, 'migration history is append-only');
END;
