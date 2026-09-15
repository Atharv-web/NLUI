CREATE TABLE policy_decisions (
    decision_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    step_id TEXT NOT NULL REFERENCES steps(step_id),
    plan_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL,
    policy_version TEXT NOT NULL,
    risk TEXT NOT NULL CHECK(risk IN ('R0', 'R1', 'R2', 'R3', 'R4')),
    disposition TEXT NOT NULL CHECK(disposition IN ('allow', 'require_approval', 'deny')),
    reasons_json TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    normalized_arguments_hash TEXT NOT NULL CHECK(length(normalized_arguments_hash) = 64),
    exact_target_hash TEXT NOT NULL CHECK(length(exact_target_hash) = 64),
    scope_hash TEXT NOT NULL CHECK(length(scope_hash) = 64),
    capability_constraints_json TEXT NOT NULL,
    evaluated_at TEXT NOT NULL,
    FOREIGN KEY(plan_id, plan_version) REFERENCES plans(plan_id, version)
) STRICT;

CREATE INDEX policy_decisions_step_idx
ON policy_decisions(task_id, step_id, evaluated_at);

CREATE TRIGGER policy_decisions_no_update
BEFORE UPDATE ON policy_decisions
BEGIN
    SELECT RAISE(ABORT, 'policy decisions are immutable');
END;

CREATE TRIGGER policy_decisions_no_delete
BEFORE DELETE ON policy_decisions
BEGIN
    SELECT RAISE(ABORT, 'policy decisions are immutable');
END;

ALTER TABLE approvals ADD COLUMN policy_decision_id TEXT REFERENCES policy_decisions(decision_id);
ALTER TABLE approvals ADD COLUMN tool_name TEXT;
ALTER TABLE approvals ADD COLUMN normalized_arguments_hash TEXT
    CHECK(normalized_arguments_hash IS NULL OR length(normalized_arguments_hash) = 64);
ALTER TABLE approvals ADD COLUMN exact_target_hash TEXT
    CHECK(exact_target_hash IS NULL OR length(exact_target_hash) = 64);
ALTER TABLE approvals ADD COLUMN revoked_at TEXT;
ALTER TABLE approvals ADD COLUMN decision_channel TEXT;

CREATE INDEX approvals_scope_idx
ON approvals(task_id, step_id, scope_hash, decision, expires_at);

CREATE TRIGGER approvals_scope_no_update
BEFORE UPDATE ON approvals
WHEN OLD.task_id IS NOT NEW.task_id
  OR OLD.step_id IS NOT NEW.step_id
  OR OLD.plan_id IS NOT NEW.plan_id
  OR OLD.plan_version IS NOT NEW.plan_version
  OR OLD.risk IS NOT NEW.risk
  OR OLD.reason IS NOT NEW.reason
  OR OLD.scope_hash IS NOT NEW.scope_hash
  OR OLD.channel IS NOT NEW.channel
  OR OLD.expires_at IS NOT NEW.expires_at
  OR OLD.created_at IS NOT NEW.created_at
  OR OLD.policy_decision_id IS NOT NEW.policy_decision_id
  OR OLD.tool_name IS NOT NEW.tool_name
  OR OLD.normalized_arguments_hash IS NOT NEW.normalized_arguments_hash
  OR OLD.exact_target_hash IS NOT NEW.exact_target_hash
BEGIN
    SELECT RAISE(ABORT, 'approval scope is immutable');
END;

CREATE TRIGGER approvals_no_delete
BEFORE DELETE ON approvals
BEGIN
    SELECT RAISE(ABORT, 'approvals are immutable');
END;

CREATE TABLE capability_grants (
    capability_grant_id TEXT PRIMARY KEY,
    policy_decision_id TEXT NOT NULL REFERENCES policy_decisions(decision_id),
    approval_id TEXT REFERENCES approvals(approval_id),
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    step_id TEXT NOT NULL REFERENCES steps(step_id),
    plan_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL,
    tool_name TEXT NOT NULL,
    normalized_arguments_hash TEXT NOT NULL CHECK(length(normalized_arguments_hash) = 64),
    exact_target_hash TEXT NOT NULL CHECK(length(exact_target_hash) = 64),
    scope_hash TEXT NOT NULL CHECK(length(scope_hash) = 64),
    risk TEXT NOT NULL CHECK(risk IN ('R0', 'R1', 'R2', 'R3')),
    constraints_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('issued', 'consumed', 'revoked', 'expired')),
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(plan_id, plan_version) REFERENCES plans(plan_id, version)
) STRICT;

CREATE INDEX capability_grants_scope_idx
ON capability_grants(task_id, step_id, status, expires_at);

CREATE TRIGGER capability_grants_scope_no_update
BEFORE UPDATE ON capability_grants
WHEN OLD.policy_decision_id IS NOT NEW.policy_decision_id
  OR OLD.approval_id IS NOT NEW.approval_id
  OR OLD.task_id IS NOT NEW.task_id
  OR OLD.step_id IS NOT NEW.step_id
  OR OLD.plan_id IS NOT NEW.plan_id
  OR OLD.plan_version IS NOT NEW.plan_version
  OR OLD.tool_name IS NOT NEW.tool_name
  OR OLD.normalized_arguments_hash IS NOT NEW.normalized_arguments_hash
  OR OLD.exact_target_hash IS NOT NEW.exact_target_hash
  OR OLD.scope_hash IS NOT NEW.scope_hash
  OR OLD.risk IS NOT NEW.risk
  OR OLD.constraints_json IS NOT NEW.constraints_json
  OR OLD.expires_at IS NOT NEW.expires_at
  OR OLD.created_at IS NOT NEW.created_at
BEGIN
    SELECT RAISE(ABORT, 'capability scope is immutable');
END;

CREATE TRIGGER capability_grants_no_delete
BEFORE DELETE ON capability_grants
BEGIN
    SELECT RAISE(ABORT, 'capability grants are immutable');
END;

ALTER TABLE tool_invocations ADD COLUMN policy_decision_id TEXT REFERENCES policy_decisions(decision_id);
ALTER TABLE tool_invocations ADD COLUMN capability_grant_id TEXT REFERENCES capability_grants(capability_grant_id);
ALTER TABLE tool_invocations ADD COLUMN approval_id TEXT REFERENCES approvals(approval_id);

CREATE TRIGGER tool_invocation_authorization_no_rebind
BEFORE UPDATE ON tool_invocations
WHEN OLD.policy_decision_id IS NOT NEW.policy_decision_id
  OR OLD.capability_grant_id IS NOT NEW.capability_grant_id
  OR OLD.approval_id IS NOT NEW.approval_id
BEGIN
    SELECT RAISE(ABORT, 'invocation authorization is immutable');
END;
