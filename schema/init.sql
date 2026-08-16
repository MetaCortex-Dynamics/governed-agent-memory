CREATE TABLE proposals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_proposal_id UUID NULL REFERENCES proposals(id),
    source_modify_decision_id UUID NULL,
    source_modify_decision_value STRING NULL
        CHECK (source_modify_decision_value IS NULL
               OR source_modify_decision_value = 'MODIFY'),
    agent_id STRING NOT NULL,
    session_id STRING NOT NULL,
    action_type STRING NOT NULL,
    action_type_key STRING NOT NULL,
    target STRING NOT NULL,
    target_key STRING NOT NULL,
    reasoning STRING NOT NULL,
    purpose STRING NOT NULL,
    parameters JSONB NOT NULL,
    impact_assessment JSONB NOT NULL DEFAULT '{}'::JSONB,
    predicted_outcome JSONB NOT NULL DEFAULT '{}'::JSONB,
    evidence JSONB NOT NULL DEFAULT '[]'::JSONB,
    dependencies JSONB NOT NULL DEFAULT '[]'::JSONB,
    embedding VECTOR(1536) NOT NULL,
    embedding_model STRING NOT NULL DEFAULT 'text-embedding-3-small',
    embedding_dimensions INT2 NOT NULL DEFAULT 1536,
    embedding_input_digest STRING(64) NOT NULL,
    action_digest STRING(64) NOT NULL,
    proposal_digest STRING(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT proposals_embedding_model_ck
        CHECK (embedding_model = 'text-embedding-3-small'),
    CONSTRAINT proposals_embedding_dimensions_ck
        CHECK (embedding_dimensions = 1536),
    CONSTRAINT proposals_evidence_array_ck
        CHECK (jsonb_typeof(evidence) = 'array'),
    CONSTRAINT proposals_parameters_object_ck
        CHECK (jsonb_typeof(parameters) = 'object'),
    CONSTRAINT proposals_dependencies_array_ck
        CHECK (jsonb_typeof(dependencies) = 'array'),
    CONSTRAINT proposals_digest_ck CHECK (
        length(embedding_input_digest) = 64
        AND length(action_digest) = 64
        AND length(proposal_digest) = 64
    ),
    CONSTRAINT proposals_lineage_shape_ck CHECK (
        (parent_proposal_id IS NULL
         AND source_modify_decision_id IS NULL
         AND source_modify_decision_value IS NULL)
        OR
        (parent_proposal_id IS NOT NULL
         AND source_modify_decision_id IS NOT NULL
         AND source_modify_decision_value = 'MODIFY')
    ),
    CONSTRAINT proposals_id_action_digest_uq UNIQUE (id, action_digest),
    CONSTRAINT proposals_action_binding_uq
        UNIQUE (id, action_type_key, target_key, action_digest),
    CONSTRAINT proposals_id_proposal_digest_uq UNIQUE (id, proposal_digest)
);

CREATE TABLE gate_evaluations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proposal_id UUID NOT NULL REFERENCES proposals(id),
    prior_evaluation_id UUID NULL,
    evaluator_version STRING NOT NULL,
    rule_config_digest STRING(64) NOT NULL,
    input_snapshot JSONB NOT NULL,
    input_snapshot_digest STRING(64) NOT NULL,
    profile_version STRING NULL UNIQUE,
    policy_snapshot JSONB NOT NULL,
    policy_digest STRING(64) NOT NULL,
    similarity_threshold DECIMAL(5,4) NOT NULL DEFAULT 0.8500,
    divergence_threshold DECIMAL(5,4) NOT NULL DEFAULT 0.5000,
    verdict STRING NULL CHECK (verdict IN ('YES','NO','MAYBE','IFF')),
    risk STRING NULL CHECK (risk IN ('LOW','MEDIUM','HIGH')),
    operator_trace JSONB NOT NULL DEFAULT '[]'::JSONB,
    evidence_gaps JSONB NOT NULL DEFAULT '[]'::JSONB,
    dependencies JSONB NOT NULL DEFAULT '[]'::JSONB,
    precedent_refs JSONB NOT NULL DEFAULT '[]'::JSONB,
    consequence_warning_refs JSONB NOT NULL DEFAULT '[]'::JSONB,
    changed_fact_rule_ids JSONB NOT NULL DEFAULT '[]'::JSONB,
    because_step_id STRING NULL,
    trace_digest STRING(64) NOT NULL,
    status STRING NOT NULL CHECK (status IN ('FINALIZED','BLOCKED')),
    blocked_reason STRING NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT gate_eval_thresholds_ck CHECK (
        similarity_threshold = 0.8500
        AND divergence_threshold = 0.5000
    ),
    CONSTRAINT gate_eval_arrays_ck CHECK (
        jsonb_typeof(input_snapshot) = 'object'
        AND jsonb_typeof(policy_snapshot) = 'object'
        AND jsonb_typeof(operator_trace) = 'array'
        AND jsonb_typeof(evidence_gaps) = 'array'
        AND jsonb_typeof(dependencies) = 'array'
        AND jsonb_typeof(precedent_refs) = 'array'
        AND jsonb_typeof(consequence_warning_refs) = 'array'
        AND jsonb_typeof(changed_fact_rule_ids) = 'array'
    ),
    CONSTRAINT gate_eval_state_ck CHECK (
        (status = 'FINALIZED'
         AND verdict IS NOT NULL
         AND risk IS NOT NULL
         AND because_step_id IS NOT NULL
         AND blocked_reason IS NULL)
        OR
        (status = 'BLOCKED'
         AND verdict IS NULL
         AND risk IS NULL
         AND because_step_id IS NULL
         AND blocked_reason IS NOT NULL)
    ),
    CONSTRAINT gate_eval_profile_state_ck CHECK (
        profile_version IS NULL OR status = 'FINALIZED'
    ),
    CONSTRAINT gate_eval_digest_ck CHECK (
        length(rule_config_digest) = 64
        AND length(input_snapshot_digest) = 64
        AND length(policy_digest) = 64
        AND length(trace_digest) = 64
        AND (profile_version IS NULL OR length(profile_version) > 0)
    ),
    CONSTRAINT gate_eval_replay_uq UNIQUE (
        proposal_id, evaluator_version, rule_config_digest,
        input_snapshot_digest, policy_digest
    ),
    CONSTRAINT gate_eval_id_trace_uq UNIQUE (id, trace_digest),
    CONSTRAINT gate_eval_id_proposal_uq UNIQUE (id, proposal_id),
    CONSTRAINT gate_eval_prior_fk FOREIGN KEY (prior_evaluation_id, proposal_id)
        REFERENCES gate_evaluations (id, proposal_id),
    CONSTRAINT gate_eval_prior_ck CHECK (
        prior_evaluation_id IS NOT NULL
        OR changed_fact_rule_ids = '[]'::JSONB
    ),
    CONSTRAINT gate_eval_bound_uq UNIQUE (id, proposal_id, trace_digest),
    CONSTRAINT gate_eval_decision_binding_uq
        UNIQUE (id, proposal_id, trace_digest, status)
);

CREATE TABLE decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proposal_id UUID NOT NULL REFERENCES proposals(id),
    evaluation_id UUID NOT NULL,
    evaluation_trace_digest STRING(64) NOT NULL,
    evaluation_status STRING NOT NULL DEFAULT 'FINALIZED'
        CHECK (evaluation_status = 'FINALIZED'),
    decision STRING NOT NULL CHECK (decision IN ('APPROVE','REJECT','MODIFY')),
    decided_by STRING NOT NULL,
    rationale STRING NOT NULL,
    conditions JSONB NOT NULL DEFAULT '{}'::JSONB,
    decision_digest STRING(64) NOT NULL,
    idempotency_key STRING NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT decisions_eval_fk FOREIGN KEY (
        evaluation_id, proposal_id, evaluation_trace_digest,
        evaluation_status
    ) REFERENCES gate_evaluations (
        id, proposal_id, trace_digest, status
    ),
    CONSTRAINT decisions_digest_ck CHECK (
        length(evaluation_trace_digest) = 64
        AND length(decision_digest) = 64
        AND jsonb_typeof(conditions) = 'object'
    ),
    CONSTRAINT decisions_one_per_proposal_uq UNIQUE (proposal_id),
    CONSTRAINT decisions_one_per_evaluation_uq UNIQUE (evaluation_id),
    CONSTRAINT decisions_id_value_uq UNIQUE (id, decision),
    CONSTRAINT decisions_lineage_uq UNIQUE (id, decision, proposal_id),
    CONSTRAINT decisions_bound_uq UNIQUE (
        id, proposal_id, evaluation_id, evaluation_trace_digest
    ),
    CONSTRAINT decisions_execution_binding_uq UNIQUE (
        id, decision, proposal_id, evaluation_id,
        evaluation_trace_digest, decision_digest
    )
);

ALTER TABLE proposals ADD CONSTRAINT proposals_modify_lineage_fk
    FOREIGN KEY (
        source_modify_decision_id,
        source_modify_decision_value,
        parent_proposal_id
    ) REFERENCES decisions (id, decision, proposal_id);

CREATE TABLE dependency_facts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dependency_key STRING NOT NULL,
    fact_version INT8 NOT NULL CHECK (fact_version > 0),
    prior_fact_id UUID NULL,
    prior_fact_version INT8 NULL,
    subject_ref STRING NOT NULL,
    predicate STRING NOT NULL,
    observed_value JSONB NULL,
    state STRING NOT NULL CHECK (state IN ('TRUE','FALSE','UNRESOLVED')),
    snapshot_digest STRING(64) NOT NULL,
    evidence_refs JSONB NOT NULL DEFAULT '[]'::JSONB,
    recorded_by STRING NOT NULL,
    fact_digest STRING(64) NOT NULL,
    idempotency_key STRING NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT dependency_facts_state_ck CHECK (
        (state = 'UNRESOLVED' AND observed_value IS NULL)
        OR (state IN ('TRUE','FALSE') AND observed_value IS NOT NULL)
    ),
    CONSTRAINT dependency_facts_shape_ck CHECK (
        jsonb_typeof(evidence_refs) = 'array'
        AND length(snapshot_digest) = 64
        AND length(fact_digest) = 64
    ),
    CONSTRAINT dependency_facts_lineage_ck CHECK (
        (fact_version = 1
         AND prior_fact_id IS NULL
         AND prior_fact_version IS NULL)
        OR
        (fact_version > 1
         AND prior_fact_id IS NOT NULL
         AND prior_fact_version = fact_version - 1)
    ),
    CONSTRAINT dependency_facts_key_version_uq
        UNIQUE (dependency_key, fact_version),
    CONSTRAINT dependency_facts_id_key_version_uq
        UNIQUE (id, dependency_key, fact_version),
    CONSTRAINT dependency_facts_prior_fk FOREIGN KEY (
        prior_fact_id, dependency_key, prior_fact_version
    ) REFERENCES dependency_facts (id, dependency_key, fact_version)
);

CREATE TABLE demo_kv (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proposal_id UUID NOT NULL,
    evaluation_id UUID NOT NULL,
    evaluation_trace_digest STRING(64) NOT NULL,
    decision_id UUID NOT NULL,
    decision_value STRING NOT NULL DEFAULT 'APPROVE'
        CHECK (decision_value = 'APPROVE'),
    decision_digest STRING(64) NOT NULL,
    action_type_key STRING NOT NULL DEFAULT 'set_demo_value'
        CHECK (action_type_key = 'set_demo_value'),
    target_key STRING NOT NULL,
    effect_key STRING NOT NULL,
    effect_version INT8 NOT NULL CHECK (effect_version > 0),
    prior_effect_id UUID NULL,
    prior_effect_version INT8 NULL,
    before_effect_digest STRING(64) NOT NULL,
    effect_value JSONB NOT NULL,
    effect_digest STRING(64) NOT NULL,
    action_digest STRING(64) NOT NULL,
    executor_id STRING NOT NULL,
    idempotency_key STRING NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT demo_kv_proposal_action_fk FOREIGN KEY (
        proposal_id, action_type_key, target_key, action_digest
    ) REFERENCES proposals (id, action_type_key, target_key, action_digest),
    CONSTRAINT demo_kv_approved_decision_fk FOREIGN KEY (
        decision_id, decision_value, proposal_id, evaluation_id,
        evaluation_trace_digest, decision_digest
    ) REFERENCES decisions (
        id, decision, proposal_id, evaluation_id,
        evaluation_trace_digest, decision_digest
    ),
    CONSTRAINT demo_kv_digest_ck CHECK (
        length(action_digest) = 64
        AND length(evaluation_trace_digest) = 64
        AND length(decision_digest) = 64
        AND length(before_effect_digest) = 64
        AND length(effect_digest) = 64
    ),
    CONSTRAINT demo_kv_scalar_value_ck CHECK (
        jsonb_typeof(effect_value) IN ('string','number','boolean','null')
        AND target_key = 'demo_kv:' || effect_key
        AND effect_key ~ '^[a-z][a-z0-9_-]{0,63}$'
    ),
    CONSTRAINT demo_kv_version_lineage_ck CHECK (
        (effect_version = 1
         AND prior_effect_id IS NULL
         AND prior_effect_version IS NULL)
        OR
        (effect_version > 1
         AND prior_effect_id IS NOT NULL
         AND prior_effect_version = effect_version - 1)
    ),
    CONSTRAINT demo_kv_key_version_uq UNIQUE (effect_key, effect_version),
    CONSTRAINT demo_kv_id_key_version_uq
        UNIQUE (id, effect_key, effect_version, effect_digest),
    CONSTRAINT demo_kv_prior_version_fk FOREIGN KEY (
        prior_effect_id, effect_key, prior_effect_version,
        before_effect_digest
    ) REFERENCES demo_kv (id, effect_key, effect_version, effect_digest),
    CONSTRAINT demo_kv_one_effect_per_decision_uq UNIQUE (decision_id),
    CONSTRAINT demo_kv_attempt_binding_uq UNIQUE (
        id, decision_id, proposal_id, evaluation_id,
        evaluation_trace_digest, decision_digest, action_digest, effect_key,
        target_key, effect_version, before_effect_digest, effect_digest,
        executor_id
    )
);

CREATE TABLE execution_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proposal_id UUID NOT NULL,
    evaluation_id UUID NOT NULL,
    evaluation_trace_digest STRING(64) NOT NULL,
    decision_id UUID NOT NULL,
    decision_value STRING NOT NULL DEFAULT 'APPROVE'
        CHECK (decision_value = 'APPROVE'),
    decision_digest STRING(64) NOT NULL,
    action_type_key STRING NOT NULL DEFAULT 'set_demo_value'
        CHECK (action_type_key = 'set_demo_value'),
    action_digest STRING(64) NOT NULL,
    target_key STRING NOT NULL,
    effect_key STRING NOT NULL,
    requested_value JSONB NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL,
    terminal_status STRING NOT NULL CHECK (terminal_status IN ('OBSERVED','ERROR')),
    demo_effect_id UUID NULL UNIQUE REFERENCES demo_kv(id),
    before_effect_digest STRING(64) NOT NULL,
    after_effect_digest STRING(64) NULL,
    observed_effect_version INT8 NULL,
    outcome JSONB NOT NULL,
    outcome_digest STRING(64) NOT NULL,
    attempt_digest STRING(64) NOT NULL,
    executor_id STRING NOT NULL,
    idempotency_key STRING NOT NULL UNIQUE,
    error_code STRING NULL,
    safe_message STRING NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT attempts_approved_decision_fk FOREIGN KEY (
        decision_id, decision_value, proposal_id, evaluation_id,
        evaluation_trace_digest, decision_digest
    ) REFERENCES decisions (
        id, decision, proposal_id, evaluation_id,
        evaluation_trace_digest, decision_digest
    ),
    CONSTRAINT attempts_proposal_action_fk FOREIGN KEY (
        proposal_id, action_type_key, target_key, action_digest
    ) REFERENCES proposals (id, action_type_key, target_key, action_digest),
    CONSTRAINT attempts_observed_effect_fk FOREIGN KEY (
        demo_effect_id, decision_id, proposal_id, evaluation_id,
        evaluation_trace_digest, decision_digest, action_digest, effect_key,
        target_key, observed_effect_version, before_effect_digest,
        after_effect_digest, executor_id
    ) REFERENCES demo_kv (
        id, decision_id, proposal_id, evaluation_id,
        evaluation_trace_digest, decision_digest, action_digest, effect_key,
        target_key, effect_version, before_effect_digest, effect_digest,
        executor_id
    ),
    CONSTRAINT attempts_terminal_ck CHECK (
        finished_at >= started_at
        AND (
            (terminal_status = 'OBSERVED'
             AND demo_effect_id IS NOT NULL
             AND after_effect_digest IS NOT NULL
             AND observed_effect_version IS NOT NULL
             AND observed_effect_version > 0
             AND error_code IS NULL
             AND safe_message IS NULL)
            OR
            (terminal_status = 'ERROR'
             AND demo_effect_id IS NULL
             AND after_effect_digest IS NULL
             AND observed_effect_version IS NULL
             AND error_code IS NOT NULL
             AND safe_message IS NOT NULL)
        )
    ),
    CONSTRAINT attempts_scalar_value_ck CHECK (
        jsonb_typeof(requested_value) IN ('string','number','boolean','null')
        AND target_key = 'demo_kv:' || effect_key
        AND effect_key ~ '^[a-z][a-z0-9_-]{0,63}$'
        AND jsonb_typeof(outcome) = 'object'
    ),
    CONSTRAINT attempts_digest_ck CHECK (
        length(evaluation_trace_digest) = 64
        AND length(decision_digest) = 64
        AND length(action_digest) = 64
        AND length(before_effect_digest) = 64
        AND (after_effect_digest IS NULL OR length(after_effect_digest) = 64)
        AND length(outcome_digest) = 64
        AND length(attempt_digest) = 64
    ),
    CONSTRAINT attempts_terminal_binding_uq
        UNIQUE (id, terminal_status, outcome_digest, attempt_digest),
    CONSTRAINT attempts_decision_binding_uq
        UNIQUE (id, decision_id, proposal_id, evaluation_id,
                evaluation_trace_digest, decision_digest, action_digest,
                target_key, before_effect_digest, executor_id),
    CONSTRAINT attempts_observation_binding_uq UNIQUE (
        id, terminal_status, after_effect_digest, observed_effect_version
    )
);

CREATE TABLE execution_receipts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attempt_id UUID NOT NULL,
    attempt_digest STRING(64) NOT NULL,
    proposal_id UUID NOT NULL,
    evaluation_id UUID NOT NULL,
    evaluation_trace_digest STRING(64) NOT NULL,
    decision_id UUID NOT NULL,
    decision_value STRING NOT NULL DEFAULT 'APPROVE'
        CHECK (decision_value = 'APPROVE'),
    decision_digest STRING(64) NOT NULL,
    action_digest STRING(64) NOT NULL,
    target_key STRING NOT NULL,
    attempt_terminal_status STRING NOT NULL
        CHECK (attempt_terminal_status IN ('OBSERVED','ERROR')),
    outcome_digest STRING(64) NOT NULL,
    before_effect_digest STRING(64) NOT NULL,
    after_effect_digest STRING(64) NULL,
    observed_effect_version INT8 NULL,
    executor_id STRING NOT NULL,
    idempotency_key STRING NOT NULL UNIQUE,
    verified BOOLEAN NOT NULL,
    receipt_digest STRING(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT receipts_attempt_terminal_fk FOREIGN KEY (
        attempt_id, attempt_terminal_status, outcome_digest, attempt_digest
    ) REFERENCES execution_attempts (
        id, terminal_status, outcome_digest, attempt_digest
    ),
    CONSTRAINT receipts_attempt_binding_fk FOREIGN KEY (
        attempt_id, decision_id, proposal_id, evaluation_id,
        evaluation_trace_digest, decision_digest, action_digest,
        target_key, before_effect_digest, executor_id
    ) REFERENCES execution_attempts (
        id, decision_id, proposal_id, evaluation_id,
        evaluation_trace_digest, decision_digest, action_digest,
        target_key, before_effect_digest, executor_id
    ),
    CONSTRAINT receipts_observation_binding_fk FOREIGN KEY (
        attempt_id, attempt_terminal_status, after_effect_digest,
        observed_effect_version
    ) REFERENCES execution_attempts (
        id, terminal_status, after_effect_digest, observed_effect_version
    ),
    CONSTRAINT receipts_approved_decision_fk FOREIGN KEY (
        decision_id, decision_value, proposal_id, evaluation_id,
        evaluation_trace_digest, decision_digest
    ) REFERENCES decisions (
        id, decision, proposal_id, evaluation_id,
        evaluation_trace_digest, decision_digest
    ),
    CONSTRAINT receipts_terminal_shape_ck CHECK (
        (attempt_terminal_status = 'OBSERVED'
         AND after_effect_digest IS NOT NULL
         AND observed_effect_version IS NOT NULL
         AND observed_effect_version > 0)
        OR
        (attempt_terminal_status = 'ERROR'
         AND after_effect_digest IS NULL
         AND observed_effect_version IS NULL)
    ),
    CONSTRAINT receipts_digest_ck CHECK (
        length(attempt_digest) = 64
        AND length(evaluation_trace_digest) = 64
        AND length(decision_digest) = 64
        AND length(action_digest) = 64
        AND length(outcome_digest) = 64
        AND length(before_effect_digest) = 64
        AND (after_effect_digest IS NULL OR length(after_effect_digest) = 64)
        AND length(receipt_digest) = 64
    ),
    CONSTRAINT receipts_verified_ck CHECK (verified),
    CONSTRAINT receipts_one_per_attempt_uq UNIQUE (attempt_id),
    CONSTRAINT receipts_id_proposal_uq UNIQUE (id, proposal_id),
    CONSTRAINT receipts_consequence_binding_uq UNIQUE (
        id, proposal_id, attempt_terminal_status, receipt_digest
    )
);

CREATE TABLE consequence_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proposal_id UUID NOT NULL REFERENCES proposals(id),
    receipt_id UUID NOT NULL,
    receipt_terminal_status STRING NOT NULL DEFAULT 'OBSERVED'
        CHECK (receipt_terminal_status = 'OBSERVED'),
    receipt_digest STRING(64) NOT NULL,
    observation_number INT4 NOT NULL CHECK (observation_number > 0),
    predicted_snapshot_digest STRING(64) NOT NULL,
    actual_snapshot_digest STRING(64) NOT NULL,
    comparison_version STRING NOT NULL,
    predicted_outcome JSONB NOT NULL,
    actual_outcome JSONB NOT NULL,
    leaf_report JSONB NOT NULL CHECK (jsonb_typeof(leaf_report) = 'array'),
    divergence_score DECIMAL(7,6) NOT NULL
        CHECK (divergence_score >= 0.0 AND divergence_score <= 1.0),
    divergence_threshold DECIMAL(7,6) NOT NULL DEFAULT 0.500000
        CHECK (divergence_threshold = 0.500000),
    divergence_summary STRING NOT NULL,
    reported_by STRING NOT NULL,
    report_digest STRING(64) NOT NULL CHECK (length(report_digest) = 64),
    idempotency_key STRING NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT consequences_receipt_fk FOREIGN KEY (
        receipt_id, proposal_id, receipt_terminal_status, receipt_digest
    ) REFERENCES execution_receipts (
        id, proposal_id, attempt_terminal_status, receipt_digest
    ),
    CONSTRAINT consequences_snapshot_digest_ck CHECK (
        length(predicted_snapshot_digest) = 64
        AND length(actual_snapshot_digest) = 64
        AND length(receipt_digest) = 64
    ),
    CONSTRAINT consequences_receipt_observation_uq
        UNIQUE (receipt_id, observation_number)
);

CREATE TABLE exclusions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_type STRING NOT NULL,
    action_type_key STRING NOT NULL,
    target STRING NOT NULL,
    target_key STRING NOT NULL,
    reason STRING NOT NULL,
    source_proposal_id UUID NOT NULL REFERENCES proposals(id),
    source_evaluation_id UUID NOT NULL,
    source_evaluation_trace_digest STRING(64) NOT NULL,
    source_decision_id UUID NOT NULL,
    source_decision_value STRING NOT NULL DEFAULT 'REJECT'
        CHECK (source_decision_value = 'REJECT'),
    source_decision_digest STRING(64) NOT NULL,
    exclusion_digest STRING(64) NOT NULL CHECK (length(exclusion_digest) = 64),
    idempotency_key STRING NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT exclusions_eval_fk FOREIGN KEY (
        source_evaluation_id, source_proposal_id,
        source_evaluation_trace_digest
    ) REFERENCES gate_evaluations (id, proposal_id, trace_digest),
    CONSTRAINT exclusions_decision_binding_fk FOREIGN KEY (
        source_decision_id, source_decision_value, source_proposal_id,
        source_evaluation_id, source_evaluation_trace_digest,
        source_decision_digest
    ) REFERENCES decisions (
        id, decision, proposal_id, evaluation_id,
        evaluation_trace_digest, decision_digest
    ),
    CONSTRAINT exclusions_digest_ck CHECK (
        length(source_evaluation_trace_digest) = 64
        AND length(source_decision_digest) = 64
        AND length(exclusion_digest) = 64
    ),
    CONSTRAINT exclusions_source_uq UNIQUE (
        action_type_key, target_key, source_decision_id
    )
);

CREATE TABLE tool_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool_name STRING NOT NULL CHECK (tool_name = 'ccloud'),
    tool_version STRING NOT NULL,
    redacted_command_argv JSONB NOT NULL
        CHECK (jsonb_typeof(redacted_command_argv) = 'array'),
    command_digest STRING(64) NOT NULL,
    help_digest STRING(64) NOT NULL,
    config_digest STRING(64) NOT NULL,
    cluster_name STRING NOT NULL DEFAULT 'governed-agent-memory'
        CHECK (cluster_name = 'governed-agent-memory'),
    cluster_name_digest STRING(64) NOT NULL,
    observed_cluster_id_digest STRING(64) NOT NULL,
    observed_version STRING NOT NULL,
    observed_state STRING NOT NULL,
    observed_plan STRING NOT NULL,
    observed_cloud STRING NOT NULL,
    normalized_redacted_output JSONB NOT NULL,
    redaction_manifest JSONB NOT NULL
        CHECK (jsonb_typeof(redaction_manifest) = 'array'),
    raw_output_digest STRING(64) NOT NULL,
    normalized_output_digest STRING(64) NOT NULL,
    exit_status INT4 NOT NULL CHECK (exit_status = 0),
    captured_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    captured_by STRING NOT NULL,
    evidence_digest STRING(64) NOT NULL,
    idempotency_key STRING NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT tool_evidence_digest_ck CHECK (
        length(command_digest) = 64
        AND length(help_digest) = 64
        AND length(config_digest) = 64
        AND length(cluster_name_digest) = 64
        AND length(observed_cluster_id_digest) = 64
        AND length(raw_output_digest) = 64
        AND length(normalized_output_digest) = 64
        AND length(evidence_digest) = 64
        AND jsonb_typeof(normalized_redacted_output) = 'object'
    ),
    CONSTRAINT tool_evidence_freshness_ck CHECK (expires_at > captured_at)
);

CREATE VECTOR INDEX idx_proposals_embedding
    ON proposals (embedding vector_cosine_ops);

CREATE INDEX idx_proposals_action_target
    ON proposals (action_type_key, target_key);
CREATE INDEX idx_gate_eval_proposal_created
    ON gate_evaluations (proposal_id, created_at DESC);
CREATE INDEX idx_decisions_proposal
    ON decisions (proposal_id);
CREATE INDEX idx_dependency_facts_latest
    ON dependency_facts (dependency_key, fact_version DESC);
CREATE INDEX idx_attempts_decision
    ON execution_attempts (decision_id, created_at DESC);
CREATE INDEX idx_receipts_proposal
    ON execution_receipts (proposal_id);
CREATE INDEX idx_consequences_receipt
    ON consequence_reports (receipt_id, observation_number);
CREATE INDEX idx_exclusions_action_target
    ON exclusions (action_type_key, target_key);
CREATE INDEX idx_tool_evidence_created
    ON tool_evidence (created_at DESC);
