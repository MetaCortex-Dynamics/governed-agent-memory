CREATE ROLE IF NOT EXISTS gam_reader_role NOLOGIN;
CREATE ROLE IF NOT EXISTS gam_app_role NOLOGIN;
CREATE ROLE IF NOT EXISTS gam_decider_role NOLOGIN;
CREATE ROLE IF NOT EXISTS gam_executor_role NOLOGIN;

REVOKE CREATE ON SCHEMA public FROM public;
REVOKE ALL ON TABLE proposals, gate_evaluations, decisions, dependency_facts, demo_kv,
    execution_attempts, execution_receipts, consequence_reports, exclusions,
    tool_evidence
    FROM public;

GRANT USAGE ON SCHEMA public TO gam_reader_role, gam_app_role,
    gam_decider_role, gam_executor_role;

GRANT SELECT ON TABLE proposals, gate_evaluations, decisions, dependency_facts, demo_kv,
    execution_attempts, execution_receipts, consequence_reports, exclusions,
    tool_evidence
    TO gam_reader_role;

GRANT SELECT ON TABLE proposals, gate_evaluations, decisions, dependency_facts,
    execution_attempts, execution_receipts, consequence_reports, exclusions,
    tool_evidence
    TO gam_app_role;
GRANT INSERT ON TABLE proposals, gate_evaluations, dependency_facts, consequence_reports,
    tool_evidence TO gam_app_role;

GRANT SELECT ON TABLE proposals, gate_evaluations, decisions, dependency_facts, exclusions
    TO gam_decider_role;
GRANT INSERT ON TABLE decisions, exclusions TO gam_decider_role;

GRANT SELECT ON TABLE proposals, gate_evaluations, decisions, demo_kv,
    execution_attempts, execution_receipts TO gam_executor_role;
GRANT INSERT ON TABLE demo_kv, execution_attempts, execution_receipts
    TO gam_executor_role;
