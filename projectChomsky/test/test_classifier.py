"""
Tests for Module 2 — classifier.py
Style: pytest, one class per concern.
Targets Python patterns only (no CONSOLE_LEAK).
"""

import pytest
from src.classifier import (
    classify,
    classify_findings,
    dfa_info,
    SAFE,
    NEEDS_REVIEW,
    SECURITY_VIOLATION,
)
from src.detector import detect_file

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def label(tokens: list) -> str:
    """Return just the label string for a token sequence."""
    return classify(tokens).label


# ---------------------------------------------------------------------------
# DFA structure tests
# ---------------------------------------------------------------------------

class TestDFAStructure:
    def test_is_deterministic(self):
        info = dfa_info()
        assert info['is_deterministic'] is True

    def test_has_correct_start_state(self):
        assert dfa_info()['start_state'] == 'q_start'

    def test_final_states_are_the_three_outcomes(self):
        finals = set(dfa_info()['final_states'])
        assert 'q_violation' in finals
        assert 'q_review'    in finals
        assert 'q_safe'      in finals

    def test_all_ten_tokens_in_alphabet(self):
        alpha = set(dfa_info()['alphabet'])
        for tok in ['HARDCODED_CRED', 'PRINT_LEAK',
                    'AWS_KEY', 'IPv4', 'ENV_REF', 'TODO',
                    'SUSPICIOUS_URL', 'LOG_LEAK', 'DANGEROUS_CALL', 'INSECURE_REQUEST']:
            assert tok in alpha

    def test_transition_count_is_correct(self):
        # 6 states × 10 tokens = 60 transitions (all defined)
        assert dfa_info()['transitions'] == 60


# ---------------------------------------------------------------------------
# SAFE classification
# ---------------------------------------------------------------------------

class TestSafe:
    def test_empty_sequence_is_safe(self):
        assert label([]) == SAFE

    def test_single_env_ref_is_safe(self):
        assert label(['ENV_REF']) == SAFE

    def test_multiple_env_refs_are_safe(self):
        assert label(['ENV_REF', 'ENV_REF', 'ENV_REF']) == SAFE

    def test_final_state_is_q_safe(self):
        result = classify(['ENV_REF'])
        assert result.final_state == 'q_safe'


# ---------------------------------------------------------------------------
# NEEDS_REVIEW classification
# ---------------------------------------------------------------------------

class TestNeedsReview:
    def test_print_leak_alone(self):
        assert label(['PRINT_LEAK']) == NEEDS_REVIEW

    def test_ipv4_alone(self):
        assert label(['IPv4']) == NEEDS_REVIEW

    def test_todo_alone(self):
        assert label(['TODO']) == NEEDS_REVIEW

    def test_suspicious_url_alone_is_review(self):
        assert label(['SUSPICIOUS_URL']) == NEEDS_REVIEW

    def test_log_leak_alone_is_review(self):
        assert label(['LOG_LEAK']) == NEEDS_REVIEW

    def test_cred_without_leak_is_needs_review(self):
        # Credential found but never leaked — still suspicious
        assert label(['HARDCODED_CRED', 'IPv4']) == NEEDS_REVIEW

    def test_cred_alone_is_needs_review(self):
        assert label(['HARDCODED_CRED']) == NEEDS_REVIEW

    def test_multiple_leaks_no_cred_stays_review(self):
        assert label(['PRINT_LEAK', 'TODO']) == NEEDS_REVIEW

    def test_env_ref_then_todo_is_needs_review(self):
        # Good practice followed by unfinished work → still suspicious
        assert label(['ENV_REF', 'TODO']) == NEEDS_REVIEW

    def test_suspicious_url_then_log_leak_is_review(self):
        # Neither SUSPICIOUS_URL nor LOG_LEAK alone is a credential,
        # so the DFA stays in q_review (suspicious but not confirmed).
        # A violation would require a prior HARDCODED_CRED or AWS_KEY.
        assert label(['SUSPICIOUS_URL', 'LOG_LEAK']) == NEEDS_REVIEW


# ---------------------------------------------------------------------------
# SECURITY_VIOLATION classification
# ---------------------------------------------------------------------------

class TestSecurityViolation:
    def test_cred_then_print(self):
        assert label(['HARDCODED_CRED', 'PRINT_LEAK']) == SECURITY_VIOLATION

    def test_aws_key_then_print(self):
        assert label(['AWS_KEY', 'PRINT_LEAK']) == SECURITY_VIOLATION

    def test_cred_then_log_leak(self):
        assert label(['HARDCODED_CRED', 'LOG_LEAK']) == SECURITY_VIOLATION

    def test_dangerous_call_alone_is_violation(self):
        # Immediately flags since it's eval/exec
        assert label(['DANGEROUS_CALL']) == SECURITY_VIOLATION

    def test_insecure_request_alone_is_violation(self):
        assert label(['INSECURE_REQUEST']) == SECURITY_VIOLATION

    def test_log_leak_then_insecure_request(self):
        assert label(['LOG_LEAK', 'INSECURE_REQUEST']) == SECURITY_VIOLATION

    def test_multiple_creds_then_leak(self):
        assert label(['HARDCODED_CRED', 'HARDCODED_CRED', 'PRINT_LEAK']) == SECURITY_VIOLATION

    def test_cred_ip_then_leak(self):
        # Noise between credential and leak does not prevent violation
        assert label(['HARDCODED_CRED', 'IPv4', 'PRINT_LEAK']) == SECURITY_VIOLATION

    def test_cred_todo_then_print(self):
        assert label(['HARDCODED_CRED', 'TODO', 'PRINT_LEAK']) == SECURITY_VIOLATION

    def test_violation_final_state_is_q_violation(self):
        result = classify(['HARDCODED_CRED', 'PRINT_LEAK'])
        assert result.final_state == 'q_violation'

    def test_tokens_after_violation_go_to_sink(self):
        # After violation, more tokens lead to q_sink (trap state)
        result = classify(['HARDCODED_CRED', 'PRINT_LEAK', 'ENV_REF', 'TODO'])
        assert result.final_state == 'q_sink'
        assert result.label == SECURITY_VIOLATION

    def test_bad_app_py_token_sequence(self):
        # Mirrors the actual output of detector on bad_app.py
        tokens = ['HARDCODED_CRED', 'HARDCODED_CRED', 'IPv4',
                  'PRINT_LEAK', 'PRINT_LEAK']
        assert label(tokens) == SECURITY_VIOLATION


# ---------------------------------------------------------------------------
# State transition logic
# ---------------------------------------------------------------------------

class TestStateTransitions:
    def test_env_ref_escalates_from_safe_to_review_on_todo(self):
        result = classify(['ENV_REF', 'TODO'])
        assert result.final_state == 'q_review'

    def test_review_escalates_to_cred_on_hardcoded(self):
        # PRINT_LEAK → q_review, then HARDCODED_CRED → q_cred
        result = classify(['PRINT_LEAK', 'HARDCODED_CRED'])
        assert result.final_state == 'q_cred'

    def test_review_then_cred_then_leak_is_violation(self):
        result = classify(['TODO', 'HARDCODED_CRED', 'PRINT_LEAK'])
        assert result.label == SECURITY_VIOLATION

    def test_q_cred_is_not_final_state(self):
        # q_cred is not in F — cred alone doesn't complete the DFA
        info = dfa_info()
        assert 'q_cred' not in info['final_states']

    def test_token_path_preserved_in_result(self):
        tokens = ['HARDCODED_CRED', 'PRINT_LEAK']
        result = classify(tokens)
        assert result.token_path == tokens


# ---------------------------------------------------------------------------
# ClassificationResult fields
# ---------------------------------------------------------------------------

class TestClassificationResult:
    def test_result_has_label(self):
        result = classify(['HARDCODED_CRED', 'PRINT_LEAK'])
        assert result.label == SECURITY_VIOLATION

    def test_result_has_message(self):
        result = classify(['ENV_REF'])
        assert isinstance(result.message, str)
        assert len(result.message) > 0

    def test_result_has_token_path(self):
        tokens = ['ENV_REF', 'HARDCODED_CRED']
        result = classify(tokens)
        assert result.token_path == tokens

    def test_result_has_final_state(self):
        result = classify(['PRINT_LEAK'])
        assert result.final_state == 'q_review'


# ---------------------------------------------------------------------------
# Integration: full pipeline (detector → classifier)
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_insecure_python_file_is_violation(self):
        findings = detect_file('samples/insecure/bad_app.py')
        result = classify_findings(findings)
        assert result.label == SECURITY_VIOLATION

    def test_safe_python_file_is_safe(self):
        findings = detect_file('samples/safe/good_app.py')
        result = classify_findings(findings)
        assert result.label == SAFE

    def test_mixed_python_file_is_violation(self):
        findings = detect_file('samples/mixed/mixed_app.py')
        result = classify_findings(findings)
        assert result.label == SECURITY_VIOLATION