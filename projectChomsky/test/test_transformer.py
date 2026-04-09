"""
Tests for Module 3 — transformer.py
Style: pytest, one class per concern.
Targets Python source code only.
"""

import pytest
from src.transformer import (
    transform,
    transform_file,
    translate_token,
    fst_info,
    ACTION_REWRITE_CRED,
    ACTION_REMOVE_LEAK,
    ACTION_FLAG_IP,
    ACTION_PASSTHROUGH,
)
from src.detector import detect


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def run(code: str, filepath: str = 'test.py') -> object:
    """Run detect + transform on a code snippet."""
    findings = detect(code)
    return transform(findings, code, filepath)


# ---------------------------------------------------------------------------
# FST structure tests
# ---------------------------------------------------------------------------

class TestFSTStructure:
    def test_has_two_states(self):
        assert len(fst_info()['states']) == 2

    def test_start_state_is_q0(self):
        assert 'q0' in fst_info()['start_state']

    def test_final_state_is_q1(self):
        assert 'q1' in fst_info()['final_states']

    def test_input_alphabet_has_ten_tokens(self):
        assert len(fst_info()['input_alpha']) == 10

    def test_output_alphabet_has_six_actions(self):
        assert len(fst_info()['output_alpha']) == 6

    def test_eleven_transitions(self):
        # 10 token types + 1 extra for IPv4 non-determinism = 11
        assert fst_info()['transitions'] == 11


# ---------------------------------------------------------------------------
# translate_token — FST transduction
# ---------------------------------------------------------------------------

class TestTranslateToken:
    def test_hardcoded_cred_maps_to_rewrite(self):
        assert ACTION_REWRITE_CRED in translate_token('HARDCODED_CRED')

    def test_aws_key_maps_to_rewrite(self):
        assert ACTION_REWRITE_CRED in translate_token('AWS_KEY')

    def test_print_leak_maps_to_remove(self):
        assert ACTION_REMOVE_LEAK in translate_token('PRINT_LEAK')

    def test_env_ref_maps_to_passthrough(self):
        assert ACTION_PASSTHROUGH in translate_token('ENV_REF')

    def test_todo_maps_to_passthrough(self):
        assert ACTION_PASSTHROUGH in translate_token('TODO')

    def test_ipv4_is_nondeterministic(self):
        # IPv4 has two possible outputs — demonstrates non-determinism
        actions = translate_token('IPv4')
        assert len(actions) == 2
        assert ACTION_FLAG_IP in actions
        assert ACTION_PASSTHROUGH in actions

    def test_suspicious_url_maps_to_use_https(self):
        assert 'USE_HTTPS' in translate_token('SUSPICIOUS_URL')

    def test_log_leak_maps_to_remove_leak(self):
        assert ACTION_REMOVE_LEAK in translate_token('LOG_LEAK')

    def test_insecure_request_maps_to_enforce_ssl(self):
        assert 'ENFORCE_SSL' in translate_token('INSECURE_REQUEST')

    def test_dangerous_call_maps_to_passthrough(self):
        assert ACTION_PASSTHROUGH in translate_token('DANGEROUS_CALL')


# ---------------------------------------------------------------------------
# Python rewrites
# ---------------------------------------------------------------------------

class TestPythonRewrites:
    def test_password_rewritten_to_getenv(self):
        report = run('password = "admin123"\n')
        assert 'os.getenv("PASSWORD")' in report.transformed_source

    def test_api_key_rewritten_to_getenv(self):
        report = run('api_key = "AKIA1234567890ABCDEF"\n')
        assert 'os.getenv("API_KEY")' in report.transformed_source

    def test_secret_rewritten_to_getenv(self):
        report = run('secret = "mysecret"\n')
        assert 'os.getenv("SECRET")' in report.transformed_source

    def test_print_leak_removed(self):
        report = run('print(password)\n')
        assert '# [CHOMSKY] sensitive output removed' in report.transformed_source

    def test_print_api_key_removed(self):
        report = run('print(api_key)\n')
        assert '# [CHOMSKY] sensitive output removed' in report.transformed_source

    def test_ipv4_flagged(self):
        report = run('db_host = "192.168.1.100"\n')
        assert '<HOST_PLACEHOLDER>' in report.transformed_source

    def test_suspicious_url_rewrites_to_https(self):
        report = run('url = "http://internal-service.local/api"\n')
        assert 'https://internal-service.local/api' in report.transformed_source

    def test_log_leak_removed(self):
        report = run('logging.info(f"User pass is {password}")\n')
        assert '# [CHOMSKY] sensitive output removed' in report.transformed_source

    def test_insecure_request_enforced_ssl(self):
        report = run('requests.get("https://api.com", verify=False)\n')
        assert 'verify=True' in report.transformed_source

    def test_dangerous_call_passed_through_unchanged(self):
        report = run('eval(user_input)\n')
        assert 'eval(user_input)' in report.transformed_source
        assert report.has_changes is False

    def test_original_line_preserved_in_transformation(self):
        report = run('password = "admin123"\n')
        t = report.transformations[0]
        assert 'admin123' in t.original_line

    def test_transformation_records_line_number(self):
        report = run('\n\npassword = "admin123"\n')
        assert report.transformations[0].line_number == 3

    def test_has_changes_is_true_when_rewrites_applied(self):
        report = run('password = "admin123"\n')
        assert report.has_changes is True

    def test_has_changes_is_false_for_safe_code(self):
        report = run('import os\npassword = os.getenv("APP_PASSWORD")\n')
        assert report.has_changes is False


# ---------------------------------------------------------------------------
# TransformationReport fields
# ---------------------------------------------------------------------------

class TestTransformationReport:
    def test_report_has_language_python(self):
        report = run('password = "abc123"\n', 'app.py')
        assert report.language == 'python'

    def test_report_has_filepath(self):
        report = run('password = "x"\n', 'src/main.py')
        assert report.filepath == 'src/main.py'

    def test_report_transformations_list(self):
        report = run('password = "abc123"\nprint(password)\n', 'app.py')
        assert len(report.transformations) == 2

    def test_transformation_action_label_is_correct(self):
        report = run('password = "admin123"\n', 'app.py')
        assert report.transformations[0].action == ACTION_REWRITE_CRED

    def test_transformed_source_is_string(self):
        report = run('password = "abc123"\n', 'app.py')
        assert isinstance(report.transformed_source, str)

    def test_safe_code_transformed_source_equals_original(self):
        code = 'import os\npassword = os.getenv("APP_PASSWORD")\n'
        report = run(code, 'app.py')
        assert report.transformed_source == code


# ---------------------------------------------------------------------------
# Integration: full pipeline on sample files
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_insecure_python_file_has_changes(self):
        report = transform_file('samples/insecure/bad_app.py')
        assert report.has_changes is True

    def test_safe_python_file_has_no_changes(self):
        report = transform_file('samples/safe/good_app.py')
        assert report.has_changes is False

    def test_insecure_python_output_contains_getenv(self):
        report = transform_file('samples/insecure/bad_app.py')
        assert 'os.getenv(' in report.transformed_source

    def test_insecure_python_output_has_no_print_leak(self):
        report = transform_file('samples/insecure/bad_app.py')
        # All print(sensitive_var) lines should be replaced
        assert 'print(password)' not in report.transformed_source
        assert 'print(api_key)'  not in report.transformed_source
