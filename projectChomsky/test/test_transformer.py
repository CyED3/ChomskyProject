"""
Tests for Module 3 — transformer.py
Style: pytest, one class per concern, mirrors previous test modules.
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

    def test_input_alphabet_has_seven_tokens(self):
        assert len(fst_info()['input_alpha']) == 7

    def test_output_alphabet_has_four_actions(self):
        assert len(fst_info()['output_alpha']) == 4

    def test_eight_transitions(self):
        # 7 token types + 1 extra for IPv4 non-determinism = 8
        assert fst_info()['transitions'] == 8


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

    def test_console_leak_maps_to_remove(self):
        assert ACTION_REMOVE_LEAK in translate_token('CONSOLE_LEAK')

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
# JavaScript rewrites
# ---------------------------------------------------------------------------

class TestJavaScriptRewrites:
    def test_js_apikey_rewritten_to_process_env(self):
        report = run('const apiKey = "AKIA1234567890ABCDEF";\n', 'app.js')
        assert 'process.env.API_KEY' in report.transformed_source

    def test_js_password_rewritten(self):
        report = run('const password = "supersecret99";\n', 'app.js')
        assert 'process.env.PASSWORD' in report.transformed_source

    def test_js_camelcase_converted_to_screaming_snake(self):
        report = run('const dbPassword = "pass123";\n', 'app.js')
        assert 'process.env.DB_PASSWORD' in report.transformed_source

    def test_js_console_log_removed(self):
        report = run('    console.log(apiKey);\n', 'app.js')
        assert '// [CHOMSKY] sensitive output removed' in report.transformed_source

    def test_js_console_warn_removed(self):
        report = run('    console.warn(token);\n', 'app.js')
        assert '// [CHOMSKY] sensitive output removed' in report.transformed_source

    def test_js_safe_variable_not_rewritten(self):
        code = 'const username = "john_doe";\n'
        report = run(code, 'app.js')
        assert report.has_changes is False

    def test_js_safe_process_env_not_changed(self):
        code = 'const apiKey = process.env.API_KEY;\n'
        report = run(code, 'app.js')
        assert report.has_changes is False


# ---------------------------------------------------------------------------
# Config / .env rewrites
# ---------------------------------------------------------------------------

class TestConfigRewrites:
    def test_env_password_rewritten_to_secure_ref(self):
        report = run('DB_PASSWORD=admin123\n', 'config.env')
        assert '${SECURE_DB_PASSWORD}' in report.transformed_source

    def test_env_api_key_rewritten(self):
        report = run('API_KEY=AKIA1234567890ABCDEF\n', 'config.env')
        assert '${SECURE_API_KEY}' in report.transformed_source

    def test_env_already_safe_not_changed(self):
        report = run('DB_PASSWORD=${SECURE_DB_PASSWORD}\n', 'config.env')
        assert report.has_changes is False


# ---------------------------------------------------------------------------
# TransformationReport fields
# ---------------------------------------------------------------------------

class TestTransformationReport:
    def test_report_has_language_python(self):
        report = run('password = "abc123"\n', 'app.py')
        assert report.language == 'python'

    def test_report_has_language_javascript(self):
        report = run('const password = "x";\n', 'app.js')
        assert report.language == 'javascript'

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

    def test_insecure_js_file_has_changes(self):
        report = transform_file('samples/insecure/leaked_key.js')
        assert report.has_changes is True

    def test_safe_python_file_has_no_changes(self):
        report = transform_file('samples/safe/good_app.py')
        assert report.has_changes is False

    def test_safe_js_file_has_no_changes(self):
        report = transform_file('samples/safe/secure_fetch.js')
        assert report.has_changes is False

    def test_insecure_python_output_contains_getenv(self):
        report = transform_file('samples/insecure/bad_app.py')
        assert 'os.getenv(' in report.transformed_source

    def test_insecure_python_output_has_no_print_leak(self):
        report = transform_file('samples/insecure/bad_app.py')
        # All print(sensitive_var) lines should be replaced
        assert 'print(password)' not in report.transformed_source
        assert 'print(api_key)'  not in report.transformed_source

    def test_insecure_js_output_contains_process_env(self):
        report = transform_file('samples/insecure/leaked_key.js')
        assert 'process.env.' in report.transformed_source

    def test_insecure_js_output_has_no_console_leak(self):
        report = transform_file('samples/insecure/leaked_key.js')
        assert 'console.log(apiKey)'  not in report.transformed_source
        assert 'console.log(password)' not in report.transformed_source
