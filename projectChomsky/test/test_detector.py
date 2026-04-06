"""
Tests for Module 1 — detector.py
"""

import pytest
from src.detector import detect, detect_file, summarize, token_sequence, Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def types(code: str) -> list:
    """Return pattern_type list for a code snippet."""
    return token_sequence(detect(code))


# ---------------------------------------------------------------------------
# Individual pattern tests
# ---------------------------------------------------------------------------

class TestAWSKey:
    def test_detects_aws_key_in_python(self):
        code = 'api_key = "AKIA1234567890ABCDEF"'
        assert 'HARDCODED_CRED' in types(code)

    def test_aws_key_exact_16_chars(self):
        findings = detect('key = "AKIA1234567890ABCDEF"')
        values = [f.value for f in findings]
        assert any('AKIA' in v for v in values)

    def test_aws_key_too_short_not_matched(self):
        # 15 chars after AKIA — should NOT match AWS_KEY group specifically
        findings = detect('AKIA123456789ABCD')  # only 15 chars
        aws = [f for f in findings if f.pattern_type == 'AWS_KEY']
        assert len(aws) == 0


class TestHardcodedCred:
    def test_python_password_string(self):
        assert 'HARDCODED_CRED' in types('password = "admin123"')

    def test_javascript_const_password(self):
        assert 'HARDCODED_CRED' in types('const password = "secret99";')

    def test_env_file_plain_value(self):
        assert 'HARDCODED_CRED' in types('DB_PASSWORD=admin123')

    def test_safe_getenv_not_flagged(self):
        assert 'HARDCODED_CRED' not in types('password = os.getenv("APP_PASSWORD")')

    def test_safe_process_env_not_flagged(self):
        assert 'HARDCODED_CRED' not in types('const password = process.env.APP_PASSWORD;')

    def test_safe_env_ref_not_flagged(self):
        assert 'HARDCODED_CRED' not in types('DB_PASSWORD=${SECURE_DB_PASSWORD}')

    def test_token_keyword(self):
        assert 'HARDCODED_CRED' in types('token = "abc123xyz"')

    def test_secret_keyword(self):
        assert 'HARDCODED_CRED' in types('secret = "mysecretvalue"')


class TestPrintLeak:
    def test_print_password_variable(self):
        assert 'PRINT_LEAK' in types('print(password)')

    def test_print_api_key_variable(self):
        assert 'PRINT_LEAK' in types('print(api_key)')

    def test_print_token_variable(self):
        assert 'PRINT_LEAK' in types('print(token)')

    def test_print_non_sensitive_not_flagged(self):
        assert 'PRINT_LEAK' not in types('print("hello world")')

    def test_print_username_not_flagged(self):
        assert 'PRINT_LEAK' not in types('print(username)')


class TestConsoleLeak:
    def test_console_log_apikey(self):
        assert 'CONSOLE_LEAK' in types('console.log(apiKey)')

    def test_console_log_password(self):
        assert 'CONSOLE_LEAK' in types('console.log(password)')

    def test_console_warn_token(self):
        assert 'CONSOLE_LEAK' in types('console.warn(token)')

    def test_console_log_safe_string_not_flagged(self):
        assert 'CONSOLE_LEAK' not in types('console.log("App started")')


class TestIPv4:
    def test_detects_private_ip(self):
        assert 'IPv4' in types('db_host = "192.168.1.100"')

    def test_detects_10_network(self):
        assert 'IPv4' in types('host = "10.0.0.1"')

    def test_invalid_ip_not_matched(self):
        assert 'IPv4' not in types('version = "999.999.999.999"')


class TestEnvRef:
    def test_os_getenv(self):
        assert 'ENV_REF' in types('x = os.getenv("SECRET")')

    def test_process_env(self):
        assert 'ENV_REF' in types('const x = process.env.SECRET_KEY;')

    def test_dollar_brace_ref(self):
        assert 'ENV_REF' in types('KEY=${MY_SECRET}')


class TestTodo:
    def test_python_todo_comment(self):
        assert 'TODO' in types('# TODO: remove hardcoded key')

    def test_js_todo_comment(self):
        assert 'TODO' in types('// TODO: migrate to env vars')

    def test_regular_comment_not_flagged(self):
        assert 'TODO' not in types('# this is a normal comment')


# ---------------------------------------------------------------------------
# Integration: full file scenarios
# ---------------------------------------------------------------------------

class TestFullScenarios:
    def test_insecure_python_produces_expected_tokens(self):
        code = (
            'password = "admin123"\n'
            'api_key = "AKIA1234567890ABCDEF"\n'
            'print(password)\n'
        )
        tokens = types(code)
        assert 'HARDCODED_CRED' in tokens
        assert 'PRINT_LEAK' in tokens

    def test_insecure_js_produces_expected_tokens(self):
        code = (
            'const apiKey = "AKIA1234567890ABCDEF";\n'
            'console.log(apiKey);\n'
            '// TODO: remove this\n'
        )
        tokens = types(code)
        assert 'HARDCODED_CRED' in tokens
        assert 'CONSOLE_LEAK' in tokens
        assert 'TODO' in tokens

    def test_safe_python_no_dangerous_tokens(self):
        code = (
            'import os\n'
            'password = os.getenv("APP_PASSWORD")\n'
            'api_key = os.getenv("API_KEY")\n'
        )
        tokens = types(code)
        assert 'HARDCODED_CRED' not in tokens
        assert 'PRINT_LEAK' not in tokens

    def test_safe_js_no_dangerous_tokens(self):
        code = (
            'const password = process.env.APP_PASSWORD;\n'
            'const apiKey = process.env.API_KEY;\n'
        )
        tokens = types(code)
        assert 'HARDCODED_CRED' not in tokens
        assert 'CONSOLE_LEAK' not in tokens

    def test_mixed_file_has_both_safe_and_insecure(self):
        code = (
            'const dbHost = process.env.DB_HOST;\n'   
            'const apiKey = "AKIA1234567890ABCDEF";\n' 
            'console.log(apiKey);\n'                   
        )
        tokens = types(code)
        assert 'ENV_REF' in tokens
        assert 'HARDCODED_CRED' in tokens
        assert 'CONSOLE_LEAK' in tokens


# ---------------------------------------------------------------------------
# summarize() and token_sequence() helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_summarize_counts_correctly(self):
        code = (
            'password = "abc123"\n'
            'secret = "xyz789"\n'
            'print(password)\n'
        )
        s = summarize(detect(code))
        assert s['HARDCODED_CRED'] == 2
        assert s['PRINT_LEAK'] == 1

    def test_token_sequence_order_preserved(self):
        code = (
            'password = "abc123"\n'
            'print(password)\n'
        )
        tokens = token_sequence(detect(code))
        assert tokens.index('HARDCODED_CRED') < tokens.index('PRINT_LEAK')

    def test_empty_file_returns_empty_list(self):
        assert detect('') == []
        assert detect('# just a comment\n') == []

    def test_finding_has_correct_line_number(self):
        code = '\n\npassword = "admin123"\n'
        findings = detect(code)
        assert findings[0].line == 3

    def test_finding_excerpt_contains_match_line(self):
        code = 'x = 1\npassword = "admin123"\ny = 2\n'
        findings = detect(code)
        cred = next(f for f in findings if f.pattern_type == 'HARDCODED_CRED')
        assert 'password' in cred.excerpt


# ---------------------------------------------------------------------------
# detect_file() — reads actual sample files
# ---------------------------------------------------------------------------

class TestDetectFile:
    def test_insecure_python_sample(self):
        findings = detect_file('samples/insecure/bad_app.py')
        tokens = token_sequence(findings)
        assert 'HARDCODED_CRED' in tokens
        assert 'PRINT_LEAK' in tokens

    def test_insecure_js_sample(self):
        findings = detect_file('samples/insecure/leaked_key.js')
        tokens = token_sequence(findings)
        assert 'HARDCODED_CRED' in tokens
        assert 'CONSOLE_LEAK' in tokens

    def test_safe_python_sample(self):
        findings = detect_file('samples/safe/good_app.py')
        tokens = token_sequence(findings)
        assert 'HARDCODED_CRED' not in tokens
        assert 'PRINT_LEAK' not in tokens

    def test_safe_js_sample(self):
        findings = detect_file('samples/safe/secure_fetch.js')
        tokens = token_sequence(findings)
        assert 'HARDCODED_CRED' not in tokens
        assert 'CONSOLE_LEAK' not in tokens