"""
Tests for Module 1 — detector.py
Targets Python source code only.
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

    def test_python_const_password(self):
        assert 'HARDCODED_CRED' in types('password = "secret99"')

    def test_safe_getenv_not_flagged(self):
        assert 'HARDCODED_CRED' not in types('password = os.getenv("APP_PASSWORD")')

    def test_safe_environ_not_flagged(self):
        assert 'HARDCODED_CRED' not in types('password = os.environ["APP_PASSWORD"]')

    def test_token_keyword(self):
        assert 'HARDCODED_CRED' in types('token = "abc123xyz"')

    def test_secret_keyword(self):
        assert 'HARDCODED_CRED' in types('secret = "mysecretvalue"')

    def test_api_key_keyword(self):
        assert 'HARDCODED_CRED' in types('api_key = "myapikey123"')

    def test_credential_keyword(self):
        assert 'HARDCODED_CRED' in types('credential = "user:pass"')


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

    def test_os_environ(self):
        assert 'ENV_REF' in types('x = os.environ["SECRET_KEY"]')


class TestTodo:
    def test_python_todo_comment(self):
        assert 'TODO' in types('# TODO: remove hardcoded key')

    def test_todo_with_detail(self):
        assert 'TODO' in types('# TODO move password to env var')

    def test_regular_comment_not_flagged(self):
        assert 'TODO' not in types('# this is a normal comment')


class TestSuspiciousUrl:
    def test_detects_http_url(self):
        assert 'SUSPICIOUS_URL' in types('url = "http://internal-service.local/api"')

    def test_https_not_flagged(self):
        assert 'SUSPICIOUS_URL' not in types('url = "https://secure-api.com"')

class TestLogLeak:
    def test_logging_info_leak(self):
        assert 'LOG_LEAK' in types('logging.info(f"User pass is {password}")')

    def test_logging_error_leak(self):
        assert 'LOG_LEAK' in types('logging.error(api_key)')

    def test_logging_safe_not_flagged(self):
        assert 'LOG_LEAK' not in types('logging.info("Server started successfully")')

class TestDangerousCall:
    def test_eval_flagged(self):
        assert 'DANGEROUS_CALL' in types('eval(user_input)')

    def test_exec_flagged(self):
        assert 'DANGEROUS_CALL' in types('exec(code_string)')

    def test_pickle_loads_flagged(self):
        assert 'DANGEROUS_CALL' in types('pickle.loads(payload)')

class TestInsecureRequest:
    def test_verify_false_flagged(self):
        assert 'INSECURE_REQUEST' in types('requests.get("https://api.com", verify=False)')

    def test_verify_true_not_flagged(self):
        assert 'INSECURE_REQUEST' not in types('requests.get("https://api.com", verify=True)')

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

    def test_safe_python_no_dangerous_tokens(self):
        code = (
            'import os\n'
            'password = os.getenv("APP_PASSWORD")\n'
            'api_key = os.getenv("API_KEY")\n'
        )
        tokens = types(code)
        assert 'HARDCODED_CRED' not in tokens
        assert 'PRINT_LEAK' not in tokens

    def test_mixed_file_has_both_safe_and_insecure(self):
        code = (
            'import os\n'
            'db_host = os.getenv("DB_HOST")\n'
            'password = "admin123"\n'
            'print(password)\n'
        )
        tokens = types(code)
        assert 'ENV_REF' in tokens
        assert 'HARDCODED_CRED' in tokens
        assert 'PRINT_LEAK' in tokens

    def test_only_env_refs_are_safe(self):
        code = (
            'import os\n'
            'secret = os.getenv("SECRET")\n'
            'token = os.environ["TOKEN"]\n'
        )
        tokens = types(code)
        assert 'HARDCODED_CRED' not in tokens
        assert all(t == 'ENV_REF' for t in tokens)


    def test_dangerous_eval(self):
        code = "user_input = eval(request.data)"
        assert 'DANGEROUS_CALL' in types(code)

    def test_insecure_request_flagged(self):
        code = "requests.get('https://api.com', verify=False)"
        assert 'INSECURE_REQUEST' in types(code)


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

    def test_safe_python_sample(self):
        findings = detect_file('samples/safe/good_app.py')
        tokens = token_sequence(findings)
        assert 'HARDCODED_CRED' not in tokens
        assert 'PRINT_LEAK' not in tokens

    def test_mixed_python_sample(self):
        findings = detect_file('samples/mixed/mixed_app.py')
        tokens = token_sequence(findings)
        assert 'HARDCODED_CRED' in tokens