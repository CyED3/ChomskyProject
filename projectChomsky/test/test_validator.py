"""
Tests for Module 4 — validator.py
Style: pytest, one class per concern.
"""

import pytest
from src.validator import validate, validate_file, grammar_info, SENSITIVE_KEYS


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def is_valid(source: str) -> bool:
    """Return just the is_valid bool for a config string."""
    return validate(source).is_valid


# ---------------------------------------------------------------------------
# Grammar structure tests
# ---------------------------------------------------------------------------

class TestGrammarStructure:
    def test_metamodel_loads(self):
        from src.validator import _META
        assert _META is not None

    def test_grammar_info_returns_dict(self):
        info = grammar_info()
        assert isinstance(info, dict)

    def test_has_non_terminals(self):
        nts = grammar_info()['non_terminals']
        assert 'ConfigFile' in nts
        assert 'Section' in nts
        assert 'Entry' in nts

    def test_start_symbol(self):
        assert grammar_info()['start_symbol'] == 'ConfigFile'


# ---------------------------------------------------------------------------
# Valid syntax
# ---------------------------------------------------------------------------

class TestValidSyntax:
    def test_simple_section(self):
        source = 'server { host = "localhost"; }'
        assert is_valid(source)

    def test_multiple_sections(self):
        source = '''
        database {
            host = "localhost";
        }
        api {
            url = "https://example.com";
        }
        '''
        assert is_valid(source)

    def test_env_ref_value(self):
        source = 'db { password = ${DB_PASSWORD}; }'
        assert is_valid(source)

    def test_number_value(self):
        source = 'server { port = 8080; }'
        assert is_valid(source)

    def test_bool_value(self):
        source = 'app { debug = false; }'
        assert is_valid(source)


# ---------------------------------------------------------------------------
# Invalid syntax
# ---------------------------------------------------------------------------

class TestInvalidSyntax:
    def test_missing_closing_brace(self):
        source = 'server { host = "localhost"; '
        assert not is_valid(source)

    def test_missing_semicolon(self):
        source = 'server { host = "localhost" }'
        assert not is_valid(source)

    def test_missing_equals(self):
        source = 'server { host "localhost"; }'
        assert not is_valid(source)

    def test_empty_input(self):
        source = ''
        assert not is_valid(source)

    def test_assignment_outside_section(self):
        source = 'host = "localhost";'
        assert not is_valid(source)


# ---------------------------------------------------------------------------
# Sensitive key enforcement
# ---------------------------------------------------------------------------

class TestSensitiveKeyEnforcement:
    def test_password_with_env_ref_is_valid(self):
        source = 'db { password = ${DB_PASS}; }'
        assert is_valid(source)

    def test_password_with_string_is_invalid(self):
        source = 'db { password = "admin123"; }'
        assert not is_valid(source)

    def test_token_with_string_is_invalid(self):
        source = 'api { token = "my_secret_token"; }'
        assert not is_valid(source)

    def test_secret_with_env_ref_is_valid(self):
        source = 'app { secret = ${APP_SECRET}; }'
        assert is_valid(source)

    def test_api_key_with_string_is_invalid(self):
        source = 'service { api_key = "AKIA1234567890AB"; }'
        assert not is_valid(source)

    def test_regular_key_with_string_is_valid(self):
        # non-sensitive key can use string literal
        source = 'server { host = "localhost"; }'
        assert is_valid(source)


# ---------------------------------------------------------------------------
# Nested sections
# ---------------------------------------------------------------------------

class TestNestedSections:
    def test_one_level_nesting(self):
        source = '''
        app {
            database {
                host = "localhost";
            }
        }
        '''
        assert is_valid(source)

    def test_two_level_nesting(self):
        source = '''
        infra {
            cloud {
                aws {
                    region = "us_east_1";
                }
            }
        }
        '''
        assert is_valid(source)

    def test_three_level_nesting(self):
        source = '''
        root {
            level1 {
                level2 {
                    level3 {
                        key = "deep";
                    }
                }
            }
        }
        '''
        assert is_valid(source)

    def test_nested_sensitive_keys_valid(self):
        source = '''
        database {
            primary {
                password = ${PRIMARY_PASS};
            }
            replica {
                password = ${REPLICA_PASS};
            }
        }
        '''
        assert is_valid(source)


# ---------------------------------------------------------------------------
# ValidationResult fields
# ---------------------------------------------------------------------------

class TestValidationResult:
    def test_has_is_valid(self):
        result = validate('app { debug = true; }')
        assert hasattr(result, 'is_valid')

    def test_has_errors_list(self):
        result = validate('app { debug = true; }')
        assert isinstance(result.errors, list)

    def test_has_sections_found(self):
        result = validate('a { x = 1; } b { y = 2; }')
        assert result.sections_found == 2

    def test_has_message(self):
        result = validate('app { debug = true; }')
        assert isinstance(result.message, str)
        assert len(result.message) > 0


# ---------------------------------------------------------------------------
# Full pipeline — real sample files
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_valid_secure_config(self):
        result = validate_file('samples/configs/valid_secure.conf')
        assert result.is_valid
        assert result.sections_found == 2

    def test_invalid_insecure_config(self):
        result = validate_file('samples/configs/invalid_insecure.conf')
        assert not result.is_valid
        assert len(result.errors) == 2   # password + token

    def test_invalid_syntax_config(self):
        result = validate_file('samples/configs/invalid_syntax.conf')
        assert not result.is_valid

    def test_nested_valid_config(self):
        result = validate_file('samples/configs/nested_valid.conf')
        assert result.is_valid
        assert result.sections_found == 1  # one top-level section
