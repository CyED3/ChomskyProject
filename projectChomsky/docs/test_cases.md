# Test Cases — Chomsky Security Analyzer

Summary of all test cases organized by module. All tests use pytest.

---

## Module 1: Detector (`test_detector.py`) — 43 tests

### TestAWSKey (3 tests)
| Test | Input | Expected |
|------|-------|----------|
| `test_detects_aws_key_in_python` | `AKIA1234567890ABCDEF` | Detected as AWS_KEY |
| `test_aws_key_exact_16_chars` | Key with exactly 16 chars after AKIA | Match |
| `test_aws_key_too_short_not_matched` | Key with 15 chars after AKIA | No match |

### TestHardcodedCred (8 tests)
| Test | Input | Expected |
|------|-------|----------|
| `test_python_password_string` | `password = "admin123"` | HARDCODED_CRED |
| `test_javascript_const_password` | `const password = "..."` | HARDCODED_CRED |
| `test_env_file_plain_value` | `DB_PASSWORD=admin123` | HARDCODED_CRED |
| `test_safe_getenv_not_flagged` | `password = os.getenv("X")` | No match (safe) |
| `test_safe_process_env_not_flagged` | `process.env.PASSWORD` | No match (safe) |
| `test_safe_env_ref_not_flagged` | `${PASSWORD}` | No match (safe) |
| `test_token_keyword` | `token = "abc123"` | HARDCODED_CRED |
| `test_secret_keyword` | `secret = "abc123"` | HARDCODED_CRED |

### TestPrintLeak (5 tests)
| Test | Input | Expected |
|------|-------|----------|
| `test_print_password_variable` | `print(password)` | PRINT_LEAK |
| `test_print_api_key_variable` | `print(api_key)` | PRINT_LEAK |
| `test_print_token_variable` | `print(token)` | PRINT_LEAK |
| `test_print_non_sensitive_not_flagged` | `print("hello")` | No match |
| `test_print_username_not_flagged` | `print(username)` | No match |

### TestConsoleLeak (4 tests)
| Test | Input | Expected |
|------|-------|----------|
| `test_console_log_apikey` | `console.log(apiKey)` | CONSOLE_LEAK |
| `test_console_log_password` | `console.log(password)` | CONSOLE_LEAK |
| `test_console_warn_token` | `console.warn(token)` | CONSOLE_LEAK |
| `test_console_log_safe_string_not_flagged` | `console.log("hello")` | No match |

### TestIPv4 (3 tests)
| Test | Input | Expected |
|------|-------|----------|
| `test_detects_private_ip` | `192.168.1.100` | IPv4 |
| `test_detects_10_network` | `10.0.0.1` | IPv4 |
| `test_invalid_ip_not_matched` | `999.999.999.999` | No match |

### TestEnvRef (3 tests)
| Test | Input | Expected |
|------|-------|----------|
| `test_os_getenv` | `os.getenv("VAR")` | ENV_REF |
| `test_process_env` | `process.env.VAR` | ENV_REF |
| `test_dollar_brace_ref` | `${VAR_NAME}` | ENV_REF |

### TestTodo (3 tests)
| Test | Input | Expected |
|------|-------|----------|
| `test_python_todo_comment` | `# TODO fix this` | TODO |
| `test_js_todo_comment` | `// TODO fix this` | TODO |
| `test_regular_comment_not_flagged` | `# normal comment` | No match |

### TestFullScenarios (5 tests)
Integration tests using multi-line code snippets that combine multiple
patterns. Verifies that insecure, safe, and mixed code produce the
correct token sequences.

### TestHelpers (5 tests)
Tests for `summarize()`, `token_sequence()`, empty input, line numbers,
and excerpt content.

### TestDetectFile (4 tests)
Tests using actual sample files from `samples/insecure/` and `samples/safe/`.

---

## Module 2: Classifier (`test_classifier.py`) — 38 tests

### TestDFAStructure (5 tests)
Verifies the DFA construction: determinism, start state, final states,
alphabet size (7 tokens), and transition count.

### TestSafe (4 tests)
| Test | Input tokens | Expected |
|------|-------------|----------|
| `test_empty_sequence_is_safe` | `[]` | SAFE |
| `test_single_env_ref_is_safe` | `[ENV_REF]` | SAFE |
| `test_multiple_env_refs_are_safe` | `[ENV_REF, ENV_REF]` | SAFE |
| `test_final_state_is_q_safe` | `[ENV_REF]` | final_state = q_safe |

### TestNeedsReview (8 tests)
Tests for: leak alone, console alone, IPv4 alone, TODO alone, credential
without leak, multiple leaks without credential, env_ref then TODO.

### TestSecurityViolation (11 tests)
Tests for: cred+print, cred+console, AWS+console, AWS+print, multiple
creds then leak, cred+IP+leak, violation goes to sink, and full pipeline
tests with actual sample files.

### TestStateTransitions (5 tests)
Verifies specific state transition paths: safe->review, review->cred,
review->cred->leak->violation, q_cred is not final, token path preserved.

### TestClassificationResult (4 tests)
Checks that results have all fields: label, message, token_path, final_state.

### TestFullPipeline (6 tests)
End-to-end tests using `detect_file()` + `classify_findings()` on the
actual sample files (insecure, safe, mixed).

---

## Module 3: Transformer (`test_transformer.py`) — 48 tests

### TestFSTStructure (6 tests)
Verifies: 2 states, start=q0, final=q1, 7 input symbols, 4 output
actions, 8 transitions (IPv4 has 2).

### TestTranslateToken (7 tests)
Tests the FST translation for each of the 7 token types. The IPv4 test
verifies non-determinism (returns both FLAG_IP and PASSTHROUGH).

### TestPythonRewrites (10 tests)
| Test | What it checks |
|------|----------------|
| `test_password_rewritten_to_getenv` | `password = "x"` -> `os.getenv(...)` |
| `test_api_key_rewritten_to_getenv` | `api_key = "x"` -> `os.getenv(...)` |
| `test_secret_rewritten_to_getenv` | `secret = "x"` -> `os.getenv(...)` |
| `test_print_leak_removed` | `print(password)` -> comment |
| `test_print_api_key_removed` | `print(api_key)` -> comment |
| `test_ipv4_flagged` | `192.168.1.1` -> `<HOST_PLACEHOLDER>` |
| `test_original_line_preserved` | Original line saved in Transformation |
| `test_transformation_records_line_number` | Correct line number |
| `test_has_changes_is_true` | has_changes=True when rewrites applied |
| `test_has_changes_is_false_for_safe_code` | has_changes=False for clean code |

### TestJavaScriptRewrites (7 tests)
Verifies JS-specific rewrites: `const apiKey` -> `process.env.API_KEY`,
camelCase to SCREAMING_SNAKE conversion, console removal, safe variables
not rewritten.

### TestConfigRewrites (3 tests)
Tests .env file rewrites: `DB_PASSWORD=admin` -> `DB_PASSWORD=${SECURE_DB_PASSWORD}`,
already-safe references not changed.

### TestTransformationReport (7 tests)
Checks report fields: language detection (python/javascript), filepath,
transformations list, action labels, transformed_source type.

### TestFullPipeline (8 tests)
End-to-end tests with actual sample files. Verifies that insecure files
have changes, safe files don't, and output contains expected patterns
(os.getenv, process.env, no print/console leaks).

---

## Module 4: Validator (`test_validator.py`) — 28 tests

### TestGrammarStructure (4 tests)
Verifies metamodel loads, grammar_info returns dict, non-terminals and
start symbol are correct.

### TestValidSyntax (5 tests)
Valid configs: simple section, multiple sections, env ref values, number
values, boolean values.

### TestInvalidSyntax (5 tests)
| Test | Input | Expected |
|------|-------|----------|
| `test_missing_closing_brace` | `db { x = 1;` | Syntax error |
| `test_missing_semicolon` | `db { x = 1 }` | Syntax error |
| `test_missing_equals` | `db { x 1; }` | Syntax error |
| `test_empty_input` | `""` | Invalid |
| `test_assignment_outside_section` | `x = 1;` | Syntax error |

### TestSensitiveKeyEnforcement (6 tests)
Tests the semantic check: password with env ref = valid, password with
string = invalid, token/secret/api_key with strings = invalid, regular
(non-sensitive) keys with strings = valid.

### TestNestedSections (4 tests)
Tests recursive nesting: 1 level, 2 levels, 3 levels deep, and nested
sections with sensitive keys validated correctly.

### TestValidationResult (4 tests)
Checks result fields: is_valid, errors list, sections_found, message.

### TestFullPipeline (4 tests)
End-to-end: valid secure config, invalid insecure config, invalid syntax,
nested valid config.

---

## Total test count

| Module | File | Tests |
|--------|------|-------|
| 1 - Detector | test_detector.py | 43 |
| 2 - Classifier | test_classifier.py | 38 |
| 3 - Transformer | test_transformer.py | 48 |
| 4 - Validator | test_validator.py | 28 |
| **Total** | | **157** |
