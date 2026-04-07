# Design Document — Chomsky Security Analyzer

## Module 1: Detection — Regular Expressions

---

### 1.1 Overview

The detection module is the entry point of the Chomsky pipeline. It treats every
source code file as a **string over a finite alphabet Σ** (printable ASCII characters)
and uses regular expressions to locate substrings that match known insecure patterns.

The output of this module is a structured list of **findings**, where each finding
carries a `pattern_type` label — an abstract token that represents the security
concern identified. This sequence of tokens becomes the input alphabet consumed
by the finite automaton in Module 2.

```
File (raw string)
      │
      ▼
  MASTER_PATTERN.finditer()
      │
      ▼
[Finding(pattern_type, value, line, excerpt), ...]
      │
      ▼
token_sequence() → ['HARDCODED_CRED', 'PRINT_LEAK', ...]
      │
      ▼
  → Module 2 (DFA Classifier)
```

---

### 1.2 Formal Definition

Each regular expression defines a **regular language** over Σ = ASCII.
The full detector recognizes the union of all individual languages:

```
L(detector) = L(AWS_KEY)
            ∪ L(HARDCODED_CRED)
            ∪ L(PRINT_LEAK)
            ∪ L(CONSOLE_LEAK)
            ∪ L(IPv4)
            ∪ L(ENV_REF)
            ∪ L(TODO)
```

This union is expressible as a single regular expression via the `|` operator,
which corresponds directly to the **union operation** on regular languages.
By Kleene's theorem, every regular expression defines a regular language
recognizable by a finite automaton.

In Python, the implementation uses **named capturing groups** `(?P<NAME>...)`,
which allows the engine to report *which* sub-language a match belongs to —
this is the mechanism that produces the abstract token labels.

---

### 1.3 Pattern Descriptions

#### P1 — `AWS_KEY`

Detects Amazon Web Services access key identifiers.

**Regular expression:**

```
AKIA[0-9A-Z]{16}
```

**Language recognized:**
Strings that begin with the literal prefix `AKIA` followed by exactly 16
characters drawn from the set `[0-9A-Z]`.

```
L(AWS_KEY) = { AKIA·w | w ∈ ([0-9] ∪ [A-Z])^16 }
```

**Example matches:**

| Input | Match? |
|-------|--------|
| `AKIA1234567890ABCDEF` | ✅ |
| `AKIA123456789ABCDE` | ❌ (only 15 chars) |
| `AKIB1234567890ABCDEF` | ❌ (wrong prefix) |

---

#### P2 — `HARDCODED_CRED`

Detects assignments of plaintext credential values to sensitive variable names.
Covers Python, JavaScript/TypeScript, and `.env` files.

**Regular expression (simplified notation):**

```
(password|passwd|pwd|secret|api_key|token|credential)
\s*=\s*
(?! os.getenv | process.env | ${ )
( "..." | '...' | bare_value )
```

**Language recognized:**
Strings of the form `<keyword> = <literal_value>` where:

- `<keyword>` ∈ { password, passwd, pwd, secret, api_key, token, credential }
- `<literal_value>` is a quoted string or bare word of length ≥ 2
- The right-hand side is **not** a safe environment variable reference

The **negative lookahead** `(?!os\.getenv|process\.env|\$\{)` is critical:
it excludes safe patterns like `password = os.getenv("APP_PASSWORD")` from
being flagged, avoiding false positives.

**Example matches:**

| Input | Match? | Reason |
|-------|--------|--------|
| `password = "admin123"` | ✅ | plaintext string |
| `const apiKey = "AKIA..."` | ✅ | JS plaintext |
| `DB_PASSWORD=admin123` | ✅ | .env bare value |
| `password = os.getenv("X")` | ❌ | safe: env ref |
| `const p = process.env.PASS` | ❌ | safe: env ref |

---

#### P3 — `PRINT_LEAK`

Detects Python `print()` calls that pass a sensitive variable directly as argument,
which would expose the secret value in stdout or logs.

**Regular expression:**

```
print\s*\(\s*
(password|api_key|token|secret|pwd|credential)\w*
\s*\)
```

**Language recognized:**
Strings of the form `print(<sensitive_var>)` where `<sensitive_var>` starts
with any of the sensitive keywords.

**Example matches:**

| Input | Match? |
|-------|--------|
| `print(password)` | ✅ |
| `print(api_key)` | ✅ |
| `print(token_value)` | ✅ |
| `print("hello")` | ❌ |
| `print(username)` | ❌ |

---

#### P4 — `CONSOLE_LEAK`

Detects JavaScript `console.log/warn/error/info()` calls that expose sensitive
variables. This is the JavaScript equivalent of `PRINT_LEAK`.

**Regular expression:**

```
console\s*\.\s*(log|warn|error|info)\s*\(\s*
(password|api_key|token|secret|pwd|credential)\w*
\s*\)
```

**Example matches:**

| Input | Match? |
|-------|--------|
| `console.log(apiKey)` | ✅ |
| `console.warn(password)` | ✅ |
| `console.log("App started")` | ❌ |

---

#### P5 — `IPv4`

Detects hardcoded IPv4 addresses. Exposing internal IP addresses in source code
can reveal infrastructure topology to attackers.

**Regular expression:**

```
\b( (25[0-5] | 2[0-4]\d | [01]?\d\d?) \. ){3}
   (25[0-5] | 2[0-4]\d | [01]?\d\d?) \b
```

**Language recognized:**
Strings that form a valid IPv4 address in dotted-decimal notation, where each
octet is a decimal integer in [0, 255]. The `\b` word boundaries prevent
partial matches inside longer strings.

**Example matches:**

| Input | Match? |
|-------|--------|
| `192.168.1.100` | ✅ |
| `10.0.0.1` | ✅ |
| `255.255.255.0` | ✅ |
| `999.999.999.999` | ❌ (out of range) |

---

#### P6 — `ENV_REF` *(safe pattern)*

Detects safe environment variable references. Unlike the other patterns,
`ENV_REF` marks a **secure practice**. It is used by the DFA in Module 2
to distinguish files that use proper secret management from those that do not.

**Regular expression (three alternatives):**

```
os\.(?:getenv|environ)\s*[\[(]["']?\w+["']?[\])]   # Python
| process\.env\.\w+                                 # JavaScript
| \$\{[A-Z_][A-Z0-9_]*\}                           # .env / shell
```

**Example matches:**

| Input | Match? |
|-------|--------|
| `os.getenv("APP_PASSWORD")` | ✅ |
| `os.environ["SECRET"]` | ✅ |
| `process.env.API_KEY` | ✅ |
| `${SECURE_DB_PASSWORD}` | ✅ |

---

#### P7 — `TODO`

Detects TODO comments in Python (`#`) and JavaScript (`//`) that may indicate
unfinished security remediation work.

**Regular expression:**

```
#\s*TODO[^\n]*   # Python comment
| //\s*TODO[^\n]* # JS/TS comment
```

**Example matches:**

| Input | Match? |
|-------|--------|
| `# TODO: remove hardcoded key` | ✅ |
| `// TODO: migrate to env vars` | ✅ |
| `# this is a normal comment` | ❌ |

---

### 1.4 MASTER_PATTERN — Union of All Languages

The seven patterns are combined into a single compiled regex via union:

```python
MASTER_PATTERN = re.compile(
    _AWS_KEY
    + '|' + _HARDCODED_CRED
    + '|' + _PRINT_LEAK
    + '|' + _CONSOLE_LEAK
    + '|' + _IPv4
    + '|' + _ENV_REF
    + '|' + _TODO,
    re.IGNORECASE | re.MULTILINE
)
```

The flags used:

- `re.IGNORECASE` — makes keyword matching case-insensitive (`Password`, `PASSWORD`, etc.)
- `re.MULTILINE` — makes `^` and `$` match line boundaries, enabling correct TODO detection

Since the groups are named and mutually exclusive in order, `match.lastgroup`
always returns the name of the first group that matched — this is the abstract
token label.

---

### 1.5 Module API

| Function | Input | Output | Description |
|----------|-------|--------|-------------|
| `detect(source, context_lines)` | `str` | `list[Finding]` | Scan a string, return all findings |
| `detect_file(filepath, context_lines)` | `str` | `list[Finding]` | Read file then call `detect()` |
| `summarize(findings)` | `list[Finding]` | `dict[str, int]` | Count findings by pattern type |
| `token_sequence(findings)` | `list[Finding]` | `list[str]` | Extract ordered token labels → input for Module 2 |

#### `Finding` dataclass

```python
@dataclass
class Finding:
    pattern_type: str   # abstract token label (e.g. "HARDCODED_CRED")
    value:        str   # raw matched text
    line:         int   # 1-based line number in the file
    excerpt:      str   # surrounding lines with line numbers
```

---

### 1.6 Connection to Module 2

The `token_sequence()` function is the bridge between Module 1 and Module 2.
It converts the raw list of `Finding` objects into a sequence of abstract symbols:

```
detect_file("bad_app.py")
    → [Finding(HARDCODED_CRED, ...), Finding(IPv4, ...), Finding(PRINT_LEAK, ...)]

token_sequence(findings)
    → ['HARDCODED_CRED', 'IPv4', 'PRINT_LEAK']
```

This sequence is then fed to the DFA in `classifier.py`, which recognizes
whether the combination of events constitutes a `Safe`, `Needs Review`,
or `Security Violation` classification.

---

### 1.7 Supported File Types

| Extension | Language | Patterns active |
|-----------|----------|----------------|
| `.py` | Python | All except CONSOLE_LEAK |
| `.js` / `.ts` | JavaScript / TypeScript | All except PRINT_LEAK |
| `.env` | Environment config | HARDCODED_CRED, ENV_REF |
| `.yml` / `.yaml` | YAML config | HARDCODED_CRED, ENV_REF |

---

### 1.8 Test Coverage

The test suite in `test/test_detector.py` covers 43 test cases organized as:

| Test class | Cases | What it verifies |
|------------|-------|-----------------|
| `TestAWSKey` | 3 | AWS key format and boundary conditions |
| `TestHardcodedCred` | 8 | Python, JS, .env; safe patterns excluded |
| `TestPrintLeak` | 5 | Sensitive vs non-sensitive variable names |
| `TestConsoleLeak` | 4 | JS console methods; safe strings excluded |
| `TestIPv4` | 3 | Valid IP, invalid range |
| `TestEnvRef` | 3 | Python, JS, .env safe references |
| `TestTodo` | 3 | Python and JS TODO comments |
| `TestFullScenarios` | 5 | Full file integration: insecure, safe, mixed |
| `TestHelpers` | 5 | summarize(), token_sequence(), edge cases |
| `TestDetectFile` | 4 | Real sample files from samples/ directory |

---

## Module 2: Classification — Finite Automaton (DFA)

---

### 2.1 Overview

The classification module receives the ordered sequence of abstract tokens
produced by Module 1 and determines the **security posture** of the file.
Instead of looking at raw characters, the DFA operates over a high-level
alphabet of security events, which allows it to reason about **combinations
of patterns** rather than individual matches.

```
token_sequence(['HARDCODED_CRED', 'IPv4', 'PRINT_LEAK'])
        │
        ▼
   DFA M = (Q, Σ, δ, q₀, F)
        │
        ▼
ClassificationResult(
    label       = 'SECURITY_VIOLATION',
    final_state = 'q_violation',
    message     = 'Hardcoded credential exposed via print()'
)
```

The key insight is that a `PRINT_LEAK` alone is less dangerous than
`HARDCODED_CRED` followed by `PRINT_LEAK`. The DFA captures this
**sequential dependency** — something a set of independent regex checks
could not do.

---

### 2.2 Formal Definition — 5-tuple

The classifier is a **Deterministic Finite Automaton** (DFA):

```
M = (Q, Σ, δ, q₀, F)
```

| Component | Value |
|-----------|-------|
| **Q** | { q_start, q_cred, q_violation, q_review, q_safe, q_sink } |
| **Σ** | { HARDCODED_CRED, PRINT_LEAK, CONSOLE_LEAK, AWS_KEY, IPv4, ENV_REF, TODO } |
| **δ** | Transition function — see Section 2.4 |
| **q₀** | q_start |
| **F** | { q_violation, q_review, q_safe } |

**Note:** q_start and q_cred are not final states. A file that ends at q_cred
(credential found but no leak confirmed) is mapped to NEEDS_REVIEW by the
output function — the DFA halts but no accepting state is reached, so the
classifier applies a default label.

---

### 2.3 State Descriptions

| State | Meaning |
|-------|---------|
| `q_start` | Initial state — no tokens seen yet |
| `q_cred` | A credential token was seen (`HARDCODED_CRED` or `AWS_KEY`) — waiting for a leak |
| `q_violation` | Confirmed violation — credential followed by a print/console leak |
| `q_review` | Suspicious but not confirmed — leaked output, exposed IP, or TODO without a credential |
| `q_safe` | Only safe environment variable references seen so far |
| `q_sink` | Absorbing trap — reached after q_violation, all further tokens stay here |

**q_sink** exists to make the DFA complete (every state must have a transition
for every symbol). After a violation is confirmed, additional tokens cannot
"undo" it.

---

### 2.4 Transition Table δ

| From state | Token | To state |
|------------|-------|----------|
| q_start | HARDCODED_CRED | q_cred |
| q_start | AWS_KEY | q_cred |
| q_start | PRINT_LEAK | q_review |
| q_start | CONSOLE_LEAK | q_review |
| q_start | IPv4 | q_review |
| q_start | TODO | q_review |
| q_start | ENV_REF | q_safe |
| q_cred | PRINT_LEAK | **q_violation** |
| q_cred | CONSOLE_LEAK | **q_violation** |
| q_cred | HARDCODED_CRED | q_cred |
| q_cred | AWS_KEY | q_cred |
| q_cred | IPv4 | q_cred |
| q_cred | TODO | q_cred |
| q_cred | ENV_REF | q_cred |
| q_review | HARDCODED_CRED | q_cred |
| q_review | AWS_KEY | q_cred |
| q_review | PRINT_LEAK | q_review |
| q_review | CONSOLE_LEAK | q_review |
| q_review | IPv4 | q_review |
| q_review | TODO | q_review |
| q_review | ENV_REF | q_review |
| q_safe | ENV_REF | q_safe |
| q_safe | HARDCODED_CRED | q_cred |
| q_safe | AWS_KEY | q_cred |
| q_safe | PRINT_LEAK | q_review |
| q_safe | CONSOLE_LEAK | q_review |
| q_safe | IPv4 | q_review |
| q_safe | TODO | q_review |
| q_violation | (any token) | q_sink |
| q_sink | (any token) | q_sink |

**Total transitions: 42** (6 states × 7 tokens = 42, fully defined DFA).

---

### 2.5 Transition Diagram

```
                    HARDCODED_CRED / AWS_KEY
                   ┌─────────────────────────┐
                   │                         ▼
           ENV_REF │    HARDCODED_CRED    ┌────────┐  PRINT_LEAK     ┌─────────────┐
  ┌─────────┐ ─────┤    AWS_KEY           │ q_cred │──────────────►  │ q_violation │
  │ q_start │      │    ──────────────►   └────────┘  CONSOLE_LEAK   └─────────────┘
  └─────────┘      │                                                        │
       │           ▼                                                  (any) │
       │      ┌────────┐   HARDCODED_CRED / AWS_KEY                         ▼
       │      │ q_safe │──────────────────────────────►  q_cred        ┌────────┐
       │      └────────┘                                                │ q_sink │
       │                                                                └────────┘
       │  PRINT_LEAK / CONSOLE_LEAK / IPv4 / TODO
       └──────────────────────────────────────────► ┌───────────────┐
                                                     │ q_review│
                                                     └───────────────┘
```

---

### 2.6 Classification Output Mapping

| Final state reached | Label | Description |
|--------------------|-------|-------------|
| q_safe | `SAFE` | Only secure env references found |
| q_review | `NEEDS_REVIEW` | Suspicious patterns, no confirmed leak |
| q_cred | `NEEDS_REVIEW` | Credential found, no leak yet |
| q_violation | `SECURITY_VIOLATION` | Confirmed credential leak |
| q_sink | `SECURITY_VIOLATION` | Post-violation trap |
| q_start | `SAFE` | Empty token sequence |

---

### 2.7 Why a DFA and Not Just Counting Tokens?

A simple counter would flag any file with both a `HARDCODED_CRED` token
and a `PRINT_LEAK` token, regardless of **order**. The DFA enforces
**temporal order**: the credential must appear *before* the leak for a
violation to be confirmed. This models the actual security risk — a
`print(api_key)` statement is only dangerous if `api_key` was hardcoded
somewhere earlier in the file.

Additionally, the DFA handles **escalation paths**: a file that starts with
only a `PRINT_LEAK` (→ q_review) can be escalated to q_cred if a
credential is found later, and then to q_violation if a second leak follows.

---

### 2.8 Module API

| Function | Input | Output | Description |
|----------|-------|--------|-------------|
| `classify(token_seq)` | `list[str]` | `ClassificationResult` | Run DFA on token sequence |
| `classify_findings(findings)` | `list[Finding]` | `ClassificationResult` | Convenience wrapper over `classify()` |
| `dfa_info()` | — | `dict` | Returns 5-tuple metadata for documentation |

#### `ClassificationResult` dataclass

```python
@dataclass
class ClassificationResult:
    label:       str    # SAFE | NEEDS_REVIEW | SECURITY_VIOLATION
    final_state: str    # name of the DFA state reached
    token_path:  list   # the token sequence that was processed
    message:     str    # human-readable explanation
```

---

### 2.9 Connection to Module 1 and Module 3

```
Module 1                Module 2                 Module 3
────────                ────────                 ────────
detect_file()     →     classify_findings()  →   transform()
  returns                 returns                  receives
  list[Finding]           ClassificationResult      list[Finding]
                          .label                    and rewrites
                                                    insecure lines
```

The `classify_findings()` function accepts the raw `list[Finding]` output
from Module 1 directly, extracting the token sequence internally.

---

### 2.10 Test Coverage

The test suite in `test/test_classifier.py` covers 43 test cases:

| Test class | Cases | What it verifies |
|------------|-------|-----------------|
| `TestDFAStructure` | 5 | Determinism, state count, alphabet, transition count |
| `TestSafe` | 4 | Empty input, ENV_REF sequences, final state |
| `TestNeedsReview` | 8 | Isolated leaks, IPv4, TODO, cred without leak |
| `TestSecurityViolation` | 11 | All violation paths, sink state, real file sequences |
| `TestStateTransitions` | 5 | Escalation paths, q_cred not in F, token path |
| `TestClassificationResult` | 4 | All dataclass fields present and correct |
| `TestFullPipeline` | 6 | detector + classifier on all 6 sample files |

## Module 3: Transformation — Finite State Transducer (FST)

---

### 3.1 Overview

The transformation module receives the list of findings from Module 1 and
produces a **refactored version** of the source file where insecure patterns
have been replaced with secure alternatives. It does this in two layers:

```
list[Finding]
      │
      ▼  Layer 1 — FST transduction
translate_token(token_type)
      │  token → action label
      ▼
ACTION_REWRITE_CRED | ACTION_REMOVE_LEAK | ACTION_FLAG_IP | ACTION_PASSTHROUGH
      │
      ▼  Layer 2 — language-specific regex rewriter
_py_rewrite_cred() / _js_rewrite_cred() / _env_rewrite_cred()
_py_remove_leak()  / _js_remove_leak()
_py_flag_ip()      / _js_flag_ip()
      │
      ▼
TransformationReport(transformed_source, transformations, has_changes)
```

**Layer 1 (FST)** is the formal model — it maps the input alphabet of
security tokens to an output alphabet of abstract refactoring actions.

**Layer 2 (regex)** is the concrete implementation — it applies each
action to the actual source line, producing human-readable output.

---

### 3.2 Formal Definition — 7-tuple

The transformer is a **Finite State Transducer** (FST):

```
T = (Q, Σ, Δ, δ, q₀, F, λ)
```

| Component | Value |
|-----------|-------|
| **Q** | { q0, q1 } |
| **Σ** (input alphabet) | { HARDCODED_CRED, PRINT_LEAK, CONSOLE_LEAK, AWS_KEY, IPv4, ENV_REF, TODO } |
| **Δ** (output alphabet) | { REWRITE_CRED, REMOVE_LEAK, FLAG_IP, PASSTHROUGH } |
| **δ** | Transition function — see Section 3.3 |
| **q₀** | q0 |
| **F** | { q1 } |
| **λ** | Output function — encoded in each transition's output list |

---

### 3.3 Transition Table and Non-Determinism

| Input token | Output action | Note |
|-------------|---------------|------|
| HARDCODED_CRED | REWRITE_CRED | deterministic |
| AWS_KEY | REWRITE_CRED | deterministic |
| PRINT_LEAK | REMOVE_LEAK | deterministic |
| CONSOLE_LEAK | REMOVE_LEAK | deterministic |
| IPv4 | FLAG_IP | non-deterministic (branch 1) |
| IPv4 | PASSTHROUGH | non-deterministic (branch 2) |
| ENV_REF | PASSTHROUGH | deterministic |
| TODO | PASSTHROUGH | deterministic |

**Total transitions: 8** (7 deterministic + 1 extra for IPv4 non-determinism).

The FST is **non-deterministic for IPv4** — reading this token produces
two possible output labels simultaneously. This directly demonstrates the
concept from the course notebook (Exercises 2 and 3: non-deterministic
branching where `translate()` returns multiple paths).

In the implementation, `translate_token()` returns all possible actions
as a list (mirroring `list(map(lambda x: ''.join(x), list(fst.translate(...))))`
from the notebook). The `_pick_action()` function then resolves
non-determinism by selecting the highest-priority action:

```
_ACTION_PRIORITY = [REWRITE_CRED, REMOVE_LEAK, FLAG_IP, PASSTHROUGH]
```

This priority order encodes the security principle: always prefer the
most security-relevant transformation over a passthrough.

---

### 3.4 Output Alphabet — Action Descriptions

| Action | Input example | Output example |
|--------|--------------|----------------|
| `REWRITE_CRED` (Python) | `password = "admin123"` | `password = os.getenv("PASSWORD")` |
| `REWRITE_CRED` (JS) | `const apiKey = "AKIA..."` | `const apiKey = process.env.API_KEY` |
| `REWRITE_CRED` (.env) | `DB_PASSWORD=admin123` | `DB_PASSWORD=${SECURE_DB_PASSWORD}` |
| `REMOVE_LEAK` (Python) | `print(password)` | `# [CHOMSKY] sensitive output removed` |
| `REMOVE_LEAK` (JS) | `console.log(apiKey);` | `// [CHOMSKY] sensitive output removed` |
| `FLAG_IP` | `db_host = "192.168.1.100"` | `db_host = "<HOST_PLACEHOLDER>"` |
| `PASSTHROUGH` | `password = os.getenv("X")` | *(unchanged)* |

---

### 3.5 Two-Layer Architecture Justification

A pure FST operating character-by-character could express simple
substitutions (like replacing `a` with `x` in Exercise 1 of the notebook),
but it cannot:

- Infer environment variable names from camelCase (`apiKey` → `API_KEY`)
- Handle language-specific syntax (`const` in JS vs plain assignment in Python)
- Preserve indentation across rewritten lines

The two-layer design solves this cleanly: the FST handles the
**formal classification** of what needs to change, while regex handles
the **language-aware rewriting**. This mirrors the separation of concerns
between formal language theory (what) and implementation (how).

---

### 3.6 Module API

| Function | Input | Output | Description |
|----------|-------|--------|-------------|
| `translate_token(token)` | `str` | `list[str]` | FST transduction — returns all action labels |
| `transform(findings, source, filepath)` | `list[Finding], str, str` | `TransformationReport` | Apply rewrites to source string |
| `transform_file(filepath)` | `str` | `TransformationReport` | Read file, detect, transform |
| `fst_info()` | — | `dict` | Returns 7-tuple metadata |

#### `TransformationReport` dataclass

```python
@dataclass
class TransformationReport:
    filepath:           str
    language:           str          # 'python' | 'javascript' | 'config'
    transformations:    list         # list[Transformation]
    has_changes:        bool
    transformed_source: str
```

#### `Transformation` dataclass

```python
@dataclass
class Transformation:
    original_line:    str
    transformed_line: str
    action:           str   # ACTION_REWRITE_CRED | ACTION_REMOVE_LEAK | ...
    token_type:       str   # input token that triggered this transformation
    line_number:      int
```

---

### 3.7 Connection to Modules 1, 2, and 4

```
Module 1          Module 2              Module 3              Module 4
────────          ────────              ────────              ────────
detect_file()  →  classify_findings() → transform_file()  →  validate()
list[Finding]     ClassificationResult  TransformationReport  ValidationResult
                  .label == VIOLATION   .transformed_source   checks CFG
```

Module 3 is invoked after Module 2 confirms a finding. Its output
(`transformed_source`) can optionally be fed into Module 4 to validate
that the refactored configuration now passes the secure grammar.

---

### 3.8 Test Coverage

The test suite in `tests/test_transformer.py` covers 48 test cases:

| Test class | Cases | What it verifies |
|------------|-------|-----------------|
| `TestFSTStructure` | 6 | States, alphabets, transition count |
| `TestTranslateToken` | 7 | All 7 tokens → correct action, IPv4 non-determinism |
| `TestPythonRewrites` | 10 | getenv rewrite, print removal, IPv4 flag, line number, has_changes |
| `TestJavaScriptRewrites` | 7 | process.env rewrite, camelCase conversion, console removal, safe vars |
| `TestConfigRewrites` | 3 | .env secure ref rewrite, already-safe passthrough |
| `TestTransformationReport` | 7 | All dataclass fields, language detection, filepath |
| `TestFullPipeline` | 8 | Real sample files — changes applied / not applied |

---
---

## Module 5: CLI — Command-Line Interface

---

### 5.1 Overview

The CLI module (`cli.py`) is the user-facing component that ties together all
four analysis modules into a single pipeline. It receives a file or directory
path, runs each module in sequence, and presents the results in a readable
format.

The general flow is:

```
User input (file path)
      |
      v
  find_files()          -- collect supported files (.py, .js, .env, ...)
      |
      v
  analyze_file()        -- for each file, run the full pipeline:
      |
      +-- detect()            Module 1: regex-based detection
      +-- classify()          Module 2: DFA classification
      +-- transform()         Module 3: FST transformation suggestions
      +-- validate()          Module 4: CFG validation
      |
      v
  print_report()        -- display the 5 sections per file
      |
      v
  Final Summary         -- aggregate stats across all files
```

---

### 5.2 Graceful Degradation

Since the project is being developed incrementally, some modules may not be
implemented yet. The CLI handles this with **conditional imports**:

```python
_HAS_CLASSIFIER = False
try:
    from classifier import classify
    _HAS_CLASSIFIER = True
except (ImportError, AttributeError):
    pass
```

When a module is not available, the CLI falls back to heuristic functions
that approximate the expected behavior:

| Module | Expected function | Fallback function         |
|--------|-------------------|---------------------------|
| 2      | `classify()`      | `_fallback_classify()`    |
| 3      | `transform()`     | `_fallback_transform()`   |
| 4      | `validate()`      | `_fallback_validate()`    |

This way, as each module is implemented and exports the expected function,
the CLI automatically picks it up without any changes needed.

---

### 5.3 Fallback Logic

#### `_fallback_classify(tokens) -> str`

Simulates the DFA classification based on the token sequence from Module 1:

- If the sequence contains a credential token (`HARDCODED_CRED` or `AWS_KEY`)
  **and** a leak token (`PRINT_LEAK` or `CONSOLE_LEAK`) -> `Security Violation`
- If it contains only credential or only leak tokens -> `Needs Review`
- If it contains only warning tokens (`IPv4`, `TODO`) -> `Needs Review`
- Otherwise -> `Safe`

#### `_fallback_transform(findings) -> list[dict]`

Generates a before/after suggestion for each dangerous finding:

| Finding type     | Suggested fix                                      |
|------------------|----------------------------------------------------|
| `HARDCODED_CRED` | Replace with `os.getenv("VAR_NAME")`               |
| `AWS_KEY`        | Replace with `os.getenv("AWS_ACCESS_KEY_ID")`      |
| `PRINT_LEAK`     | Replace with `# [REMOVED] Output sensible eliminado` |
| `CONSOLE_LEAK`   | Replace with `// [REMOVED] Output sensible eliminado` |
| `IPv4`           | Replace with `os.getenv("SERVER_HOST")`             |

#### `_fallback_validate(findings) -> dict`

Returns a simple pass/fail result:

- `PASS` if no dangerous findings are present
- `FAIL` with the list of violations otherwise

---

### 5.4 Report Sections

The CLI displays 5 sections per analyzed file:

**[1] Original Code** -- Shows the source code line by line. Lines where a
finding was detected are marked with `>>>` so the user can quickly spot them.

**[2] Detection (Module 1)** -- Lists each finding with its type, line number,
and matched value. Also shows a count summary per type and the token sequence
that would be fed into Module 2.

**[3] Classification (Module 2)** -- Shows the classification result: `Safe`,
`Needs Review`, or `Security Violation`. Indicates whether the real DFA or
the heuristic fallback was used.

**[4] Transformation Suggestions (Module 3)** -- For each dangerous finding,
shows the original line and a suggested replacement. Indicates whether the
real FST or the heuristic fallback was used.

**[5] Validation (Module 4)** -- Shows `PASS` or `FAIL` with a list of
specific violations. Indicates whether the real CFG or the heuristic fallback
was used.

After all files, a **Final Summary** shows aggregate counts.

---

### 5.5 Output Modes

| Flag       | Format   | Description                           |
|------------|----------|---------------------------------------|
| *(none)*   | Text     | Human-readable report with sections   |
| `--json`   | JSON     | Machine-readable output, one object per file |
| `-r`       | --       | Recursively scan directories          |

---

### 5.6 Public API

The CLI can also be used as a library from other Python code:

| Function                           | Description                                  |
|------------------------------------|----------------------------------------------|
| `analyze_file(filepath) -> dict`   | Run full pipeline on a file, return result   |
| `find_files(path, recursive) -> list` | Collect supported files from a path       |
| `print_report(result)`             | Print formatted report for one file          |
| `print_json(results)`              | Print JSON output for a list of results      |
