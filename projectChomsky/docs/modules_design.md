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

The test suite in `tests/test_detector.py` covers 43 test cases organized as:

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
| **Q** | { q_start, q_cred, q_violation, q_needs_review, q_safe, q_sink } |
| **Σ** | { HARDCODED_CRED, PRINT_LEAK, CONSOLE_LEAK, AWS_KEY, IPv4, ENV_REF, TODO } |
| **δ** | Transition function — see Section 2.4 |
| **q₀** | q_start |
| **F** | { q_violation, q_needs_review, q_safe } |

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
| `q_needs_review` | Suspicious but not confirmed — leaked output, exposed IP, or TODO without a credential |
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
| q_start | PRINT_LEAK | q_needs_review |
| q_start | CONSOLE_LEAK | q_needs_review |
| q_start | IPv4 | q_needs_review |
| q_start | TODO | q_needs_review |
| q_start | ENV_REF | q_safe |
| q_cred | PRINT_LEAK | **q_violation** |
| q_cred | CONSOLE_LEAK | **q_violation** |
| q_cred | HARDCODED_CRED | q_cred |
| q_cred | AWS_KEY | q_cred |
| q_cred | IPv4 | q_cred |
| q_cred | TODO | q_cred |
| q_cred | ENV_REF | q_cred |
| q_needs_review | HARDCODED_CRED | q_cred |
| q_needs_review | AWS_KEY | q_cred |
| q_needs_review | PRINT_LEAK | q_needs_review |
| q_needs_review | CONSOLE_LEAK | q_needs_review |
| q_needs_review | IPv4 | q_needs_review |
| q_needs_review | TODO | q_needs_review |
| q_needs_review | ENV_REF | q_needs_review |
| q_safe | ENV_REF | q_safe |
| q_safe | HARDCODED_CRED | q_cred |
| q_safe | AWS_KEY | q_cred |
| q_safe | PRINT_LEAK | q_needs_review |
| q_safe | CONSOLE_LEAK | q_needs_review |
| q_safe | IPv4 | q_needs_review |
| q_safe | TODO | q_needs_review |
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
                                                     │ q_needs_review│
                                                     └───────────────┘
```

---

### 2.6 Classification Output Mapping

| Final state reached | Label | Description |
|--------------------|-------|-------------|
| q_safe | `SAFE` | Only secure env references found |
| q_needs_review | `NEEDS_REVIEW` | Suspicious patterns, no confirmed leak |
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
only a `PRINT_LEAK` (→ q_needs_review) can be escalated to q_cred if a
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

The test suite in `tests/test_classifier.py` covers 43 test cases:

| Test class | Cases | What it verifies |
|------------|-------|-----------------|
| `TestDFAStructure` | 5 | Determinism, state count, alphabet, transition count |
| `TestSafe` | 4 | Empty input, ENV_REF sequences, final state |
| `TestNeedsReview` | 8 | Isolated leaks, IPv4, TODO, cred without leak |
| `TestSecurityViolation` | 11 | All violation paths, sink state, real file sequences |
| `TestStateTransitions` | 5 | Escalation paths, q_cred not in F, token path |
| `TestClassificationResult` | 4 | All dataclass fields present and correct |
| `TestFullPipeline` | 6 | detector + classifier on all 6 sample files |
