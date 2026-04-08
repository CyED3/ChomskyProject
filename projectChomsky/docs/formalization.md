# Formal Definitions — Chomsky Security Analyzer

This document contains the formal definitions of the automata and grammars
used in each module. These follow the notation from the course (CyED3).

---

## Module 1: Regular Expressions (Detector)

The detector defines 7 regular languages over the ASCII alphabet. Each one
is recognized by a named group in a single compiled regex.

### Alphabet

Sigma = printable ASCII characters

### Languages

Each pattern P_i defines a regular language L(P_i). The detector recognizes
their union:

```
L(detector) = L(AWS_KEY) U L(HARDCODED_CRED) U L(PRINT_LEAK)
            U L(CONSOLE_LEAK) U L(IPv4) U L(ENV_REF) U L(TODO)
```

Since regular languages are closed under union, the result is also regular
and can be expressed as a single regex via the `|` operator.

### Pattern definitions

| Pattern        | Regex (simplified)                            | Language                                        |
|----------------|-----------------------------------------------|-------------------------------------------------|
| AWS_KEY        | `AKIA[0-9A-Z]{16}`                            | { AKIA.w : w in [0-9A-Z]^16 }                  |
| HARDCODED_CRED | `(password\|...) = <literal>`                  | Sensitive key = plaintext value (not env ref)   |
| PRINT_LEAK     | `print(<sensitive_var>)`                       | Python print exposing a sensitive variable      |
| CONSOLE_LEAK   | `console.(log\|warn\|error)(<sensitive_var>)`  | JS console exposing a sensitive variable        |
| IPv4           | `(\d{1,3}\.){3}\d{1,3}` (with range check)    | Valid dotted-decimal IPv4 addresses             |
| ENV_REF        | `os.getenv(...) \| process.env.X \| ${X}`     | Safe environment variable references            |
| TODO           | `# TODO... \| // TODO...`                      | TODO comments in Python or JS                   |

### Output

The detector produces a list of `Finding` objects. The function `token_sequence()`
extracts the `pattern_type` labels as an ordered list of abstract tokens. This
is the input for Module 2.

---

## Module 2: DFA (Classifier)

### 5-tuple definition

```
M = (Q, Sigma, delta, q0, F)
```

**Q** (states):
```
Q = { q_start, q_cred, q_violation, q_review, q_safe, q_sink }
```

**Sigma** (input alphabet — abstract tokens from Module 1):
```
Sigma = { HARDCODED_CRED, PRINT_LEAK, CONSOLE_LEAK, AWS_KEY,
          IPv4, ENV_REF, TODO }
```

**q0** (initial state):
```
q0 = q_start
```

**F** (accepting states):
```
F = { q_violation, q_review, q_safe }
```

### Transition function delta

| Current state | HARDCODED_CRED | AWS_KEY  | PRINT_LEAK  | CONSOLE_LEAK | IPv4     | TODO     | ENV_REF  |
|---------------|----------------|----------|-------------|--------------|----------|----------|----------|
| q_start       | q_cred         | q_cred   | q_review    | q_review     | q_review | q_review | q_safe   |
| q_cred        | q_cred         | q_cred   | q_violation | q_violation  | q_cred   | q_cred   | q_cred   |
| q_review      | q_cred         | q_cred   | q_review    | q_review     | q_review | q_review | q_review |
| q_safe        | q_cred         | q_cred   | q_review    | q_review     | q_review | q_review | q_safe   |
| q_violation   | q_sink         | q_sink   | q_sink      | q_sink       | q_sink   | q_sink   | q_sink   |
| q_sink        | q_sink         | q_sink   | q_sink      | q_sink       | q_sink   | q_sink   | q_sink   |

### State-to-classification mapping

| Final state  | Classification     |
|--------------|--------------------|
| q_start      | SAFE               |
| q_safe       | SAFE               |
| q_review     | NEEDS_REVIEW       |
| q_cred       | NEEDS_REVIEW       |
| q_violation  | SECURITY_VIOLATION |
| q_sink       | SECURITY_VIOLATION |

### Key idea

The DFA captures the *combination* of events: a hardcoded credential by
itself is `NEEDS_REVIEW`, but if a leak follows (print/console.log) it
becomes `SECURITY_VIOLATION`. This cannot be determined by looking at
individual tokens in isolation — the DFA tracks the state across the
entire sequence.

### Implementation

Built with the `pyformlang` library. The DFA is constructed once at module
load time and reused for every call to `classify()`.

---

## Module 3: FST (Transformer)

### 7-tuple definition

```
T = (Q, Sigma, Delta, delta, q0, F, lambda)
```

**Q** (states):
```
Q = { q0, q1 }
```

**Sigma** (input alphabet — same tokens as the DFA):
```
Sigma = { HARDCODED_CRED, PRINT_LEAK, CONSOLE_LEAK, AWS_KEY,
          IPv4, ENV_REF, TODO }
```

**Delta** (output alphabet — action labels):
```
Delta = { REWRITE_CRED, REMOVE_LEAK, FLAG_IP, PASSTHROUGH }
```

**q0** (initial state):
```
q0 = q0
```

**F** (final states):
```
F = { q1 }
```

### Transition and output table

| From | Input          | To | Output         |
|------|----------------|----|----------------|
| q0   | HARDCODED_CRED | q1 | REWRITE_CRED   |
| q0   | AWS_KEY        | q1 | REWRITE_CRED   |
| q0   | PRINT_LEAK     | q1 | REMOVE_LEAK    |
| q0   | CONSOLE_LEAK   | q1 | REMOVE_LEAK    |
| q0   | IPv4           | q1 | FLAG_IP        |
| q0   | IPv4           | q1 | PASSTHROUGH    |
| q0   | ENV_REF        | q1 | PASSTHROUGH    |
| q0   | TODO           | q1 | PASSTHROUGH    |

### Non-determinism

IPv4 has two transitions from the same state with the same input but
different outputs (FLAG_IP and PASSTHROUGH). This makes the FST
**non-deterministic**, which is the key concept from the FST theory in
the course. In practice, we resolve this by picking the most restrictive
action (FLAG_IP has higher priority than PASSTHROUGH).

### Two-layer architecture

- **Layer 1 (FST)**: maps tokens to action labels (the formal transduction)
- **Layer 2 (regex rewrites)**: applies the action concretely to the source
  line, with language-specific rules for Python, JavaScript, and .env files

### Implementation

Built with `pyformlang.fst.FST`. The transducer is built once at module
load time.

---

## Module 4: CFG (Validator)

### 4-tuple definition

```
G = (V, T, P, S)
```

**V** (non-terminals):
```
V = { ConfigFile, Section, Entry, Assignment, Value,
      EnvRef, StringLiteral, NumberLiteral, BoolLiteral }
```

**T** (terminals):
```
T = { ID, STRING, INT, '{', '}', '=', ';', '${', 'true', 'false' }
```

**S** (start symbol):
```
S = ConfigFile
```

**P** (production rules):
```
ConfigFile  ->  Section+
Section     ->  ID '{' Entry+ '}'
Entry       ->  Assignment | Section
Assignment  ->  ID '=' Value ';'
Value       ->  EnvRef | StringLiteral | NumberLiteral | BoolLiteral
EnvRef      ->  '${' ID '}'
StringLiteral -> STRING
NumberLiteral -> INT
BoolLiteral   -> 'true' | 'false'
```

### Recursive production

The rule `Entry -> Assignment | Section` makes the grammar recursive because
a Section contains Entry+, and an Entry can be a Section. This means sections
can be nested to any depth:

```
database {
    connection {
        password = ${DB_PASSWORD};
    }
}
```

This nesting with matched braces cannot be recognized by any regular language
(by the pumping lemma), which is why we need a CFG here instead of regex.

### Two-phase validation

1. **Syntactic**: textX parses the input against the grammar. If the input
   does not match the productions, a syntax error is returned.
2. **Semantic**: after parsing, we walk the tree and check that sensitive
   keys (password, api_key, token, etc.) use `${ENV_VAR}` references
   instead of plaintext values.

### Implementation

The grammar is defined in `secure_config.tx` (textX format). The metamodel
is built once at module load time with `metamodel_from_file()`.
