# Chomsky: Code Hazard Observation via Modeling of Syntax and KeY-patterns

By: Juan David Calderón, Andrés Felipe López and Jaime Muñoz

Chomsky is a **Code Repository Security Analyzer** that processes source code and configuration files, detects security vulnerabilities, classifies their severity, and suggests automated transformations. It leverages Formal Language Theory across four distinct modules — one for each relevant level of the Chomsky hierarchy.

## Project Structure and Formal Models

The system corresponds directly to the theoretical progression of formal languages:

1. **Module 1 — Detector (Lexical, Type 3):** Uses **Regular Expressions** to detect predefined insecure patterns (credentials, exposed IPs, debug leaks, suspicious URLs, dangerous calls, insecure HTTP requests).
2. **Module 2 — Classifier (Behavioral, Type 3):** Uses a **Deterministic Finite Automaton (DFA)** built with `pyformlang` over the sequences of detected abstract tokens to establish file security posture (`SAFE`, `NEEDS_REVIEW`, `SECURITY_VIOLATION`). The DFA enforces temporal ordering — e.g. a credential must precede a leak for the file to be flagged as a confirmed violation.
3. **Module 3 — Transformer (Rewriting):** Uses a **Finite State Transducer (FST)** (also built with `pyformlang`) to rewrite insecure code into secure formats — for instance, swapping hardcoded credentials for OS environment variables, or stripping debug prints that expose secrets.
4. **Module 4 — Validator (Structural, Type 2):** Uses a **Context-Free Grammar (CFG)** built with `textX` to enforce the syntactic and semantic correctness of nested, scope-based configuration files. The CFG is strictly necessary: nested matched braces cannot be validated by a regular language (proof via the Pumping Lemma in [`docs/grammar.md`](docs/grammar.md)).

## Prerequisites

- **Python 3.10+**
- Virtual environment support

### Dependencies

The project leverages `pyformlang` (Automata and FST logic) and `textX` (Context-Free Grammars).

```bash
# Create a virtual environment
python -m venv .venv
source .venv/bin/activate          # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

You can analyze individual files or entire directories from the CLI.

```bash
# Analyze a single Python file with hardcoded credentials
python src/cli.py samples/insecure/bad_app.py

# Analyze a safe file
python src/cli.py samples/safe/good_app.py

# Recursively scan a directory
python src/cli.py samples/ -r

# Validate a configuration file against the CFG
python src/cli.py samples/configs/valid_secure.conf
python src/cli.py samples/configs/invalid_insecure.conf

# Emit JSON output (useful for CI pipelines)
python src/cli.py samples/insecure/bad_app.py --json
```

### Sample files shipped with the project

- `samples/insecure/` — Python and JS files with hardcoded credentials, AWS keys, leaked secrets.
- `samples/safe/` — Clean files using environment variable references and best practices.
- `samples/configs/` — Configuration files exercising the CFG validator (valid, invalid syntax, nested, and insecure variants).

## Running the Test Suite

The project includes an exhaustive unit-testing suite enforcing correct deterministic state transitions, regex captures, token assignments, FST rewrites, and CFG parsing constraints.

```bash
python -m pytest test/ -v
```

All **163 tests** should pass cleanly across the four modules:

| Module | File | Tests |
|--------|------|-------|
| Detector (Regex) | `test/test_detector.py` | 48 |
| Classifier (DFA) | `test/test_classifier.py` | 43 |
| Transformer (FST) | `test/test_transformer.py` | 40 |
| Validator (CFG) | `test/test_validator.py` | 32 |

## Documentation

Comprehensive design specs, formal system tuple definitions, and testing methodologies live in the `docs/` folder:

- [`docs/formalization.md`](docs/formalization.md) — Mathematical definitions (5-tuples, 7-tuples, 4-tuples) of every model.
- [`docs/modules_design.md`](docs/modules_design.md) — Pipeline architecture, module APIs, and inter-module contracts.
- [`docs/grammar.md`](docs/grammar.md) — Full BNF of the Secure Configuration Language plus the formal proof (Pumping Lemma) that the language is **not** regular.
- [`docs/literature.md`](docs/literature.md) — Literature review matching theoretical language constraints to practical software security analysis.
- [`docs/test_cases.md`](docs/test_cases.md) — Documented test cases and expected outputs.
- [`docs/poster/`](docs/poster/) — Academic research poster.

## Repository

Source code and history: [github.com/CyED3/ChomskyProject](https://github.com/CyED3/ChomskyProject)

