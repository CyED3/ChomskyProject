# Chomsky: Code Hazard Observation via Modeling of Syntax and KeY-patterns

By: Juan David Calderón, Andres Lopez and Jaime Muñoz

Chomsky is a Code Repository Security Analyzer that processes source code and configuration files, detects security vulnerabilities, classifies their severity, and suggests automated transformations. It leverages Formal Language Theory across four distinct modules.

## Project Structure and Formal Models

The system corresponds directly to the theoretical progression of formal languages:

1. **Module 1 (Detector — Lexical):** Uses Regular Expressions to detect predefined insecure patterns (credentials, exposed IPs, debug leaks).
2. **Module 2 (Classifier — Behavioral):** Uses a Deterministic Finite Automaton (DFA) over the sequences of detected abstract tokens to establish file security posture (`SAFE`, `NEEDS_REVIEW`, `SECURITY_VIOLATION`).
3. **Module 3 (Transformer — Rewriting):** Uses a Finite State Transducer (FST) to rewrite insecure code into secure formats (e.g., swapping hardcoded credentials for OS environments variables).
4. **Module 4 (Validator — Structural):** Uses a Context-Free Grammar (CFG) to enforce syntactic and semantic correctness over nested and scope-based configuration formats, impossible to validate simply using regular methods.

## Prerequisites

- **Python 3.10+**
- Virtual environment support

### Dependencies

The project leverages `pyformlang` for Automata logic and `textx` for Context-Free Grammars. Install the required dependencies:

```bash
# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows, use `.venv\Scripts\activate`

# Install dependencies
pip install -r requirements.txt
```

## Usage

You can test individual files or full directory paths leveraging the CLI.

```bash
# Analyze a single Python file
python src/cli.py samples/insecure/bad_app.py

# Analyze a safe file
python src/cli.py samples/safe/good_app.py

# Recursively scan all files in a directory
python src/cli.py samples/ -r
```

## Running the Test Suite

The project includes an exhaustive unit-testing suite enforcing correct deterministic state transitions, regex captures, token assignments, and parsing constraints. Ensure `pytest` is installed.

```bash
pytest test/ -v
```

All 163 tests should pass cleanly.

## Documentation

Comprehensive design specs, formal system tuple definitions, and testing methodologies can be found in the `docs/` folder:

- `docs/formalization.md`: Mathematical definitions (5-tuples, 7-tuples) of the models.
- `docs/modules_design.md`: Pipeline design, module architectures, outputs, and APIs.
- `docs/literature.md`: Literature review matching Theoretical Language Constraints to Practical Software Security Analysis.

---
**Course:** Discrete Mathematics 3 (CyED3) 2026
**Term:** 2026-1
**IDE used:** Visual Studio Code / IntelliJ IDEA
