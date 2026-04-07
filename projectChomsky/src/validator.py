"""
Module 4 — Validation (Context-Free Grammar)
=============================================
Uses textX to define a context-free grammar (CFG) for a secure
configuration language and validates configuration files against it.

Formal definition
-----------------
The CFG is a 4-tuple  G = (V, T, P, S)  where:

    V  = { ConfigFile, Section, Entry, Assignment, Value,
           EnvRef, StringLiteral, NumberLiteral, BoolLiteral }
    T  = { ID, STRING, INT, '{', '}', '=', ';', '${', 'true', 'false' }
    P  = production rules (see secure_config.tx)
    S  = ConfigFile       (start symbol)

Why context-free?
-----------------
The language requires matched nested braces: sections can contain
sections to arbitrary depth. This cannot be recognized by any finite
automaton (by the pumping lemma for regular languages), but is
naturally expressed by the recursive production:

    Entry ::= Assignment | Section
    Section ::= ID '{' Entry+ '}'
"""
from dataclasses import dataclass
from pathlib import Path


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

@dataclass
class ValidationError:
    message: str
    line: int
    column: int


@dataclass
class ValidationResult:
    is_valid: bool
    errors: list          # list[ValidationError]
    sections_found: int
    message: str


# ---------------------------------------------------------------------------
# Grammar loading
# ---------------------------------------------------------------------------

_GRAMMAR_PATH = Path(__file__).parent / 'secure_config.tx'


def _build_metamodel():
    """Load the textX grammar and return the metamodel (parser)."""
    from textx import metamodel_from_file
    return metamodel_from_file(str(_GRAMMAR_PATH))


_META = _build_metamodel()


# ---------------------------------------------------------------------------
# Sensitive keys — these MUST use ${ENV_VAR} references
# ---------------------------------------------------------------------------

SENSITIVE_KEYS = frozenset({
    'password', 'passwd', 'pwd', 'secret',
    'api_key', 'token', 'credential',
    'db_password', 'api_secret',
})


# ---------------------------------------------------------------------------
# Semantic check — walk the parsed model tree
# ---------------------------------------------------------------------------

def _check_section(section):
    """
    Check all entries in a section. If a key is sensitive,
    its value must be an EnvRef (e.g. ${DB_PASSWORD}).
    Recurses into nested sections.
    """
    errors = []
    for entry in section.entries:
        cls_name = entry.__class__.__name__
        if cls_name == 'Assignment':
            key_lower = entry.key.lower()
            if key_lower in SENSITIVE_KEYS:
                val_cls = entry.value.__class__.__name__
                if val_cls != 'EnvRef':
                    errors.append(ValidationError(
                        message=(
                            f"Sensitive key '{entry.key}' must use "
                            f"env var reference (${{...}}), "
                            f"got literal value instead"
                        ),
                        line=entry._tx_position,
                        column=0,
                    ))
        else:
            # nested section — recurse
            errors.extend(_check_section(entry))
    return errors


def _check_sensitive_keys(model):
    """Walk all top-level sections and check sensitive key usage."""
    errors = []
    for section in model.sections:
        errors.extend(_check_section(section))
    return errors


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate(source: str) -> ValidationResult:
    """
    Parse and validate a secure configuration string.

    Two-phase validation:
      1. Syntactic — textX parses the string against the CFG
      2. Semantic — sensitive keys must use ${ENV_VAR} references
    """
    from textx import TextXSyntaxError

    if not source or not source.strip():
        return ValidationResult(
            is_valid=False,
            errors=[ValidationError("Empty configuration", 1, 1)],
            sections_found=0,
            message="Configuration is empty",
        )

    # Phase 1: syntactic validation
    try:
        model = _META.model_from_str(source)
    except TextXSyntaxError as e:
        return ValidationResult(
            is_valid=False,
            errors=[ValidationError(str(e), e.line, e.col)],
            sections_found=0,
            message=f"Syntax error at line {e.line}, col {e.col}",
        )

    # Phase 2: semantic validation (sensitive keys)
    semantic_errors = _check_sensitive_keys(model)
    num_sections = len(model.sections)

    if semantic_errors:
        return ValidationResult(
            is_valid=False,
            errors=semantic_errors,
            sections_found=num_sections,
            message=f"Found {len(semantic_errors)} insecure key(s)",
        )

    return ValidationResult(
        is_valid=True,
        errors=[],
        sections_found=num_sections,
        message=f"Valid configuration with {num_sections} section(s)",
    )


def validate_file(filepath: str) -> ValidationResult:
    """Read a configuration file from disk and validate it."""
    path = Path(filepath)
    if not path.exists():
        return ValidationResult(
            is_valid=False,
            errors=[ValidationError(f"File not found: {filepath}", 0, 0)],
            sections_found=0,
            message=f"File not found: {filepath}",
        )
    source = path.read_text(encoding='utf-8')
    return validate(source)


def grammar_info() -> dict:
    """Return metadata about the CFG (4-tuple description)."""
    return {
        'type': 'Context-Free Grammar',
        'start_symbol': 'ConfigFile',
        'non_terminals': [
            'ConfigFile', 'Section', 'Entry', 'Assignment',
            'Value', 'EnvRef', 'StringLiteral', 'NumberLiteral',
            'BoolLiteral',
        ],
        'terminals': [
            'ID', 'STRING', 'INT', '{', '}', '=', ';',
            '${', 'true', 'false',
        ],
        'recursive_production': 'Entry ::= Assignment | Section',
        'grammar_file': str(_GRAMMAR_PATH),
    }
