"""
Module 3 — Transformation (Finite State Transducer)
====================================================
Uses a pyformlang FST to map sequences of abstract security tokens to
refactoring actions, then applies regex-based line rewrites to produce
safe output code.

Architecture — two-layer design
---------------------------------
Layer 1 (FST):  token sequence  →  action sequence
    The FST operates over the same abstract token alphabet as the DFA
    (Module 2).  Each input token is mapped to one of four action labels:

        REWRITE_CRED    — replace hardcoded value with env var reference
        REMOVE_LEAK     — comment out / suppress the leaking statement
        FLAG_IP         — replace hardcoded IP with a named placeholder
        PASSTHROUGH     — line is already safe, copy unchanged

    This is the formal transduction step (the FST 7-tuple).

Layer 2 (regex): action + original line  →  transformed line
    A set of language-specific regex substitutions implement each action
    concretely for Python and JavaScript.

Formal definition
-----------------
The FST is a 7-tuple  T = (Q, Σ, Δ, δ, q₀, F, λ)  where:

    Q  = { q0, q1 }
    Σ  = { HARDCODED_CRED, PRINT_LEAK, CONSOLE_LEAK, AWS_KEY,
           IPv4, ENV_REF, TODO }         ← input alphabet
    Δ  = { REWRITE_CRED, REMOVE_LEAK, FLAG_IP, PASSTHROUGH }  ← output alphabet
    δ  = transition function  (see _build_fst())
    q₀ = q0
    F  = { q1 }
    λ  = output function (encoded in each transition's output list)

Non-determinism note
--------------------
The FST is non-deterministic for IPv4 (two possible output labels) to
demonstrate the non-determinism concept from the course notebook.
All other token types are deterministic (one output per input token).
"""

import re
from dataclasses import dataclass, field
from pyformlang.fst import FST

from src.detector import Finding


# ---------------------------------------------------------------------------
# Action labels — the output alphabet Δ
# ---------------------------------------------------------------------------

ACTION_REWRITE_CRED = 'REWRITE_CRED'   # replace hardcoded value → env var
ACTION_REMOVE_LEAK  = 'REMOVE_LEAK'    # suppress print/console.log leak
ACTION_FLAG_IP      = 'FLAG_IP'        # replace IP → named placeholder
ACTION_PASSTHROUGH  = 'PASSTHROUGH'    # copy line unchanged (already safe)


# ---------------------------------------------------------------------------
# Transformation result
# ---------------------------------------------------------------------------

@dataclass
class Transformation:
    original_line:    str
    transformed_line: str
    action:           str    # one of the ACTION_* constants
    token_type:       str    # the input token that triggered this
    line_number:      int


@dataclass
class TransformationReport:
    filepath:        str
    language:        str                        # 'python' | 'javascript' | 'config'
    transformations: list = field(default_factory=list)
    has_changes:     bool = False
    transformed_source: str = ''


# ---------------------------------------------------------------------------
# FST construction — Layer 1
# ---------------------------------------------------------------------------

def _build_fst() -> FST:
    """
    Build the FST that maps input tokens to action labels.

    Transition table (non-deterministic for IPv4):

    (q0, HARDCODED_CRED) → (q1, REWRITE_CRED)
    (q0, AWS_KEY)        → (q1, REWRITE_CRED)
    (q0, PRINT_LEAK)     → (q1, REMOVE_LEAK)
    (q0, CONSOLE_LEAK)   → (q1, REMOVE_LEAK)
    (q0, IPv4)           → (q1, FLAG_IP)       ← branch 1
    (q0, IPv4)           → (q1, PASSTHROUGH)   ← branch 2 (non-det.)
    (q0, ENV_REF)        → (q1, PASSTHROUGH)
    (q0, TODO)           → (q1, PASSTHROUGH)

    Non-determinism for IPv4 demonstrates the FST concept: the transducer
    simultaneously considers both flagging and passing through an IP address.
    In the implementation, we always pick FLAG_IP (the first translation).
    """
    fst = FST()

    fst.add_transitions([
        # Credential tokens → rewrite to env var reference
        ('q0', 'HARDCODED_CRED', 'q1', [ACTION_REWRITE_CRED]),
        ('q0', 'AWS_KEY',        'q1', [ACTION_REWRITE_CRED]),

        # Leak tokens → suppress the leaking statement
        ('q0', 'PRINT_LEAK',   'q1', [ACTION_REMOVE_LEAK]),
        ('q0', 'CONSOLE_LEAK', 'q1', [ACTION_REMOVE_LEAK]),

        # IPv4 — non-deterministic: flag it OR pass it through
        # (demonstrates non-determinism from the course notebook)
        # FLAG_IP is listed first so translate_token()[0] always picks it
        ('q0', 'IPv4', 'q1', [ACTION_FLAG_IP]),
        ('q0', 'IPv4', 'q1', [ACTION_PASSTHROUGH]),

        # Safe tokens — pass through unchanged
        ('q0', 'ENV_REF', 'q1', [ACTION_PASSTHROUGH]),
        ('q0', 'TODO',    'q1', [ACTION_PASSTHROUGH]),
    ])

    fst.add_start_state('q0')
    fst.add_final_state('q1')

    return fst


# ---------------------------------------------------------------------------
# Singleton FST — built once
# ---------------------------------------------------------------------------

_FST = _build_fst()


def translate_token(token: str) -> list[str]:
    """
    Run the FST on a single token and return all possible action labels.

    For deterministic tokens returns a one-element list.
    For IPv4 (non-deterministic) returns both possible actions.

    Uses the pipeline from the course notebook:
        list(map(lambda x: ''.join(x), list(fst.translate([token]))))
    """
    raw = list(_FST.translate([token]))
    return list(map(lambda x: ''.join(x), raw))


# ---------------------------------------------------------------------------
# Layer 2 — language-specific line rewriters
# ---------------------------------------------------------------------------

# Sensitive keyword pattern (shared)
_SENSITIVE_KW = (
    r'(?:password|passwd|pwd|secret|api[_-]?key|token|credential)'
)

# ── Python rewrites ──────────────────────────────────────────────────────────

_PY_CRED_PATTERN = re.compile(
    r'(?P<indent>\s*)'
    r'(?P<varname>' + _SENSITIVE_KW + r'\w*)'
    r'\s*=\s*'
    r'(?!os\.(?:getenv|environ)|process\.env|\$\{)'
    r'(?:"[^"]*"|\'[^\']*\'|[^\s\'"${\n][^\s\n]*)',
    re.IGNORECASE
)

_PY_PRINT_PATTERN = re.compile(
    r'(?P<indent>\s*)'
    r'(print\s*\(.*?\))',
    re.IGNORECASE
)

_PY_IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)


def _py_rewrite_cred(line: str) -> str:
    """password = "admin123"  →  password = os.getenv("PASSWORD")"""
    def _rep(m: re.Match) -> str:
        env_name = m.group('varname').upper().replace('-', '_')
        return f'{m.group("indent")}{m.group("varname")} = os.getenv("{env_name}")'
    return _PY_CRED_PATTERN.sub(_rep, line)


def _py_remove_leak(line: str) -> str:
    """print(password)  →  # [CHOMSKY] sensitive output removed"""
    return _PY_PRINT_PATTERN.sub(
        lambda m: f'{m.group("indent")}# [CHOMSKY] sensitive output removed',
        line
    )


def _py_flag_ip(line: str) -> str:
    """192.168.1.100  →  <HOST_PLACEHOLDER>"""
    return _PY_IP_PATTERN.sub('<HOST_PLACEHOLDER>', line)


# ── JavaScript rewrites ──────────────────────────────────────────────────────

_JS_CRED_PATTERN = re.compile(
    r'(?P<indent>\s*)'
    r'(?:(?:const|let|var)\s+)?'
    r'(?P<varname>[a-zA-Z_$][\w$]*)'
    r'\s*=\s*'
    r'(?:"[^"]*"|'"'"'[^'"'"']*'"'"'|`[^`]*`)',
    re.IGNORECASE
)

_JS_SENSITIVE = re.compile(
    r'password|passwd|pwd|secret|api[_-]?key|token|credential',
    re.IGNORECASE
)


_JS_CONSOLE_PATTERN = re.compile(
    r'(?P<indent>\s*)'
    r'(console\s*\.\s*(?:log|warn|error|info)\s*\(.*?\)\s*;?)',
    re.IGNORECASE
)

_JS_IP_PATTERN = _PY_IP_PATTERN  # same regex


def _camel_to_screaming(name: str) -> str:
    """apiKey → API_KEY"""
    s = re.sub(r'([A-Z])', r'_\1', name).upper().lstrip('_')
    return s.replace('-', '_')


def _js_rewrite_cred(line: str) -> str:
    """const apiKey = "AKIA..."  →  const apiKey = process.env.API_KEY"""
    def _rep(m: re.Match) -> str:
        varname = m.group('varname')
        if not _JS_SENSITIVE.search(varname):
            return m.group(0)  # not a sensitive variable, leave unchanged
        env_name = _camel_to_screaming(varname)
        return f'{m.group("indent")}const {varname} = process.env.{env_name}'
    return _JS_CRED_PATTERN.sub(_rep, line)


def _js_remove_leak(line: str) -> str:
    """console.log(apiKey);  →  // [CHOMSKY] sensitive output removed"""
    return _JS_CONSOLE_PATTERN.sub(
        lambda m: f'{m.group("indent")}// [CHOMSKY] sensitive output removed',
        line
    )


def _js_flag_ip(line: str) -> str:
    return _JS_IP_PATTERN.sub('<HOST_PLACEHOLDER>', line)


# ── .env rewrites ────────────────────────────────────────────────────────────

_ENV_CRED_PATTERN = re.compile(
    r'^(?P<key>[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|PWD|SECRET|KEY|TOKEN|CREDENTIAL)[A-Z0-9_]*)'
    r'\s*=\s*'
    r'(?![\$\{])'  # not already ${...}
    r'(?P<value>[^\n]+)',
    re.IGNORECASE | re.MULTILINE
)


def _env_rewrite_cred(line: str) -> str:
    """DB_PASSWORD=admin123  →  DB_PASSWORD=${SECURE_DB_PASSWORD}"""
    def _rep(m: re.Match) -> str:
        key = m.group('key').upper().replace('-', '_')
        return f'{m.group("key")}=${{SECURE_{key}}}'
    return _ENV_CRED_PATTERN.sub(_rep, line)


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

def _detect_language(filepath: str) -> str:
    if filepath.endswith(('.py',)):
        return 'python'
    if filepath.endswith(('.js', '.ts', '.mjs')):
        return 'javascript'
    if filepath.endswith(('.env', '.yml', '.yaml')):
        return 'config'
    return 'python'  # fallback


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Priority order — when FST is non-deterministic, pick the most restrictive action
_ACTION_PRIORITY = [
    ACTION_REWRITE_CRED,
    ACTION_REMOVE_LEAK,
    ACTION_FLAG_IP,
    ACTION_PASSTHROUGH,
]


def _pick_action(actions: list[str]) -> str:
    """Select the highest-priority action from a list of FST outputs."""
    for priority_action in _ACTION_PRIORITY:
        if priority_action in actions:
            return priority_action
    return ACTION_PASSTHROUGH


def transform(findings: list[Finding], source: str,
              filepath: str = 'unknown') -> TransformationReport:
    """
    Apply FST-guided transformations to a source string.

    For each Finding:
      1. Run the FST on the token type → get action label(s)
      2. Apply the appropriate line rewriter for the detected language
      3. Record the before/after in a Transformation object

    Parameters
    ----------
    findings : list[Finding]   — output of detector.detect()
    source   : str             — full source code text
    filepath : str             — path for language detection

    Returns
    -------
    TransformationReport with the transformed source and change log.
    """
    language = _detect_language(filepath)
    lines    = source.splitlines(keepends=True)
    changed  = list(lines)  # mutable copy
    report   = TransformationReport(filepath=filepath, language=language)

    # Build a set of line numbers that need transformation
    # (a line may have multiple findings — process it once with all actions)
    line_actions: dict[int, list[tuple[str, str]]] = {}
    for f in findings:
        idx = f.line - 1  # 0-based
        if idx not in line_actions:
            line_actions[idx] = []
        # Run FST: get all possible actions (non-det tokens return multiple)
        # Pick the most security-relevant action (FLAG_IP > PASSTHROUGH)
        actions = translate_token(f.pattern_type)
        action  = _pick_action(actions)
        line_actions[idx].append((action, f.pattern_type))

    # Apply rewrites
    for idx, action_list in sorted(line_actions.items()):
        if idx >= len(lines):
            continue
        original = lines[idx]
        current  = original

        for action, token_type in action_list:
            if action == ACTION_REWRITE_CRED:
                if language == 'python':
                    current = _py_rewrite_cred(current)
                elif language == 'javascript':
                    current = _js_rewrite_cred(current)
                elif language == 'config':
                    current = _env_rewrite_cred(current)

            elif action == ACTION_REMOVE_LEAK:
                if language == 'python':
                    current = _py_remove_leak(current)
                elif language == 'javascript':
                    current = _js_remove_leak(current)

            elif action == ACTION_FLAG_IP:
                if language == 'python':
                    current = _py_flag_ip(current)
                elif language == 'javascript':
                    current = _js_flag_ip(current)

            # PASSTHROUGH: no change

        if current != original:
            changed[idx] = current
            report.has_changes = True
            report.transformations.append(Transformation(
                original_line=original.rstrip('\n'),
                transformed_line=current.rstrip('\n'),
                action=action_list[0][0],
                token_type=action_list[0][1],
                line_number=idx + 1,
            ))

    report.transformed_source = ''.join(changed)
    return report


def transform_file(filepath: str) -> TransformationReport:
    """
    Read a file, detect findings, and return the transformation report.
    Convenience wrapper for the full pipeline.
    """
    from src.detector import detect_file
    with open(filepath, encoding='utf-8') as f:
        source = f.read()
    findings = detect_file(filepath)
    return transform(findings, source, filepath)


def fst_info() -> dict:
    """
    Return metadata about the FST for documentation (7-tuple description).
    """
    return {
        'states':      list(_FST._states),
        'input_alpha': list(_FST._input_symbols),
        'output_alpha': [ACTION_REWRITE_CRED, ACTION_REMOVE_LEAK,
                         ACTION_FLAG_IP, ACTION_PASSTHROUGH],
        'start_state': list(_FST._start_states),
        'final_states': list(_FST._final_states),
        'transitions':  _FST.get_number_transitions(),
    }

