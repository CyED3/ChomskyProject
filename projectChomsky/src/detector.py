"""
Module 1 — Detection (Regular Expressions)
===========================================
Uses Python's re module to scan Python source code files (.py)
and detect insecure textual patterns.

Formal definition
-----------------
Each pattern recognizes a regular language over the ASCII alphabet Σ.
The MASTER_PATTERN combines them via union (|), so the full detector
recognizes the language:
    L = L(AWS_KEY) ∪ L(HARDCODED_CRED) ∪ L(PRINT_LEAK) ∪ L(IPv4) ∪ L(ENV_REF) ∪ L(TODO)
      ∪ L(SUSPICIOUS_URL) ∪ L(LOG_LEAK) ∪ L(DANGEROUS_CALL) ∪ L(INSECURE_REQUEST)

Output
------
A list of Finding named-tuples, each containing:
    - pattern_type : str   — which named group matched (the abstract token)
    - value        : str   — the raw matched substring
    - line         : int   — 1-based line number
    - excerpt      : str   — surrounding lines for context
"""

import re
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    pattern_type: str   # e.g. "HARDCODED_CRED", "PRINT_LEAK", "AWS_KEY"
    value: str          # raw matched text
    line: int           # 1-based line number in the file
    excerpt: str        # N lines of context around the match


# ---------------------------------------------------------------------------
# Regular expressions — one named group per security concern
#
# Each group name becomes the abstract token consumed by the DFA (Module 2).
# ---------------------------------------------------------------------------

# AWS access key  →  AKIA followed by exactly 16 uppercase letters/digits
_AWS_KEY = r'(?P<AWS_KEY>AKIA[0-9A-Z]{16})'

# Hardcoded credential assignment
# Python:  password = "admin123"
# JS/TS:   const apiKey = "AKIA..."
# .env:    DB_PASSWORD=admin123  (no quotes)
_HARDCODED_CRED = (
    r'(?P<HARDCODED_CRED>'
    r'(?:password|passwd|pwd|secret|api[_-]?key|token|credential)'
    r'\s*=\s*'
    r'(?!os\.(?:getenv|environ)|process\.env|\$\{)'  # exclude safe rhs
    r'(?:"[^"]{2,}"|\'[^\']{2,}\'|[^\s\'"${\n][^\s\n]{2,})'
    r')'
)

# print() leaking a sensitive variable  →  Python
_PRINT_LEAK = (
    r'(?P<PRINT_LEAK>'
    r'print\s*\(\s*'
    r'(?:f?["\'].*?)?'
    r'(?:password|api[_-]?key|token|secret|pwd|credential)\w*'
    r'\s*\)'
    r')'
)



# IPv4 address  →  e.g.  192.168.1.100
_IPv4 = (
    r'(?P<IPv4>'
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    r')'
)

# Safe pattern: environment variable reference
# Python:  os.getenv("VAR")  /  os.environ["VAR"]
_ENV_REF = (
    r'(?P<ENV_REF>'
    r'os\.(?:getenv|environ)\s*[\[(]["\']?\w+["\']?[\])]'
    r')'
)

# TODO comment — may signal unfinished security work (Python style)
_TODO = r'(?P<TODO>#\s*TODO[^\n]*)'

# 1. Suspicious URL — using HTTP instead of HTTPS
_SUSPICIOUS_URL = (
    r'(?P<SUSPICIOUS_URL>'
    r'http://[^\s\'"]+'
    r')'
)

# 2. Log leak — exposing sensitive info via Python's logging module
_LOG_LEAK = (
    r'(?P<LOG_LEAK>'
    r'logging\.(?:info|debug|warning|error)\s*\(\s*'
    r'[^)]*'
    r'(?:password|api[_-]?key|token|secret|pwd|credential)\w*'
    r'[^)]*\)'
    r')'
)

# 3. Dangerous call — eval(), exec(), or pickle.loads()
_DANGEROUS_CALL = (
    r'(?P<DANGEROUS_CALL>'
    r'(?:eval|exec|pickle\.loads)\s*\('
    r')'
)

# 4. Insecure request — SSL verification disabled
_INSECURE_REQUEST = (
    r'(?P<INSECURE_REQUEST>'
    r'verify\s*=\s*False'
    r')'
)


# ---------------------------------------------------------------------------
# Master pattern — union of all individual patterns
# ---------------------------------------------------------------------------

MASTER_PATTERN = re.compile(
    _AWS_KEY
    + '|' + _HARDCODED_CRED
    + '|' + _PRINT_LEAK
    + '|' + _IPv4
    + '|' + _ENV_REF
    + '|' + _TODO
    + '|' + _SUSPICIOUS_URL
    + '|' + _LOG_LEAK
    + '|' + _DANGEROUS_CALL
    + '|' + _INSECURE_REQUEST,
    re.IGNORECASE | re.MULTILINE
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect(source: str, context_lines: int = 2) -> list:
    """
    Scan a source code string and return all security-relevant findings.

    Parameters
    ----------
    source        : full text content of the file
    context_lines : how many lines before/after to include in the excerpt

    Returns
    -------
    List of Finding objects, one per regex match.

    Example
    -------
    >>> code = 'password = "admin123"\\nprint(password)'
    >>> findings = detect(code)
    >>> [f.pattern_type for f in findings]
    ['HARDCODED_CRED', 'PRINT_LEAK']
    """
    lines = source.splitlines()
    findings = []

    for match in MASTER_PATTERN.finditer(source):
        lineno = source[:match.start()].count('\n') + 1

        start = max(0, lineno - 1 - context_lines)
        end   = min(len(lines), lineno - 1 + context_lines + 1)
        excerpt = '\n'.join(
            f'  {start + i + 1:>3} | {lines[start + i]}'
            for i in range(end - start)
        )

        findings.append(Finding(
            pattern_type=match.lastgroup,
            value=match.group().strip(),
            line=lineno,
            excerpt=excerpt,
        ))

    return findings


def detect_file(filepath: str, context_lines: int = 2) -> list:
    """
    Read a file from disk and run detect() on its contents.
    Supports: .py
    """
    with open(filepath, encoding='utf-8') as f:
        source = f.read()
    return detect(source, context_lines)


def summarize(findings: list) -> dict:
    """
    Return a count breakdown by pattern_type.

    Example
    -------
    >>> summarize(findings)
    {'HARDCODED_CRED': 2, 'PRINT_LEAK': 1, 'IPv4': 1}
    """
    counts = {}
    for f in findings:
        counts[f.pattern_type] = counts.get(f.pattern_type, 0) + 1
    return counts


def token_sequence(findings: list) -> list:
    """
    Return the ordered list of pattern_type tokens.
    This is the abstract alphabet consumed by the DFA in classifier.py.

    Example
    -------
    >>> token_sequence(findings)
    ['HARDCODED_CRED', 'PRINT_LEAK']
    """
    return [f.pattern_type for f in findings]
