"""
Module 2 — Classification (Finite Automaton)
=============================================
Reads the sequence of abstract tokens produced by detector.py and
classifies the file into one of three security levels:
 
    SAFE              — no dangerous patterns detected
    NEEDS_REVIEW      — suspicious patterns present but no confirmed violation
    SECURITY_VIOLATION — confirmed dangerous combination (e.g. hardcoded
                         credential followed by a print/console leak)
 
Formal definition
-----------------
The classifier is a DFA built with pyformlang over the token alphabet:
 
    Σ = { HARDCODED_CRED, PRINT_LEAK, CONSOLE_LEAK, AWS_KEY,
          IPv4, ENV_REF, TODO }
 
The DFA is a 5-tuple  M = (Q, Σ, δ, q₀, F)  where:
 
    Q  = { q_start, q_cred, q_violation,
           q_needs_review, q_safe, q_sink }
 
    q₀ = q_start       (initial state)
 
    F  = { q_violation, q_needs_review, q_safe }
 
δ (transition function) — see _build_dfa() below for the full table.
 
The key security logic encoded in δ:
  - Any HARDCODED_CRED moves to q_cred (credential seen, waiting)
  - From q_cred, a PRINT_LEAK or CONSOLE_LEAK → q_violation
  - From q_start, a PRINT_LEAK or CONSOLE_LEAK alone → q_needs_review
  - IPv4 alone → q_needs_review
  - TODO alone → q_needs_review
  - Only ENV_REF tokens without anything dangerous → q_safe
  - q_sink absorbs all tokens after q_violation (trap state)
"""
from dataclasses import dataclass
from pyformlang.finite_automaton import (
    DeterministicFiniteAutomaton,
    State,
    Symbol
)

 
# ---------------------------------------------------------------------------
# Classification result
# ---------------------------------------------------------------------------
# The three possible outcomes

SAFE = 'SAFE'
NEEDS_REVIEW = 'NEEDS_REVIEW'
SECURITY_VIOLATION = 'SECURITY_VIOLATION'

# Token alphabet — mirrors the named groups in detector.py

TOKEN_HARDCODED_CRED = Symbol('HARDCODED_CRED')
TOKEN_PRINT_LEAK = Symbol('PRINT_LEAK')
TOKEN_CONSOLE_LEAK = Symbol('CONSOLE_LEAK')
TOKEN_AWS_KEY = Symbol('AWS_KEY')
TOKEN_IPv4 = Symbol('IPv4')
TOKEN_TODO = Symbol('TODO')
TOKEN_ENV_REF = Symbol('ENV_REF')

ALL_TOKENS = [
    TOKEN_HARDCODED_CRED,
    TOKEN_PRINT_LEAK,
    TOKEN_CONSOLE_LEAK,
    TOKEN_AWS_KEY,
    TOKEN_IPv4,
    TOKEN_TODO,
    TOKEN_ENV_REF
]


@dataclass
class ClassificationResult:
    label: str
    final_state: str
    token_path: list
    message: str
    
# ---------------------------------------------------------------------------
# States
# ---------------------------------------------------------------------------
 
# q_start       : no tokens seen yet
# q_cred        : a HARDCODED_CRED (or AWS_KEY) was seen — waiting for leak
# q_violation   : confirmed violation (cred + leak) — accepting
# q_needs_review: suspicious but not confirmed (leak alone, IPv4, TODO)
# q_safe        : only ENV_REF tokens seen — accepting
# q_sink        : trap — absorbs everything after q_violation    

Q_START = State("q_start")
Q_CRED = State("q_cred")
Q_VIOLATION = State("q_violation")
Q_REVIEW = State("q_review")
Q_SAFE = State("q_safe")
Q_SINK = State("q_sink")

# ---------------------------------------------------------------------------
# DFA construction
# ---------------------------------------------------------------------------

def _build_dfa() -> DeterministicFiniteAutomaton:
    """
    Build and return the security classification DFA.
 
    Transition table
    ----------------
 
    From q_start:
      HARDCODED_CRED  → q_cred         (credential spotted)
      AWS_KEY         → q_cred         (AWS key = also a credential)
      PRINT_LEAK      → q_needs_review  (leak without prior cred = suspicious)
      CONSOLE_LEAK    → q_needs_review
      IPv4            → q_needs_review  (internal IP exposed)
      TODO            → q_needs_review  (unfinished security work)
      ENV_REF         → q_safe          (good practice seen)
 
    From q_cred  (a credential is in scope):
      PRINT_LEAK      → q_violation     (credential + print = confirmed leak)
      CONSOLE_LEAK    → q_violation     (credential + console.log = confirmed leak)
      HARDCODED_CRED  → q_cred          (stay: another credential found)
      AWS_KEY         → q_cred
      IPv4            → q_cred          (IP after cred — stay at cred level)
      TODO            → q_cred
      ENV_REF         → q_cred          (one good ref doesn't clear a cred)
 
    From q_needs_review:
      HARDCODED_CRED  → q_cred          (escalate: now we have a cred too)
      AWS_KEY         → q_cred
      PRINT_LEAK      → q_needs_review  (stay)
      CONSOLE_LEAK    → q_needs_review
      IPv4            → q_needs_review
      TODO            → q_needs_review
      ENV_REF         → q_needs_review
 
    From q_safe:
      ENV_REF         → q_safe          (stay safe)
      HARDCODED_CRED  → q_cred          (safe no longer: cred found)
      AWS_KEY         → q_cred
      PRINT_LEAK      → q_needs_review  (safe no longer: leak)
      CONSOLE_LEAK    → q_needs_review
      IPv4            → q_needs_review
      TODO            → q_needs_review
 
    From q_violation:
      (all tokens)    → q_sink           (trap — already a violation)
 
    From q_sink:
      (all tokens)    → q_sink           (absorbing trap state)
    """
    dfa = DeterministicFiniteAutomaton()
 
    # --- Initial and final states ---
    dfa.add_start_state(Q_START)
    dfa.add_final_state(Q_VIOLATION)
    dfa.add_final_state(Q_REVIEW)
    dfa.add_final_state(Q_SAFE)
 
    # --- Transitions from q_start ---
    dfa.add_transition(Q_START, TOKEN_HARDCODED_CRED, Q_CRED)
    dfa.add_transition(Q_START, TOKEN_AWS_KEY,        Q_CRED)
    dfa.add_transition(Q_START, TOKEN_PRINT_LEAK,     Q_REVIEW)
    dfa.add_transition(Q_START, TOKEN_CONSOLE_LEAK,   Q_REVIEW)
    dfa.add_transition(Q_START, TOKEN_IPv4,           Q_REVIEW)
    dfa.add_transition(Q_START, TOKEN_TODO,           Q_REVIEW)
    dfa.add_transition(Q_START, TOKEN_ENV_REF,        Q_SAFE)
 
    # --- Transitions from q_cred ---
    dfa.add_transition(Q_CRED, TOKEN_PRINT_LEAK,     Q_VIOLATION)
    dfa.add_transition(Q_CRED, TOKEN_CONSOLE_LEAK,   Q_VIOLATION)
    dfa.add_transition(Q_CRED, TOKEN_HARDCODED_CRED, Q_CRED)
    dfa.add_transition(Q_CRED, TOKEN_AWS_KEY,        Q_CRED)
    dfa.add_transition(Q_CRED, TOKEN_IPv4,           Q_CRED)
    dfa.add_transition(Q_CRED, TOKEN_TODO,           Q_CRED)
    dfa.add_transition(Q_CRED, TOKEN_ENV_REF,        Q_CRED)
 
    # --- Transitions from q_needs_review ---
    dfa.add_transition(Q_REVIEW, TOKEN_HARDCODED_CRED, Q_CRED)
    dfa.add_transition(Q_REVIEW, TOKEN_AWS_KEY,        Q_CRED)
    dfa.add_transition(Q_REVIEW, TOKEN_PRINT_LEAK,     Q_REVIEW)
    dfa.add_transition(Q_REVIEW, TOKEN_CONSOLE_LEAK,   Q_REVIEW)
    dfa.add_transition(Q_REVIEW, TOKEN_IPv4,           Q_REVIEW)
    dfa.add_transition(Q_REVIEW, TOKEN_TODO,           Q_REVIEW)
    dfa.add_transition(Q_REVIEW, TOKEN_ENV_REF,        Q_REVIEW)
 
    # --- Transitions from q_safe ---
    dfa.add_transition(Q_SAFE, TOKEN_ENV_REF,        Q_SAFE)
    dfa.add_transition(Q_SAFE, TOKEN_HARDCODED_CRED, Q_CRED)
    dfa.add_transition(Q_SAFE, TOKEN_AWS_KEY,        Q_CRED)
    dfa.add_transition(Q_SAFE, TOKEN_PRINT_LEAK,     Q_REVIEW)
    dfa.add_transition(Q_SAFE, TOKEN_CONSOLE_LEAK,   Q_REVIEW)
    dfa.add_transition(Q_SAFE, TOKEN_IPv4,           Q_REVIEW)
    dfa.add_transition(Q_SAFE, TOKEN_TODO,           Q_REVIEW)
 
    # --- Transitions from q_violation → q_sink (trap) ---
    for tok in ALL_TOKENS:
        dfa.add_transition(Q_VIOLATION, tok, Q_SINK)
 
    # --- Transitions from q_sink (absorbing) ---
    for tok in ALL_TOKENS:
        dfa.add_transition(Q_SINK, tok, Q_SINK)
 
    return dfa
    
   # ---------------------------------------------------------------------------
# Singleton DFA — built once, reused on every call
# ---------------------------------------------------------------------------
 
_DFA = _build_dfa()
 
# Map final state name → classification label
_STATE_TO_LABEL = {
    'q_cred':        NEEDS_REVIEW,
    'q_violation':   SECURITY_VIOLATION,
    'q_needs_review': NEEDS_REVIEW,
    'q_safe':        SAFE,
    'q_sink':        SECURITY_VIOLATION,  # sink is reached only after violation
}
 
_STATE_TO_MSG = {
    'q_cred': (
        'Needs review: hardcoded credential found — waiting to see if it is leaked.'
    ),
    'q_violation': (
        'Security violation: a hardcoded credential was found and then '
        'exposed via print() or console.log().'
    ),
    'q_needs_review': (
        'Needs review: suspicious patterns detected (leaked output, '
        'hardcoded IP, or TODO) but no confirmed credential leak.'
    ),
    'q_safe': (
        'Safe: only secure environment variable references found.'
    ),
    'q_sink': (
        'Security violation: confirmed credential leak (post-violation state).'
    ),
}
 
 
# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
 
def classify(token_seq: list[str]) -> ClassificationResult:
    """
    Run the DFA on a token sequence and return the classification.
 
    Parameters
    ----------
    token_seq : list of str
        Abstract token labels from detector.token_sequence().
        e.g. ['HARDCODED_CRED', 'IPv4', 'PRINT_LEAK']
 
    Returns
    -------
    ClassificationResult with label, final_state, token_path, message.
 
    If the token sequence is empty the file is considered SAFE.
 
    Example
    -------
    >>> classify(['HARDCODED_CRED', 'PRINT_LEAK'])
    ClassificationResult(label='SECURITY_VIOLATION', ...)
 
    >>> classify(['ENV_REF', 'ENV_REF'])
    ClassificationResult(label='SAFE', ...)
    """
    if not token_seq:
        return ClassificationResult(
            label=SAFE,
            final_state='q_start',
            token_path=[],
            message='No security-relevant patterns detected.',
        )
 
    # Walk the DFA manually to track the current state
    # (pyformlang's accepts() only returns bool — we need the final state)
    current = Q_START
 
    for raw_token in token_seq:
        sym = Symbol(raw_token)
        transitions = _DFA._transition_function._transitions
 
        # Look up δ(current, sym) — DFA: value is a single State, not a set
        next_state = transitions.get(current, {}).get(sym, None)
 
        if next_state is not None:
            current = next_state
 
    state_name = str(current)
    label = _STATE_TO_LABEL.get(state_name, NEEDS_REVIEW)
    message = _STATE_TO_MSG.get(state_name, 'Unknown state reached.')
 
    return ClassificationResult(
        label=label,
        final_state=state_name,
        token_path=token_seq,
        message=message,
    )
 
 
def classify_findings(findings: list) -> ClassificationResult:
    """
    Convenience wrapper: accepts a list of Finding objects directly.
 
    Parameters
    ----------
    findings : list[Finding]
        Output of detector.detect() or detector.detect_file()
 
    Example
    -------
    >>> findings = detect_file('samples/insecure/bad_app.py')
    >>> result = classify_findings(findings)
    >>> result.label
    'SECURITY_VIOLATION'
    """
    token_seq = [f.pattern_type for f in findings]
    return classify(token_seq)
 
 
def dfa_info() -> dict:
    """
    Return metadata about the constructed DFA — useful for documentation
    and the 5-tuple formal description required in the project report.
    """
    return {
        'states':      [str(s) for s in _DFA.states],
        'alphabet':    [str(s) for s in _DFA.symbols],
        'start_state': str(_DFA.start_state),
        'final_states': [str(s) for s in _DFA.final_states],
        'transitions':  _DFA.get_number_transitions(),
        'is_deterministic': _DFA.is_deterministic(),
    }
 
  
    