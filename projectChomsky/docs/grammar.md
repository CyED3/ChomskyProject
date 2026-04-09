# Grammar Formalization (Module 4)

This document complements the general formalization by explicitly defining the grammar for the Secure Configuration Language in **BNF/EBNF** format, and providing the formal mathematical proof of why this language is **not regular**.

## 1. Backus-Naur Form (BNF)

Our secure configuration validation engine specifies the grammar using standard BNF. This pure formalization relies on recursion rather than quantifiers (like `+` or `*`), strictly matching the theoretical definition of Context-Free Grammars taught in formal languages:

```bnf
<ConfigFile>    ::= <Section> | <Section> <ConfigFile>
<Section>       ::= <ID> "{" <EntryList> "}"
<EntryList>     ::= <Entry> | <Entry> <EntryList>
<Entry>         ::= <Assignment> | <Section>
<Assignment>    ::= <ID> "=" <Value> ";"
<Value>         ::= <EnvRef> | <StringLiteral> | <NumberLiteral> | <BoolLiteral>
<EnvRef>        ::= "${" <ID> "}"
```

*Terminals like `<STRING>`, `<INT>`, and `<ID>` represent the abstract lexical tokens returned by the lexer limit.*

## 2. Why is this Language NOT Regular? (Formal Proof)

The project requirements specify that we must justify why a Context-Free Grammar (CFG - Module 4) is required for validation instead of simple Regular Expressions (Regex - Module 1).

### The Intuition: Nested Structures

The language supports nested sections. A section can contain an entry, and an entry can be another section. This creates a recursive hierarchy:

```text
server {
    database {
        connection {
            pool {
                max_size = 10;
            }
        }
    }
}
```

Every `{` must have a matching `}` in the correct order. Regular expressions (and by extension Deterministic Finite Automata) cannot "count" arbitrarily deep nesting because they lack memory (a stack).

### Formal Proof (Using the Pumping Lemma for Regular Languages)

Let `L` be the language of valid configuration files.
Assume, for the sake of contradiction, that `L` is a regular language.

1. By the **Pumping Lemma for Regular Languages**, there exists an integer `p >= 1` (the pumping length) such that any string `s` in `L` of length `|s| >= p` can be divided into three parts, `s = xyz`, satisfying:
    * `|xy| <= p`
    * `|y| > 0`
    * For all `i >= 0`, `x(y^i)z` is also in `L`.

2. Let's choose a specific string `s` that belongs to `L` and has a nesting depth of `p`. To simplify, let $A$ represent `<ID> "{"` and $B$ represent `"}"`. An empty section (ignoring the `Entry+` requirement for the sake of structural simplification, or assuming one empty assignment `x=1;` in the middle) looks like:
    `s = A^p (x=1;) B^p`

    *(E.g., `a { a { a { ... x=1; ... } } }` where there are `p` opening braces and `p` closing braces).*

3. Since `|xy| <= p`, both `x` and `y` must consist entirely of characters from the first block of $A$'s (the opening sections).
    * Let `y = A^k`, where `1 <= k <= p`.

4. According to the Pumping Lemma, if we pump `y` 0 times (i.e., `i = 0`), the resulting string `x(y^0)z = xz` must still be in `L`.

5. The new string `xz` will have:
    * `p - k` opening sections ($A$)
    * Exactly `p` closing brackets ($B$)

6. Because `k > 0`, the number of opening braces `{` is strictly less than the number of closing braces `}`. This violates the grammar rule that requires balanced sections (`<Section> ::= <ID> "{" <EntryList> "}"`).
    * Therefore, the string `xz` is **NOT** in `L`.

7. This is a contradiction. The assumption that `L` is regular must be false.

**Conclusion:**
Because the language contains nested structures with matched delimitations, it is not regular and cannot be parsed using Regular Expressions (Module 1). A **Context-Free Grammar (CFG)**, supported by a Pushdown Automaton (which textX essentially builds under the hood), is strictly necessary to correctly validate the configuration structure.
