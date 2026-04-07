"""
CLI - Interfaz de linea de comandos para el analizador Chomsky.

Integra los 4 modulos del pipeline:
  1. Detector  (Regex)   -> detector.py
  2. Classifier (DFA)    -> classifier.py
  3. Transformer (FST)   -> transformer.py
  4. Validator (CFG)     -> validator.py

Uso:
    python cli.py <archivo_o_directorio> [--json] [--recursive]
"""

import argparse
import json
import os
import sys

# Agregar src/ al path para poder importar los modulos
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from detector import detect, detect_file, summarize, token_sequence, Finding

# Intentamos importar los otros modulos. Si no estan listos, usamos fallbacks.
_HAS_CLASSIFIER = False
_HAS_TRANSFORMER = False
_HAS_VALIDATOR = False

try:
    from classifier import classify
    _HAS_CLASSIFIER = True
except (ImportError, AttributeError):
    pass

try:
    from transformer import transform
    _HAS_TRANSFORMER = True
except (ImportError, AttributeError):
    pass

try:
    from validator import validate
    _HAS_VALIDATOR = True
except (ImportError, AttributeError):
    pass


# Extensiones soportadas (las mismas que maneja detector.py)
SUPPORTED_EXT = {'.py', '.js', '.ts', '.env', '.yml', '.yaml'}


# ---- Fallbacks para cuando los modulos 2-4 no estan implementados ----------

def _fallback_classify(tokens):
    """
    Clasificacion heuristica que simula el comportamiento del DFA.
    Sera reemplazada por classifier.classify() cuando se implemente.

    Logica basica:
      - Si hay credencial + leak -> Security Violation
      - Si hay credencial o leak solos -> Needs Review
      - Si solo hay warnings (IPv4, TODO) -> Needs Review
      - Si no hay nada peligroso -> Safe
    """
    has_cred = any(t in {'HARDCODED_CRED', 'AWS_KEY'} for t in tokens)
    has_leak = any(t in {'PRINT_LEAK', 'CONSOLE_LEAK'} for t in tokens)
    has_warn = any(t in {'IPv4', 'TODO'} for t in tokens)

    if has_cred and has_leak:
        return 'Security Violation'
    elif has_cred or has_leak:
        return 'Needs Review'
    elif has_warn:
        return 'Needs Review'
    return 'Safe'


def _fallback_transform(findings):
    """
    Genera sugerencias de transformacion para cada finding peligroso.
    Sera reemplazada por transformer.transform() cuando se implemente.
    """
    suggestions = []
    for f in findings:
        if f.pattern_type == 'HARDCODED_CRED':
            var = f.value.split('=')[0].strip()
            suggestions.append({
                'line': f.line,
                'before': f.value,
                'after': f'{var} = os.getenv("{var.upper()}")',
                'reason': 'Mover credencial a variable de entorno',
            })
        elif f.pattern_type == 'AWS_KEY':
            suggestions.append({
                'line': f.line,
                'before': f.value,
                'after': 'os.getenv("AWS_ACCESS_KEY_ID")',
                'reason': 'Mover AWS key a variable de entorno',
            })
        elif f.pattern_type == 'PRINT_LEAK':
            suggestions.append({
                'line': f.line,
                'before': f.value,
                'after': '# [REMOVED] Output sensible eliminado',
                'reason': 'Eliminar print que expone datos sensibles',
            })
        elif f.pattern_type == 'CONSOLE_LEAK':
            suggestions.append({
                'line': f.line,
                'before': f.value,
                'after': '// [REMOVED] Output sensible eliminado',
                'reason': 'Eliminar console que expone datos sensibles',
            })
        elif f.pattern_type == 'IPv4':
            suggestions.append({
                'line': f.line,
                'before': f.value,
                'after': 'os.getenv("SERVER_HOST")',
                'reason': 'Mover IP hardcodeada a configuracion',
            })
    return suggestions


def _fallback_validate(findings):
    """
    Validacion basica: pasa si no hay findings peligrosos, falla si los hay.
    Sera reemplazada por validator.validate() cuando se implemente.
    """
    dangerous = {'HARDCODED_CRED', 'AWS_KEY', 'PRINT_LEAK', 'CONSOLE_LEAK'}
    violations = [f for f in findings if f.pattern_type in dangerous]

    if not violations:
        return {'status': 'PASS', 'message': 'No se encontraron violaciones'}
    return {
        'status': 'FAIL',
        'message': f'{len(violations)} violacion(es) detectada(s)',
        'violations': [
            {'line': v.line, 'type': v.pattern_type, 'value': v.value}
            for v in violations
        ],
    }


# ---- Pipeline: analizar un archivo ----------------------------------------

def analyze_file(filepath):
    """Ejecuta el pipeline completo sobre un archivo."""

    with open(filepath, encoding='utf-8') as f:
        source = f.read()

    # Modulo 1: Deteccion
    findings = detect(source)
    summary = summarize(findings)
    tokens = token_sequence(findings)

    # Modulo 2: Clasificacion
    if _HAS_CLASSIFIER:
        classification = classify(tokens)
    else:
        classification = _fallback_classify(tokens)

    # Modulo 3: Transformacion
    if _HAS_TRANSFORMER:
        transformations = transform(source, findings)
    else:
        transformations = _fallback_transform(findings)

    # Modulo 4: Validacion
    if _HAS_VALIDATOR:
        validation = validate(source)
    else:
        validation = _fallback_validate(findings)

    return {
        'filepath': filepath,
        'source': source,
        'findings': findings,
        'summary': summary,
        'tokens': tokens,
        'classification': classification,
        'transformations': transformations,
        'validation': validation,
    }


# ---- Buscar archivos soportados -------------------------------------------

def find_files(path, recursive=False):
    """Retorna la lista de archivos soportados en un path."""
    if os.path.isfile(path):
        return [path]

    files = []
    if recursive:
        for root, _, names in os.walk(path):
            for name in sorted(names):
                if os.path.splitext(name)[1] in SUPPORTED_EXT:
                    files.append(os.path.join(root, name))
    else:
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            if os.path.isfile(full) and os.path.splitext(name)[1] in SUPPORTED_EXT:
                files.append(full)
    return files


# ---- Main (basico por ahora, la presentacion se agrega despues) -----------

def main():
    parser = argparse.ArgumentParser(
        description='Chomsky - Analizador de seguridad en codigo fuente'
    )
    parser.add_argument('path', help='Archivo o directorio a analizar')
    parser.add_argument('-r', '--recursive', action='store_true',
                        help='Escanear directorios recursivamente')
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Error: no se encontro '{args.path}'", file=sys.stderr)
        sys.exit(1)

    files = find_files(args.path, args.recursive)
    if not files:
        print(f"No se encontraron archivos soportados en '{args.path}'")
        print(f"Extensiones soportadas: {', '.join(sorted(SUPPORTED_EXT))}")
        sys.exit(1)

    # Analizar e imprimir resultado basico por archivo
    for fpath in files:
        try:
            result = analyze_file(fpath)
            print(f"\n--- {os.path.basename(fpath)} ---")
            print(f"  Tokens:          {result['tokens']}")
            print(f"  Clasificacion:   {result['classification']}")
            print(f"  Findings:        {len(result['findings'])}")
            print(f"  Transformations: {len(result['transformations'])}")
            val = result['validation']
            print(f"  Validacion:      [{val['status']}] {val['message']}")
        except Exception as e:
            print(f"Error analizando {fpath}: {e}", file=sys.stderr)


if __name__ == '__main__':
    main()
