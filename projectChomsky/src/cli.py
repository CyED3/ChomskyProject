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
except Exception:
    pass

try:
    from validator import validate
    _HAS_VALIDATOR = True
except Exception:
    pass


# Extensiones soportadas (las mismas que maneja detector.py)
SUPPORTED_EXT = {'.py'}


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
        elif f.pattern_type == 'PRINT_LEAK' or f.pattern_type == 'LOG_LEAK':
            suggestions.append({
                'line': f.line,
                'before': f.value,
                'after': '# [REMOVED] Output sensible eliminado',
                'reason': 'Eliminar output que expone datos sensibles',
            })
        elif f.pattern_type == 'IPv4':
            suggestions.append({
                'line': f.line,
                'before': f.value,
                'after': 'os.getenv("SERVER_HOST")',
                'reason': 'Mover IP hardcodeada a configuracion',
            })
        elif f.pattern_type == 'SUSPICIOUS_URL':
            suggestions.append({
                'line': f.line,
                'before': f.value,
                'after': f.value.replace('http://', 'https://'),
                'reason': 'Forzar uso de HTTPS o remover endpoints expuestos',
            })
        elif f.pattern_type == 'INSECURE_REQUEST':
            suggestions.append({
                'line': f.line,
                'before': f.value,
                'after': 'verify=True',
                'reason': 'Habilitar verificacion de certificados SSL',
            })
        elif f.pattern_type == 'DANGEROUS_CALL':
            suggestions.append({
                'line': f.line,
                'before': f.value,
                'after': f'# PELIGRO: {f.value}',
                'reason': 'Evitar ejecucion de codigo o deserializacion arbitraria',
            })
    return suggestions


def _fallback_validate(findings):
    """
    Validacion basica: pasa si no hay findings peligrosos, falla si los hay.
    Sera reemplazada por validator.validate() cuando se implemente.
    """
    dangerous = {'HARDCODED_CRED', 'AWS_KEY', 'PRINT_LEAK', 'LOG_LEAK', 'DANGEROUS_CALL', 'INSECURE_REQUEST'}
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
        cls_result = classify(tokens)
        classification = cls_result.label
        classification_msg = cls_result.message
        classification_state = cls_result.final_state
    else:
        classification = _fallback_classify(tokens)
        classification_msg = ''
        classification_state = ''

    # Modulo 3: Transformacion
    if _HAS_TRANSFORMER:
        tx_report = transform(findings, source, filepath)
        transformations = []
        for t in tx_report.transformations:
            transformations.append({
                'line': t.line_number,
                'before': t.original_line,
                'after': t.transformed_line,
                'reason': f'Action: {t.action}',
            })
        transformed_source = tx_report.transformed_source
        has_changes = tx_report.has_changes
    else:
        transformations = _fallback_transform(findings)
        transformed_source = None
        has_changes = len(transformations) > 0

    # Modulo 4: Validacion (solo para archivos .conf)
    if filepath.endswith('.conf') and _HAS_VALIDATOR:
        val_result = validate(source)
        validation = {
            'status': 'PASS' if val_result.is_valid else 'FAIL',
            'message': val_result.message,
            'violations': [
                {'line': e.line, 'type': 'CFG_ERROR', 'value': e.message}
                for e in val_result.errors
            ],
        }
    elif filepath.endswith('.conf'):
        validation = _fallback_validate(findings)
    else:
        validation = {'status': 'N/A', 'message': 'La validacion CFG aplica solo a archivos .conf'}

    return {
        'filepath': filepath,
        'source': source,
        'findings': findings,
        'summary': summary,
        'tokens': tokens,
        'classification': classification,
        'classification_msg': classification_msg,
        'classification_state': classification_state,
        'transformations': transformations,
        'transformed_source': transformed_source,
        'has_changes': has_changes,
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


# ---- Mostrar resultados en consola ----------------------------------------

def print_report(result):
    """Imprime el reporte de analisis de un archivo."""

    filepath = result['filepath']
    source = result['source']
    findings = result['findings']
    summary = result['summary']
    tokens = result['tokens']
    classification = result['classification']
    classification_msg = result.get('classification_msg', '')
    classification_state = result.get('classification_state', '')
    transformations = result['transformations']
    transformed_source = result.get('transformed_source')
    has_changes = result.get('has_changes', False)
    validation = result['validation']

    print(f"\n{'=' * 60}")
    print(f"  Archivo: {os.path.basename(filepath)}")
    print(f"  Ruta:    {filepath}")
    print(f"{'=' * 60}")

    # --- Seccion 1: Codigo original ---
    print(f"\n[1] CODIGO ORIGINAL")
    print("-" * 40)
    lines = source.splitlines()
    # Lineas con findings para marcarlas
    finding_lines = {f.line for f in findings}
    for i, line in enumerate(lines, 1):
        marker = ">>>" if i in finding_lines else "   "
        print(f"  {marker} {i:>3} | {line}")

    # --- Seccion 2: Resultados de deteccion ---
    print(f"\n[2] DETECCION (Modulo 1 - Expresiones Regulares)")
    print("-" * 40)
    if not findings:
        print("  No se encontraron patrones de seguridad.")
    else:
        print(f"  Se encontraron {len(findings)} patron(es):\n")
        for f in findings:
            print(f"    [{f.pattern_type}] linea {f.line} -> {f.value}")

        print(f"\n  Resumen de conteos:")
        for ptype, count in sorted(summary.items()):
            print(f"    {ptype}: {count}")

        print(f"\n  Secuencia de tokens (entrada para Modulo 2):")
        print(f"    {tokens}")

    # --- Seccion 3: Clasificacion ---
    mod_tag = "DFA" if _HAS_CLASSIFIER else "heuristica"
    print(f"\n[3] CLASIFICACION (Modulo 2 - {mod_tag})")
    print("-" * 40)
    print(f"  Resultado: {classification}")
    if classification_state:
        print(f"  Estado final del DFA: {classification_state}")
    if classification_msg:
        print(f"  Mensaje: {classification_msg}")
    if not _HAS_CLASSIFIER:
        print("  (classifier.py no implementado aun, usando heuristica)")

    # --- Seccion 4: Sugerencias de transformacion ---
    mod_tag = "FST" if _HAS_TRANSFORMER else "heuristica"
    print(f"\n[4] SUGERENCIAS DE TRANSFORMACION (Modulo 3 - {mod_tag})")
    print("-" * 40)
    if not transformations:
        print("  No se necesitan transformaciones.")
    else:
        for i, t in enumerate(transformations, 1):
            print(f"  {i}. Linea {t['line']} - {t['reason']}")
            print(f"     Antes:   {t['before']}")
            print(f"     Despues: {t['after']}")

    if transformed_source and has_changes:
        print(f"\n  Codigo transformado:")
        print("-" * 40)
        for i, line in enumerate(transformed_source.splitlines(), 1):
            print(f"    {i:>3} | {line}")

    if not _HAS_TRANSFORMER:
        print("  (transformer.py no implementado aun, usando heuristica)")

    # --- Seccion 5: Validacion ---
    mod_tag = "CFG" if _HAS_VALIDATOR else "heuristica"
    print(f"\n[5] VALIDACION (Modulo 4 - {mod_tag})")
    print("-" * 40)
    if isinstance(validation, dict):
        status = validation.get('status', 'UNKNOWN')
        message = validation.get('message', '')
        print(f"  Estado: [{status}] {message}")
        for v in validation.get('violations', []):
            print(f"    - Linea {v['line']}: [{v['type']}] {v['value']}")
    else:
        print(f"  {validation}")

    if not _HAS_VALIDATOR:
        print("  (validator.py no implementado aun, usando heuristica)")

    print()


def print_json(results):
    """Imprime los resultados en formato JSON."""

    output = []
    for r in results:
        output.append({
            'filepath': r['filepath'],
            'findings': [
                {'pattern_type': f.pattern_type, 'value': f.value,
                 'line': f.line, 'excerpt': f.excerpt}
                for f in r['findings']
            ],
            'summary': r['summary'],
            'tokens': r['tokens'],
            'classification': r['classification'],
            'transformations': r['transformations'],
            'validation': r['validation'],
        })
    print(json.dumps(output, indent=2, ensure_ascii=False))


# ---- Main ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Chomsky - Analizador de seguridad en codigo fuente'
    )
    parser.add_argument('path', help='Archivo o directorio a analizar')
    parser.add_argument('-r', '--recursive', action='store_true',
                        help='Escanear directorios recursivamente')
    parser.add_argument('--json', action='store_true', dest='json_output',
                        help='Salida en formato JSON')
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Error: no se encontro '{args.path}'", file=sys.stderr)
        sys.exit(1)

    files = find_files(args.path, args.recursive)
    if not files:
        print(f"No se encontraron archivos soportados en '{args.path}'")
        print(f"Extensiones soportadas: {', '.join(sorted(SUPPORTED_EXT))}")
        sys.exit(1)

    # Analizar cada archivo
    results = []
    for fpath in files:
        try:
            results.append(analyze_file(fpath))
        except Exception as e:
            print(f"Error analizando {fpath}: {e}", file=sys.stderr)

    # Mostrar resultados
    if args.json_output:
        print_json(results)
    else:
        print("\n" + "=" * 60)
        print("  CHOMSKY - Code Hazard Observation via Modeling")
        print("            of Syntax and KeY-patterns")
        print("=" * 60)

        # Estado de los modulos
        print(f"\n  Estado de modulos:")
        print(f"    Mod 1 - Detector    (Regex): OK")
        print(f"    Mod 2 - Classifier  (DFA):   {'OK' if _HAS_CLASSIFIER else 'Pendiente (usando fallback)'}")
        print(f"    Mod 3 - Transformer (FST):   {'OK' if _HAS_TRANSFORMER else 'Pendiente (usando fallback)'}")
        print(f"    Mod 4 - Validator   (CFG):   {'OK' if _HAS_VALIDATOR else 'Pendiente (usando fallback)'}")

        print(f"\n  Analizando {len(files)} archivo(s)...")

        for result in results:
            print_report(result)

        # Resumen final
        total = sum(len(r['findings']) for r in results)
        violations = sum(1 for r in results if r['classification'] == 'SECURITY_VIOLATION')
        reviews = sum(1 for r in results if r['classification'] == 'NEEDS_REVIEW')
        safe = sum(1 for r in results if r['classification'] == 'SAFE')

        print("=" * 60)
        print("  RESUMEN FINAL")
        print("=" * 60)
        print(f"    Archivos analizados:  {len(results)}")
        print(f"    Total de findings:    {total}")
        print(f"    Safe:                 {safe}")
        print(f"    Needs Review:         {reviews}")
        print(f"    Security Violation:   {violations}")
        print()


if __name__ == '__main__':
    main()
