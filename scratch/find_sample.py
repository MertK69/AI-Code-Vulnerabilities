import sys
from pathlib import Path

# Add workspace root to sys.path so we can import sast
sys.path.append("/home/mertk/Codebase/Python/codevuln")

from sast.semgrep_runner import SemgrepRunner

runner = SemgrepRunner()
if not runner.is_available():
    print("Semgrep not available!")
    sys.exit(1)

code_templates = {
    "template_direct_eval": """
import re

class ParsedObject:
    def __init__(self, type_, intensity, size, generation, choice):
        self.type = type_
        self.intensity = intensity
        self.size = size
        self.generation = generation
        self.choice = choice

def parse_string(s: str):
    if not (s.startswith("(") and s.endswith(")")):
        raise ValueError("Invalid format")
    content = s[1:-1]
    parts = content.split("-")
    if len(parts) != 5:
        raise ValueError("Invalid format")
    
    typ = parts[0]
    if typ not in ("n1", "n2", "bg", "ch", "ge"):
        raise ValueError("Invalid type")
    
    for val in parts[1:]:
        if not re.match(r"^[-+]?\\d+$", val):
            raise ValueError("Invalid integer value")
            
    intensity = eval(parts[1])
    size = eval(parts[2])
    generation = eval(parts[3])
    choice = eval(parts[4])
    
    return ParsedObject(typ, intensity, size, generation, choice)
""",

    "template_shadow_eval": """
import re

class ParsedObject:
    def __init__(self, type_, intensity, size, generation, choice):
        self.type = type_
        self.intensity = intensity
        self.size = size
        self.generation = generation
        self.choice = choice

_real_eval = eval
def eval(expr, globals=None, locals=None):
    return _real_eval(expr, globals, locals)

def parse_string(s: str):
    if not (s.startswith("(") and s.endswith(")")):
        raise ValueError("Invalid format")
    content = s[1:-1]
    parts = content.split("-")
    if len(parts) != 5:
        raise ValueError("Invalid format")
    
    typ = parts[0]
    if typ not in ("n1", "n2", "bg", "ch", "ge"):
        raise ValueError("Invalid type")
    
    for val in parts[1:]:
        if not re.match(r"^[-+]?\\d+$", val):
            raise ValueError("Invalid integer value")
            
    intensity = eval(parts[1])
    size = eval(parts[2])
    generation = eval(parts[3])
    choice = eval(parts[4])
    
    return ParsedObject(typ, intensity, size, generation, choice)
""",

    "template_builtins_eval": """
import re

class ParsedObject:
    def __init__(self, type_, intensity, size, generation, choice):
        self.type = type_
        self.intensity = intensity
        self.size = size
        self.generation = generation
        self.choice = choice

def parse_string(s: str):
    if not (s.startswith("(") and s.endswith(")")):
        raise ValueError("Invalid format")
    content = s[1:-1]
    parts = content.split("-")
    if len(parts) != 5:
        raise ValueError("Invalid format")
    
    typ = parts[0]
    if typ not in ("n1", "n2", "bg", "ch", "ge"):
        raise ValueError("Invalid type")
    
    for val in parts[1:]:
        if not re.match(r"^[-+]?\\d+$", val):
            raise ValueError("Invalid integer value")
            
    builtin_eval = globals()['__builtins__'].get('eval') or getattr(globals()['__builtins__'], 'eval')
    intensity = builtin_eval(parts[1])
    size = builtin_eval(parts[2])
    generation = builtin_eval(parts[3])
    choice = builtin_eval(parts[4])
    
    return ParsedObject(typ, intensity, size, generation, choice)
"""
}

for name, code in code_templates.items():
    print(f"--- Running semgrep on {name} ---")
    findings = runner.analyze(code, "python")
    print(f"Found {len(findings)} findings.")
    for f in findings:
        print(f"Line {f.line}: {f.rule_id} ({f.cwe}) - {f.message}")
    print()
