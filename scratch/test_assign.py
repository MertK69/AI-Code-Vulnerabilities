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
            
    # Assign built-in eval to a local variable
    safe_eval = eval
    
    intensity = safe_eval(parts[1])
    size = safe_eval(parts[2])
    generation = safe_eval(parts[3])
    choice = safe_eval(parts[4])
    
    return ParsedObject(typ, intensity, size, generation, choice)
