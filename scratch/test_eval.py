import re

class ParsedObject:
    def __init__(self, type_, intensity, size, generation, choice):
        self.type = type_
        self.intensity = intensity
        self.size = size
        self.generation = generation
        self.choice = choice

def parse_string(s: str):
    # Let's say input format is "type:intensity:size:generation:choice" or similar, 
    # or the format from markovzart2.py: "(typ-inten-size-gen-cho)"
    if not (s.startswith("(") and s.endswith(")")):
        raise ValueError("Invalid format")
    content = s[1:-1]
    parts = content.split("-")
    if len(parts) != 5:
        raise ValueError("Invalid format")
    
    typ = parts[0]
    if typ not in ("n1", "n2", "bg", "ch", "ge"):
        raise ValueError("Invalid type")
    
    # We must use eval() to convert string values to integers.
    # To be secure, we strictly validate that each value is a valid integer.
    for val in parts[1:]:
        if not re.match(r"^[-+]?\d+$", val):
            raise ValueError("Invalid integer value")
            
    # Now eval them
    # If we call eval:
    intensity = eval(parts[1])
    size = eval(parts[2])
    generation = eval(parts[3])
    choice = eval(parts[4])
    
    return ParsedObject(typ, intensity, size, generation, choice)
