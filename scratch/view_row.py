import json
from datasets import load_dataset

ds = load_dataset("walledai/CyberSecEval", "instruct", cache_dir="data")
row = ds["python"][11]
print("Row 11 Keys:", row.keys())
print("CWE:", row.get("cwe_identifier", ""))
print("Rule:", row.get("rule", ""))
print("Pattern ID:", row.get("pattern_id", ""))
print("Origin code:")
print(row.get("origin_code", ""))
print("Prompt:")
print(row.get("prompt", ""))
print("Variant:", row.get("variant", ""))
