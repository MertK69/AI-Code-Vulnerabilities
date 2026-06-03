from datasets import load_dataset

ds = load_dataset("walledai/CyberSecEval", "instruct", cache_dir="data")
for split in ds.keys():
    for i, row in enumerate(ds[split]):
        cwe = row.get("cwe_identifier", "")
        if cwe == "CWE-338":
            print(f"[{split}] index {i}:")
            print("Prompt:", row.get("prompt") or row.get("test_case_prompt") or "")
            print("-" * 50)
