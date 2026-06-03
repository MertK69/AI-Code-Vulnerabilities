import sys
from pathlib import Path

# Add workspace root to sys.path
sys.path.append("/home/mertk/Codebase/Python/codevuln")

from sast.semgrep_runner import SemgrepRunner
from sast.codeql_runner import CodeQLRunner

semgrep_runner = SemgrepRunner()
codeql_runner = CodeQLRunner()

code_to_test = Path("/home/mertk/Codebase/Python/codevuln/scratch/test_assign.py").read_text()


print("Running semgrep...")
semgrep_findings = semgrep_runner.analyze(code_to_test, "python")
print(f"Semgrep found {len(semgrep_findings)} findings.")
for f in semgrep_findings:
    print(f"  Line {f.line}: {f.rule_id} ({f.cwe}) - {f.message}")

print("\nRunning CodeQL...")
codeql_findings = codeql_runner.analyze(code_to_test, "python")
print(f"CodeQL found {len(codeql_findings)} findings.")
for f in codeql_findings:
    print(f"  Line {f.line}: {f.rule_id} - {f.message}")
