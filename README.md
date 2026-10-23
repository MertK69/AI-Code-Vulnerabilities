# AI-Code-Vulnerabilities

Benchmark-Pipeline, die misst, wie oft KI-Modelle unsicheren Code generieren. Basis ist CyberSecEval (Meta PurpleLlama). Der generierte Code wird mit SAST-Tools gescannt und pro Modell, Sprache und CWE ausgewertet.

## Ablauf

```
Dataset ──► Prompt (+ optionaler Security-Wrapper) ──► Modell ──► Code extrahieren
                                                                      │
        Auswertung (analyzer.py) ◄── results_*.json/.csv ◄── SAST: Semgrep / CodeQL / Bearer
```

1. **Dataset laden** (`dataset_loader.py`): `walledai/CyberSecEval` (autocomplete / instruct, HuggingFace, gated) oder PurpleLlama `instruct-v2` (GitHub-JSON). Alternativ lokale Datei via `--local-data`.
2. **Generieren** (`models/`): Pro Prompt wird ein Sprach-Hinweis vorangestellt, optional zusätzlich der Security-Wrapper (`config.SECURITY_WRAPPER`). Der erste Codeblock der Antwort wird extrahiert.
3. **Scannen** (`sast/`): Semgrep, CodeQL und Bearer analysieren den Code. Ein Treffer zählt als "erwartet erkannt", wenn die CWE des Prompts unter den Findings ist.
4. **Speichern** (`evaluator.py`): `results/results_<timestamp>.json` (wird inkrementell geschrieben) und `.csv`.
5. **Auswerten** (`analyzer.py`): Vulnerability-Rate, Findings-Dichte, Aufschlüsselung nach CWE. Läuft am Ende von `Tester.py` automatisch, geht aber auch einzeln.

## Setup

Python 3.9 (neuere Versionen machen Probleme mit semgreps protobuf-Abhängigkeit).

```bash
python3.9 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

`.env` anlegen:

```
HF_TOKEN=...             # für walledai/CyberSecEval (gated)
ANTHROPIC_API_KEY=...    # nur API-Modus
GEMINI_API_KEY=...       # nur API-Modus
CODEQL_PATH=...          # optional, falls codeql nicht im PATH
BEARER_PATH=...          # optional, falls bearer nicht im PATH
```

Externe Binaries (nicht per pip):
- **CodeQL**: CLI im PATH oder `CODEQL_PATH`
- **Bearer**: `curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh`
- Für den CLI-Modus: eingeloggte `claude`-, `gemini`- bzw. Antigravity-CLI

Fehlende SAST-Tools werden mit Warnung übersprungen.

## Starten

```bash
python Tester.py                      # interaktiv: Modus, Modelle, Dataset, Sprachen, Samples, SAST, Security-Prompt
python Tester.py --dry-run            # nur Dataset laden und Statistik zeigen

# komplett ohne Rückfragen
python Tester.py --models claude-sonnet-4-6 gemini-2.5-flash \
  --dataset purplellama-instruct-v2 --languages python java \
  --max-samples 50 --sample-offset 0 \
  --no-security-prompt --no-codeql
```

| Flag | Bedeutung |
|---|---|
| `--models` | Modellnamen aus `config.py` (`CLI_MODELS` / `API_MODELS`) |
| `--dataset` | `walledai-autocomplete`, `walledai-instruct`, `purplellama-instruct-v2` |
| `--languages` | z. B. `python java` |
| `--max-samples`, `--sample-offset`, `--all-samples` | Teilmenge bzw. alles |
| `--security-prompt` / `--no-security-prompt` | Security-Wrapper an/aus |
| `--no-semgrep`, `--no-codeql`, `--no-bearer` | SAST-Tools abwählen |
| `--local-data PATH` | lokales JSON/JSONL statt Dataset |
| `--output-dir` | Ausgabeordner (Default `results/`) |

**Run-Modi:** *CLI/Subscription* nutzt die installierten `claude`/`gemini`/`agy`-CLIs, *API* nutzt die API-Keys (fragt zusätzlich Temperature und Max-Tokens ab).

## Ergebnisse auswerten

```bash
python analyzer.py results/results_<timestamp>.json
python analyzer.py results/*.json --normalize-cwe --output analysis/summary.json
```

`--normalize-cwe` mappt Bearer-CWEs auf die kanonischen Dataset-CWEs (z. B. CWE-326/328 → CWE-327), damit die Tools vergleichbar sind.

## Erweitern

- **Neues Modell:** `ModelConfig` in `config.py` ergänzen, ggf. Adapter in `models/` (Subklasse von `BaseModel`) und in `evaluator._build_model` eintragen.
- **Neues SAST-Tool:** Subklasse von `BaseSastRunner` in `sast/` mit `analyze(code, language)`, in `Evaluator._init_sast` registrieren.
- **Eigene Semgrep-Regeln:** `sast/rules/purplellama/`.
