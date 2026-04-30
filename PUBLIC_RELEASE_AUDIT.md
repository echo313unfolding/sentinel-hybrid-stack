# Public Release Audit — Sentinel Hybrid Stack v0.1

**Audit date:** 2026-04-30
**Auditor:** Automated sanitization check + manual review
**Status:** PASS — ready for publication pending final human review

## Sanitization Checks

| Check | Status | Notes |
|-------|--------|-------|
| No private filesystem paths | PASS | No `/home/`, `~/`, `.claude/` references |
| No API keys or tokens | PASS | No HF_TOKEN, ANTHROPIC_API_KEY, etc. |
| No internal model paths | PASS | No `.gguf`, model file paths, or server ports |
| No internal tool references | PASS | No echo_nav, echo_bridge, sentinel.db |
| No hardware identifiers | PASS | No T2000, RunPod, pod references |
| No internal receipt paths | PASS | No `~/receipts/` references |
| No `.claude` memory references | PASS | No memory files or session data |
| Only synthetic eval data | PASS | All alert text is synthetic/fictional |
| No real IPs or hostnames | PASS | Only RFC 5737 (203.0.113.x), RFC 1918 (10.x, 192.168.x) |
| No real usernames | PASS | All names are synthetic (ops_admin, finance_temp2, etc.) |
| No real CVE IDs | PASS | All CVEs are fictional (CVE-2026-xxxx) |

## Tests

```
60 passed in 0.22s
```

- `test_features.py` — 17 tests: Level 0 feature extraction
- `test_gate.py` — 22 tests: All 4 gate rules (G1/G2/G4/G6) + edge cases
- `test_ssm.py` — 21 tests: State creation, decay, stage advancement, suppressor, LRU eviction, summarization

No LLM server required for any test. All tests use deterministic state logic with synthetic verdicts.

## File Inventory

| File | Lines | Role |
|------|-------|------|
| `src/sentinel_hybrid_stack/__init__.py` | 18 | Public API exports |
| `src/sentinel_hybrid_stack/features.py` | 150 | Level 0 regex feature extraction |
| `src/sentinel_hybrid_stack/codons.py` | 240 | Entity/action/quality codon encoding |
| `src/sentinel_hybrid_stack/ssm.py` | 380 | Handmade SSM state engine |
| `src/sentinel_hybrid_stack/gate.py` | 200 | Post-LLM gate rules |
| `src/sentinel_hybrid_stack/scorer.py` | 75 | Verdict scoring |
| `tests/test_features.py` | 80 | Feature extraction tests |
| `tests/test_ssm.py` | 200 | SSM state tests |
| `tests/test_gate.py` | 270 | Gate rule tests |
| `examples/walkthrough.py` | 130 | End-to-end demo (no LLM) |
| `pyproject.toml` | 22 | Package config |
| `README.md` | 150 | Documentation |
| `LICENSE` | 21 | MIT license |

## Provenance

This public skeleton is derived from frozen internal code at:
- `tools/sentinel/runtime/hybrid_stack.py` (gate logic)
- `tools/sentinel/memory/handmade_ssm.py` (SSM engine)
- `tools/sentinel/eval/level0_handfeatures.py` (features)
- `tools/sentinel/eval/handcrafted_codon_memory.py` (codons)
- `tools/sentinel/eval/scorer.py` (scorer)

Changes from internal code:
1. All imports rewritten to use `sentinel_hybrid_stack.*` package structure
2. Removed all internal path constants (LLAMA_SERVER, MODEL_PATH, RECEIPTS_DIR)
3. Removed LLM query functions (query_llama) — not needed for the public API
4. Removed eval runner infrastructure (server lifecycle, warm-up, receipt writing)
5. Removed internal eval event sets (hard20, extended60, stress20) — replaced with synthetic examples
6. Gate and SSM are self-contained with no external dependencies

## SHA256 Manifest

```
fc84498f5cdf7a3d556858ab802ab83a2b0c4b9a66e7529d3f39e8d5ca3d47e6  ./examples/walkthrough.py
aa3589c575b5976e4250591c77f46d18b36b63471b88b37d44ce46d57eae7fe9  ./LICENSE
216a4903b0c3f1febc968f2454c91dde5b011e48fb8eecc1354bd8b6a1ed8058  ./pyproject.toml
af90ee70477d977637c14a3c1dc822387e85ebf3aeffa0a8d231228d0da14dc6  ./README.md
73ace6fe9c7ebe9b52fcc350d38b3485ef6d6380f955d2d93c6c352240d6fcfb  ./src/sentinel_hybrid_stack/codons.py
175aeb34269f7618d2fae0eb3996baaa5dfd381a0726eea7e2867b34b6d80b05  ./src/sentinel_hybrid_stack/features.py
01c0505376afa5be4586af72ec14fcbc98fad0b5cc3e0d317c3f17a2ad056fd7  ./src/sentinel_hybrid_stack/gate.py
e3d246e779fd64045bd506bcb457f1a8a69d3e80c173008aefa1364c47f2df6e  ./src/sentinel_hybrid_stack/__init__.py
d67bef864aa5568035c547a8d178bd011a1ddc209d4f8c4fcdf3c24555977d46  ./src/sentinel_hybrid_stack/scorer.py
2c192eb786100e82514dda22369d580fa66319af0450afd6f91a7b59d9545ebb  ./src/sentinel_hybrid_stack/ssm.py
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ./tests/__init__.py
ebec346b416452e88522d296c663c2774084eb2f6dbdda8c72eb32bbeba8c501  ./tests/test_features.py
d313a72dd620fa03335e91ff8a8f82091cda7029c65e09f00235b2438b380fdc  ./tests/test_gate.py
c1d94ad7c59ccbf72c30d52eb2768c3e49caeaa9ceccd8d98cea3832ef5fc7e3  ./tests/test_ssm.py
```

## Verification

```bash
cd sentinel-hybrid-stack-public
pip install -e ".[dev]"
pytest -v                          # 60 tests, no LLM required
python examples/walkthrough.py     # end-to-end demo

# Verify no private content
grep -rn '/home/\|~/\.\|\.claude\|api.key\|HF_TOKEN\|ANTHROPIC\|voidstr\|echo_nav\|sentinel\.db' src/ tests/ examples/
# Expected: no output
```
