# Regulated Asset AI Adapter

## What this is

Sentinel is a local AI risk and policy layer for regulated asset systems. It
reads attestations from external providers (identity, custody, oracles,
compliance), applies configured policy, and emits a decision with a receipt.

It does not provide KYC, custody, settlement, legal compliance, oracle trust,
or ZK proofs. It consumes the outputs of systems that do.

## Architecture

```
Regulated asset application
  ├── identity / KYC provider        → kyc_attestation
  ├── custody provider               → signer_status
  ├── settlement rail / chain        → settlement_metadata
  ├── oracle / data feed provider    → oracle_signal
  ├── legal / compliance framework   → policy_config
  ├── optional ZK / proof system     → proof_reference
  └── Sentinel local AI risk layer   → decision + receipt
```

Sentinel sits at the bottom. It reads all inputs, classifies risk, and
outputs a recommendation. The asset system above decides what to do with it.

## What Sentinel provides

- **Local model inference** — runs on-device, no data leaves the box
- **Local event memory** — sliding window of recent events with state hashing
- **Risk classification** — low / medium / high / critical
- **Reason codes** — machine-readable explanations (velocity, counterparty_risk,
  jurisdiction_mismatch, pattern_anomaly, etc.)
- **Receipt** — every decision produces a JSON receipt with model ID, codec,
  runtime, memory state hash, input attestation hashes, and SHA256 of the
  full receipt
- **Recommendation** — allow / hold / review / escalate / reject

## What Sentinel does NOT provide

- **Legal finality** — Sentinel outputs risk assessments, not legal rulings
- **KYC verification** — Sentinel reads KYC attestations; it does not verify
  identity documents
- **Custody** — Sentinel gates actions before signing; it does not hold keys
- **Settlement** — Sentinel runs pre-checks; it does not execute transactions
- **Oracle trust** — Sentinel consumes verified oracle outputs; it does not
  attest to external data
- **ZK proofs** — Sentinel emits evidence that can be committed or hashed
  into a proof system; it does not generate proofs

## Integration boundary

### Inputs (consumed from external providers)

| Input | Schema | Provider |
|---|---|---|
| Transfer/event request | `regulated_asset_event.schema.json` | Asset application |
| KYC attestation | `kyc_attestation.schema.json` | Identity provider |
| Oracle risk signal | `oracle_signal.schema.json` | Oracle network / data feed |
| Policy configuration | Sentinel config file | Compliance / legal counsel |

### Output (produced by Sentinel)

| Output | Schema | Consumer |
|---|---|---|
| AI decision receipt | `ai_decision_receipt.schema.json` | Asset application, audit log |

### Adapter pattern

Each external system is accessed through an adapter — a thin translation
layer that converts the provider's native format into the schema Sentinel
expects.

```python
class KycAdapter:
    """Translates KYC provider response into kyc_attestation schema."""
    def translate(self, provider_response: dict) -> dict:
        return {
            "attestation_id": provider_response["id"],
            "provider": "example_kyc_provider",
            "status": provider_response["verification_status"],
            "jurisdiction": provider_response["country_code"],
            "risk_tier": map_risk(provider_response["risk_score"]),
            "timestamp": provider_response["verified_at"],
            "hash": sha256(canonical_json(provider_response)),
        }
```

Sentinel never calls external APIs directly. Adapters are injected by the
asset application. This keeps Sentinel portable and testable without live
provider connections.

## Decision flow

```
1. Asset app receives transfer request
2. Asset app collects attestations (KYC, oracle, custody status)
3. Asset app sends event + attestations to Sentinel
4. Sentinel:
   a. Updates local memory with event
   b. Extracts features (velocity, amount, counterparty history, etc.)
   c. Runs local model inference (HXQ-compressed, GGUF/llama.cpp or native)
   d. Applies policy rules (jurisdiction, limits, blocklists)
   e. Classifies risk level
   f. Emits decision + receipt
5. Asset app reads decision and acts (allow / hold / review / reject)
6. Receipt is logged for audit
```

## Receipt contract

Every decision produces a receipt. The receipt is the proof that a specific
model, with specific inputs, at a specific time, produced a specific output.

```json
{
  "receipt_version": "1.0",
  "event_id": "evt_20260502_001",
  "asset_id": "asset_abc123",
  "asset_type": "tokenized_equity",
  "policy_version": "policy_2026_05_02",
  "model_id": "zamba2-2.7b-sentinel-lora",
  "model_codec": "hxq_affine_6",
  "runtime": "local_llama_cpp",
  "memory_state_hash": "sha256:abc...",
  "input_attestation_hashes": [
    "sha256:kyc_...",
    "sha256:oracle_..."
  ],
  "decision": "review",
  "risk_level": "high",
  "reason_codes": ["velocity", "counterparty_risk"],
  "confidence": 0.82,
  "timestamp": "2026-05-02T17:45:00Z",
  "sha256": "full_receipt_hash"
}
```

## Why this is useful

Most systems have the rails and legal wrappers, but their AI/risk layer is:

- Closed (proprietary model, no inspection)
- Hosted (data leaves the perimeter)
- Expensive (per-call pricing)
- Opaque (no receipt, no reason codes)
- Hard to audit (model versions undocumented)

Sentinel can be:

- **Local** — runs on-device, air-gapped if needed
- **Open** — MIT license, inspectable source
- **Receipt-backed** — every decision has a verifiable proof
- **Runtime-portable** — GGUF/llama.cpp, native C, or Python
- **Calibration-free** — HXQ codec requires no training data exposure
- **Auditable** — model ID, codec, policy version, memory hash in every receipt

## Schemas

See `schemas/` directory:

- `regulated_asset_event.schema.json` — transfer/event input
- `kyc_attestation.schema.json` — identity attestation input
- `oracle_signal.schema.json` — oracle/data feed input
- `ai_decision_receipt.schema.json` — decision output

## Examples

See `examples/` directory:

- `synthetic_transfer_event.json` — sample transfer request
- `synthetic_decision_receipt.json` — sample AI decision output
