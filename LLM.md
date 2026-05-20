# Lux Contracts

Canonical Solidity helpers and interfaces for the Lux EVM. Thin wrappers
around the native precompiles in `luxfi/precompile`. One source of truth
for L1 contract authors.

**Latest commit**: `cb13a04` (initial PQAuth library + IPQVerify
interface + Foundry tests). No tags yet — repo is pre-`v0.1.0`.

## Post-E2E-PQ State (current)

This repo lands the on-chain Solidity surface for the strict-PQ profile:

- `PQAuth.sol` library + concrete `PQVerify` contract — thin wrappers
  around the ML-DSA / SLH-DSA / Ringtail precompiles.
- `IPQVerify.sol` interface — what callers depend on. `verifyZAuthProof`
  is reserved for the tx-type 0x05 PQAuthTx path (Option B in the
  strict-PQ rollout plan, currently reverts).
- Foundry test suite (`test/pqauth/PQAuth.t.sol`) uses `vm.etch` to mock
  the native precompiles, so tests run without a Lux node.

The companion change in `luxfi/geth` provides the
`vm.SetActiveSecurityProfile` install point and the
`ErrClassicalAuthForbidden` error path. The on-chain refusal of
`ecrecover` under `ForbidECDSAContractAuth=true` is geth-side; this repo
only owns the canonical PQ wrappers.

### Cross-repo dependencies
- `luxfi/precompile` → native precompile addresses (0x012201..0x012204,
  0x002221).
- `luxfi/geth` → `vm.LuxSecurityProfile` install point.
- `luxfi/consensus/config` → canonical `ChainSecurityProfile`.
- `luxfi/consensus/protocol/auth/hash.go` → TupleHash256 digest spec
  (off-chain producer side; on-chain takes precomputed digest).

### Active versions
- This repo: pre-tag (commit `cb13a04`).
- Foundry: `solc 0.8.27`, `evm_version=cancun`.

### Where to look for X
- PQAuth library: `src/pqauth/PQAuth.sol`
- IPQVerify interface: `src/pqauth/IPQVerify.sol`
- Foundry tests: `test/pqauth/PQAuth.t.sol`
- Permit digest convention: see `luxfi/consensus/protocol/auth/hash.go`

## Layout

```
src/
  pqauth/
    IPQVerify.sol     -- interface: verify ML-DSA-65, ML-DSA-87, SLH-DSA, zAuth proof
    PQAuth.sol        -- library + concrete PQVerify contract
test/
  pqauth/
    PQAuth.t.sol      -- Foundry tests against etched mock precompiles
foundry.toml          -- single Foundry config, evm_version=cancun, solc 0.8.27
lib/forge-std/        -- Foundry's stdlib (test framework)
```

## PQAuth: native precompile wrappers

Native precompile addresses (canonical, see `luxfi/precompile`):

| Address  | Precompile         | Notes                              |
|----------|--------------------|------------------------------------|
| 0x012201 | ML-KEM-768         | FIPS 203 key encapsulation         |
| 0x012202 | ML-DSA verify      | FIPS 204 signatures (44/65/87)     |
| 0x012203 | SLH-DSA verify     | FIPS 205 hash-based signatures     |
| 0x012204 | Ringtail threshold | Lattice threshold verify (PQ)      |
| 0x002221 | X-Wing hybrid KEM  | X25519 + ML-KEM-768 hybrid         |

`PQAuth` library functions (internal, no external call):
- `verifyMLDSA44(pubkey, msgDigest, sig) -> bool`
- `verifyMLDSA65(pubkey, msgDigest, sig) -> bool`
- `verifyMLDSA87(pubkey, msgDigest, sig) -> bool`
- `verifySLHDSA (pubkey, msgDigest, sig) -> bool`
- `verifyPermit(pubkey, msgDigest, sig)` — reverts on invalid

`PQVerify` is a concrete `IPQVerify` deployment when callers need an
address rather than a library import.

## Permit digest convention

The on-chain contract takes a `bytes32 msgDigest`. Off-chain signers
compute the digest as:

```
msgDigest = TupleHash256(parts, 32, "LUX_PQ_PERMIT_V1")
```

per NIST SP 800-185 §5, where `parts` is the canonical permit field
sequence. Reference Go implementation:
`luxfi/consensus/protocol/auth/hash.go`.

We do not implement TupleHash256 in Solidity. The EVM lacks cSHAKE256
and Solidity emulation costs ~200k gas with a high risk of subtle
field-framing bugs. The on-chain contract accepts a precomputed digest
and verifies against it.

## Gas comparison

| Path                                 | Verify gas (32-byte digest) |
|--------------------------------------|-----------------------------|
| ETHDILITHIUM (LGPL-3.0, Solidity YUL) | ~8,100,000                  |
| **PQAuth.verifyMLDSA65 (native)**    | **100,000 + 320 = 100,320** |
| **PQAuth.verifyMLDSA87 (native)**    | **150,000 + 320 = 150,320** |
| **PQAuth.verifyMLDSA44 (native)**    | **75,000 + 320 = 75,320**   |

The native precompile is ~80x cheaper than ETHDILITHIUM. Do not vendor
or re-implement ML-DSA in user contracts — both for gas reasons and
because ETHDILITHIUM is LGPL-3.0 and not compatible with the Lux
contracts BSD-3-Clause licence.

## Strict-PQ profile

The Lux EVM enforces post-quantum auth at the precompile layer when the
active `ChainSecurityProfile` has `ForbidECDSAContractAuth=true`. In
that mode the classical `ecrecover` precompile at `0x01` returns
`ErrClassicalAuthForbidden` instead of a recovered address. Contracts
under that profile MUST use `PQAuth` (or another PQ verifier) for
authentication.

See:
- `luxfi/geth/core/vm/lux_security_profile.go` — atomic-pointer install
  point and `ErrClassicalAuthForbidden` error
- `luxfi/consensus/config/security_profile.go` — canonical profile
  definition
- `luxfi/genesis/pkg/genesis/security_profile.go` — genesis-level pin
  and hash verification

## Building

```bash
forge build       # compile
forge test        # run tests (uses vm.etch to mock precompiles)
forge test -vvv   # verbose with traces
```

## Open work

- **F102 wiring** (`luxfi/node`): copy `ForbidECDSAContractAuth` from the
  resolved profile into a `vm.LuxSecurityProfile` and call
  `vm.SetActiveSecurityProfile` at chain bootstrap. Without this, the
  strict-PQ refusal is dormant. The geth-side machinery is in place.
- **Tx-type 0x05 PQAuthTx** (Option B in the strict-PQ rollout plan):
  separate multi-week project. The `verifyZAuthProof` method on
  `IPQVerify` is reserved for this path and currently reverts.

## Licence

BSD-3-Clause. See `LICENSE`.
