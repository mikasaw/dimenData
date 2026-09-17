# dimenData — Windows Hardware Inventory & Device Fingerprint Tool

[![CI](https://github.com/mikasaw/dimenData/actions/workflows/ci.yml/badge.svg)](https://github.com/mikasaw/dimenData/actions/workflows/ci.yml)

Collects key hardware and system identifiers on Windows and produces a device fingerprint
(primary use case: software licensing / device binding; also usable for IT asset inventory).

**Language:** [中文](README.md) | English &nbsp;·&nbsp; **License:** MIT

> ⚠️ **Privacy notice.** This tool reads device identifiers (board/system/disk serial numbers,
> SMBIOS UUID, NIC MAC addresses, GPU UUID, OS identifiers). Reports it produces therefore
> contain device-identifying data — treat generated reports as sensitive and do not commit them
> to public repositories. All device identifiers shown in the documentation and test fixtures of
> this repository are masked or synthetic.

## Design highlights

- **Modular multi-channel collection**: every collection technique (smbios / wmi / registry /
  native / cpuid …) implements one `IChannel` interface and self-registers into
  `ChannelRegistry`; all channels run concurrently on a thread pool, and results for the same
  field are merged by `FIRST_BY_PRIORITY` / `CONSENSUS` (cross-validation) / `MERGE_LIST`
  (multiplicity-preserving union) / `CONSENSUS_ALIGNED` (per-instance alignment, e.g. disks by
  slot index).
- **Fingerprint algorithm**: value normalization (cpu.id byte-order unification R1/R2, disk
  serial R4, dates R12) → weighted selection → SHA-256 (CNG). Produces a master fingerprint plus
  per-component sub-fingerprints (bios/board/cpu/disk/gpu/memory/nic/os/sys) and a
  group-weighted similarity score that tolerates minor hardware changes.
- **Algorithm version stamp**: the fingerprint depends on {field set + weights + normalization
  rules}, so reports carry `fingerprint.algo`. After an algorithm revision, `--verify` reports
  `algorithm_changed:true` with `integrity:null` and exit code 4 instead of falsely flagging a
  report as tampered.
- **Zero third-party runtime dependencies**: hashing uses Windows CNG, the CRT is linked
  statically; `build/hwfp.exe` is a single distributable file. All helpers in this repository
  (JSON parser/writer, unit-test framework, thread pool) are implemented in-tree — no external
  library code is vendored or linked.
- **Offline licensing loop** (`src/license/`): RSA-2048 + SHA-256 + PKCS#1 v1.5 signatures
  (pure CNG — Ed25519 is not offered by CNG). `keygen` creates a key pair → `license --issue`
  signs a canonical license text (machine-bound via fingerprint, or floating) → `license
  --check` verifies signature + expiry + machine binding (group-weighted similarity threshold,
  default 0.85, tolerant to minor hardware changes). All license payload fields (sub/features)
  are covered by the signature — tampering any of them fails verification.

## Build (MSVC, no CMake)

```bat
build.cmd               # build and run all unit tests (69 cases)
build.cmd app           # build build\hwfp.exe
build.cmd smoke         # build and run smoke test (collect + merge + fingerprint)
build.cmd fuzz 200000   # build and run the deterministic fuzzer (default 200k rounds)
build.cmd dll           # build build\hwfp.dll (C ABI integration library)
build.cmd dlltest       # build hwfp.dll and run the integration consumer self-check
build.cmd clean         # remove the build dir and stray .obj files
```

Requires Visual Studio (currently the VS 18 Insiders toolchain; the `vcvars64.bat` path is
resolved inside `build.cmd`).

## hwfp.dll integration API (C ABI)

`build/hwfp.dll` can be loaded by host applications (implicit link against `build/hwfp.lib`
or `LoadLibrary`). All strings are UTF-8; output buffers must be released with `Hwfp_Free`
(static CRT — never free across module boundaries):

```c
#include "dll/hwfp_dll.h"          // ships with the repo, header-only, no deps

Hwfp_Version();                    // "0.1.0"
Hwfp_Collect(&json);               // collect + fingerprint -> schema-v1 JSON (defaults)
Hwfp_CollectWithConfig(cfg, &j);   // same, config JSON text provided by the caller
Hwfp_CheckLicense(lic, pub, 0.85, &result);
                                   // returns 0 valid / 5 format or signature invalid /
                                   // 6 expired or machine mismatch / 3 collect failed /
                                   // 2 bad arguments
Hwfp_Free(p);
```

The DLL never reads a config file implicitly (defaults = all channels at default
priority/weight). Every entry point is independent and reentrant. `build.cmd dlltest`
builds the DLL and runs the `tools/dll_consumer.cpp` integration self-check.

## Usage

```bat
hwfp.exe                                  :: collect, write schema-v1 JSON to stdout
hwfp.exe --config config/hwfp.json -o report.json
hwfp.exe --text                           :: human-readable summary
hwfp.exe --verify report.json             :: compare against a historical report
                                          :: (integrity + similarity)
hwfp.exe --fields                         :: list field keys, merge strategy, weight
hwfp.exe keygen --privkey k.priv --pubkey k.pub   :: licensing key pair (RSA-2048)
hwfp.exe license --issue --licensee Acme --privkey k.priv [--expires 2027-12-31]
                                          :: issue a license (machine-bound by default;
                                          :: --floating for a floating license)
hwfp.exe license --check license.json --pubkey k.pub [--threshold 0.85]
                                          :: verify signature + expiry + machine binding
:: exit codes: 0 ok/valid / 2 bad args or config / 3 collect, integrity or key-op failure
::             4 algorithm version mismatch / 5 license format or signature invalid
::             6 license expired or machine mismatch
```

Configuration (`config/hwfp.json`): per-channel enable/priority, per-field merge strategy and
weight (wildcards such as `memory.*` supported), worker count, and the wmi `tpm_probe` option
(off by default: on some motherboards connecting to the `MicrosoftTpm` namespace blocks for ~5 s,
see rule R16).

## Tests & fuzzing

- **Unit tests**: 69 cases, zero-dependency in-house framework (`tests/`); all parser and
  license fixtures use synthetic values.
- **Fuzzing** (`tools/fuzz_main.cpp`, `build.cmd fuzz [rounds] [seed]`): seven targets
  (json / config / smbios / edid / nvidiasmi / pipeline / license), fully deterministic seeds
  with built-in oracles — valid baselines must be recovered exactly, failures must carry an
  error message, JSON number text must be self-stable, nvidia-smi CSV parsing is cross-checked
  field-by-field against an independent re-implementation, merge output must satisfy structural
  invariants, report round-trips must reproduce the original fingerprint, and any accepted
  license must be field-identical to its original. Failures print a reproduction seed and dump
  `build/fuzz_repro_<target>.bin` (it caught a real `NumberToString` `%.6g` exponential-form
  text drift).
- **CI** (GitHub Actions, `windows-latest`): unit tests → build hwfp.exe → CLI sanity →
  smoke collect (real identifiers stay on the ephemeral runner, only the timing summary line
  reaches the public log) → fuzz; a 2M-round long run is scheduled weekly.

## Repository layout

```
src/core/        field table (fields.def), IChannel/ChannelRegistry, merger, scheduler, JSON, config
src/channels/    channel modules: smbios / registry / native / wmi (+ pure-function parsers)
src/fingerprint/ fingerprint engine (normalization, weighting, SHA-256) and CNG wrapper
src/license/     offline licensing (RSA-2048 signatures / canonical / verification)
src/dll/         hwfp.dll C ABI exports (public header hwfp_dll.h)
src/cli/         hwfp.exe entry point and report (schema v1) build/parse
tests/           zero-dependency unit tests (69 cases)
tools/           smoke runner, deterministic fuzz harness, DLL integration consumer
poc/             M1 proof-of-concept collectors (kept as engineering evidence)
config/          default configuration
docs/            M1 POC availability matrix (measured values + rules R1–R17)
开发计划.md       development plan (Chinese): architecture, milestones, risks
```

## Documentation

- [Development plan (Chinese)](开发计划.md) — multi-channel architecture, milestones, risks
- [M1 POC availability matrix (Chinese)](docs/M1-POC-采集项可用性矩阵.md) — dual-environment
  measurements and 17 normalization rules (R1–R17)

> Both deep-dive documents are currently Chinese-only; this README is the English entry point.

## Status

| Milestone | Status |
|---|---|
| M1 technical POC | ✅ verified on host + VMware guest |
| M2 collection framework (multi-channel) | ✅ 4 channels + scheduler + merger (reviewed) |
| M3 fingerprint engine | ✅ normalization / weighting / master+sub fingerprints / similarity (reviewed) |
| M4 CLI & output | ✅ hwfp.exe (schema v1 / verify / configurable) |
| Integration | ✅ host: 86 field instances, ~210 ms; guest: 44 instances, ~460 ms; fingerprints byte-identical across runs |
| Remaining | TPM re-test with admin rights, validation on ≥3 OEM machines, code signing, M5 hardening |

## Known limitations

- WMI semi-synchronous enumeration cannot be interrupted safely; a single query has no hard
  timeout (`per_task_timeout_ms` is recorded in the config for future use).
- Virtual devices are filtered by PNP bus prefix (R6): ROOT/SWD software display adapters
  (e.g. GameViewer, Microsoft Basic Display) and virtual NICs (VMware VMnet) are excluded;
  PCI-bus virtual display adapters inside a VM (VMware SVGA/VirtualBox/QXL/Virtio) are kept, as
  they are that machine's real display hardware.
- Memory serial numbers are unreliable (R8) — only capacity/DIMM count feed the fingerprint;
  disks are aligned per slot (ConsensusAligned, R5).
- TPM fields are not probed by default (R16: ~5 s block on some motherboards; enable with
  `tpm_probe: 1`).
- `gpu.uuid` requires spawning `nvidia-smi` (absolute System32 path, 3 s hard timeout, explicit
  handle-inheritance whitelist) — a process-creation behavior that AV/EDR products may flag.
  Consumer GPUs expose no serial number, so the UUID is their only stable identifier (R17).
  **This field participates in the fingerprint** (group `gpu`, weight 5): only NVIDIA platforms
  have a value (AMD/Intel simply produce no such group and are unaffected), and swapping or
  adding a GPU changes the master fingerprint and the `gpu` sub-fingerprint — relevant for
  strict device-binding scenarios.
- `--verify` recomputes with the **currently configured weights**, which must match those used
  when the report was generated; the `weights_override` output flag tells whether a config
  override was in effect (in which case the integrity verdict is meaningful only if both sides
  used the same weights).

## License

[MIT License](LICENSE) © 2026 mikasaw