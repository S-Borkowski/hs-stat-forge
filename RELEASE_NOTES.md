# HS Offline Stat Forge v2.2.0 — Adaptive Build Resolver

## Fixed

- Removed the single-build `Hero_Siege.exe` SHA-256 allow-list that rejected compatible Steam and non-Steam Season 10 executables.
- Magic Find, Movement Speed and All Skills now resolve by exact GameMaker function name and validate the native YYC entry structure before patching.
- EXP Multiplier now resolves by a unique instruction context without requiring a whole-file fingerprint.
- Existing local v2 configuration files migrate automatically to adaptive v3 resolver definitions.
- Restore operations verify original bytes before proxy memory is released.
- Non-finite stat values are rejected.
- The packaged application requests administrator privileges automatically.

## Verification

- Read-only resolver tests pass against Hero Siege 7.0.0 (`ba72b95a...`).
- Read-only resolver tests pass against Steam Hero Siege 7.0.2 (`0766aa8b...`).
- Private proxy allocation, write, verification and release pass in a live Windows process.
- Corrupted function entries are rejected without process writes.

## Upgrade

Close older StatForge versions, extract the v2.2.0 package into a fresh folder, launch Hero Siege without EAC and run the new executable.

Offline/single-player only. `Hero_Siege.exe` on disk is never modified.
