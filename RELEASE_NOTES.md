# HS Offline Stat Forge v2.1.0

This is the completed Season 10 rebuild of StatForge.

## Highlights

- Added verified native Season 10 runtime routes for Magic Find, Movement Speed, All Skills and EXP Multiplier.
- Replaced obsolete Season 9 addresses and removed retired unsafe bindings.
- Added reversible proxy patches with original-byte restoration and **Restore All** support.
- Added game-build fingerprint validation so unsupported executables are rejected safely.
- Reduced toggle delays by caching PE section data and resolved function addresses.
- Rebuilt the interface in the Obsidian Forge design language used by LootForge.
- Added modern stat cards, live status indicator, active-forge strip, hover states and a redesigned process selector.
- Fixed packaged configuration persistence: `hs_statforge_stats.json` is now read and saved beside the executable.

## Default values

- Magic Find: `500`
- Movement Speed: `111`
- All Skills: `28`
- EXP Multiplier: `10x`

These are editable starting values, not hard limits except where the interface shows a defined maximum.

## Important

Offline/single-player only. The executable on disk is never modified.
