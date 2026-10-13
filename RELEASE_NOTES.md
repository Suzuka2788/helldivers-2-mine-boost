# Suzuka’s Mine Boost v1.0.1

Helldivers 2 minefield addon for Bingus Shared Loader v15+.

## Gameplay
- Anti-tank mines retain their original model, physics and trigger threshold, using Melta explosion type 368: 2000 normal/durable damage, AP 7/7/7/0, inner/outer radius 2.5/6 m.
- Anti-personnel and incendiary mines require Medium or larger units to trigger. Small enemies and Helldivers do not trigger them by stepping; shooting can still detonate mines. This is a size filter, not faction filtering or damage immunity.
- Mine count, spread, cooldown and timing are unchanged.

## Changes in v1.0.1
- Bind Windows functions with private FFI signatures to avoid conflicting declarations from other addons.
- Detect active legacy mine scripts and avoid duplicate writes; support polling without a pre-existing update callback.
- Use a verified PE fingerprint with SHA-256 fallback and shared hash cache to reduce startup work.
- Batch validation reads, reuse buffers and stagger verification frames. Mock steady-state reads decreased from 60 to 30 over 6000 frames.
- Preserve the v1.0.0 GUID and gameplay resources.

## Installation
Close the game. Disable older AT-Melta-Native-Model, Mines-Medium-Trigger and Mine Deployer Swap packages. Import the ZIP into your mod manager and enable this combined addon with Bingus Shared Loader v15+.

## Validation
Offline tests passed for FFI conflicts, read-only page writes, lifecycle/rollback/restoration, fingerprint/hash fallback, legacy coexistence, scheduling, Lua syntax and ZIP integrity. Gameplay assets match v1.0.0. v1.0.1 has not yet been tested in game; unsupported game builds are rejected.

SHA-256: `4e031dacce6317484bd08e960d2f20baeec7b0e473e736a43299a579dfd53d00`
