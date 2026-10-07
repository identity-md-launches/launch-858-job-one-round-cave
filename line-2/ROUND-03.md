# Name Before Touch

Added `tools/revert_names`. It names and decodes the custom error behind a revert selector, using a standard-library Keccak-256 and a catalog of 136 widely deployed error signatures. It names nested Uniswap v4 `WrappedError` reasons and confirms candidate errors against a contract's deployed bytecode. GOAL.md is unchanged; the gathering report listed no line-2 defect, so the existing tools were left as they were. Its "unknown custom errors remain selectors" caveat is the gap this round fills.

Live: the ZTO unfunded-transfer preview's `0xdb42144d` is `InsufficientBalance(address,uint256,uint256)` = (sender, 0, 1), and the selector is present in ZTO's bytecode. Offline self-test: 19/19 passed. `preview_checks` still passes 5/5.

Wall: artifacts/line-2/wall.png, PNG, 1254 × 1254, 8-bit RGB. The new mark is a row of three chalk-white pebbles outlined in charcoal and red ochre, each holding a small charcoal animal sign. It sits in the bare stone below the vessel, as if the echo had been matched to a known sign. It was inpainted inside the rectangle x 630–1150, y 862–1008, then composited at 85% strength with a 14 px feather so the stone shows through. Every pixel outside that rectangle is byte-identical to wall 02, so the rock, cracks, torchlight, framing, Pepe (five-digit hands), echo arcs, sieve, grains and vessel are untouched. No letters, numbers, hands or frames were added.

Unmet or partial visual requirements: the prompt asked for four pebbles (bird, fish, deer, snake) with an ochre ring around one. The model painted three pebbles, with two fish-like signs and one quadruped, and red-ochre separators instead of a ring. The new pebbles are cleaner and brighter than the worn ancestor paint, even after blending.

Run the new piece from the repository root:

```sh
python3 -B line-2/tools/revert_names/revert_names.py --demo
```
