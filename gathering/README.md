# The Patient Carrier — gathering 03

Wall: artifacts/gathering/wall.png, PNG, 1254 × 1254, matching predecessor 02.
Record: dist/gathering/03.json. The ancestor was downloaded from its recorded
artifact URL and SHA-256 verified before editing. Only the final wall image is
saved in the workspace; named outputs remain untracked.

Built-in imagegen edit added an ochre/charcoal tortoise carrying a chalk-white
pebble on vacant rock to Pepe's upper right. Visual inspection found the main
Pepe's wide mouth/heavy-lidded eyes, ancestral birds, trails and hearth retained,
along with the warm rock, cracks, light and square framing. No text, numbers,
logos, signatures, borders, real people or prohibited symbols were observed.
No new hands or handprints; ancestral hands remain concealed, so there are no
visible digits to count. Tortoise feet are animal feet, not hands.

Unmet visual requirement: exact preservation of every rock/pigment pixel cannot
be certified. The generative edit has slight texture/pigment variation; it retains
visible ancestral marks in place. Structural checks do not establish visual
quality or perfect ancestry preservation. Visual review was performed explicitly.

Final prompt (built-in imagegen, edit mode): preserve the ancestral 1254-square
wall's dimensions, rock, cracks, colors, light, framing and every existing mark,
including Pepe, birds sharing a white stone, dotted trails and fire. Add only a
small primitive ochre/charcoal tortoise on vacant rock at Pepe's upper right,
carrying a white pebble. Worn irregular earth pigment, bare rock showing through,
Lascaux torchlight; Pepe remains main figure. No hands, text, numbers, logos,
watermarks, frames, people or prohibited symbols. Return the whole PNG wall.

Shared deliverable: agreement-gated ZTO preview now names custom reverts while
retaining raw data. All copied modules have source hashes in shared/provenance.json.
Offline composition checks and live supply/revert previews passed. Every line's
checks, remaining defects and scope assessment are in REPORT.md. COINS.md says
none: public reads and local analysis require no new coin or deployment.

Run from the workspace root:

```sh
python3 -B shared/check_named.py
```

This checks complete ZTO error arguments, truncation, unknown selectors and
provider generators without network. Existing shared checks also pass. Gallery
is self-contained HTML/CSS, with all recorded artifact URLs grouped by wall,
newest first; its images require access to those public URLs. Rebuild it with
`python3 -B gathering/build_gallery.py`. No transaction was sent or signed.
