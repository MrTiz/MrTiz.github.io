"""
Subset Inter (sans) and Cascadia Code (mono) woff2 files down to the Unicode
ranges actually used by this site, plus a defensive margin for future content.
Overwrites the files in assets/fonts/ in place.

Ranges were picked from _tools/audit_chars.py output. If you add content that
uses new code points outside the current subsets, either:
  (a) extend INTER_UNICODES / CASCADIA_UNICODES here and re-run, or
  (b) replace the char with something inside the current subset.
Re-run audit_chars.py to check.

Requires: pip install fonttools brotli
"""

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FONTS = REPO / "assets" / "fonts"

INTER_UNICODES = ",".join([
    "U+0000-00FF",   # Basic Latin + Latin-1 Supplement (Italian àèéìòù, §, ×, ·, ...)
    "U+0131",        # dotless i
    "U+0152-0153",   # OE / oe ligature
    "U+02BB-02BC",   # modifier letters (Hawaiian-style okina, apostrophes)
    "U+02C6",        # combining circumflex
    "U+02DA",        # ring above
    "U+02DC",        # small tilde
    "U+2000-206F",   # General Punctuation (em/en dash, curly quotes, bullets, ellipsis)
    "U+2074",        # superscript 4
    "U+20AC",        # € Euro sign
    "U+2122",        # ™ trade mark
    "U+2190-2193",   # ↑ → ↓ ← (defensive)
    "U+2212",        # − minus sign
    "U+2215",        # ∕ division slash
    "U+2265",        # ≥ (used in prose in CET post)
    "U+FEFF",        # BOM
    "U+FFFD",        # replacement character
])

CASCADIA_UNICODES = ",".join([
    "U+0000-00FF",   # Basic Latin + Latin-1 Supplement
    "U+0131",
    "U+0152-0153",
    "U+2000-206F",   # General Punctuation
    "U+2190-21FF",   # Arrows (full block — → ← and related)
    "U+2200-22FF",   # Mathematical Operators (≥ ≤ ± ≠ ∈ ∀ etc.)
    "U+2500-257F",   # Box Drawing (stack diagrams in CET post)
    "U+2580-259F",   # Block Elements
    "U+FEFF",
    "U+FFFD",
])

TARGETS = [
    ("InterVariable.woff2", INTER_UNICODES),
    ("InterVariable-Italic.woff2", INTER_UNICODES),
    ("cascadia-code.woff2", CASCADIA_UNICODES),
    ("cascadia-code-italic.woff2", CASCADIA_UNICODES),
]


def subset_one(font_name, unicodes):
    src = FONTS / font_name
    if not src.exists():
        print(f"  [skip] {font_name} not found")
        return None

    before = src.stat().st_size
    tmp = src.with_suffix(".woff2.new")

    cmd = [
        sys.executable, "-m", "fontTools.subset",
        str(src),
        f"--output-file={tmp}",
        f"--unicodes={unicodes}",
        "--flavor=woff2",
        "--layout-features=*",   # keep OpenType features (ligatures, kerning, ...)
        "--no-hinting",          # variable fonts have no TT hinting
        "--desubroutinize",      # better woff2 compression
        "--name-legacy",         # keep name records for local() lookups
        "--drop-tables=",        # empty list -> don't drop any table (preserves fvar/STAT for variable fonts)
    ]
    subprocess.run(cmd, check=True, capture_output=True)

    after = tmp.stat().st_size
    src.unlink()
    tmp.rename(src)
    return before, after


def main():
    if not FONTS.is_dir():
        print(f"ERROR: {FONTS} not found. Run from repo root.")
        sys.exit(1)

    print(f"Subsetting fonts in {FONTS.relative_to(REPO)}\n")
    total_before = 0
    total_after = 0

    for name, unicodes in TARGETS:
        result = subset_one(name, unicodes)
        if result is None:
            continue
        b, a = result
        total_before += b
        total_after += a
        pct = 100 * a // b if b else 0
        print(f"  {name:32s} {b:>7,} B  ->  {a:>7,} B   ({pct}% of original)")

    if total_before:
        pct = 100 * total_after // total_before
        saved = total_before - total_after
        print(f"\n  {'TOTAL':32s} {total_before:>7,} B  ->  {total_after:>7,} B   ({pct}% of original)")
        print(f"  saved: {saved:,} B ({saved // 1024} KiB)")


if __name__ == "__main__":
    main()
