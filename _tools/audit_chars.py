"""
Report every code point >= U+0080 used anywhere in the site content and
templates, sorted by frequency. Categorises each against the Unicode ranges
that _tools/subset_fonts.py ships to the browser, so it's obvious whether a
new char is covered, needs a subset extension, or should be replaced.

Run before adding heavy new content that mixes prose + code with unusual
symbols, or after updating the site's Unicode budget.
"""

import io
import sys
import unicodedata
from collections import defaultdict
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

REPO = Path(__file__).resolve().parent.parent

PATTERNS = [
    "_posts/*.md",
    "_includes/*.html",
    "_layouts/*.html",
    "*.md",
    "*.html",
    "_config.yml",
]

EXCLUDE_PARTS = {"_site", "vendor", "node_modules", ".jekyll-cache", ".git"}

# Ranges that subset_fonts.py ships. Keep in sync with INTER_UNICODES.
INTER_RANGES = [
    (0x0000, 0x00FF), (0x0131, 0x0131), (0x0152, 0x0153),
    (0x02BB, 0x02BC), (0x02C6, 0x02C6), (0x02DA, 0x02DA), (0x02DC, 0x02DC),
    (0x2000, 0x206F), (0x2074, 0x2074), (0x20AC, 0x20AC), (0x2122, 0x2122),
    (0x2190, 0x2193), (0x2212, 0x2212), (0x2215, 0x2215), (0x2265, 0x2265),
    (0xFEFF, 0xFEFF), (0xFFFD, 0xFFFD),
]
CASCADIA_RANGES = [
    (0x0000, 0x00FF), (0x0131, 0x0131), (0x0152, 0x0153),
    (0x2000, 0x206F),
    (0x2190, 0x21FF), (0x2200, 0x22FF),
    (0x2500, 0x257F), (0x2580, 0x259F),
    (0xFEFF, 0xFEFF), (0xFFFD, 0xFFFD),
]


def in_ranges(cp, ranges):
    return any(a <= cp <= b for a, b in ranges)


def scan_files():
    files = set()
    for pat in PATTERNS:
        for p in REPO.glob(pat):
            if any(part in EXCLUDE_PARTS for part in p.parts):
                continue
            if p.is_file():
                files.add(p)
    return sorted(files)


def collect(files):
    # cp -> {"count": int, "refs": [(file, line, snippet)]}
    findings = defaultdict(lambda: {"count": 0, "refs": []})

    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for ch in line:
                cp = ord(ch)
                if cp < 0x0080:
                    continue
                data = findings[cp]
                data["count"] += 1
                if len(data["refs"]) < 2:
                    data["refs"].append((f.relative_to(REPO), line_no, line.strip()[:80]))
    return findings


def report(findings):
    inter_only = []       # in Inter subset (prose OK)
    cascadia_only = []    # in Cascadia only (code OK, prose falls back)
    both = []             # in both
    neither = []          # falls back to system font everywhere

    for cp, data in findings.items():
        in_i = in_ranges(cp, INTER_RANGES)
        in_c = in_ranges(cp, CASCADIA_RANGES)
        if in_i and in_c:
            both.append((cp, data))
        elif in_i:
            inter_only.append((cp, data))
        elif in_c:
            cascadia_only.append((cp, data))
        else:
            neither.append((cp, data))

    def dump(title, rows):
        print(f"\n=== {title} ({len(rows)} unique chars) ===")
        for cp, data in sorted(rows, key=lambda r: -r[1]["count"]):
            ch = chr(cp)
            try:
                name = unicodedata.name(ch, "<unnamed>")
            except ValueError:
                name = "<unnamed>"
            display = ch if ch.isprintable() else "<control>"
            print(f"  U+{cp:04X}  {display!r:6s}  {data['count']:>5}x  {name}")
            for fp, ln, snip in data["refs"]:
                print(f"           {fp}:{ln}  |  {snip[:70]}")

    print(f"Scanned. Found {len(findings)} unique non-ASCII code points.")
    dump("Covered by BOTH Inter and Cascadia subsets", both)
    dump("Covered ONLY by Inter (prose fine, code falls back)", inter_only)
    dump("Covered ONLY by Cascadia (code fine, prose falls back)", cascadia_only)
    dump("NOT covered by any subset (system-font fallback everywhere)", neither)

    if neither:
        print("\n> These chars will render in the browser's system font — visible")
        print("> but off-style. Either extend subset_fonts.py or replace them.")
    if inter_only:
        print("\n> Inter-only chars in <code> would fall back — check the refs.")
    if cascadia_only:
        print("\n> Cascadia-only chars in prose would fall back — check the refs.")


def main():
    files = scan_files()
    print(f"Scanning {len(files)} files under {REPO.name}/\n")
    findings = collect(files)
    report(findings)


if __name__ == "__main__":
    main()
