"""
Generate CSS @font-face override values so locally-installed fallback fonts
render with identical line-box metrics to our custom web fonts (Inter and
Cascadia Code). Output goes to stdout, ready to paste into _sass/_base.scss.

Why: with font-display: swap, the browser shows a system fallback while the
web font is fetching. Without size-adjust and ascent/descent overrides, the
fallback has different metrics, so the swap produces a visible layout shift
and glyph pop. This script computes the exact override values that make the
fallback line box match the web font's at the pixel.

Portable: no local font files, no OS-specific paths. Target metrics come
from the webfont files shipped in this repo (assets/fonts/*.woff2), and
fallback metrics come from either:
  (a) @capsizecss/metrics via jsdelivr -- covers most open-source fonts, plus
      Cascadia Code/Mono and Segoe UI (Microsoft-licensed but capsize has
      metrics available); or
  (b) a small hardcoded table for the handful of proprietary fonts capsize
      doesn't ship (Consolas, Menlo, SF Mono, DejaVu, Liberation). These
      fonts haven't changed metrics in over a decade, so hardcoding is safe.

Usage:
    pip install fonttools brotli
    python _tools/compute_fallback_overrides.py > /tmp/overrides.css
    # then paste into _sass/_base.scss under "Metric-adjusted fallback fonts"

Formula (Fontaine / Vercel next/font):
    size-adjust        = (target.xWidthAvg / fallback.xWidthAvg) * 100
    adjusted_em        = target.unitsPerEm * (size-adjust / 100)
    ascent-override    = target.ascent  / adjusted_em * 100
    descent-override   = |target.descent| / adjusted_em * 100
    line-gap-override  = target.lineGap / adjusted_em * 100
"""

import os
import re
import sys
import time
import urllib.error
import urllib.request
import importlib.util
from typing import Any

if importlib.util.find_spec("brotli") is None:
    sys.exit(
        "Missing 'brotli' package (needed to decode the WOFF2 files in "
        "assets/fonts/). Install with:\n\n    pip install brotli\n"
    )

from fontTools.ttLib import TTFont

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WEBFONTS  = os.path.join(REPO_ROOT, "assets", "fonts")

# @capsizecss/metrics on jsdelivr. Pin a version so regenerations are
# reproducible even if capsize retunes a metric later. jsdelivr is chosen
# over unpkg because unpkg tail-latencies out on several of the files we
# need (notoSans, ubuntuMono, robotoMono all hang past 20s consistently).
CAPSIZE_VERSION = "4.2.0"
CAPSIZE = f"https://cdn.jsdelivr.net/npm/@capsizecss/metrics@{CAPSIZE_VERSION}/entireMetricsCollection"

# Cache each fetched metric on disk. Since we pin the capsize version, cached
# entries never go stale; the cache just makes reruns instant and shields the
# script from transient CDN blips. Gitignored via _tools/.
CACHE_DIR = os.path.join(os.path.dirname(__file__), f".capsize_cache-{CAPSIZE_VERSION}")

# Same weighted sample capsize/fontaine use for xWidthAvg. Six trailing
# spaces reflect the frequency of space in English prose.
SAMPLE = "aaabcdeeeefghiijklmnnoopqrrssttuvwxyz      "

# Static metrics for fonts capsize doesn't publish. Extracted once from the
# authoritative font files; hardcoded because these fonts have shipped with
# stable metrics for over a decade. If you ever need to regenerate, run:
#   python -c "from fontTools.ttLib import TTFont; f=TTFont('path/to/font');
#     print(f['head'].unitsPerEm, f['hhea'].ascent, f['hhea'].descent,
#     f['hhea'].lineGap)"
# and recompute xWidthAvg with the SAMPLE above.
STATIC_METRICS = {
    "consolas"  : {"unitsPerEm": 2048, "ascent": 1521, "descent": -527,
                   "lineGap": 350, "xWidthAvg": 1126.0},
    "menlo"     : {"unitsPerEm": 2048, "ascent": 1901, "descent": -483,
                   "lineGap": 0, "xWidthAvg": 1233.0},
    "sfmono"    : {"unitsPerEm": 2048, "ascent": 1950, "descent": -494,
                   "lineGap": 0, "xWidthAvg": 1266.0},
    "dejavusans": {"unitsPerEm": 2048, "ascent": 1901, "descent": -483,
                   "lineGap": 0, "xWidthAvg": 1070.3023255813953},
    "dejavumono": {"unitsPerEm": 2048, "ascent": 1901, "descent": -483,
                   "lineGap": 0, "xWidthAvg": 1233.0},
    "libmono"   : {"unitsPerEm": 2048, "ascent": 1705, "descent": -615,
                   "lineGap": 0, "xWidthAvg": 1229.0},
}


def x_width_avg(font: Any) -> float:
    cmap  = font.getBestCmap()
    hmtx  = font["hmtx"]
    total = 0

    for ch in SAMPLE:
        gname = cmap.get(ord(ch))

        if gname is None:
            continue

        adv, _ = hmtx[gname]
        total += adv

    return total / len(SAMPLE)


def read_font_file(path: str) -> dict:
    """Metrics from a local font file (used for the webfonts we ship).

    fontTools decodes OpenType tables lazily and exposes their fields as
    dynamic attributes on the returned object -- static type checkers can't
    see them, so we bind through Any to keep the idiomatic access clean.
    """
    f = TTFont(path)
    head: Any = f["head"]
    hhea: Any = f["hhea"]

    return {
        "unitsPerEm": head.unitsPerEm,
        "ascent":     hhea.ascent,
        "descent":    hhea.descent,
        "lineGap":    hhea.lineGap,
        "xWidthAvg":  x_width_avg(f),
    }


def _fetch_capsize(name):
    """Fetch a single capsize metrics file. On-disk cache + retry with backoff
    (CDN tail-latency and 5xx blips are common on burst requests)."""
    cache_path = os.path.join(CACHE_DIR, f"{name}.cjs")

    if os.path.exists(cache_path):
        with open(cache_path, encoding="utf-8") as fh:
            return fh.read()

    url = f"{CAPSIZE}/{name}/index.cjs"
    last_err = None

    for attempt in range(4):
        try:
            with urllib.request.urlopen(url, timeout=15) as r:
                text = r.read().decode("utf-8")

            os.makedirs(CACHE_DIR, exist_ok=True)

            with open(cache_path, "w", encoding="utf-8") as fh:
                fh.write(text)

            return text
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_err = e
            time.sleep(0.5 * (2 ** attempt))

    raise RuntimeError(f"Failed to fetch capsize/{name} after 4 tries: {last_err}")


def read_capsize(name):
    """Metrics from @capsizecss/metrics via jsdelivr (cached on disk)."""
    text = _fetch_capsize(name)
    out = {}

    for f in ("unitsPerEm", "ascent", "descent", "lineGap", "xHeight", "xWidthAvg"):
        m = re.search(rf"\b{f}\s*:\s*(-?\d+(?:\.\d+)?)", text)

        if m:
            val = m.group(1)
            out[f] = float(val) if "." in val else int(val)

    return out


# ---- targets: the fonts we ship (read from repo files, always portable) ----

targets = {
    "inter_reg"   : read_font_file(os.path.join(WEBFONTS, "InterVariable.woff2"       )),
    "inter_it"    : read_font_file(os.path.join(WEBFONTS, "InterVariable-Italic.woff2")),
    "cascadia_reg": read_font_file(os.path.join(WEBFONTS, "cascadia-code.woff2"       )),
    "cascadia_it" : read_font_file(os.path.join(WEBFONTS, "cascadia-code-italic.woff2")),
}

# ---- fallback metrics (capsize where available, static otherwise) ----

fb = {
    # sans (from capsize)
    "arial"       : read_capsize("arial"       ),
    "roboto"      : read_capsize("roboto"      ),
    "ubuntu"      : read_capsize("ubuntu"      ),
    "notosans"    : read_capsize("notoSans"    ),
    "segoeui"     : read_capsize("segoeUI"     ),
    # mono (from capsize)
    "cascadiamono": read_capsize("cascadiaMono"),
    "robotomono"  : read_capsize("robotoMono"  ),
    "ubuntumono"  : read_capsize("ubuntuMono"  ),
    "notomono"    : read_capsize("notoSansMono"),
    # everything else -> static (capsize doesn't publish these)
    "consolas"    : STATIC_METRICS["consolas"  ],
    "menlo"       : STATIC_METRICS["menlo"     ],
    "sfmono"      : STATIC_METRICS["sfmono"    ],
    "dejavusans"  : STATIC_METRICS["dejavusans"],
    "dejavumono"  : STATIC_METRICS["dejavumono"],
    "libmono"     : STATIC_METRICS["libmono"   ],
}


def emit(target, fallback, family_name, local_src, style):
    size_adjust = target["xWidthAvg"] / fallback["xWidthAvg"] * 100
    adj_em      = target["unitsPerEm"] * (size_adjust / 100)
    ascent      = target["ascent"]       / adj_em * 100
    descent     = abs(target["descent"]) / adj_em * 100
    line_gap    = target["lineGap"]      / adj_em * 100
    print("@font-face {")
    print(f'    font-family: "{family_name}";')
    print(f"    src: {local_src};")
    print(f"    font-style: {style};")
    print(f"    size-adjust: {size_adjust:.4f}%;")
    print(f"    ascent-override: {ascent:.4f}%;")
    print(f"    descent-override: {descent:.4f}%;")
    print(f"    line-gap-override: {line_gap:.4f}%;" if line_gap != 0 else "    line-gap-override: 0%;")
    print("}")
    print()


# Each fallback gets its OWN font-family name (e.g. "Inter Fallback Arial")
# so that per-platform overrides are preserved. The CSS spec's "last @font-face
# with identical face descriptors wins" rule would otherwise collapse multiple
# same-name rules into just the last one, silently dropping fallbacks whose
# local() fails. Then --font-sans / --font-mono list every fallback name in
# specific-to-universal order so the browser tries each in turn via local()
# and the first one that resolves wins with ITS own tuned overrides.

print("// --- Inter fallbacks ---")
print()
# Segoe UI (Windows native UI font). Full name matches family name, but we
# include the PostScript form too for browsers that only match on PostScript.
emit(targets["inter_reg"], fb["segoeui"], "Inter Fallback Segoe UI",
     'local("Segoe UI"), local("SegoeUI")', "normal")
emit(targets["inter_it"],  fb["segoeui"], "Inter Fallback Segoe UI",
     'local("Segoe UI Italic"), local("SegoeUI-Italic")', "italic")

# Ubuntu (Ubuntu Linux native)
emit(targets["inter_reg"], fb["ubuntu"], "Inter Fallback Ubuntu",
     'local("Ubuntu")', "normal")
emit(targets["inter_it"],  fb["ubuntu"], "Inter Fallback Ubuntu",
     'local("Ubuntu Italic")', "italic")

# Roboto (Android native, ChromeOS UI)
emit(targets["inter_reg"], fb["roboto"], "Inter Fallback Roboto",
     'local("Roboto")', "normal")
emit(targets["inter_it"],  fb["roboto"], "Inter Fallback Roboto",
     'local("Roboto Italic")', "italic")

# DejaVu Sans (Debian/Ubuntu default sans)
emit(targets["inter_reg"], fb["dejavusans"], "Inter Fallback DejaVu",
     'local("DejaVu Sans")', "normal")
emit(targets["inter_it"],  fb["dejavusans"], "Inter Fallback DejaVu",
     'local("DejaVu Sans Oblique")', "italic")

# Noto Sans (ChromeOS, generic Linux)
emit(targets["inter_reg"], fb["notosans"], "Inter Fallback Noto",
     'local("Noto Sans")', "normal")
emit(targets["inter_it"],  fb["notosans"], "Inter Fallback Noto",
     'local("Noto Sans Italic")', "italic")

# Arial (Windows/macOS/iOS universal, Liberation Sans bundled as metric-compat)
emit(targets["inter_reg"], fb["arial"], "Inter Fallback Arial",
     'local("Arial"), local("Liberation Sans")', "normal")
emit(targets["inter_it"],  fb["arial"], "Inter Fallback Arial",
     'local("Arial Italic"), local("Liberation Sans Italic")', "italic")

print("// --- Cascadia Code fallbacks ---")
print()
# Cascadia Mono (Windows Terminal, Win 10/11). Near-identical metrics to
# Cascadia Code. Win 11 ships it as a wght-only variable font with PostScript
# name "CascadiaMono-Roman", so we try Full name, PostScript name, and family
# name variants -- one of these matches whatever the browser resolves against.
emit(targets["cascadia_reg"], fb["cascadiamono"], "Cascadia Code Fallback Cascadia Mono",
     'local("Cascadia Mono Regular"), local("CascadiaMono-Roman"), local("CascadiaMonoRoman"), local("CascadiaMono"), local("Cascadia Mono")', "normal")
emit(targets["cascadia_it"],  fb["cascadiamono"], "Cascadia Code Fallback Cascadia Mono",
     'local("Cascadia Mono Italic"), local("CascadiaMono-Italic"), local("CascadiaMonoItalic")', "italic")

# SF Mono (macOS modern, Xcode default)
emit(targets["cascadia_reg"], fb["sfmono"], "Cascadia Code Fallback SF Mono",
     'local("SF Mono"), local("SFMono-Regular")', "normal")
emit(targets["cascadia_it"],  fb["sfmono"], "Cascadia Code Fallback SF Mono",
     'local("SF Mono Italic"), local("SFMono-RegularItalic")', "italic")

# Menlo (macOS traditional)
emit(targets["cascadia_reg"], fb["menlo"], "Cascadia Code Fallback Menlo",
     'local("Menlo")', "normal")
emit(targets["cascadia_it"],  fb["menlo"], "Cascadia Code Fallback Menlo",
     'local("Menlo Italic")', "italic")

# Consolas (Windows)
emit(targets["cascadia_reg"], fb["consolas"], "Cascadia Code Fallback Consolas",
     'local("Consolas")', "normal")
emit(targets["cascadia_it"],  fb["consolas"], "Cascadia Code Fallback Consolas",
     'local("Consolas Italic")', "italic")

# Ubuntu Mono (Ubuntu native)
emit(targets["cascadia_reg"], fb["ubuntumono"], "Cascadia Code Fallback Ubuntu",
     'local("Ubuntu Mono"), local("UbuntuMono-Regular"), local("UbuntuMono-R"), local("UbuntuMono")', "normal")
emit(targets["cascadia_it"],  fb["ubuntumono"], "Cascadia Code Fallback Ubuntu",
     'local("Ubuntu Mono Italic"), local("UbuntuMono-Italic"), local("UbuntuMono-RI")', "italic")

# Roboto Mono (Android)
emit(targets["cascadia_reg"], fb["robotomono"], "Cascadia Code Fallback Roboto",
     'local("Roboto Mono"), local("RobotoMono-Regular"), local("RobotoMono")', "normal")
emit(targets["cascadia_it"],  fb["robotomono"], "Cascadia Code Fallback Roboto",
     'local("Roboto Mono Italic"), local("RobotoMono-Italic")', "italic")

# DejaVu Sans Mono (Debian/Ubuntu default mono, headless Chromium on Linux CI)
emit(targets["cascadia_reg"], fb["dejavumono"], "Cascadia Code Fallback DejaVu",
     'local("DejaVu Sans Mono"), local("DejaVuSansMono"), local("DejaVuSansMono-Book"), local("DejaVu Sans Mono Book")', "normal")
emit(targets["cascadia_it"],  fb["dejavumono"], "Cascadia Code Fallback DejaVu",
     'local("DejaVu Sans Mono Oblique"), local("DejaVuSansMono-Oblique"), local("DejaVu Sans Mono BookOblique"), local("DejaVuSansMono-BookOblique")', "italic")

# Liberation Mono (RHEL/Fedora default mono)
emit(targets["cascadia_reg"], fb["libmono"], "Cascadia Code Fallback Liberation",
     'local("Liberation Mono"), local("LiberationMono-Regular"), local("LiberationMono")', "normal")
emit(targets["cascadia_it"],  fb["libmono"], "Cascadia Code Fallback Liberation",
     'local("Liberation Mono Italic"), local("LiberationMono-Italic")', "italic")

# Noto Sans Mono (ChromeOS, generic mono)
emit(targets["cascadia_reg"], fb["notomono"], "Cascadia Code Fallback Noto",
     'local("Noto Sans Mono"), local("NotoSansMono-Regular"), local("NotoSansMono")', "normal")
emit(targets["cascadia_it"],  fb["notomono"], "Cascadia Code Fallback Noto",
     'local("Noto Sans Mono Italic"), local("NotoSansMono-Italic")', "italic")
