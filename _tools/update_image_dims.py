"""
Rewrite the width="X" height="Y" attributes on <img> tags (and kramdown IAL
markers) in every post to reflect a target display width instead of the
image's natural dimensions.

Image files are NOT touched. Aspect ratio is preserved by reading each
file's real size (PIL) and scaling proportionally to TARGET_WIDTH.

Why: the current attributes are the file's natural dimensions (e.g.
1080x2340). The browser lays them out at the reading-column CSS width, so
declaring the display size upfront is semantically closer to reality and
still works as a CLS aspect-ratio hint (only the ratio matters).

Note: this does NOT reduce transfer bytes. Full-size files are still
downloaded. PageSpeed's "properly size images" audit will keep flagging
the natural-vs-displayed mismatch — accepted trade-off.

Requires: pip install Pillow
"""

import re
import sys
from pathlib import Path
from PIL import Image

REPO = Path(__file__).resolve().parent.parent
IMG_DIR = REPO / "assets" / "img"
POSTS_DIR = REPO / "_posts"

TARGET_HEIGHT = 1000   # cap intrinsic height; width scales proportionally
EXTS = {".png", ".jpg", ".jpeg", ".gif"}


def target_dims(path):
    """Return (target_w, target_h) with height capped at TARGET_HEIGHT
    (width scales proportionally). Returns the natural dims if already
    within cap. None if unreadable."""
    try:
        im = Image.open(path)
        w, h = im.size
        im.close()
    except Exception:
        return None

    if h <= TARGET_HEIGHT:
        return (w, h)

    new_h = TARGET_HEIGHT
    new_w = round(w * (TARGET_HEIGHT / h))

    return (new_w, new_h)


def update_md(post_path, url_fragment, new_w, new_h):
    """Rewrite width="..." and height="..." for tags whose src/URL contains
    url_fragment. Returns tuple (matches_updated, matches_seen)."""
    text = post_path.read_text(encoding="utf-8")
    original = text
    updated = 0
    seen = 0

    def rewrite_img_tag(m):
        nonlocal updated, seen
        tag = m.group(0)

        if url_fragment not in tag:
            return tag

        seen += 1
        new_tag = re.sub(r'width="\d+"', f'width="{new_w}"', tag)
        new_tag = re.sub(r'height="\d+"', f'height="{new_h}"', new_tag)

        if new_tag != tag:
            updated += 1

        return new_tag

    text = re.sub(r'<img[^>]*>', rewrite_img_tag, text)

    def rewrite_ial(m):
        nonlocal updated, seen
        line = m.group(0)

        if url_fragment not in line:
            return line

        seen += 1
        new_line = re.sub(r'width="\d+"', f'width="{new_w}"', line)
        new_line = re.sub(r'height="\d+"', f'height="{new_h}"', new_line)

        if new_line != line:
            updated += 1

        return new_line

    text = re.sub(r'!\[[^\]]*\]\([^)]*\)\{:[^}]*\}', rewrite_ial, text)

    if text != original:
        post_path.write_text(text, encoding="utf-8")

    return (updated, seen)


def main():
    if not IMG_DIR.is_dir():
        print(f"ERROR: {IMG_DIR} not found. Run from repo root.")
        sys.exit(1)

    images = sorted(
        p for p in IMG_DIR.rglob("*")
        if p.is_file() and p.suffix.lower() in EXTS
    )

    posts = list(POSTS_DIR.glob("*.md"))
    print(f"Scanning {len(images)} images, target height = {TARGET_HEIGHT}px\n")
    total_updated = 0

    for img in images:
        dims = target_dims(img)

        if dims is None:
            continue

        new_w, new_h = dims
        url_fragment = str(img.relative_to(IMG_DIR)).replace("\\", "/")

        for post in posts:
            updated, _ = update_md(post, url_fragment, new_w, new_h)

            if updated:
                total_updated += updated
                print(f"  {img.relative_to(REPO)} -> {new_w}x{new_h}   "
                      f"({updated} refs in {post.name})")

    print(f"\nTotal <img> / IAL refs updated: {total_updated}")


if __name__ == "__main__":
    main()
