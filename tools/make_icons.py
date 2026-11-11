"""Derive the final icon set for lovelyreverse from the chosen candidate.

Input : assets/icons/candidate-A-heart-sprite.png (2K master, badge on light bg)
Output: assets/icons/master-rounded.png            1024px working master (rounded alpha)
        src/lovelyreverse/resources/static/favicon.ico       16-256 multi-size
        src/lovelyreverse/resources/static/favicon-32.png
        src/lovelyreverse/resources/static/apple-touch-icon.png  (180, opaque full-bleed)
        docs/icons/social-preview.png              1280x640 README/GitHub banner
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont, ImageOps

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "assets" / "icons" / "candidate-A-heart-sprite.png"
STATIC = ROOT / "src" / "lovelyreverse" / "resources" / "static"
DOCS = ROOT / "docs" / "icons"

ROSE = (255, 93, 143)
GRAPHITE = (42, 36, 51)
DIM = (155, 145, 169)
CREAM = (253, 249, 236)

CASCADIA = "C:/Windows/Fonts/CascadiaCode.ttf"
CASCADIA_BD = "C:/Windows/Fonts/CascadiaCodeBold.ttf"
MSYH = "C:/Windows/Fonts/msyh.ttc"


def badge_bbox(img: Image.Image) -> tuple[int, int, int, int]:
    """Bounding box of the badge: pixels that differ clearly from the outer bg."""
    rgb = img.convert("RGB")
    w, h = rgb.size
    corner = rgb.getpixel((4, 4))
    px = rgb.load()
    step = 4
    xs, ys = [], []
    for y in range(0, h, step):
        for x in range(0, w, step):
            r, g, b = px[x, y]
            if abs(r - corner[0]) + abs(g - corner[1]) + abs(b - corner[2]) > 42:
                xs.append(x)
                ys.append(y)
    # trim soft shadow margin
    pad = int(w * 0.005)
    return (max(min(xs) - pad, 0), max(min(ys) - pad, 0),
            min(max(xs) + pad, w), min(max(ys) + pad, h))


def rounded(img: Image.Image, radius_ratio: float = 0.19) -> Image.Image:
    side = min(img.size)
    img = ImageOps.fit(img, (side, side), Image.LANCZOS)
    mask = Image.new("L", (side, side), 0)
    d = ImageDraw.Draw(mask)
    r = int(side * radius_ratio)
    d.rounded_rectangle([0, 0, side - 1, side - 1], radius=r, fill=255)
    img.putalpha(mask)
    return img


def save_opaque(master: Image.Image, size: int, path: Path) -> None:
    """Full-bleed square (no rounded corners) — badge pasted on its own bg color."""
    flat = Image.new("RGB", master.size, CREAM)
    flat.paste(master, (0, 0), master)
    flat.resize((size, size), Image.LANCZOS).save(path)


def main() -> None:
    img = Image.open(SRC)
    bbox = badge_bbox(img)
    print(f"badge bbox: {bbox} of {img.size}")
    badge = img.crop(bbox)
    master = rounded(badge).resize((1024, 1024), Image.LANCZOS)
    master_path = ROOT / "assets" / "icons" / "master-rounded.png"
    master.save(master_path)

    STATIC.mkdir(parents=True, exist_ok=True)
    DOCS.mkdir(parents=True, exist_ok=True)

    # favicon.ico — multi-size
    master.save(STATIC / "favicon.ico",
                sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    # favicon pngs
    master.resize((32, 32), Image.LANCZOS).save(STATIC / "favicon-32.png")
    save_opaque(master, 180, STATIC / "apple-touch-icon.png")

    # ── social preview 1280x640 ────────────────────────────────────────
    W, H = 1280, 640
    banner = Image.new("RGB", (W, H), CREAM)
    d = ImageDraw.Draw(banner)
    # soft rose radial glow behind the icon
    glow = Image.new("L", (W, H), 0)
    gd = ImageDraw.Draw(glow)
    gd.ellipse([-180, -160, 640, 800], fill=46)
    rose_layer = Image.new("RGB", (W, H), (255, 214, 229))
    banner = Image.composite(rose_layer, banner, glow)
    d = ImageDraw.Draw(banner)

    icon = master.resize((420, 420), Image.LANCZOS)
    banner.paste(icon, (78, (H - 420) // 2), icon)

    tx = 540
    maxw = W - tx - 48

    def fit(text: str, path: str, size: int, stroke: int = 0):
        """Shrink font size until the text fits the remaining width."""
        s = size
        while s > 12:
            f = ImageFont.truetype(path, s)
            try:
                f.set_variation_by_name("Bold")
            except Exception:
                pass
            if d.textbbox((0, 0), text, font=f, stroke_width=stroke)[2] <= maxw:
                return f
            s -= 2
        return ImageFont.truetype(path, 12)

    f_brand = fit("lovelyreverse", CASCADIA, 84, stroke=2)
    f_tag_cn = fit("手搓向的逆向工程工作站 · no AI", MSYH, 38)
    f_tag_en = fit("decompile · call graph · decoder lab · crypto constants",
                   CASCADIA, 26)
    f_hex = ImageFont.truetype(CASCADIA, 22)

    y = 196
    w1 = d.textbbox((0, 0), "lovely", font=f_brand, stroke_width=2)[2]
    d.text((tx, y), "lovely", font=f_brand, fill=GRAPHITE,
           stroke_width=2, stroke_fill=GRAPHITE)
    d.text((tx + w1, y), "reverse", font=f_brand, fill=ROSE,
           stroke_width=2, stroke_fill=ROSE)
    y += 122
    d.text((tx, y), "手搓向的逆向工程工作站 · no AI", font=f_tag_cn, fill=GRAPHITE)
    y += 72
    d.text((tx, y), "decompile · call graph · decoder lab · crypto constants",
           font=f_tag_en, fill=DIM)
    # faint hex strip
    d.text((tx, H - 74), "00 FF A3 C2 7F 1A 6B E9 04 D3 52 88 …",
           font=f_hex, fill=(230, 170, 192))

    banner.save(DOCS / "social-preview.png")
    print("written:")
    for p in [master_path, STATIC / "favicon.ico", STATIC / "favicon-32.png",
              STATIC / "apple-touch-icon.png", DOCS / "social-preview.png"]:
        print(" ", p)


if __name__ == "__main__":
    main()
