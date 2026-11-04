"""Story image for shuang (1080x1920) — big RU typography + real terminal log."""

from PIL import Image, ImageDraw, ImageFilter, ImageFont

W, H = 1080, 1920
BG = (16, 18, 22)
CARD = (29, 32, 38)
FG = (240, 240, 240)
MUTED = (150, 155, 160)
FROST = (122, 162, 247)
GREEN = (76, 210, 120)
ORANGE = (255, 170, 60)

img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)

# very subtle vignette glow behind the headline
glow = Image.new("RGB", (W, H), BG)
gd = ImageDraw.Draw(glow)
gd.ellipse([W // 2 - 700, -300, W // 2 + 700, 900], fill=(26, 32, 46))
img = Image.blend(img, glow.filter(ImageFilter.GaussianBlur(120)), 0.9)
d = ImageDraw.Draw(img)


def f(path, size):
    return ImageFont.truetype(path, size)


SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
CJK = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"


def left(x, y, text, font, fill=FG):
    d.text((x, y), text, font=font, fill=fill)
    bbox = d.textbbox((x, y), text, font=font)
    return bbox[3] + 8


# ── top: small brand row ────────────────────────────────────────────────────
y = 240
d.text((120, y), "霜", font=f(CJK, 76), fill=FROST)
d.text((210, y + 14), "shuang", font=f(SANS_B, 56), fill=FG)
d.text((120, y + 100), "kill switch для приложений", font=f(SANS, 36), fill=MUTED)

# ── headline ────────────────────────────────────────────────────────────────
y = 460
y = left(120, y, "VPN упал —", f(SANS_B, 108))
y = left(120, y, "Claude не умер,", f(SANS_B, 108))
y = left(120, y, "а заморожен", f(SANS_B, 108), FROST)
d.text((120, y + 16), "и продолжит с того же места, когда VPN вернётся",
       font=f(SANS, 38), fill=MUTED)

# ── terminal card with REAL output of a live run ────────────────────────────
tx, ty, tw = 90, 1010, W - 180
th = 560
d.rounded_rectangle([tx, ty, tx + tw, ty + th], radius=28, fill=CARD)
d.rounded_rectangle([tx, ty, tx + tw, ty + th], radius=28, outline=(46, 50, 58), width=2)
for i, color in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
    d.ellipse([tx + 34 + i * 44, ty + 30, tx + 58 + i * 44, ty + 54], fill=color)

# real lines from the live demo (mock service flipped the IP for 10 s)
lines = [
    ("$ shuang run -- claude", FG, False),
    ("shuang: protecting claude (pid 1907031)", MUTED, False),
    ("20:55:53  tick 5", FG, False),
    ("shuang: IP 198.51.100.50 not allowed — froze 2 process(es)", ORANGE, True),
    ("shuang: frozen, 18s left for the allowed IP", ORANGE, False),
    ("shuang: allowed IP is back — resumed", GREEN, True),
    ("20:56:03  tick 6   ← продолжил ровно с места остановки", GREEN, False),
]
ly = ty + 86
for text, color, bold in lines:
    d.text((tx + 40, ly), text, font=f(MONO_B if bold else MONO, 32), fill=color)
    ly += 64

# ── bullets ─────────────────────────────────────────────────────────────────
y = 1660
for line in [
    "ни одного байта мимо VPN  ·  IPv6 и DNS-утечки видны",
    "трей · панель · уведомления · Linux, macOS, Windows",
]:
    d.text((120, y), "· " + line, font=f(SANS, 38), fill=FG)
    y += 66

# ── bottom bar ──────────────────────────────────────────────────────────────
d.rectangle([0, H - 200, W, H], fill=(22, 26, 34))
d.text((120, H - 150), "github.com/rasuvaeff/shuang", font=f(MONO_B, 52), fill=FROST)
d.text((120, H - 82), "open source · GPL-3.0 · бесплатно", font=f(SANS, 34), fill=MUTED)
d.text((W - 200, H - 150), "霜", font=f(CJK, 92), fill=(52, 60, 74))

img.save("docs/story.png")
print("saved", img.size)
