"""Story image for shuang (1080x1920, Telegram story).

Frost theme: dark background, big 霜, status ring like the tray icon
(green = protected), the core promise in RU, install line at the bottom.
"""

from PIL import Image, ImageDraw, ImageFilter, ImageFont

W, H = 1080, 1920
BG = (20, 22, 26)
FG = (230, 230, 230)
MUTED = (154, 154, 154)
FROST = (122, 162, 247)  # #7aa2f7
GREEN = (76, 175, 80)
ORANGE = (255, 152, 0)

img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)

# --- frosted snowfall background (soft dots) --------------------------------
import random

random.seed(42)
snow = Image.new("RGB", (W, H), BG)
sd = ImageDraw.Draw(snow)
for _ in range(220):
    x, y = random.randint(0, W), random.randint(0, H)
    r = random.randint(1, 5)
    shade = random.randint(28, 48)
    sd.ellipse([x - r, y - r, x + r, y + r], fill=(shade, shade + 4, shade + 10))
img = Image.blend(img, snow.filter(ImageFilter.GaussianBlur(2)), 0.8)
d = ImageDraw.Draw(img)


def font(size, bold=False):
    for path in [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans%s.ttf" % ("-Bold" if bold else ""),
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
    ]:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            continue
    return ImageFont.load_default()


def center(text, y, f, fill=FG, spacing=10):
    w = d.textlength(text, font=f)
    d.text(((W - w) / 2, y), text, font=f, fill=fill)
    bbox = d.textbbox((0, 0), text, font=f)
    return y + (bbox[3] - bbox[1]) + spacing


# --- top: big 霜 -------------------------------------------------------------
# CJK glyph via Noto if present, else skip to the latin name only
try:
    f_big = ImageFont.truetype(
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", 420
    )
    w = d.textlength("霜", font=f_big)
    d.text(((W - w) / 2, 140), "霜", font=f_big, fill=FROST)
    y = 660
except Exception:
    y = 200

f_name = font(120, bold=True)
y = center("shuang", y, f_name, FG)

f_tag = font(52)
y = center("Freeze apps when the VPN drops.", y + 30, f_tag)
y = center("Suspend, don't kill.", y, f_tag, FROST)

# --- status ring (like the tray icon) ---------------------------------------
cx, cy, r = W // 2, y + 330, 190
ring = Image.new("RGB", (W, H), BG)
rd = ImageDraw.Draw(ring)
rd.ellipse([cx - r, cy - r, cx + r, cy + r], outline=GREEN, width=34)
ring = ring.filter(ImageFilter.GaussianBlur(0))
img.paste(ring.filter(ImageFilter.GaussianBlur(18)), (0, 0), None)
d = ImageDraw.Draw(img)
d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=GREEN, width=10)

f_ring = font(46, bold=True)
t1 = "VPN упал"
t2 = "Claude Code — на паузе"
t3 = "Ни один байт не утёк"
w1 = d.textlength(t1, font=f_ring)
d.text(((W - w1) / 2, cy - 92), t1, font=f_ring, fill=FG)
w2 = d.textlength(t2, font=f_ring)
d.text(((W - w2) / 2, cy - 18), t2, font=f_ring, fill=FG)
w3 = d.textlength(t3, font=f_ring)
d.text(((W - w3) / 2, cy + 56), t3, font=f_ring, fill=MUTED)

# --- bottom: bullets + install ----------------------------------------------
y = cy + r + 120
f_b = font(44)
for line in [
    "✓ заморозка вместо убийства — сессия жива",
    "✓ утечки IPv6 / DNS / split-routing — видно",
    "✓ трей, панель, уведомления",
    "✓ Linux · macOS · Windows · open source",
]:
    y = center(line, y, f_b, FG)

f_link = font(54, bold=True)
y = center("github.com/rasuvaeff/shuang", y + 50, f_link, FROST)

img.save("docs/story.png")
print("saved docs/story.png", img.size)
