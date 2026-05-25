from PIL import Image, ImageDraw, ImageFont
import os

W, H = 1200, 630
OUT = os.path.join(os.path.dirname(__file__), "loaders-banner.png")

# Catppuccin-ish palette
BG       = (30, 30, 46)
WIN_BG   = (17, 17, 27)
WIN_BORDER = (49, 50, 68)
TITLEBAR = (24, 24, 37)
RED      = (243, 139, 168)
YEL      = (249, 226, 175)
GRN      = (166, 227, 161)
GRAY_DIM = (108, 112, 134)
GRAY_FG  = (127, 132, 156)
FG       = (205, 214, 244)
PURPLE   = (203, 166, 247)
BLUE     = (137, 180, 250)
GREEN_S  = (166, 227, 161)
YELLOW_F = (249, 226, 175)
ORANGE   = (250, 179, 135)

img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)

# Window
WIN_X, WIN_Y, WIN_W, WIN_H = 120, 105, 960, 420
d.rounded_rectangle([WIN_X, WIN_Y, WIN_X+WIN_W, WIN_Y+WIN_H], radius=12, fill=WIN_BG, outline=WIN_BORDER, width=1)
# Title bar
d.rounded_rectangle([WIN_X, WIN_Y, WIN_X+WIN_W, WIN_Y+42], radius=12, fill=TITLEBAR)
d.rectangle([WIN_X, WIN_Y+30, WIN_X+WIN_W, WIN_Y+42], fill=TITLEBAR)

# Traffic lights
for cx, color in [(148, RED), (170, YEL), (192, GRN)]:
    d.ellipse([cx-7, 119, cx+7, 133], fill=color)

# Fonts
def font(size, bold=False):
    candidates = [
        "C:/Windows/Fonts/consolab.ttf" if bold else "C:/Windows/Fonts/consola.ttf",
        "C:/Windows/Fonts/cour.ttf",
    ]
    for p in candidates:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()

def font_sans(size, bold=False):
    p = "C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf"
    if os.path.exists(p):
        return ImageFont.truetype(p, size)
    return ImageFont.load_default()

f_code = font(20)
f_code_b = font(20, bold=True)
f_small = font(16)
f_title = font_sans(40, bold=True)
f_sub   = font_sans(24)

# Filename centered in title bar
fname = "loader.c — 0xDbgMan"
tw = d.textlength(fname, font=f_small)
d.text((WIN_X + WIN_W/2 - tw/2, 116), fname, font=f_small, fill=GRAY_FG)

# Code lines
def line(y, parts):
    """parts: list of (text, color)"""
    x = WIN_X + 35
    for text, color in parts:
        d.text((x, y), text, font=f_code, fill=color)
        x += d.textlength(text, font=f_code)

LN_X = WIN_X + 35
def num(y, n):
    d.text((LN_X, y), f"{n:02d}", font=f_code, fill=GRAY_DIM)

y = 175
num(y, 1)
line(y, [("    ", FG), ("#include ", PURPLE), ("<windows.h>", GREEN_S)])

y += 30
num(y, 2)

y += 30
num(y, 3)
line(y, [("    ", FG), ("int ", BLUE), ("main", YELLOW_F), ("() {", FG)])

y += 30
num(y, 4)
line(y, [("        void *mem = ", FG), ("VirtualAlloc", YELLOW_F), ("(0, sz, ", FG),
         ("MEM_COMMIT", ORANGE), (", ", FG), ("PAGE_RWX", ORANGE), (");", FG)])

y += 30
num(y, 5)
line(y, [("        ", FG), ("memcpy", YELLOW_F), ("(mem, payload, sz);", FG)])

y += 30
num(y, 6)
line(y, [("        ((void(*)())mem)();", FG)])

y += 30
num(y, 7)
line(y, [("    }", FG)])

# Title under window
title = "Shellcode Loaders"
sub   = "  — the art of execution"
tw1 = d.textlength(title, font=f_title)
tw2 = d.textlength(sub, font=f_sub)
total = tw1 + tw2
start = (W - total) / 2
d.text((start, 555), title, font=f_title, fill=FG)
d.text((start + tw1, 568), sub, font=f_sub, fill=GRAY_FG)

img.save(OUT, "PNG")
print(f"wrote {OUT}")
