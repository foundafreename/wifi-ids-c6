#!/usr/bin/env python3
"""Adafruit/LovyanGFX-GFXfont-Generator mit Latin-1 (0x20..0xFF) aus einer TTF.
Aufruf: gen_gfxfont.py <ttf> <pixelhoehe> <name> <out.h>
Format identisch zu Adafruit fontconvert (1-bit, MSB-first, zeilenweise gepackt)."""
import sys, freetype

ttf, px, name, out = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
FIRST, LAST = 0x20, 0xFF
face = freetype.Face(ttf)
face.set_pixel_sizes(0, px)

bitmaps = bytearray()
glyphs = []
bitbuf, nbits = 0, 0

def push_bit(b):
    global bitbuf, nbits
    bitbuf = (bitbuf << 1) | (1 if b else 0)
    nbits += 1
    if nbits == 8:
        bitmaps.append(bitbuf); bitbuf, nbits = 0, 0

for cp in range(FIRST, LAST + 1):
    face.load_char(chr(cp), freetype.FT_LOAD_RENDER | freetype.FT_LOAD_TARGET_MONO)
    g = face.glyph; bm = g.bitmap
    w, h = bm.width, bm.rows
    off = len(bitmaps)
    # evtl. angefangenes Byte des Vorgaengers abschliessen (Adafruit packt pro Glyph byte-aligned)
    for y in range(h):
        row = bm.buffer[y * bm.pitch:(y + 1) * bm.pitch]
        for x in range(w):
            push_bit(row[x >> 3] & (0x80 >> (x & 7)))
    if nbits:
        bitbuf <<= (8 - nbits); bitmaps.append(bitbuf); bitbuf, nbits = 0, 0
    glyphs.append((off, w, h, g.advance.x >> 6, g.bitmap_left, -g.bitmap_top))

yadv = face.size.height >> 6
with open(out, "w") as f:
    f.write(f"// generated: {ttf.split('/')[-1]} {px}px, U+{FIRST:04X}..U+{LAST:04X}\n#pragma once\n#include <LovyanGFX.hpp>\n")
    f.write(f"static const uint8_t {name}Bitmaps[] PROGMEM = {{\n")
    for i in range(0, len(bitmaps), 16):
        f.write("  " + ", ".join(f"0x{b:02X}" for b in bitmaps[i:i+16]) + ",\n")
    f.write("};\n")
    f.write(f"static const lgfx::GFXglyph {name}Glyphs[] PROGMEM = {{\n")
    for cp, (o, w, h, a, xo, yo) in zip(range(FIRST, LAST + 1), glyphs):
        f.write(f"  {{ {o:5d}, {w:3d}, {h:3d}, {a:3d}, {xo:4d}, {yo:4d} }},  // 0x{cp:02X}\n")
    f.write("};\n")
    f.write(f"static const lgfx::GFXfont {name} PROGMEM = {{ (uint8_t*){name}Bitmaps, (lgfx::GFXglyph*){name}Glyphs, 0x{FIRST:02X}, 0x{LAST:02X}, {yadv} }};\n")
print(f"{name}: {len(bitmaps)} B bitmap, {len(glyphs)} glyphs, yAdvance {yadv}")
