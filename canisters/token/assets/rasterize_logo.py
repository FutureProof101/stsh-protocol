#!/usr/bin/env python3
"""Deterministic stdlib-only rasterizer for canisters/token/assets/stsh-logo.svg.

Scope is deliberately narrow: it accepts ONLY the shape that SVG has (one
full-tile <rect> fill #000000, one <path> fill #ffffff fill-rule evenodd whose
d uses absolute M/L/Z only, viewBox "0 0 W H") and refuses anything else.
Output: 8-bit grayscale PNG, SIZE x SIZE, anti-aliased by exact horizontal
span coverage x SUB vertical sub-scanlines. No timestamps/metadata chunks, so
the output bytes are a pure function of (svg bytes, SIZE, SUB, zlib level).

usage: rasterize_logo.py <in.svg> <out.png> [size=256]
"""
import re, struct, sys, zlib

SUB = 16  # vertical sub-scanlines per pixel


def parse(svg: str):
    vb = re.search(r'viewBox="0 0 ([0-9.]+) ([0-9.]+)"', svg)
    if not vb:
        sys.exit("refuse: viewBox must be '0 0 W H'")
    if not re.search(r'<rect width="100%" height="100%" fill="#000000"/>', svg):
        sys.exit("refuse: expected full-tile black rect")
    pm = re.findall(r'<path d="([^"]*)" fill="#ffffff" fill-rule="evenodd"/>', svg)
    if len(pm) != 1 or svg.count("<path") != 1 or svg.count("<rect") != 1:
        sys.exit("refuse: expected exactly one white evenodd path and one rect")
    toks = re.findall(r"[MLZ]|-?[0-9.]+", pm[0])
    if "".join(toks).replace(" ", "") != re.sub(r"\s+", "", pm[0]):
        sys.exit("refuse: path has commands other than absolute M/L/Z")
    polys, cur, i = [], None, 0
    while i < len(toks):
        t = toks[i]
        if t == "M":
            cur = [(float(toks[i + 1]), float(toks[i + 2]))]; i += 3
        elif t == "L":
            cur.append((float(toks[i + 1]), float(toks[i + 2]))); i += 3
        elif t == "Z":
            polys.append(cur); cur = None; i += 1
        else:
            sys.exit(f"refuse: unexpected token {t!r}")
    if cur is not None:
        sys.exit("refuse: unclosed subpath")
    return float(vb.group(1)), float(vb.group(2)), polys


def raster(W, H, polys, size):
    sx, sy = size / W, size / H
    edges = []
    for p in polys:
        for a, b in zip(p, p[1:] + p[:1]):
            (x0, y0), (x1, y1) = (a[0] * sx, a[1] * sy), (b[0] * sx, b[1] * sy)
            if y0 != y1:
                edges.append((x0, y0, x1, y1))
    cov = [[0.0] * size for _ in range(size)]
    for py in range(size):
        row = cov[py]
        for s in range(SUB):
            y = py + (s + 0.5) / SUB
            xs = []
            for x0, y0, x1, y1 in edges:
                if (y0 <= y < y1) or (y1 <= y < y0):
                    xs.append(x0 + (y - y0) * (x1 - x0) / (y1 - y0))
            xs.sort()
            for a, b in zip(xs[0::2], xs[1::2]):  # even-odd spans
                a, b = max(a, 0.0), min(b, float(size))
                if b <= a:
                    continue
                ia, ib = int(a), int(b)
                if ia == ib:
                    row[ia] += (b - a) / SUB
                    continue
                row[ia] += (ia + 1 - a) / SUB
                for k in range(ia + 1, min(ib, size)):
                    row[k] += 1.0 / SUB
                if ib < size:
                    row[ib] += (b - ib) / SUB
    return [bytes(min(255, int(round(c * 255))) for c in r) for r in cov]


def png(rows, size):
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    raw, prev = bytearray(), bytes(size)
    for r in rows:  # per-row filter choice: min sum of |signed| (libpng heuristic)
        cands = []
        for f in range(5):
            out = bytearray()
            for i, x in enumerate(r):
                a = r[i - 1] if i else 0
                b = prev[i]
                c = prev[i - 1] if i else 0
                if f == 0: pr = 0
                elif f == 1: pr = a
                elif f == 2: pr = b
                elif f == 3: pr = (a + b) // 2
                else:
                    p = a + b - c; pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                    pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                out.append((x - pr) & 0xFF)
            cands.append((sum(v if v < 128 else 256 - v for v in out), f, bytes(out)))
        _, f, out = min(cands)
        raw += bytes([f]) + out
        prev = r
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 0, 0, 0, 0)  # 8-bit grayscale
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    size = int(sys.argv[3]) if len(sys.argv) > 3 else 256
    W, H, polys = parse(open(src, encoding="utf-8").read())
    data = png(raster(W, H, polys, size), size)
    open(dst, "wb").write(data)
    print(f"{dst}: {size}x{size} gray8, {len(data)} bytes")
