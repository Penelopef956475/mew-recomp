#!/usr/bin/env python3
"""纯 Python 生成 App 图标（无 PIL / 无 freetype 依赖）。

设计：深潜主题 —— 深海军蓝渐变底 + 青色猫头剪影 + 潜水镜反光。
只用矩形/圆/多边形填充 + 简单的超采样抗锯齿，够 iOS 主屏显示。
输出到 ios_port/ios_app/icons/，供组装脚本直接拷进 .app 根目录。
"""
import math
import os
import struct
import zlib

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ios_port', 'ios_app', 'icons')


def png_write(path, w, h, rgba):
    raw = bytearray()
    stride = w * 4
    for y in range(h):
        raw.append(0)                      # filter: none
        raw += rgba[y * stride:(y + 1) * stride]

    def chunk(tag, data):
        c = struct.pack('>I', len(data)) + tag + data
        return c + struct.pack('>I', zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)
    with open(path, 'wb') as f:
        f.write(b'\x89PNG\r\n\x1a\n')
        f.write(chunk(b'IHDR', ihdr))
        f.write(chunk(b'IDAT', zlib.compress(bytes(raw), 9)))
        f.write(chunk(b'IEND', b''))


class Canvas:
    def __init__(self, n):
        self.n = n
        self.px = bytearray(n * n * 4)

    def blend(self, x, y, r, g, b, a):
        if x < 0 or y < 0 or x >= self.n or y >= self.n or a <= 0:
            return
        i = (y * self.n + x) * 4
        p = self.px
        sa = a / 255.0
        da = p[i + 3] / 255.0
        oa = sa + da * (1 - sa)
        if oa <= 0:
            return
        for k, v in enumerate((r, g, b)):
            p[i + k] = int((v * sa + p[i + k] * da * (1 - sa)) / oa)
        p[i + 3] = int(oa * 255)

    def fill_rect(self, x0, y0, x1, y1, color):
        for y in range(max(0, y0), min(self.n, y1)):
            for x in range(max(0, x0), min(self.n, x1)):
                self.blend(x, y, *color)

    def fill_circle(self, cx, cy, r, color, ss=4):
        # 超采样抗锯齿
        for y in range(max(0, int(cy - r - 1)), min(self.n, int(cy + r + 2))):
            for x in range(max(0, int(cx - r - 1)), min(self.n, int(cx + r + 2))):
                hit = 0
                for sy in range(ss):
                    for sx in range(ss):
                        px = x + (sx + 0.5) / ss
                        py = y + (sy + 0.5) / ss
                        if (px - cx) ** 2 + (py - cy) ** 2 <= r * r:
                            hit += 1
                if hit:
                    self.blend(x, y, color[0], color[1], color[2],
                               int(color[3] * hit / (ss * ss)))

    def fill_poly(self, pts, color, ss=4):
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        for y in range(max(0, int(min(ys)) - 1), min(self.n, int(max(ys)) + 2)):
            for x in range(max(0, int(min(xs)) - 1), min(self.n, int(max(xs)) + 2)):
                hit = 0
                for sy in range(ss):
                    for sx in range(ss):
                        px = x + (sx + 0.5) / ss
                        py = y + (sy + 0.5) / ss
                        inside = False
                        j = len(pts) - 1
                        for i in range(len(pts)):
                            xi, yi = pts[i]
                            xj, yj = pts[j]
                            if ((yi > py) != (yj > py)) and \
                               (px < (xj - xi) * (py - yi) / (yj - yi + 1e-9) + xi):
                                inside = not inside
                            j = i
                        if inside:
                            hit += 1
                if hit:
                    self.blend(x, y, color[0], color[1], color[2],
                               int(color[3] * hit / (ss * ss)))

    def to_rgba(self):
        return bytes(self.px)


def draw_icon(n):
    c = Canvas(n)
    s = n / 1024.0
    # 背景：深海军蓝垂直渐变
    for y in range(n):
        t = y / max(1, n - 1)
        r = int(8 + 10 * t)
        g = int(20 + 34 * t)
        b = int(38 + 46 * t)
        c.fill_rect(0, y, n, y + 1, (r, g, b, 255))

    # 水波光束（几条斜向淡青色带）
    for i in range(5):
        x0 = int((120 + i * 210) * s)
        pts = [(x0, 0), (x0 + int(70 * s), 0), (x0 - int(120 * s), n), (x0 - int(190 * s), n)]
        c.fill_poly(pts, (46, 120, 150, 26))

    # 猫耳（两个三角）
    ear = (64, 214, 214, 255)
    c.fill_poly([(int(300 * s), int(430 * s)), (int(360 * s), int(210 * s)),
                 (int(470 * s), int(400 * s))], ear)
    c.fill_poly([(int(724 * s), int(430 * s)), (int(664 * s), int(210 * s)),
                 (int(554 * s), int(400 * s))], ear)
    # 内耳
    inner = (16, 70, 92, 255)
    c.fill_poly([(int(330 * s), int(410 * s)), (int(363 * s), int(272 * s)),
                 (int(432 * s), int(396 * s))], inner)
    c.fill_poly([(int(694 * s), int(410 * s)), (int(661 * s), int(272 * s)),
                 (int(592 * s), int(396 * s))], inner)

    # 猫头
    c.fill_circle(512 * s, 560 * s, 260 * s, ear)
    # 潜水镜（深色圆角带）
    c.fill_rect(int(300 * s), int(470 * s), int(724 * s), int(650 * s), (10, 34, 52, 255))
    c.fill_rect(int(300 * s), int(470 * s), int(724 * s), int(486 * s), (86, 210, 224, 255))
    # 镜片高光
    c.fill_circle(430 * s, 560 * s, 74 * s, (150, 240, 250, 235))
    c.fill_circle(594 * s, 560 * s, 74 * s, (150, 240, 250, 235))
    c.fill_circle(452 * s, 538 * s, 22 * s, (255, 255, 255, 200))
    c.fill_circle(616 * s, 538 * s, 22 * s, (255, 255, 255, 200))
    # 呼吸管
    c.fill_rect(int(700 * s), int(300 * s), int(742 * s), int(560 * s), (86, 210, 224, 255))
    c.fill_circle(721 * s, 300 * s, 21 * s, (86, 210, 224, 255))
    # 底部胡须
    for dx in (-1, 1):
        for k in range(3):
            y0 = int((700 + k * 26) * s)
            x0 = int((512 + dx * 60) * s)
            x1 = int((512 + dx * 300) * s)
            c.fill_rect(min(x0, x1), y0, max(x0, x1), y0 + int(7 * s), (16, 70, 92, 255))
    return c.to_rgba()


def downscale(src_n, src, dst_n):
    if dst_n == src_n:
        return src
    out = bytearray(dst_n * dst_n * 4)
    f = src_n / dst_n
    for y in range(dst_n):
        y0, y1 = int(y * f), max(int(y * f) + 1, int((y + 1) * f))
        for x in range(dst_n):
            x0, x1 = int(x * f), max(int(x * f) + 1, int((x + 1) * f))
            ar = ag = ab = aa = 0
            cnt = 0
            for yy in range(y0, min(y1, src_n)):
                base = yy * src_n * 4
                for xx in range(x0, min(x1, src_n)):
                    i = base + xx * 4
                    a = src[i + 3]
                    ar += src[i] * a
                    ag += src[i + 1] * a
                    ab += src[i + 2] * a
                    aa += a
                    cnt += 1
            j = (y * dst_n + x) * 4
            if aa:
                out[j] = ar // aa
                out[j + 1] = ag // aa
                out[j + 2] = ab // aa
                out[j + 3] = aa // max(1, cnt)
    return bytes(out)


def main():
    os.makedirs(OUT, exist_ok=True)
    N = 1024
    big = draw_icon(N)
    png_write(os.path.join(OUT, 'AppIcon1024.png'), N, N, big)

    # iOS 需要的尺寸（文件名与 Info.plist 的 CFBundleIconFiles 对应）
    targets = {
        'AppIcon60x60@2x.png': 120,
        'AppIcon60x60@3x.png': 180,
        'AppIcon76x76@2x~ipad.png': 152,
        'AppIcon83.5x83.5@2x~ipad.png': 167,
        'AppIcon40x40@2x.png': 80,
        'AppIcon29x29@2x.png': 58,
    }
    for name, size in targets.items():
        png_write(os.path.join(OUT, name), size, size, downscale(N, big, size))

    for f in sorted(os.listdir(OUT)):
        p = os.path.join(OUT, f)
        print('%-32s %8d B' % (f, os.path.getsize(p)))


if __name__ == '__main__':
    main()
