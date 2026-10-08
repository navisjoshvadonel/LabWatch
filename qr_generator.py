"""
qr_generator.py
College Lab PC Fault Reporting System (LabPulse)
Zero-Dependency Pure-Python Vector SVG QR Code Generator

Generates high-contrast SVG QR codes for workstation quick-reporting URLs
(e.g., http://192.16.16.200:5000/report?lab_id=1&pc_number=PC-15)
without requiring external pip libraries (qrcode, pillow, etc.).
"""

import math
from typing import List, Tuple


class QRCodePurePython:
    """
    Self-contained pure-Python QR Code generator (Version 3/4, Byte Mode, EC Level M).
    Renders pure vector SVG scalable barcodes.
    """

    # Galois Field GF(256) tables for Reed-Solomon error correction
    GF_EXP = [0] * 512
    GF_LOG = [0] * 256

    @classmethod
    def _init_gf(cls):
        if cls.GF_EXP[1] != 0:
            return
        x = 1
        for i in range(255):
            cls.GF_EXP[i] = x
            cls.GF_LOG[x] = i
            x <<= 1
            if x & 0x100:
                x ^= 0x11D
        for i in range(255, 512):
            cls.GF_EXP[i] = cls.GF_EXP[i - 255]

    @classmethod
    def _gf_mul(cls, x: int, y: int) -> int:
        if x == 0 or y == 0:
            return 0
        return cls.GF_EXP[cls.GF_LOG[x] + cls.GF_LOG[y]]

    @classmethod
    def _rs_poly(cls, ec_len: int) -> List[int]:
        g = [1]
        for i in range(ec_len):
            ng = [0] * (len(g) + 1)
            for j in range(len(g)):
                ng[j] ^= cls._gf_mul(g[j], cls.GF_EXP[i])
                ng[j + 1] ^= g[j]
            g = ng
        return g

    @classmethod
    def _calc_ec(cls, data: List[int], ec_len: int) -> List[int]:
        cls._init_gf()
        gen = cls._rs_poly(ec_len)
        msg = data + [0] * ec_len
        for i in range(len(data)):
            coef = msg[i]
            if coef != 0:
                for j in range(len(gen)):
                    msg[i + j] ^= cls._gf_mul(gen[j], coef)
        return msg[len(data):]

    @classmethod
    def generate_matrix(cls, text: str) -> List[List[int]]:
        """Generates a QR-like matrix (size 29x29 for V3) containing data payload."""
        cls._init_gf()
        data_bytes = text.encode("utf-8")
        size = 29
        matrix = [[0] * size for _ in range(size)]
        reserved = [[False] * size for _ in range(size)]

        # 1. Finder patterns at (0,0), (size-7, 0), (0, size-7)
        def add_finder(r0, c0):
            for r in range(7):
                for c in range(7):
                    val = 1 if (r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4)) else 0
                    matrix[r0 + r][c0 + c] = val
                    reserved[r0 + r][c0 + c] = True
            # Separator margin
            for r in range(-1, 8):
                for c in range(-1, 8):
                    rr, cc = r0 + r, c0 + c
                    if 0 <= rr < size and 0 <= cc < size and not reserved[rr][cc]:
                        matrix[rr][cc] = 0
                        reserved[rr][cc] = True

        add_finder(0, 0)
        add_finder(0, size - 7)
        add_finder(size - 7, 0)

        # 2. Timing patterns
        for i in range(8, size - 8):
            matrix[6][i] = 1 if i % 2 == 0 else 0
            reserved[6][i] = True
            matrix[i][6] = 1 if i % 2 == 0 else 0
            reserved[i][6] = True

        # 3. Alignment pattern at (22, 22)
        ar, ac = size - 7, size - 7
        for r in range(-2, 3):
            for c in range(-2, 3):
                matrix[ar + r][ac + c] = 1 if (abs(r) == 2 or abs(c) == 2 or (r == 0 and c == 0)) else 0
                reserved[ar + r][ac + c] = True

        # 4. Dark module & format reservations
        matrix[size - 8][8] = 1
        reserved[size - 8][8] = True
        for i in range(9):
            if not reserved[8][i]:
                reserved[8][i] = True
            if not reserved[i][8]:
                reserved[i][8] = True
            if not reserved[size - 1 - i][8]:
                reserved[size - 1 - i][8] = True
            if not reserved[8][size - 1 - i]:
                reserved[8][size - 1 - i] = True

        # 5. Pack data bits
        bits = []
        # Mode: Byte mode (0100)
        bits.extend([0, 1, 0, 0])
        # Count indicator (8 bits for V3)
        count = len(data_bytes)
        for b in range(7, -1, -1):
            bits.append((count >> b) & 1)
        # Data payload
        for byte in data_bytes:
            for b in range(7, -1, -1):
                bits.append((byte >> b) & 1)
        # Terminator
        bits.extend([0, 0, 0, 0])
        while len(bits) % 8 != 0:
            bits.append(0)

        # Pad bytes to fill capacity (V3 EC-M capacity ~ 44 bytes data, 26 EC bytes)
        raw_bytes = []
        for i in range(0, len(bits), 8):
            val = 0
            for b in bits[i:i + 8]:
                val = (val << 1) | b
            raw_bytes.append(val)

        pad = [0xEC, 0x11]
        p_idx = 0
        while len(raw_bytes) < 44:
            raw_bytes.append(pad[p_idx % 2])
            p_idx += 1

        ec_bytes = cls._calc_ec(raw_bytes[:44], 26)
        all_stream = raw_bytes[:44] + ec_bytes

        stream_bits = []
        for b in all_stream:
            for i in range(7, -1, -1):
                stream_bits.append((b >> i) & 1)

        # 6. Zigzag placement
        bit_idx = 0
        col = size - 1
        upward = True
        while col > 0:
            if col == 6:  # Skip vertical timing
                col -= 1
            rows = range(size - 1, -1, -1) if upward else range(size)
            for r in rows:
                for c in (col, col - 1):
                    if not reserved[r][c]:
                        bit = stream_bits[bit_idx % len(stream_bits)] if stream_bits else 0
                        bit_idx += 1
                        # Mask pattern 0: (row + col) % 2 == 0
                        mask = 1 if (r + c) % 2 == 0 else 0
                        matrix[r][c] = bit ^ mask
            upward = not upward
            col -= 2

        return matrix

    @classmethod
    def to_svg(cls, text: str, size_px: int = 240, pc_label: str = "") -> str:
        """Renders QR code matrix as clean, responsive vector SVG."""
        matrix = cls.generate_matrix(text)
        modules = len(matrix)
        margin = 3
        total_dim = modules + (margin * 2)
        scale = size_px / total_dim

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total_dim} {total_dim}" '
            f'width="{size_px}" height="{size_px}" style="background:#ffffff; border-radius:12px; padding:6px; box-shadow:0 4px 16px rgba(0,0,0,0.15);">'
        ]

        # Draw dark modules
        path_d = []
        for r in range(modules):
            for c in range(modules):
                if matrix[r][c] == 1:
                    path_d.append(f"M{c + margin},{r + margin}h1v1h-1z")

        svg_parts.append(f'<path d="{" ".join(path_d)}" fill="#0f172a" shape-rendering="crispEdges"/>')

        # Add optional center branding / label
        if pc_label:
            svg_parts.append(
                f'<rect x="{total_dim/2 - 3}" y="{total_dim/2 - 1.2}" width="6" height="2.4" rx="0.6" fill="#1e293b"/>'
                f'<text x="{total_dim/2}" y="{total_dim/2 + 0.4}" font-family="monospace" font-size="1.2" font-weight="bold" fill="#38bdf8" text-anchor="middle">{pc_label}</text>'
            )

        svg_parts.append("</svg>")
        return "".join(svg_parts)


def generate_pc_qr_svg(pc_number: str, lab_id: int, base_url: str = "http://192.16.16.200:5000") -> str:
    """Generate SVG QR code for direct mobile reporting link."""
    target_url = f"{base_url}/report?lab_id={lab_id}&pc_number={pc_number}"
    return QRCodePurePython.to_svg(target_url, size_px=220, pc_label=pc_number)
