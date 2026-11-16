"""Builds tiny sample files in memory for the tests. Nothing here is a real photograph or a real AI image."""
import struct, zlib

def png(chunks, w=1024, h=1024):
    def ch(t, b):
        return struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b))
    out = b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    for t, b in chunks:
        out += ch(t, b)
    return out + ch(b"IDAT", zlib.compress(b"\x00" * 4)) + ch(b"IEND", b"")

def text(k, v):
    return (b"tEXt", k.encode() + b"\x00" + v.encode("latin-1", "replace"))

def itxt(k, v):
    return (b"iTXt", k.encode() + b"\x00\x00\x00\x00\x00" + v.encode())

def exif(make=None, model=None, software=None, shot=False):
    """A minimal little-endian TIFF block with IFD0 and, optionally, an Exif sub-IFD."""
    entries, blob = [], b""
    def add(tag, s):
        nonlocal blob
        b = s.encode() + b"\x00"
        entries.append((tag, 2, len(b), b))
    if make: add(0x010F, make)
    if model: add(0x0110, model)
    if software: add(0x0131, software)
    n = len(entries) + (1 if shot else 0)
    base = 8 + 2 + n * 12 + 4
    ifd, data = b"", b""
    for tag, typ, cnt, b in entries:
        if len(b) <= 4:
            ifd += struct.pack("<HHI", tag, typ, cnt) + b.ljust(4, b"\x00")
        else:
            ifd += struct.pack("<HHII", tag, typ, cnt, base + len(data)); data += b
    sub = b""
    if shot:
        sub_off = base + len(data)
        ifd += struct.pack("<HHII", 0x8769, 4, 1, sub_off)
        dt = b"2026:11:16 10:30:00\x00"
        s_entries = 4
        s_base = sub_off + 2 + s_entries * 12 + 4
        sub = struct.pack("<H", s_entries)
        sub += struct.pack("<HHII", 0x9003, 2, len(dt), s_base)
        sub += struct.pack("<HHII", 0x829A, 5, 1, s_base + len(dt))
        sub += struct.pack("<HHII", 0x829D, 5, 1, s_base + len(dt) + 8)
        sub += struct.pack("<HHIHH", 0x8827, 3, 1, 200, 0)
        sub += struct.pack("<I", 0) + dt + struct.pack("<II", 1, 250) + struct.pack("<II", 18, 10)
    return b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", n) + ifd + struct.pack("<I", 0) + data + sub

def jpeg(segments, w=4000, h=3000):
    out = b"\xff\xd8"
    for marker, body in segments:
        out += bytes([0xFF, marker]) + struct.pack(">H", len(body) + 2) + body
    out += b"\xff\xc0" + struct.pack(">H", 11) + b"\x08" + struct.pack(">HH", h, w) + b"\x01\x01\x11\x00"
    return out + b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + b"\x00" * 8 + b"\xff\xd9"

def xmp(inner):
    return (0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + ('<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description ' + inner + '/></rdf:RDF></x:xmpmeta>').encode())

def jumbf(payload):
    return (0xEB, b"JP\x00\x01\x00\x00\x00\x01" + struct.pack(">I", len(payload) + 16) + b"jumb" + b"\x00\x00\x00\x08c2pa" + payload)

AI_TYPE = 'Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"'
