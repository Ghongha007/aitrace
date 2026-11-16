"""aitrace: look inside an image or video file for traces of how it was made.

It reads what the file says about itself: Content Credentials (C2PA), the IPTC
"digital source type", generator settings left by AI image tools, and camera or
editing-software metadata. It does not analyse pixels and gives no probability.
"""
from __future__ import annotations

import json
import os
import re
import struct
import zlib
from dataclasses import dataclass, field, asdict

MAX_READ = 64 * 1024 * 1024          # images larger than this are scanned like videos
SCAN_CHUNK = 4 * 1024 * 1024

# IPTC digital source types (the last path segment of the IPTC NewsCodes URI)
SOURCE_TYPES = {
    "trainedAlgorithmicMedia": ("ai", "created by a generative AI model"),
    "compositeWithTrainedAlgorithmicMedia": ("ai", "edited or composited using generative AI"),
    "algorithmicMedia": ("synthetic", "created by an algorithm (not a trained AI model)"),
    "compositeSynthetic": ("synthetic", "a composite that includes synthetic elements"),
    "digitalCapture": ("camera", "captured by a digital camera"),
    "computationalCapture": ("camera", "captured by a camera with computational processing"),
    "negativeFilm": ("camera", "digitised from film negative"),
    "positiveFilm": ("camera", "digitised from film positive"),
    "print": ("camera", "digitised from a print"),
    "minorHumanEdits": ("edit", "original media with minor human edits"),
    "compositeCapture": ("edit", "a composite of captured elements"),
    "digitalArt": ("edit", "created by a person using digital tools"),
    "digitalCreation": ("edit", "created by a person using digital tools"),
    "screenCapture": ("edit", "a screen capture"),
    "dataDrivenMedia": ("synthetic", "generated from data (for example a chart)"),
    "virtualRecording": ("synthetic", "a recording of a virtual scene"),
}
# Names that identify AI generators when they appear in software/creator fields or inside a C2PA manifest.
GENERATORS = ["Midjourney", "DALL-E", "DALL·E", "ChatGPT", "OpenAI", "Sora", "Stable Diffusion", "Stability AI", "DreamStudio",
              "Adobe Firefly", "Firefly", "Imagen", "Made with Google AI", "Google AI", "Gemini", "Veo", "Bing Image Creator",
              "Microsoft Designer", "Copilot", "Leonardo.Ai", "Ideogram", "FLUX", "Black Forest Labs", "Grok", "Aurora",
              "Runway", "Pika", "Kling", "Luma", "NovelAI", "InvokeAI", "ComfyUI", "Automatic1111", "Fooocus", "Meta AI",
              "Playground", "Krea", "Recraft", "Freepik", "Canva Magic", "ElevenLabs", "HeyGen", "Synthesia"]
EDITORS = ["Adobe Photoshop", "Photoshop", "Lightroom", "GIMP", "Canva", "Snapseed", "PicsArt", "Pixelmator", "Affinity Photo",
           "Capture One", "darktable", "Paint.NET", "FaceApp", "Facetune", "Remini", "CapCut", "Premiere", "After Effects",
           "DaVinci Resolve", "Final Cut", "InShot", "Lavf", "HandBrake"]
# Sizes that popular generators output by default. Many ordinary images share them, so this is only ever a weak hint.
AI_SIZES = {(512, 512), (768, 768), (1024, 1024), (2048, 2048), (1024, 1792), (1792, 1024), (1024, 1536), (1536, 1024),
            (832, 1216), (1216, 832), (896, 1152), (1152, 896), (768, 1344), (1344, 768), (640, 1536), (1536, 640),
            (1024, 1408), (1408, 1024), (928, 1232), (1232, 928), (816, 1456), (1456, 816)}

STRONG, MODERATE, WEAK, INFO = "strong", "moderate", "weak", "info"


@dataclass
class Finding:
    kind: str          # ai | synthetic | credentials | camera | edit | info
    strength: str      # strong | moderate | weak | info
    what: str          # what was found
    where: str         # where in the file
    caveat: str = ""   # what it cannot tell you


@dataclass
class Report:
    path: str
    format: str = "unknown"
    size_bytes: int = 0
    width: int | None = None
    height: int | None = None
    verdict: str = ""
    summary: str = ""
    findings: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def add(self, *a, **k):
        f = Finding(*a, **k)
        if not any(x.kind == f.kind and x.what == f.what for x in self.findings):
            self.findings.append(f)

    def to_dict(self):
        return asdict(self)


def _txt(b: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return b.decode(enc).strip("\x00 \r\n\t")
        except UnicodeDecodeError:
            continue
    return ""


def _find_names(text: str, names) -> list[str]:
    out, low = [], text.lower()
    for n in names:
        i = low.find(n.lower())
        while i >= 0:
            before = low[i - 1] if i else " "
            after = low[i + len(n)] if i + len(n) < len(low) else " "
            if not before.isalnum() and not after.isalpha():      # a version number may follow: "Lavf60", "Veo3"
                out.append(n)
                break
            i = low.find(n.lower(), i + 1)
    # drop a short name when a longer one containing it also matched ("Firefly" inside "Adobe Firefly")
    return [n for n in out if not any(n != m and n.lower() in m.lower() for m in out)]


def _cbor_text(buf: bytes, pos: int) -> str:
    """Read the CBOR text string that starts at pos (C2PA manifests are CBOR). Returns '' if there is none."""
    if pos >= len(buf):
        return ""
    b = buf[pos]
    if 0x60 <= b <= 0x77:
        n, pos = b - 0x60, pos + 1
    elif b == 0x78 and pos + 1 < len(buf):
        n, pos = buf[pos + 1], pos + 2
    elif b == 0x79 and pos + 2 < len(buf):
        n, pos = int.from_bytes(buf[pos + 1:pos + 3], "big"), pos + 3
    else:
        return ""
    try:
        return buf[pos:pos + min(n, 300)].decode("utf-8").strip()
    except UnicodeDecodeError:
        return ""


# ---------------------------------------------------------------- EXIF (TIFF)

EXIF_TAGS = {0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model", 0x0131: "Software", 0x0132: "DateTime",
             0x013B: "Artist", 0x8298: "Copyright", 0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
             0xA434: "LensModel", 0xA433: "LensMake", 0x9286: "UserComment", 0x829A: "ExposureTime", 0x829D: "FNumber",
             0x8827: "ISO", 0x920A: "FocalLength"}


def parse_exif(tiff: bytes) -> dict:
    out: dict = {}
    if len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return out
    e = "<" if tiff[:2] == b"II" else ">"
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}

    def ifd(off: int, depth: int = 0):
        if depth > 3 or off + 2 > len(tiff):
            return
        (n,) = struct.unpack_from(e + "H", tiff, off)
        for i in range(min(n, 200)):
            p = off + 2 + i * 12
            if p + 12 > len(tiff):
                return
            tag, typ, cnt = struct.unpack_from(e + "HHI", tiff, p)
            size = sizes.get(typ, 0) * cnt
            vp = p + 8 if size <= 4 else struct.unpack_from(e + "I", tiff, p + 8)[0]
            if size == 0 or vp + size > len(tiff):
                continue
            raw = tiff[vp:vp + size]
            if tag in (0x8769, 0x8825) and typ == 4:
                if tag == 0x8825:
                    out["GPS"] = "present"
                else:
                    ifd(struct.unpack_from(e + "I", raw)[0], depth + 1)
                continue
            name = EXIF_TAGS.get(tag)
            if not name:
                continue
            if typ == 2:
                val = _txt(raw)
            elif tag == 0x9286:
                val = _txt(raw[8:]).replace("\x00", "") if len(raw) > 8 else ""
            elif typ in (3, 4) and cnt == 1:
                val = struct.unpack_from(e + ("H" if typ == 3 else "I"), raw)[0]
            elif typ == 5 and cnt == 1:
                a, b = struct.unpack_from(e + "II", raw)
                val = f"{a}/{b}" if b else ""
            else:
                continue
            if val not in ("", None):
                out[name] = val

    ifd(struct.unpack_from(e + "I", tiff, 4)[0])
    return out


# ---------------------------------------------------------------- XMP

def parse_xmp(xmp: str) -> dict:
    out: dict = {}
    m = re.findall(r"digitalsourcetype/([A-Za-z]+)", xmp, flags=re.I)
    if m:
        out["DigitalSourceType"] = sorted(set(m))
    for key, pat in (("CreatorTool", r"CreatorTool(?:>|=\")([^<\"]+)"), ("Credit", r"photoshop:Credit(?:>|=\")([^<\"]+)"),
                     ("Software", r"tiff:Software(?:>|=\")([^<\"]+)"), ("Make", r"tiff:Make(?:>|=\")([^<\"]+)"),
                     ("Model", r"tiff:Model(?:>|=\")([^<\"]+)"), ("SoftwareAgent", r"softwareAgent(?:>|=\")([^<\"]+)")):
        v = re.findall(pat, xmp)
        if v:
            out[key] = sorted(set(x.strip() for x in v))[:6]
    d = re.search(r"<dc:description>.*?<rdf:li[^>]*>(.*?)</rdf:li>", xmp, flags=re.S)
    if d:
        out["Description"] = re.sub(r"\s+", " ", d.group(1))[:300]
    if "c2pa" in xmp.lower() or "provenance" in xmp.lower():
        p = re.search(r"dcterms:provenance(?:>|=\")([^<\"]+)", xmp)
        if p:
            out["ProvenanceLink"] = p.group(1)
    return out


# ---------------------------------------------------------------- containers

def read_jpeg(data: bytes, rep: Report, parts: dict):
    i, jumbf = 2, []
    while i + 4 <= len(data):
        if data[i] != 0xFF:
            break
        m = data[i + 1]
        if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        if m == 0xD9:
            break
        (ln,) = struct.unpack_from(">H", data, i + 2)
        seg = data[i + 4:i + 2 + ln]
        if m == 0xE1 and seg[:6] == b"Exif\x00\x00":
            parts["exif"] = parse_exif(seg[6:])
        elif m == 0xE1 and seg[:29] == b"http://ns.adobe.com/xap/1.0/\x00":
            parts["xmp"] = parts.get("xmp", "") + _txt(seg[29:])
        elif m == 0xE1 and seg[:35] == b"http://ns.adobe.com/xmp/extension/\x00":
            parts["xmp"] = parts.get("xmp", "") + _txt(seg[75:])
        elif m == 0xEB and seg[:2] == b"JP":
            jumbf.append(seg[8:])
        elif m == 0xED and seg[:13] == b"Photoshop 3.0":
            parts["iptc_raw"] = seg
        elif m == 0xFE:
            parts.setdefault("comments", []).append(_txt(seg)[:300])
        elif m in (0xC0, 0xC1, 0xC2) and len(seg) >= 5:
            rep.height, rep.width = struct.unpack_from(">HH", seg, 1)
        if m == 0xDA:
            break
        i += 2 + ln
    if jumbf:
        parts["c2pa"] = b"".join(jumbf)


def read_png(data: bytes, rep: Report, parts: dict):
    i, text = 8, {}
    while i + 12 <= len(data):
        ln, typ = struct.unpack_from(">I4s", data, i)
        body = data[i + 8:i + 8 + ln]
        if typ == b"IHDR" and ln >= 8:
            rep.width, rep.height = struct.unpack_from(">II", body)
        elif typ == b"tEXt" and b"\x00" in body:
            k, v = body.split(b"\x00", 1)
            text[_txt(k)] = _txt(v)
        elif typ == b"zTXt" and b"\x00" in body:
            k, v = body.split(b"\x00", 1)
            try:
                text[_txt(k)] = _txt(zlib.decompress(v[1:]))
            except zlib.error:
                pass
        elif typ == b"iTXt" and b"\x00" in body:
            k, rest = body.split(b"\x00", 1)
            if len(rest) >= 2:
                comp = rest[0]
                segs = rest[2:].split(b"\x00", 2)
                if len(segs) == 3:
                    v = segs[2]
                    if comp:
                        try:
                            v = zlib.decompress(v)
                        except zlib.error:
                            v = b""
                    text[_txt(k)] = _txt(v)
        elif typ == b"eXIf":
            parts["exif"] = parse_exif(body)
        elif typ == b"caBX":
            parts["c2pa"] = parts.get("c2pa", b"") + body
        elif typ == b"IEND":
            break
        i += 12 + ln
    for k in list(text):
        if k.lower() in ("xml:com.adobe.xmp", "xmp"):
            parts["xmp"] = text.pop(k)
    parts["png_text"] = text


def read_webp(data: bytes, rep: Report, parts: dict):
    i = 12
    while i + 8 <= len(data):
        typ, ln = struct.unpack_from("<4sI", data, i)
        body = data[i + 8:i + 8 + ln]
        if typ == b"EXIF":
            parts["exif"] = parse_exif(body[6:] if body[:6] == b"Exif\x00\x00" else body)
        elif typ == b"XMP ":
            parts["xmp"] = _txt(body)
        elif typ == b"C2PA":
            parts["c2pa"] = body
        elif typ == b"VP8X" and ln >= 10:
            rep.width = 1 + int.from_bytes(body[4:7], "little")
            rep.height = 1 + int.from_bytes(body[7:10], "little")
        i += 8 + ln + (ln & 1)


def scan_stream(path: str, parts: dict):
    """For videos and other containers: search the whole file for an XMP packet, a C2PA box and readable tags."""
    xmp, c2pa_hits, strings, tail = b"", 0, set(), b""
    grab = re.compile(rb"(?:\xa9too|\xa9swr|encoder|Encoder|ENCODER|com\.apple\.quicktime\.(?:make|model|software)|"
                      rb"com\.android\.(?:manufacturer|model))[\x00-\x20=:]{0,24}([\x20-\x7e]{3,80})")
    atom = re.compile(rb"\xa9(?:too|swr|enc)[\x00-\xff]{4}data[\x00-\xff]{8}([\x20-\x7e]{3,80})")   # MP4/QuickTime tag atoms
    c2pa_buf = b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(SCAN_CHUNK)
            if not chunk:
                break
            buf = tail + chunk
            if not xmp:
                a = buf.find(b"<x:xmpmeta")
                if a >= 0:
                    b = buf.find(b"</x:xmpmeta>", a)
                    xmp = buf[a:b + 12] if b >= 0 else buf[a:a + 200_000]
            for key in (b"c2pa", b"jumb"):
                j = buf.find(key)
                if j >= 0:
                    c2pa_hits += 1
                    if len(c2pa_buf) < 2_000_000:
                        c2pa_buf += buf[max(0, j - 64):j + 400_000]
            for rx in (grab, atom):
                for m in rx.finditer(buf):
                    strings.add(_txt(m.group(1))[:80])
            tail = chunk[-65536:]
    if xmp:
        parts["xmp"] = _txt(xmp)
    if c2pa_hits and (b"c2pa" in c2pa_buf):
        parts["c2pa"] = c2pa_buf
    if strings:
        parts["tags"] = sorted(strings)[:12]


def detect_format(head: bytes, path: str) -> str:
    if head[:3] == b"\xff\xd8\xff":
        return "JPEG"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "WebP"
    if head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in (b"heic", b"heix", b"mif1", b"hevc"):
            return "HEIC"
        if brand in (b"avif", b"avis"):
            return "AVIF"
        return "QuickTime" if brand == b"qt  " else "MP4"
    if head[:4] == b"\x1aE\xdf\xa3":
        return "WebM/Matroska"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF"
    if head.lstrip()[:1] == b"<" and (b"html" in head.lower() or b"<?xml" in head.lower() or b"<svg" in head.lower()):
        return "not an image (HTML or XML text)"
    return os.path.splitext(path)[1].lstrip(".").upper() or "unknown"


# ---------------------------------------------------------------- interpretation

C2PA_CAVEAT = ("Content Credentials are present but this tool does not verify their signature. Confirm them at "
               "contentcredentials.org/verify or with c2patool before relying on them.")


def interpret(rep: Report, parts: dict):
    exif, xmp_raw = parts.get("exif") or {}, parts.get("xmp") or ""
    xmp = parse_xmp(xmp_raw) if xmp_raw else {}
    png = parts.get("png_text") or {}
    md = rep.metadata
    if exif:
        md["exif"] = exif
    if xmp:
        md["xmp"] = xmp
    if png:
        md["png_text"] = {k: (v[:400] + "…" if len(v) > 400 else v) for k, v in png.items()}
    if parts.get("tags"):
        md["container_tags"] = parts["tags"]
    if parts.get("comments"):
        md["comments"] = parts["comments"]

    # 1. Content Credentials (C2PA)
    c2 = parts.get("c2pa")
    if c2:
        text = c2.decode("latin-1")
        # Product names are read only from the fields that record which software wrote the credentials.
        # Searching the whole manifest would match short names by chance inside thumbnails and signatures.
        writers = []
        for m in re.finditer(rb"claim_generator(?:_info)?|softwareAgent", c2):
            pos = m.end()
            if m.group().endswith(b"_info"):             # a map follows; the product is under its "name" key
                j = c2.find(b"name", pos, pos + 80)
                if j < 0:
                    continue
                pos = j + 4
            val = _cbor_text(c2, pos)
            if val and val not in writers:
                writers.append(val[:120])
        ctx = " | ".join(writers)
        who = _find_names(ctx, GENERATORS)
        cams = _find_names(ctx, ["Leica", "Nikon", "Sony", "Canon", "Fujifilm", "Pixel Camera", "Samsung", "Truepic", "Qualcomm"])
        eds = _find_names(ctx, EDITORS)
        types = sorted(set(re.findall(r"digitalsourcetype/([A-Za-z]+)", text, flags=re.I)))
        md["c2pa"] = {"bytes": len(c2), "written_by": writers[:6], "source_types": types}
        rep.add("credentials", INFO, "Content Credentials (C2PA manifest) are embedded in the file"
                + (f"; written by: {writers[0]}" if writers else ""), "C2PA / JUMBF box", C2PA_CAVEAT)
        for t in types:
            kind, meaning = SOURCE_TYPES.get(t, ("info", "an unrecognised source type"))
            if kind == "ai":
                rep.add("ai", STRONG, f"Content Credentials declare the media as '{t}': {meaning}", "C2PA manifest", C2PA_CAVEAT)
            elif kind == "synthetic":
                rep.add("synthetic", STRONG, f"Content Credentials declare the media as '{t}': {meaning}", "C2PA manifest", C2PA_CAVEAT)
            elif kind == "camera":
                rep.add("camera", MODERATE, f"Content Credentials declare the media as '{t}': {meaning}", "C2PA manifest", C2PA_CAVEAT)
        if who:
            rep.add("ai", MODERATE, "Content Credentials name an AI product: " + ", ".join(who), "C2PA manifest",
                    "A named product may have generated the image or only edited or exported it. " + C2PA_CAVEAT)
        if cams:
            rep.add("camera", MODERATE, "Content Credentials name a camera or capture maker: " + ", ".join(cams), "C2PA manifest", C2PA_CAVEAT)
        if eds:
            rep.add("edit", MODERATE, "Content Credentials name editing software: " + ", ".join(eds), "C2PA manifest", C2PA_CAVEAT)

    # 2. IPTC digital source type in XMP
    for t in xmp.get("DigitalSourceType", []):
        kind, meaning = SOURCE_TYPES.get(t, ("info", "an unrecognised source type"))
        if kind in ("ai", "synthetic"):
            rep.add(kind, STRONG, f"Metadata declares the digital source type '{t}': {meaning}", "XMP (IPTC)",
                    "This is a label written by the tool or person that made the file. It can be removed, and it can be added to any file.")
        elif kind == "camera":
            rep.add("camera", WEAK, f"Metadata declares the digital source type '{t}': {meaning}", "XMP (IPTC)",
                    "A label anyone can write into a file.")

    # 3. Generator settings left in PNG text chunks
    low = {k.lower(): v for k, v in png.items()}
    a1111 = re.compile(r"Steps:\s*\d+.*(?:Sampler|Seed|CFG scale)", re.S)
    if "parameters" in low and a1111.search(low["parameters"]):
        rep.add("ai", STRONG, "Stable Diffusion generation settings (prompt, steps, sampler, seed) are stored in the file",
                "PNG text chunk 'parameters'", "Written by tools such as AUTOMATIC1111 or Forge. Text chunks can be added to any PNG by hand.")
    for name in ("UserComment", "ImageDescription"):
        if a1111.search(str(exif.get(name, ""))):
            rep.add("ai", STRONG, "Stable Diffusion generation settings (prompt, steps, sampler, seed) are stored in the file",
                    f"EXIF {name}", "Written by tools such as AUTOMATIC1111 or Forge. EXIF text can be written into any file by hand.")
    if "fooocus_scheme" in low or ("parameters" in low and low["parameters"].lstrip().startswith("{") and '"base_model"' in low["parameters"]):
        rep.add("ai", STRONG, "Fooocus generation settings are stored in the file", "PNG text chunks", "Text chunks can be added to any PNG by hand.")
    if "dream" in low and re.search(r"-s\s*\d+|-S\s*\d+|-C\s*[\d.]+", low["dream"]):
        rep.add("ai", STRONG, "An InvokeAI 'Dream' command (prompt with steps, seed and scale) is stored in the file",
                "PNG text chunk 'Dream'", "Text chunks can be added to any PNG by hand.")
    if ("prompt" in low and low["prompt"].lstrip().startswith("{") and "class_type" in low["prompt"]) \
            or ("workflow" in low and '"nodes"' in low["workflow"]):
        rep.add("ai", STRONG, "A ComfyUI node graph (the recipe used to generate the image) is stored in the file",
                "PNG text chunk 'prompt' or 'workflow'", "Text chunks can be added to any PNG by hand.")
    if "invokeai_metadata" in low or "sd-metadata" in low or "invokeai_graph" in low:
        rep.add("ai", STRONG, "InvokeAI generation metadata is stored in the file", "PNG text chunk", "Text chunks can be added to any PNG by hand.")
    if low.get("software", "").lower().startswith("novelai") or ("comment" in low and '"sampler"' in low["comment"] and '"steps"' in low["comment"]):
        rep.add("ai", STRONG, "NovelAI generation settings are stored in the file", "PNG text chunks", "Text chunks can be added to any PNG by hand.")

    # 4. Software and creator fields
    fields = {"EXIF Software": str(exif.get("Software", "")), "EXIF ImageDescription": str(exif.get("ImageDescription", "")),
              "EXIF UserComment": str(exif.get("UserComment", "")), "EXIF Artist": str(exif.get("Artist", "")),
              "EXIF Make": str(exif.get("Make", "")), "XMP CreatorTool": " ".join(xmp.get("CreatorTool", [])),
              "XMP Credit": " ".join(xmp.get("Credit", [])), "XMP Software": " ".join(xmp.get("Software", [])),
              "XMP Description": xmp.get("Description", ""), "XMP softwareAgent": " ".join(xmp.get("SoftwareAgent", [])),
              "PNG Software": low.get("software", ""), "PNG Description": low.get("description", ""),
              "PNG Author": low.get("author", ""), "PNG Comment": low.get("comment", "")[:500],
              "container tags": " | ".join(parts.get("tags", [])), "comments": " | ".join(parts.get("comments", []))}
    for where, val in fields.items():
        if not val:
            continue
        gens = _find_names(val, GENERATORS)
        if gens:
            rep.add("ai", MODERATE, f"An AI product is named: {', '.join(gens)} (\"{val[:90]}\")", where,
                    "Software fields are plain text that anyone can edit, and a named product may have edited the image, not generated it.")
        eds = _find_names(val, EDITORS)
        if eds:
            rep.add("edit", MODERATE if "Lavf" not in eds else WEAK, f"Editing or encoding software is named: {', '.join(eds)} (\"{val[:90]}\")", where,
                    "Shows the file passed through this software. It does not show what was changed. Many platforms re-encode every upload.")
    if re.search(r"Job ID:\s*[0-9a-f-]{20,}", fields["PNG Description"] + fields["XMP Description"] + fields["EXIF ImageDescription"]):
        rep.add("ai", MODERATE, "The description holds a prompt followed by a 'Job ID', the pattern Midjourney writes", "description field",
                "A text pattern that can be typed into any file.")

    # 5. Camera metadata
    cam = [f"{k} {exif[k]}" for k in ("Make", "Model", "LensModel") if exif.get(k)]
    shot = [k for k in ("DateTimeOriginal", "ExposureTime", "FNumber", "ISO", "FocalLength") if exif.get(k)]
    if (exif.get("Make") or exif.get("Model")) and not _find_names(" ".join(cam), GENERATORS):
        rep.add("camera", MODERATE if len(shot) >= 3 else WEAK,
                "Camera metadata is present: " + ", ".join(cam) + (f"; capture settings recorded ({', '.join(shot)})" if shot else ""),
                "EXIF", "Consistent with a photograph from that device. EXIF can be copied from another file or written by hand, "
                        "and a real photo can still be staged, edited or miscaptioned.")
    if exif.get("GPS"):
        rep.add("info", INFO, "GPS location data is embedded in the file", "EXIF",
                "Handle with care: this may reveal where a person was. It can also be forged.")

    # 6. Size hint, only when nothing else was found
    if rep.width and rep.height and (rep.width, rep.height) in AI_SIZES and not exif and not any(f.kind in ("ai", "camera") for f in rep.findings):
        rep.add("ai", WEAK, f"The image is {rep.width}x{rep.height}, a default output size of several AI image generators, and has no camera metadata",
                "image size", "Very weak. Countless ordinary images, icons and crops share these sizes.")


def conclude(rep: Report):
    by = lambda kind, *strengths: [f for f in rep.findings if f.kind == kind and (not strengths or f.strength in strengths)]
    if by("ai", STRONG):
        rep.verdict = "DECLARED AI-GENERATED"
        rep.summary = ("The file itself says it was made or altered with generative AI. That is the strongest signal a file can carry, "
                       "but it is still a statement inside the file, not a test of the pixels.")
    elif by("synthetic", STRONG):
        rep.verdict = "DECLARED SYNTHETIC"
        rep.summary = "The file itself says it is synthetic or contains synthetic elements."
    elif by("ai", MODERATE):
        rep.verdict = "AI PRODUCT NAMED"
        rep.summary = ("An AI product is named in the file's metadata. It may have generated the image or only touched it. "
                       "Treat this as a strong lead and look for the original.")
    elif by("camera", MODERATE) and by("credentials"):
        rep.verdict = "CAMERA ORIGIN CLAIMED, WITH CONTENT CREDENTIALS"
        rep.summary = "The file claims a camera origin and carries Content Credentials. Verify the credentials' signature before relying on them."
    elif by("credentials"):
        rep.verdict = "CONTENT CREDENTIALS PRESENT"
        rep.summary = "The file carries Content Credentials that this tool could not interpret further. Open them in a verifier."
    elif by("camera", MODERATE):
        rep.verdict = "CAMERA METADATA PRESENT"
        rep.summary = ("The metadata is consistent with a photograph from a camera or phone. Metadata can be forged, so this supports "
                       "but does not prove that the image is a real photograph.")
    elif by("edit"):
        rep.verdict = "EDITING OR ENCODING SOFTWARE NAMED"
        rep.summary = "The file passed through editing or encoding software. Nothing in it says how the image was first made."
    elif by("ai", WEAK) or by("camera", WEAK):
        rep.verdict = "WEAK HINTS ONLY"
        rep.summary = "Only weak hints were found. They are not enough to say anything about how the file was made."
    else:
        rep.verdict = "NO PROVENANCE SIGNALS"
        rep.summary = ("The file carries no information about how it was made. This is normal: most social platforms and messaging "
                       "apps strip metadata on upload. It tells you nothing either way about whether the image is AI-generated.")


def inspect(path: str) -> Report:
    rep = Report(path=path, size_bytes=os.path.getsize(path))
    parts: dict = {}
    with open(path, "rb") as f:
        head = f.read(64)
    rep.format = detect_format(head, path)
    if rep.format in ("JPEG", "PNG", "WebP") and rep.size_bytes <= MAX_READ:
        with open(path, "rb") as f:
            data = f.read()
        try:
            {"JPEG": read_jpeg, "PNG": read_png, "WebP": read_webp}[rep.format](data, rep, parts)
        except (struct.error, IndexError, ValueError):
            rep.add("info", INFO, "The file structure is damaged or unusual, so some metadata may have been missed", rep.format)
        if "c2pa" not in parts and "xmp" not in parts and (b"c2pa" in data or b"<x:xmpmeta" in data):
            scan_stream(path, parts)
    else:
        scan_stream(path, parts)
    interpret(rep, parts)
    conclude(rep)
    if rep.format.startswith("not an image"):
        rep.verdict = "NOT AN IMAGE OR VIDEO"
        rep.summary = ("This file is a web page or other text saved with a media file name. A download probably failed "
                       "or returned an error page. Fetch the original media file again.")
    return rep


ALWAYS = ("This tool reads what a file says about itself. It does not examine the picture, cannot detect invisible watermarks "
          "such as SynthID, and cannot tell you that an image is real.")


def render(rep: Report, verbose: bool = False) -> str:
    dims = f", {rep.width}x{rep.height}" if rep.width and rep.height else ""
    out = [f"{rep.path}", f"  {rep.format}{dims}, {rep.size_bytes:,} bytes", "", f"  {rep.verdict}", f"  {rep.summary}", ""]
    order = {STRONG: 0, MODERATE: 1, WEAK: 2, INFO: 3}
    if rep.findings:
        out.append("  What was found:")
        for f in sorted(rep.findings, key=lambda f: order[f.strength]):
            out.append(f"   [{f.strength}] {f.what}")
            out.append(f"       where: {f.where}")
            if f.caveat:
                out.append(f"       caution: {f.caveat}")
    if verbose and rep.metadata:
        out += ["", "  Metadata read from the file:", "   " + json.dumps(rep.metadata, indent=1, ensure_ascii=False, default=str).replace("\n", "\n   ")]
    return "\n".join(out)
