#!/usr/bin/env python3
"""
asher.fold-memory — leftover-memory.

identical leftover copies share one box. unique bits stay the floor.
unfold only if the file fingerprint matches, else refuse.

python 3.8+ standard library only. no network, ever.
"""
from __future__ import annotations

import argparse
import email
import email.policy
import fnmatch
import hashlib
import io
import json
import lzma
import math
import mimetypes
import os
import re
import sqlite3
import stat as stat_mod
import struct
import sys
import tarfile
import tempfile
import threading
import time
import uuid
import zipfile
import zlib
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

try:
    from compression import zstd as _zstd  # python 3.14+
except ImportError:
    _zstd = None

__version__ = "2.1.0"
INDEX_VERSION = 2  # 2.1: metadata fields masked before indexing
FORMAT = 2

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

HERE = Path(__file__).resolve().parent

# chunk sizes (min, avg, max). text gets small bites so edited lines resync
# fast; everything else gets bigger bites so metadata stays under ~0.5%.
TEXT_CHUNK = (512, 2048, 16384)
BIN_CHUNK = (8192, 32768, 262144)
READ_BLOCK = 4 << 20
PACK_LIMIT = int(os.environ.get("FOLD_MEMORY_PACK_MB", "256")) << 20
CACHE_BYTES = 32 << 20
COMMIT_EVERY_S = 2.0
COMMIT_EVERY_BYTES = 128 << 20
WRITER_STALE_NS = 3600 * 10**9
GC_GRACE_NS = 3600 * 10**9

PACK_MAGIC = b"FMPACK1\n"
REC_MAGIC = b"FMR1"
REC_HEAD = struct.Struct("<4sc32sQ")  # magic, kind, sha256, payload length

_PRIOR_SEED = (
    b"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><script>function"
    b"</script></head><body>{\"id\":null,\"type\":\"\",\"status\":true,"
    b"false}function(){return};const let var import from def class self"
    b"None True False http https www.com.json.xml.csv.txt.log.error.warn"
    b"abcdefghijklmnopqrstuvwxyz0123456789 \t\r\n"
)
PRIOR_MAX = 32768

SECRET_RX = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*\S+"),
]
SECRET_NAME_RX = re.compile(
    r"(?i)(?:^\.env(?:$|\.)|^id_(?:rsa|dsa|ecdsa|ed25519)(?:$|\.)|^cookies(?:$|\.|-journal)|"
    r"^login data|^web data|wallet\.dat$|\.keystore$|\.jks$|\.pem$|\.key$|\.p12$|\.pfx$|"
    r"\.kdbx?$|^\.netrc$|^\.pgpass$|^credentials(?:\.json)?$|^secrets?\.(?:json|ya?ml|toml)$)"
)
DEFAULT_EXCLUDE_DIRS = {
    ".ssh", ".gnupg", ".password-store", "$Recycle.Bin", "System Volume Information",
    "fold-memory-store", ".fold-memory",
}
STOP = {
    "the", "and", "for", "with", "from", "this", "that", "are", "was", "not", "into",
    "when", "then", "than", "you", "your", "our", "has", "have", "had", "but", "all",
    "can", "will", "its", "his", "her", "they", "them", "been", "were", "which",
    "of", "to", "in", "on", "at", "is", "it", "as", "by", "an", "or", "be", "if", "so",
}
PRECOMPRESSED = {
    "jpeg", "png", "gif", "webp", "heic", "avif", "mp4", "mov", "m4a", "mkv", "webm",
    "mp3", "ogg", "flac", "opus", "aac", "zip", "gzip", "bzip2", "xz", "7z", "rar",
    "zstd", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "jar", "apk", "jp2",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mask_secrets(text: str) -> str:
    for rx in SECRET_RX:
        text = rx.sub("[masked]", text)
    return text


# ---------------------------------------------------------------- tokens

_WORD_RX = re.compile(r"[^\W_]+", re.UNICODE)
_CAMEL_RX = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")
_CJK_RX = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af\uf900-\ufaff]")


def tokenize(text: str) -> list:
    """words, camelCase/digit parts, and cjk bigrams (cjk has no spaces)."""
    out = []
    for m in _WORD_RX.finditer(text or ""):
        w = m.group()
        if _CJK_RX.search(w):
            if len(w) == 1:
                out.append(w)
            out.extend(w[i:i + 2] for i in range(len(w) - 1))
            continue
        low = w.lower()
        if len(low) >= 2:
            out.append(low)
        if w.isascii():
            parts = _CAMEL_RX.findall(w)
            if len(parts) > 1:
                out.extend(p.lower() for p in parts if len(p) >= 2)
    return out


# ---------------------------------------------------------------- chunker
# content-defined cuts. each byte is projected to one pseudo-random bit;
# a cut lands where the last W bits equal a fixed non-self-overlapping
# pattern (mean spacing 2**W). translate() + find() run in C, so this is
# ~400 MB/s in pure python and cut points depend only on nearby content.

def _bit_table() -> bytes:
    order = sorted(range(256), key=lambda b: hashlib.sha256(bytes([b, 0x5A, 0xA5])).digest())
    ones = set(order[:128])
    return bytes(0x31 if b in ones else 0x30 for b in range(256))


BIT_TABLE = _bit_table()


def _has_border(p: bytes) -> bool:
    return any(p[:k] == p[-k:] for k in range(1, len(p)))


def _cut_pattern(width: int, salt: int) -> bytes:
    while True:
        h = hashlib.sha256(b"fold-memory-cut" + bytes([width, salt])).digest()
        mid = "".join("1" if (h[i // 8] >> (i % 8)) & 1 else "0" for i in range(width - 2))
        p = ("1" + mid + "0").encode()
        if not _has_border(p):
            return p
        salt += 1


def _chunk_params(sizes: tuple) -> tuple:
    mn, avg, mx = sizes
    w = avg.bit_length() - 1
    return mn, avg, mx, _cut_pattern(w + 2, 1), _cut_pattern(w - 2, 2)


TEXT_PARAMS = _chunk_params(TEXT_CHUNK)
BIN_PARAMS = _chunk_params(BIN_CHUNK)


def iter_chunks(read, params: tuple, prefix: bytes = b""):
    """yield content-defined chunks from read(n) with bounded memory."""
    mn, avg, mx, hard, easy = params
    hl, el = len(hard), len(easy)
    buf = bytearray(prefix)
    bits = bytearray(buf.translate(BIT_TABLE))
    base = 0
    start = 0
    eof = False
    while True:
        while not eof and base + len(buf) < start + mx:
            more = read(READ_BLOCK)
            if not more:
                eof = True
                break
            drop = start - hl - base
            if drop > 0:
                del buf[:drop]
                del bits[:drop]
                base += drop
            buf += more
            bits += more.translate(BIT_TABLE)
        ls = start - base
        n = len(buf)
        if ls >= n:
            return
        if n - ls <= mn:
            yield bytes(buf[ls:])
            return
        p = bits.find(hard, ls + mn - hl, min(n, ls + avg))
        if p >= 0:
            cut = p + hl
        else:
            p = bits.find(easy, ls + avg - el, min(n, ls + mx))
            cut = p + el if p >= 0 else min(n, ls + mx)
        yield bytes(buf[ls:cut])
        start = base + cut


def chunk_bytes(data: bytes, texty: bool | None = None) -> list:
    if texty is None:
        texty = is_texty(data[:8192])
    view = io.BytesIO(data)
    return list(iter_chunks(view.read, TEXT_PARAMS if texty else BIN_PARAMS))


def is_texty(sample: bytes) -> bool:
    if not sample:
        return True
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff") or sample[:3] == b"\xef\xbb\xbf":
        return True
    if b"\x00" in sample:
        return False
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.start < len(sample) - 4:  # not just a cut multi-byte char at the end
            good = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
            return good / len(sample) >= 0.85
        text = sample[:exc.start].decode("utf-8", "ignore")
    ctrl = sum(1 for ch in text if ord(ch) < 32 and ch not in "\t\n\r\f\x1b")
    return ctrl <= len(text) * 0.02


# ---------------------------------------------------------------- codecs

LEVELS = {"fast": 1, "default": 6, "max": 9}


def pack_chunk(raw: bytes, prior: bytes, level: str = "default", codec: str = "zlib",
               incompressible: bool = False) -> bytes:
    if incompressible or len(raw) < 64:
        return b"R" + raw
    if len(raw) >= 4096:
        probe = zlib.compress(raw[:4096], 1)
        if len(probe) > 3970:
            return b"R" + raw
    if codec == "zstd" and _zstd is not None:
        packed = b"S" + _zstd.compress(raw, level=3 if level != "max" else 15)
    elif level == "max":
        packed = b"X" + lzma.compress(raw, format=lzma.FORMAT_XZ, preset=6)
    else:
        c = zlib.compressobj(LEVELS.get(level, 6), zlib.DEFLATED, 15, 8,
                             zlib.Z_DEFAULT_STRATEGY, zdict=prior)
        packed = b"Z" + c.compress(raw) + c.flush()
    if len(packed) >= len(raw) + 1:
        return b"R" + raw
    return packed


class CodecMissing(Exception):
    """the bytes may be perfectly fine; this interpreter just can't decode them. never treat as damage."""


def unpack_chunk(stored: bytes, prior: bytes) -> bytes:
    kind, payload = stored[:1], stored[1:]
    if kind == b"R":
        return payload
    if kind == b"Z":
        try:
            d = zlib.decompressobj(15, zdict=prior)
            return d.decompress(payload) + d.flush()
        except zlib.error:
            return zlib.decompress(payload)
    if kind == b"X":
        return lzma.decompress(payload)
    if kind == b"S":
        if _zstd is None:
            raise CodecMissing("chunk uses zstd; this python has no compression.zstd (needs 3.14+)")
        return _zstd.decompress(payload)
    raise ValueError("unknown chunk codec %r" % kind)  # a flipped byte is likelier than a newer version


# ---------------------------------------------------------------- media sniffing
# enough of each format to name it and pull words a person would search for.
# every reader is bounded; a hostile file can cost time, never unbounded ram.

MAX_META_TEXT = 12000


def sniff_kind(head: bytes, name: str) -> str:
    h = head
    if h.startswith(b"%PDF"):
        return "pdf"
    if h.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if h.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if h[:4] == b"RIFF" and h[8:12] == b"WEBP":
        return "webp"
    if h[:4] == b"RIFF" and h[8:12] == b"WAVE":
        return "wav"
    if h[:4] == b"RIFF" and h[8:12] == b"AVI ":
        return "avi"
    if h[4:8] == b"ftyp":
        brand = h[8:12]
        if brand in (b"heic", b"heix", b"mif1", b"msf1", b"hevc"):
            return "heic"
        if brand in (b"avif", b"avis"):
            return "avif"
        if brand.startswith(b"qt"):
            return "mov"
        if brand in (b"M4A ", b"M4B "):
            return "m4a"
        return "mp4"
    if h.startswith(b"\x1aE\xdf\xa3"):
        return "webm" if b"webm" in h[:64] else "mkv"
    if h.startswith(b"ID3") or (len(h) > 1 and h[0] == 0xFF and h[1] & 0xE0 == 0xE0 and name.lower().endswith(".mp3")):
        return "mp3"
    if h.startswith(b"fLaC"):
        return "flac"
    if h.startswith(b"OggS"):
        return "opus" if b"OpusHead" in h[:64] else "ogg"
    if h.startswith(b"PK\x03\x04") or h.startswith(b"PK\x05\x06"):
        return "zip"
    if h.startswith(b"\x1f\x8b"):
        return "gzip"
    if h.startswith(b"BZh"):
        return "bzip2"
    if h.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if h.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if h.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if h.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if len(h) > 262 and h[257:262] == b"ustar":
        return "tar"
    if h.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    if h.startswith(b"\x7fELF"):
        return "elf"
    if h.startswith(b"MZ"):
        return "exe"
    if h[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho"
    if h.startswith(b"BM") and name.lower().endswith(".bmp"):
        return "bmp"
    if h[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if h.startswith(b"\x00\x00\x00\x0cjP  "):
        return "jp2"
    if h.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if h.startswith(b"PAR1"):
        return "parquet"
    if h.startswith(b"Obj\x01"):
        return "avro"
    if h.startswith(b"ORC"):
        return "orc"
    if h.startswith(b"\x89HDF\r\n\x1a\n"):
        return "hdf5"
    if h[:4] in (b"CDF\x01", b"CDF\x02"):
        return "netcdf"
    if h.startswith(b"SIMPLE  ="):
        return "fits"
    if h.startswith(b"GRIB"):
        return "grib"
    if h.startswith(b"LASF"):
        return "las"
    if len(h) >= 132 and h[128:132] == b"DICM":
        return "dicom"
    if h[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
        return "pcap"
    if h.startswith(b"QFI\xfb"):
        return "qcow2"
    if h.startswith(b"KDMV"):
        return "vmdk"
    if h.startswith(b"vhdxfile"):
        return "vhdx"
    if h.startswith(b"%!PS"):
        return "postscript"
    if h[:4] in (b"wOFF", b"wOF2", b"OTTO", b"\x00\x01\x00\x00") and name.lower().endswith((".woff", ".woff2", ".otf", ".ttf")):
        return "font"
    low = name.lower()
    ext = low.rsplit(".", 1)[-1] if "." in low else ""
    if is_texty(h[:8192]):
        stripped = h.lstrip()[:64].lower()
        if ext in ("html", "htm", "xhtml") or stripped.startswith((b"<!doctype html", b"<html")):
            return "html"
        if ext in ("xml", "svg", "kml", "gpx", "gml", "rss", "atom", "xsd", "plist") or stripped.startswith(b"<?xml"):
            return "svg" if ext == "svg" else "xml"
        if ext in ("eml", "msg") or re.match(rb"(?:Received|Return-Path|From|Message-ID|MIME-Version):", h[:200]):
            return "email"
        if ext == "mbox" or h.startswith(b"From "):
            return "mbox"
        if ext in ("json", "geojson", "jsonl", "ndjson") or stripped[:1] in (b"{", b"["):
            return "json"
        if ext in ("csv", "tsv"):
            return "csv"
        if ext == "log":
            return "log"
        if ext in ("sql",):
            return "sql"
        return "text"
    return ext or "binary"


def _strip_tags(text: str) -> str:
    text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", text)
    text = re.sub(r"<[^>]{0,2000}>", " ", text)
    for ent, ch in (("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&#39;", "'"), ("&nbsp;", " ")):
        text = text.replace(ent, ch)
    return re.sub(r"\s+", " ", text)


def _decode_text(data: bytes) -> str:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", "replace")
        if text.count("\ufffd") > len(text) * 0.05:
            return data.decode("latin-1")
        return text


def _read_limited(zf: zipfile.ZipFile, name: str, limit: int = 4 << 20) -> bytes:
    with zf.open(name) as fh:
        return fh.read(limit)


def _meta_zip(path: Path, fields: dict) -> tuple:
    texts = []
    with zipfile.ZipFile(str(path)) as zf:
        names = zf.namelist()
        kind = "zip"
        lower = set(n.lower() for n in names)
        if "word/document.xml" in lower:
            kind = "docx"
            targets = ["word/document.xml"]
        elif "xl/sharedstrings.xml" in lower or "xl/workbook.xml" in lower:
            kind = "xlsx"
            targets = [n for n in names if n.lower() in ("xl/sharedstrings.xml",)] + \
                      [n for n in names if n.lower().startswith("xl/worksheets/sheet")][:3]
        elif any(n.lower().startswith("ppt/slides/slide") for n in names):
            kind = "pptx"
            targets = sorted(n for n in names if n.lower().startswith("ppt/slides/slide") and n.endswith(".xml"))[:60]
        elif "mimetype" in lower:
            mt = _read_limited(zf, "mimetype", 200).decode("ascii", "ignore")
            kind = {"application/epub+zip": "epub",
                    "application/vnd.oasis.opendocument.text": "odt",
                    "application/vnd.oasis.opendocument.spreadsheet": "ods",
                    "application/vnd.oasis.opendocument.presentation": "odp"}.get(mt.strip(), "zip")
            if kind == "epub":
                targets = [n for n in names if n.lower().endswith((".xhtml", ".html", ".htm"))][:40]
            else:
                targets = ["content.xml"] if "content.xml" in names else []
        elif "androidmanifest.xml" in lower:
            kind, targets = "apk", []
        elif "meta-inf/manifest.mf" in lower:
            kind, targets = "jar", []
        else:
            targets = []
        for meta_name in ("docProps/core.xml", "meta.xml"):
            if meta_name in names:
                core = _read_limited(zf, meta_name, 65536).decode("utf-8", "ignore")
                for tag in ("title", "creator", "subject", "description", "keywords"):
                    m = re.search(r"<(?:dc:|cp:|meta:)?%s[^>]*>([^<]{1,500})<" % tag, core)
                    if m:
                        fields[tag] = m.group(1).strip()
        budget = MAX_META_TEXT
        for t in targets:
            if budget <= 0:
                break
            try:
                txt = _strip_tags(_read_limited(zf, t).decode("utf-8", "ignore"))
            except (KeyError, zipfile.BadZipFile, OSError, RuntimeError, zlib.error):
                continue
            texts.append(txt[:budget])
            budget -= len(txt)
        if kind == "zip" or kind in ("apk", "jar"):
            fields["members"] = len(names)
            texts.append(" ".join(names[:400]))
    return kind, " ".join(texts)


_PDF_STREAM_RX = re.compile(rb"stream\r?\n")


def _pdf_strings(content: bytes) -> str:
    out = []
    for m in re.finditer(rb"\((?:\\.|[^\\)]){1,400}\)\s*(?:Tj|'|\")|\[(?:[^\]]{1,4000})\]\s*TJ", content):
        seg = m.group()
        for s in re.findall(rb"\(((?:\\.|[^\\)])*)\)", seg):
            s = re.sub(rb"\\([nrtbf()\\])", lambda x: {b"n": b"\n", b"r": b"", b"t": b" ", b"b": b"",
                                                      b"f": b""}.get(x.group(1), x.group(1)), s)
            out.append(s.decode("latin-1"))
        out.append(" ")
    return "".join(out)


def _meta_pdf(path: Path, fields: dict) -> str:
    with open(path, "rb") as fh:
        data = fh.read(16 << 20)
    for key in (b"Title", b"Author", b"Subject", b"Keywords"):
        m = re.search(rb"/" + key + rb"\s*\(((?:\\.|[^\\)]){1,300})\)", data)
        if m:
            fields[key.decode().lower()] = m.group(1).decode("latin-1", "ignore")
    pages = len(re.findall(rb"/Type\s*/Page\b", data))
    if pages:
        fields["pages"] = pages
    texts = []
    budget = MAX_META_TEXT
    inflated_total = 0
    for m in _PDF_STREAM_RX.finditer(data):
        if budget <= 0 or inflated_total > (8 << 20):
            break
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            break
        raw = data[start:end]
        try:
            d = zlib.decompressobj()
            content = d.decompress(raw, 2 << 20)
        except zlib.error:
            content = raw if raw[:1] not in (b"\x78",) else b""
        inflated_total += len(content)
        if b"Tj" in content or b"TJ" in content:
            t = _pdf_strings(content)
            texts.append(t[:budget])
            budget -= len(t)
    return " ".join(texts)


def _meta_image(kind: str, head: bytes, fields: dict) -> None:
    try:
        if kind == "png" and head[12:16] == b"IHDR":
            fields["width"], fields["height"] = struct.unpack(">II", head[16:24])
            for m in re.finditer(rb"tEXt([A-Za-z ]{1,79})\x00([^\x00]{1,400}?)(?=[\x00-\x08]|IEND|$)", head):
                fields[m.group(1).decode("latin-1").lower()] = m.group(2).decode("latin-1", "ignore")[:200]
        elif kind == "gif":
            fields["width"], fields["height"] = struct.unpack("<HH", head[6:10])
        elif kind == "bmp":
            fields["width"], fields["height"] = struct.unpack("<ii", head[18:26])
        elif kind == "webp":
            chunk = head[12:16]
            if chunk == b"VP8X":
                fields["width"] = 1 + int.from_bytes(head[24:27], "little")
                fields["height"] = 1 + int.from_bytes(head[27:30], "little")
            elif chunk == b"VP8 ":
                w, h = struct.unpack("<HH", head[26:30])
                fields["width"], fields["height"] = w & 0x3FFF, h & 0x3FFF
        elif kind == "jpeg":
            i = 2
            while i + 9 < len(head):
                if head[i] != 0xFF:
                    i += 1
                    continue
                marker = head[i + 1]
                if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                    i += 2
                    continue
                seg_len = struct.unpack(">H", head[i + 2:i + 4])[0]
                if marker == 0xE1 and head[i + 4:i + 10] == b"Exif\x00\x00":
                    _exif(head[i + 10:i + 2 + seg_len], fields)
                if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                    fields["height"], fields["width"] = struct.unpack(">HH", head[i + 5:i + 9])
                    break
                i += 2 + seg_len
        elif kind == "tiff":
            _exif(head, fields)
    except (struct.error, IndexError, ValueError):
        pass


def _exif(tiff: bytes, fields: dict) -> None:
    if tiff[:2] == b"II":
        e = "<"
    elif tiff[:2] == b"MM":
        e = ">"
    else:
        return
    want = {0x010F: "make", 0x0110: "model", 0x0132: "datetime", 0x010E: "description",
            0x013B: "artist", 0x9003: "taken", 0x8769: None}

    def walk(off: int, depth: int) -> None:
        if depth > 2 or off + 2 > len(tiff):
            return
        n = struct.unpack(e + "H", tiff[off:off + 2])[0]
        for k in range(min(n, 200)):
            ent = tiff[off + 2 + k * 12: off + 14 + k * 12]
            if len(ent) < 12:
                return
            tag, typ, cnt = struct.unpack(e + "HHI", ent[:8])
            if tag not in want:
                continue
            if tag == 0x8769:
                walk(struct.unpack(e + "I", ent[8:12])[0], depth + 1)
                continue
            if typ != 2:
                continue
            if cnt <= 4:
                val = ent[8:8 + cnt]
            else:
                p = struct.unpack(e + "I", ent[8:12])[0]
                val = tiff[p:p + min(cnt, 256)]
            fields[want[tag]] = val.rstrip(b"\x00").decode("latin-1", "ignore").strip()

    try:
        walk(struct.unpack(e + "I", tiff[4:8])[0], 0)
    except struct.error:
        pass


def _meta_mp3(head: bytes, fields: dict) -> None:
    if not head.startswith(b"ID3"):
        return
    ver = head[3]
    size = (head[6] << 21) | (head[7] << 14) | (head[8] << 7) | head[9]
    tag = head[10:10 + size]
    names = {b"TIT2": "title", b"TPE1": "artist", b"TALB": "album", b"TYER": "year",
             b"TDRC": "year", b"TCON": "genre", b"COMM": "comment"}
    i = 0
    while i + 10 <= len(tag):
        fid = tag[i:i + 4]
        if not fid.strip(b"\x00"):
            break
        raw = tag[i + 4:i + 8]
        fsize = ((raw[0] << 21) | (raw[1] << 14) | (raw[2] << 7) | raw[3]) if ver >= 4 else struct.unpack(">I", raw)[0]
        body = tag[i + 10:i + 10 + fsize]
        if fid in names and body:
            enc, txt = body[0], body[1:]
            if fid == b"COMM":
                txt = txt[3:].split(b"\x00", 1)[-1] if enc in (0, 3) else txt[3:]
            codec = {0: "latin-1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}.get(enc, "latin-1")
            fields[names[fid]] = txt.decode(codec, "ignore").strip("\x00 ")[:200]
        if fsize <= 0:
            break
        i += 10 + fsize


def _meta_isobmff(path: Path, fields: dict) -> None:
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        total = fh.tell()
        off = 0
        for _ in range(64):
            if off + 8 > total:
                break
            fh.seek(off)
            head = fh.read(16)
            size, typ = struct.unpack(">I4s", head[:8])
            hdr = 8
            if size == 1:
                size = struct.unpack(">Q", head[8:16])[0]
                hdr = 16
            elif size == 0:
                size = total - off
            if size < hdr:
                break
            if typ == b"moov":
                fh.seek(off + hdr)
                moov = fh.read(min(size - hdr, 4 << 20))
                i = moov.find(b"mvhd")
                if i >= 4:
                    v = moov[i + 4]
                    if v == 1:
                        scale, dur = struct.unpack(">IQ", moov[i + 24:i + 36])
                    else:
                        scale, dur = struct.unpack(">II", moov[i + 16:i + 24])
                    if scale:
                        fields["seconds"] = round(dur / scale, 2)
                for tag, key in ((b"\xa9nam", "title"), (b"\xa9ART", "artist"), (b"\xa9day", "year")):
                    j = moov.find(tag + b"\x00\x00")
                    if j > 0:
                        d = moov.find(b"data", j)
                        if 0 < d < j + 32:
                            ln = struct.unpack(">I", moov[d - 4:d])[0]
                            fields[key] = moov[d + 12:d - 4 + ln].decode("utf-8", "ignore")[:200]
                break
            off += size


def _meta_audio(kind: str, head: bytes, fields: dict) -> None:
    try:
        if kind == "wav":
            i = head.find(b"fmt ")
            if i > 0:
                ch, rate = struct.unpack("<HI", head[i + 10:i + 16])
                bits = struct.unpack("<H", head[i + 22:i + 24])[0]
                fields.update(channels=ch, rate=rate, bits=bits)
                j = head.find(b"data", i)
                if j > 0 and rate and ch and bits:
                    n = struct.unpack("<I", head[j + 4:j + 8])[0]
                    fields["seconds"] = round(n / (rate * ch * bits / 8), 2)
        elif kind == "flac":
            info = head[8:42]
            rate = int.from_bytes(info[10:13], "big") >> 4
            samples = int.from_bytes(info[13:18], "big") & 0xFFFFFFFFF
            if rate:
                fields.update(rate=rate, seconds=round(samples / rate, 2))
            for m in re.finditer(rb"(TITLE|ARTIST|ALBUM|DATE)=([^\x00-\x1f]{1,200})", head, re.I):
                fields[m.group(1).decode().lower()] = m.group(2).decode("utf-8", "ignore")
        elif kind in ("ogg", "opus"):
            for m in re.finditer(rb"(TITLE|ARTIST|ALBUM|DATE)=([^\x00-\x1f]{1,200})", head, re.I):
                fields[m.group(1).decode().lower()] = m.group(2).decode("utf-8", "ignore")
    except (struct.error, IndexError):
        pass


def _meta_fits(head: bytes, fields: dict) -> None:
    for i in range(0, min(len(head), 2880 * 4), 80):
        card = head[i:i + 80].decode("ascii", "ignore")
        key = card[:8].strip()
        if key == "END":
            break
        if key in ("OBJECT", "TELESCOP", "INSTRUME", "DATE-OBS", "ORIGIN", "OBSERVER") and "=" in card:
            fields[key.lower()] = card[10:].split("/")[0].strip().strip("'").strip()


def _meta_sqlite(path: Path, fields: dict) -> str:
    uri = "file:%s?mode=ro&immutable=1" % path.resolve().as_posix()
    try:
        c = sqlite3.connect(uri, uri=True, timeout=1)
        try:
            names = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 500")]
        finally:
            c.close()
    except sqlite3.Error:
        return ""
    fields["tables"] = len(names)
    return " ".join(names)


def extract_meta(path: Path | None, name: str, head: bytes) -> dict:
    """kind + searchable fields + text for one file. never raises."""
    kind = sniff_kind(head, name)
    fields: dict = {}
    text = ""
    try:
        if kind in ("text", "log", "sql", "csv", "json"):
            text = _decode_text(head[:65536])
            if kind == "csv":
                fields["header"] = text.split("\n", 1)[0][:500]
        elif kind in ("html", "xml", "svg"):
            raw = _decode_text(head[:262144])
            m = re.search(r"(?is)<title[^>]*>(.{1,300}?)</title>", raw)
            if m:
                fields["title"] = _strip_tags(m.group(1)).strip()
            text = _strip_tags(raw)
        elif kind in ("email", "mbox"):
            msg = email.message_from_bytes(head[:262144], policy=email.policy.default)
            for k in ("subject", "from", "to", "date"):
                v = msg.get(k)
                if v:
                    fields[k] = str(v)[:300]
            body = msg.get_body(preferencelist=("plain", "html")) if msg.is_multipart() else msg
            try:
                content = body.get_content() if body is not None else ""
            except (LookupError, KeyError, ValueError, AttributeError):
                content = ""
            text = _strip_tags(content) if isinstance(content, str) else ""
        elif kind in ("png", "jpeg", "gif", "webp", "bmp", "tiff"):
            _meta_image(kind, head, fields)
        elif kind == "mp3":
            _meta_mp3(head, fields)
        elif kind in ("wav", "flac", "ogg", "opus"):
            _meta_audio(kind, head, fields)
        elif kind == "fits":
            _meta_fits(head, fields)
        elif path is not None and kind in ("mp4", "mov", "m4a", "heic", "avif"):
            _meta_isobmff(path, fields)
        elif path is not None and kind == "pdf":
            text = _meta_pdf(path, fields)
        elif path is not None and kind == "zip":
            kind, text = _meta_zip(path, fields)
        elif path is not None and kind == "tar":
            with tarfile.open(str(path), "r:") as tf:
                names = []
                for member in tf:
                    names.append(member.name)
                    if len(names) >= 400:
                        break
            fields["members"] = len(names)
            text = " ".join(names)
        elif kind == "gzip":
            if head[3] & 0x08 and len(head) > 10:  # FNAME flag
                start = 10 + (2 + struct.unpack("<H", head[10:12])[0] if head[3] & 0x04 else 0)
                end = head.find(b"\x00", start)
                if end > start:
                    fields["inner"] = head[start:end].decode("latin-1")
            if path is not None and name.lower().endswith((".tar.gz", ".tgz")):
                with tarfile.open(str(path), "r:gz") as tf:
                    names = []
                    for member in tf:
                        names.append(member.name)
                        if len(names) >= 400:
                            break
                text = " ".join(names)
        elif path is not None and kind == "sqlite":
            text = _meta_sqlite(path, fields)
    except (OSError, ValueError, KeyError, EOFError, struct.error, zipfile.BadZipFile,
            tarfile.TarError, zlib.error, lzma.LZMAError, RuntimeError, UnicodeError, IndexError) as exc:
        fields["meta_error"] = type(exc).__name__
    mime = mimetypes.guess_type(name)[0] or ""
    return {"kind": kind, "mime": mime, "fields": fields, "text": text[:MAX_META_TEXT]}


CUE_KEEP = 400  # characters of body text kept as the preview. the body is in the chunks already.


def build_cue(display_path: str, meta: dict, keep: int | None = None) -> str:
    """full cue feeds the word index; the kept cue (keep=CUE_KEEP) is what gets stored.
    v2.0-dev stored up to 16kb of body per file here, twice (sqlite + pack): a second copy of
    every text file. measured on a 1.7mb source tree: 575kb of cue for 400kb of chunks."""
    fields = " ".join("%s %s" % (k, v) for k, v in meta["fields"].items())
    text = meta["text"] if keep is None else meta["text"][:keep]
    parts = [display_path, meta["kind"], meta["mime"], fields, text]
    return mask_secrets("\n".join(p for p in parts if p))[:16000]


def fid_of(file_sha: str) -> int:
    return int.from_bytes(bytes.fromhex(file_sha[:16]), "big", signed=True)


def term_weights(path: str, cue: str, fields: dict) -> dict:
    weights: dict = {}
    norm = path.replace("\\", "/")
    name = norm.rsplit("/", 1)[-1]
    dirs = norm.rsplit("/", 1)[0] if "/" in norm else ""
    for t in tokenize(name):
        weights[t] = weights.get(t, 0.0) + 8.0
    for t in tokenize(dirs)[-40:]:
        weights[t] = weights.get(t, 0.0) + 2.0
    for v in fields.values():
        # fields (csv header, email subject, doc title...) were indexed unmasked in 2.0,
        # so a key in an email subject became a searchable word. mask them like the cue.
        for t in tokenize(mask_secrets(str(v)))[:60]:
            weights[t] = weights.get(t, 0.0) + 3.0
    body_counts: dict = {}
    for t in tokenize(cue)[:6000]:
        if t not in STOP:
            body_counts[t] = body_counts.get(t, 0) + 1
    top = sorted(body_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:96]
    for t, c in top:
        weights[t] = weights.get(t, 0.0) + 1.0 + math.log(c)
    return {t[:64]: round(w, 3) for t, w in weights.items() if t}


# ---------------------------------------------------------------- pack io

def _write_record(fh, kind: bytes, sha_raw: bytes, payload: bytes) -> int:
    fh.write(REC_HEAD.pack(REC_MAGIC, kind, sha_raw, len(payload)))
    off = fh.tell()
    fh.write(payload)
    return off


def scan_records(path: Path, with_payload: bool = True):
    """yield (kind, sha_raw, payload_offset, length, payload|None). stops at a torn tail."""
    with open(path, "rb") as fh:
        if fh.read(len(PACK_MAGIC)) != PACK_MAGIC:
            raise ValueError("not a fold-memory pack: %s" % path)
        while True:
            head = fh.read(REC_HEAD.size)
            if len(head) < REC_HEAD.size:
                return
            magic, kind, sha_raw, length = REC_HEAD.unpack(head)
            if magic != REC_MAGIC:
                return
            off = fh.tell()
            if with_payload:
                payload = fh.read(length)
                if len(payload) < length:
                    return
            else:
                payload = None
                fh.seek(length, 1)
                if fh.tell() > os.fstat(fh.fileno()).st_size:
                    return
            yield kind, sha_raw, off, length, payload


def _manifest_payload(head: dict, chunk_shas: list) -> bytes:
    """json head + raw 32-byte chunk fingerprints. the head is zlib'd once it is worth it
    (word weights made it ~1.5kb per file); "Z" + u32 length marks that form, "{" the plain one."""
    js = json.dumps(head, ensure_ascii=False, sort_keys=True).encode()
    body = b"".join(bytes.fromhex(s) for s in chunk_shas)
    if len(js) > 200:
        z = zlib.compress(js, 9)
        if len(z) + 5 < len(js) + 1:
            return b"Z" + struct.pack("<I", len(z)) + z + body
    return js + b"\n" + body


def _parse_manifest(payload: bytes) -> tuple:
    if payload[:1] == b"Z":
        (n,) = struct.unpack("<I", payload[1:5])
        head = json.loads(zlib.decompress(payload[5:5 + n]).decode())
        raw = payload[5 + n:]
    else:
        nl = payload.index(b"\n")
        head = json.loads(payload[:nl].decode())
        raw = payload[nl + 1:]
    if len(raw) % 32:
        raise ValueError("manifest chunk list torn")
    return head, [raw[i:i + 32].hex() for i in range(0, len(raw), 32)]


def scan_meta_records(path: Path):
    """like scan_records, but chunk payloads are skipped (seek, not read). for history scans."""
    with open(path, "rb") as fh:
        if fh.read(len(PACK_MAGIC)) != PACK_MAGIC:
            return
        size = os.fstat(fh.fileno()).st_size
        while True:
            head = fh.read(REC_HEAD.size)
            if len(head) < REC_HEAD.size:
                return
            magic, kind, sha_raw, length = REC_HEAD.unpack(head)
            if magic != REC_MAGIC or fh.tell() + length > size:
                return
            if kind == b"C":
                fh.seek(length, 1)
                continue
            payload = fh.read(length)
            yield kind, sha_raw, payload


def _iso(ts_ns) -> str:
    return datetime.fromtimestamp((ts_ns or 0) / 1e9, timezone.utc).isoformat(timespec="seconds")


def _retire_location(conn, praw: bytes, new_sha: str, when: str, table: str = "locations") -> None:
    """call before a path gets new contents. the version it held moves to history; history only
    ever holds replaced versions, so it costs nothing until a file actually changes."""
    key = sqlite3.Binary(praw)
    old = conn.execute("SELECT path, file_sha, size, mtime_ns, seen_at FROM %s WHERE praw=?" % table,
                       (key,)).fetchone()
    if old is not None and old[1] != new_sha:
        conn.execute("INSERT OR REPLACE INTO history(praw, file_sha, path, size, mtime_ns, first_seen, last_seen) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?)", (key, old[1], old[0], old[2], old[3], old[4], when))
    conn.execute("DELETE FROM history WHERE praw=? AND file_sha=?", (key, new_sha))  # a revert is current again


def _fsync_dir(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class _LRU:
    def __init__(self, limit_bytes: int) -> None:
        self.limit = limit_bytes
        self.size = 0
        self.d: OrderedDict = OrderedDict()

    def get(self, k):
        v = self.d.get(k)
        if v is not None:
            self.d.move_to_end(k)
        return v

    def put(self, k, v: bytes) -> None:
        if len(v) > self.limit // 4 or k in self.d:
            return
        self.d[k] = v
        self.size += len(v)
        while self.size > self.limit:
            _, old = self.d.popitem(last=False)
            self.size -= len(old)


class Refused(Exception):
    """unfold refused: missing or corrupt bits. never hand back a lookalike."""


# ---------------------------------------------------------------- store

def default_store() -> Path:
    env = os.environ.get("FOLD_MEMORY_STORE")
    if env:
        return Path(env).expanduser()
    beside = HERE / "fold-memory-store"
    if beside.exists():
        return beside
    in_site = any(part in ("site-packages", "dist-packages") for part in HERE.parts)
    if not in_site and os.access(str(HERE), os.W_OK):
        return beside
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return root / "fold-memory"


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v);
CREATE TABLE IF NOT EXISTS files (
    file_sha TEXT PRIMARY KEY, path TEXT NOT NULL, size INTEGER NOT NULL,
    chunk_count INTEGER NOT NULL, cue TEXT, ingested_at TEXT NOT NULL,
    kind TEXT, mime TEXT, fid INTEGER
);
CREATE TABLE IF NOT EXISTS chunks (
    sha TEXT PRIMARY KEY, size INTEGER NOT NULL, stored_size INTEGER NOT NULL,
    refs INTEGER NOT NULL DEFAULT 0, pack TEXT, off INTEGER, added_ns INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS file_chunks (
    file_sha TEXT NOT NULL, seq INTEGER NOT NULL, chunk_sha TEXT NOT NULL,
    PRIMARY KEY (file_sha, seq)
);
CREATE INDEX IF NOT EXISTS file_chunks_chunk ON file_chunks(chunk_sha);
CREATE TABLE IF NOT EXISTS locations (
    praw BLOB PRIMARY KEY, path TEXT NOT NULL, file_sha TEXT NOT NULL,
    size INTEGER NOT NULL, mtime_ns INTEGER, mode INTEGER, seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS locations_file ON locations(file_sha);
CREATE INDEX IF NOT EXISTS locations_path ON locations(path);
-- every version ever held at a path (2.1). locations is "what is there now"; history is
-- "what was there". rebuilt from the L records already in the packs, so no new record kind.
CREATE TABLE IF NOT EXISTS history (
    praw BLOB NOT NULL, file_sha TEXT NOT NULL, path TEXT NOT NULL, size INTEGER NOT NULL,
    mtime_ns INTEGER, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    PRIMARY KEY (praw, file_sha)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS history_file ON history(file_sha);
-- word index. fid = first 8 bytes of the file fingerprint as an integer: ~5x smaller than a
-- 64-char hex key repeated in two b-trees, which was most of the index on small text stores.
CREATE TABLE IF NOT EXISTS words (
    term TEXT NOT NULL, fid INTEGER NOT NULL, w REAL NOT NULL,
    PRIMARY KEY (term, fid)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS words_fid ON words(fid);
CREATE TABLE IF NOT EXISTS packs (name TEXT PRIMARY KEY, state TEXT NOT NULL, created_ns INTEGER NOT NULL,
    meta_bytes INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS writers (id TEXT PRIMARY KEY, pid INTEGER, started_ns INTEGER, heartbeat_ns INTEGER);
CREATE TABLE IF NOT EXISTS log (id INTEGER PRIMARY KEY, at TEXT NOT NULL, verb TEXT NOT NULL, note TEXT);
"""


class FoldMemory:
    def __init__(self, store: Path | str | None = None, level: str = "default",
                 codec: str = "zlib", jobs: int | None = None, fsync: bool = True) -> None:
        self.store = Path(store) if store else default_store()
        self.packs_dir = self.store / "packs"
        self.legacy_dir = self.store / "blobs"
        self.db_path = self.store / "fold.sqlite"
        self.prior_path = self.store / "prior.bin"
        self.level = level
        self.codec = codec
        self.fsync = fsync and os.environ.get("FOLD_MEMORY_NO_FSYNC") != "1"
        self.jobs = max(1, jobs if jobs else min(4, os.cpu_count() or 1))
        self.prior = _PRIOR_SEED
        self._conn: sqlite3.Connection | None = None
        self._cache = _LRU(CACHE_BYTES)
        self._readers: OrderedDict = OrderedDict()
        self._writer_id: str | None = None
        self._pack_fh = None
        self._pack_name: str | None = None
        self._pending_bytes = 0
        self._last_commit = time.monotonic()
        self._pool: ThreadPoolExecutor | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------ lifecycle

    def __enter__(self) -> "FoldMemory":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def open(self) -> "FoldMemory":
        self.store.mkdir(parents=True, exist_ok=True)
        self.packs_dir.mkdir(exist_ok=True)
        conn = self.db()
        legacy = self._is_legacy(conn)
        conn.executescript(SCHEMA)
        if legacy:
            self._migrate_v1(conn)
        self._upgrade_words(conn)
        self._load_prior(conn)
        fresh = conn.execute("SELECT 1 FROM files LIMIT 1").fetchone() is None
        if fresh:
            conn.execute("INSERT OR IGNORE INTO meta(k, v) VALUES ('index_version', ?)", (INDEX_VERSION,))
            conn.execute("INSERT OR IGNORE INTO meta(k, v) VALUES ('history', 1)")
        elif conn.execute("SELECT 1 FROM meta WHERE k='history'").fetchone() is None:
            self._backfill_history(conn)
        conn.execute("INSERT OR IGNORE INTO meta(k, v) VALUES ('format', ?)", (FORMAT,))
        conn.execute("INSERT OR IGNORE INTO meta(k, v) VALUES ('created', ?)", (_now(),))
        conn.commit()
        return self

    init = open

    def db(self) -> sqlite3.Connection:
        if self._conn is None:
            self.store.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path), timeout=120)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL" if self.fsync else "PRAGMA synchronous=OFF")
            self._conn.execute("PRAGMA temp_store=MEMORY")
            self._conn.execute("PRAGMA cache_size=-16000")
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._commit()
                self._seal_pack()
                if self._writer_id:
                    self._conn.execute("DELETE FROM writers WHERE id=?", (self._writer_id,))
                    self._conn.commit()
            except sqlite3.Error:
                pass
            self._conn.close()
            self._conn = None
        for fh in self._readers.values():
            fh.close()
        self._readers.clear()
        if self._pool is not None:
            self._pool.shutdown(wait=True)
            self._pool = None

    def _upgrade_words(self, conn) -> None:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(files)")]
        if "fid" not in cols:
            conn.execute("ALTER TABLE files ADD COLUMN fid INTEGER")
        conn.execute("CREATE INDEX IF NOT EXISTS files_fid ON files(fid)")
        old = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='terms'").fetchone()
        if old or conn.execute("SELECT 1 FROM files WHERE fid IS NULL LIMIT 1").fetchone():
            for r in conn.execute("SELECT file_sha, path, cue FROM files").fetchall():
                self._index_terms(r["file_sha"], r["path"], r["cue"] or "", {})
            conn.execute("DROP TABLE IF EXISTS terms")
            conn.commit()

    def _history_events(self) -> list:
        """(ts, kind, rec) for every L and D record in the packs, oldest first. chunks are skipped."""
        events = []
        for path in sorted(self.packs_dir.glob("*.pack")):
            try:
                for kind, sha_raw, payload in scan_meta_records(path):
                    if kind not in (b"L", b"D") or hashlib.sha256(payload).digest() != sha_raw:
                        continue
                    try:
                        rec = json.loads(payload.decode())
                    except (ValueError, UnicodeDecodeError):
                        continue
                    events.append((rec.get("ts", 0), kind.decode(), rec))
            except OSError:
                continue
        events.sort(key=lambda e: e[0])
        return events

    @staticmethod
    def _apply_history_event(conn, kind: str, rec: dict, table: str = "locations") -> None:
        """replay one L/D record. for L, call before `table` takes the new location."""
        if kind == "L":
            _retire_location(conn, bytes.fromhex(rec["praw"]), rec["file_sha"], _iso(rec.get("ts")), table)
        elif kind == "D":
            if rec.get("praw"):  # forget <path>: the path and everything it ever held there
                conn.execute("DELETE FROM history WHERE praw=?", (sqlite3.Binary(bytes.fromhex(rec["praw"])),))
            if rec.get("file_sha"):
                conn.execute("DELETE FROM history WHERE file_sha=?", (rec["file_sha"],))
            h = rec.get("hist")  # prune: one old version at one path
            if isinstance(h, dict) and h.get("praw") and h.get("file_sha"):
                conn.execute("DELETE FROM history WHERE praw=? AND file_sha=?",
                             (sqlite3.Binary(bytes.fromhex(h["praw"])), h["file_sha"]))

    def _backfill_history(self, conn) -> None:
        """a 2.0 store forgot old versions at a path (locations kept only the newest). the L
        records were always in the packs, so the history can be read back from them once."""
        conn.execute("DROP TABLE IF EXISTS temp.shadow_loc")
        conn.execute("CREATE TEMP TABLE shadow_loc (praw BLOB PRIMARY KEY, path TEXT, file_sha TEXT, size INTEGER, "
                     "mtime_ns INTEGER, seen_at TEXT)")
        for ts, kind, rec in self._history_events():
            try:
                self._apply_history_event(conn, kind, rec, table="shadow_loc")
                praw = sqlite3.Binary(bytes.fromhex(rec["praw"])) if rec.get("praw") else None
                if kind == "L":
                    conn.execute("INSERT OR REPLACE INTO shadow_loc VALUES (?, ?, ?, ?, ?, ?)",
                                 (praw, rec["path"], rec["file_sha"], rec["size"], rec.get("mtime_ns"),
                                  _iso(rec.get("ts"))))
                elif kind == "D":
                    if praw is not None:
                        conn.execute("DELETE FROM shadow_loc WHERE praw=?", (praw,))
                    if rec.get("file_sha"):
                        conn.execute("DELETE FROM shadow_loc WHERE file_sha=?", (rec["file_sha"],))
            except (KeyError, ValueError, TypeError):
                continue
        conn.execute("DROP TABLE temp.shadow_loc")
        conn.execute("DELETE FROM history WHERE file_sha NOT IN (SELECT file_sha FROM files)")
        conn.execute("DELETE FROM history WHERE EXISTS (SELECT 1 FROM locations l WHERE l.praw=history.praw "
                     "AND l.file_sha=history.file_sha)")
        conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('history', 1)")
        conn.commit()

    def _is_legacy(self, conn) -> bool:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(chunks)")]
        return bool(cols) and "pack" not in cols

    def _load_prior(self, conn) -> None:
        row = conn.execute("SELECT v FROM meta WHERE k='prior'").fetchone()
        if row is not None:
            self.prior = bytes(row[0])
            if not self.prior_path.exists() or self.prior_path.read_bytes() != self.prior:
                self.prior_path.write_bytes(self.prior)
            return
        prior = self.prior_path.read_bytes()[:PRIOR_MAX] if self.prior_path.exists() else _PRIOR_SEED
        conn.execute("INSERT INTO meta(k, v) VALUES ('prior', ?)", (sqlite3.Binary(prior),))
        self.prior = prior
        self.prior_path.write_bytes(prior)

    def _migrate_v1(self, conn) -> None:
        """v1 store: chunks as loose blob files, one path per file, sdm index."""
        for ddl in ("ALTER TABLE chunks ADD COLUMN pack TEXT",
                    "ALTER TABLE chunks ADD COLUMN off INTEGER",
                    "ALTER TABLE chunks ADD COLUMN added_ns INTEGER NOT NULL DEFAULT 0",
                    "ALTER TABLE files ADD COLUMN kind TEXT",
                    "ALTER TABLE files ADD COLUMN mime TEXT",
                    "ALTER TABLE files ADD COLUMN fid INTEGER"):
            try:
                conn.execute(ddl)
            except sqlite3.OperationalError:
                pass
        self._load_prior(conn)
        rows = conn.execute("SELECT file_sha, path, size, cue, ingested_at FROM files").fetchall()
        for r in rows:
            praw = os.fsencode(r["path"])
            conn.execute(
                "INSERT OR IGNORE INTO locations(praw, path, file_sha, size, mtime_ns, mode, seen_at) "
                "VALUES (?, ?, ?, ?, NULL, NULL, ?)",
                (sqlite3.Binary(praw), r["path"], r["file_sha"], r["size"], r["ingested_at"]))
            self._index_terms(r["file_sha"], r["path"], r["cue"] or "", {})
            shas = [x[0] for x in conn.execute(
                "SELECT chunk_sha FROM file_chunks WHERE file_sha=? ORDER BY seq", (r["file_sha"],))]
            head = {"t": "M", "ts": time.time_ns(), "file_sha": r["file_sha"], "size": r["size"],
                    "path": r["path"], "cue": r["cue"] or "", "kind": None, "mime": None}
            self._write_meta_record(b"M", _manifest_payload(head, shas))
            self._write_meta_record(b"L", json.dumps({"t": "L", "ts": time.time_ns(), "path": r["path"],
                                                      "praw": praw.hex(), "file_sha": r["file_sha"],
                                                      "size": r["size"]}).encode())
        conn.execute("DROP TABLE IF EXISTS sdm")
        conn.execute("DROP TABLE IF EXISTS files_fts")
        self._commit()
        self._log("migrate", {"from": 1, "to": FORMAT, "files": len(rows)})

    # ------------------------------------------------ writing

    def _register_writer(self) -> None:
        if self._writer_id is None:
            self._writer_id = uuid.uuid4().hex
            now = time.time_ns()
            conn = self.db()
            conn.execute("INSERT INTO writers(id, pid, started_ns, heartbeat_ns) VALUES (?, ?, ?, ?)",
                         (self._writer_id, os.getpid(), now, now))
            conn.commit()

    def _open_pack(self):
        if self._pack_fh is not None and self._pack_fh.tell() < PACK_LIMIT:
            return self._pack_fh
        self._register_writer()
        self._seal_pack()
        name = "%020d-%s.pack" % (time.time_ns(), uuid.uuid4().hex[:12])
        conn = self.db()
        # outside a transaction the row is committed now; inside one it lands with
        # the rows that point into the pack. a crash before that leaves an unlisted
        # pack file, which gc adopts after the grace window.
        was_in_tx = conn.in_transaction
        conn.execute("INSERT INTO packs(name, state, created_ns) VALUES (?, 'open', ?)", (name, time.time_ns()))
        if not was_in_tx:
            conn.commit()
        fh = open(self.packs_dir / name, "wb")
        fh.write(PACK_MAGIC)
        self._pack_fh, self._pack_name = fh, name
        return fh

    def _seal_pack(self) -> None:
        if self._pack_fh is None:
            return
        self._sync_pack()
        self._pack_fh.close()
        self.db().execute("UPDATE packs SET state='sealed' WHERE name=?", (self._pack_name,))
        self.db().commit()
        self._pack_fh = None
        self._pack_name = None

    def _sync_pack(self) -> None:
        if self._pack_fh is None:
            return
        self._pack_fh.flush()
        if self.fsync:
            os.fsync(self._pack_fh.fileno())

    def _commit(self) -> None:
        conn = self._conn
        if conn is None:
            return
        self._sync_pack()  # bytes durable before the rows that point at them
        if self._writer_id:
            conn.execute("UPDATE writers SET heartbeat_ns=? WHERE id=?", (time.time_ns(), self._writer_id))
        conn.commit()
        self._pending_bytes = 0
        self._last_commit = time.monotonic()

    def _maybe_commit(self) -> None:
        if (self._pending_bytes >= COMMIT_EVERY_BYTES
                or time.monotonic() - self._last_commit >= COMMIT_EVERY_S):
            self._commit()

    def flush(self) -> None:
        self._commit()

    def _write_meta_record(self, kind: bytes, payload: bytes) -> None:
        fh = self._open_pack()
        _write_record(fh, kind, hashlib.sha256(payload).digest(), payload)
        self._count_meta(REC_HEAD.size + len(payload))

    def _count_meta(self, n: int) -> None:
        self.db().execute("UPDATE packs SET meta_bytes = meta_bytes + ? WHERE name=?", (n, self._pack_name))

    def _pool_get(self) -> ThreadPoolExecutor | None:
        if self.jobs <= 1:
            return None
        if self._pool is None:
            self._pool = ThreadPoolExecutor(max_workers=self.jobs)
        return self._pool

    def _store_batch(self, batch: list, incompressible: bool, seen_now: set) -> tuple:
        """batch of (sha_hex, raw). write the new ones. returns (new_raw, new_stored, reused)."""
        conn = self.db()
        fresh = []
        reused = 0
        for sha, raw in batch:
            if sha in seen_now:
                reused += 1
                continue
            seen_now.add(sha)
            if conn.execute("SELECT 1 FROM chunks WHERE sha=?", (sha,)).fetchone():
                reused += 1
            else:
                fresh.append((sha, raw))
        if not fresh:
            return 0, 0, reused
        pool = self._pool_get()

        def job(item):
            return pack_chunk(item[1], self.prior, self.level, self.codec, incompressible)

        packed = list(pool.map(job, fresh)) if pool and len(fresh) > 1 else [job(x) for x in fresh]
        fh = self._open_pack()
        now = time.time_ns()
        new_raw = new_stored = 0
        rows = []
        for (sha, raw), blob in zip(fresh, packed):
            if fh.tell() >= PACK_LIMIT:
                fh = self._open_pack()
            off = _write_record(fh, b"C", bytes.fromhex(sha), blob)
            rows.append((sha, len(raw), len(blob), self._pack_name, off, now))
            new_raw += len(raw)
            new_stored += len(blob)
        conn.executemany("INSERT OR IGNORE INTO chunks(sha, size, stored_size, refs, pack, off, added_ns) "
                         "VALUES (?, ?, ?, 0, ?, ?, ?)", rows)
        self._pending_bytes += new_stored
        return new_raw, new_stored, reused

    def ingest_stream(self, read, display_path: str, praw: bytes | None = None,
                      real_path: Path | None = None, st: os.stat_result | None = None) -> dict:
        """fold any byte stream. read(n) -> bytes. real_path lets the sniffer open containers."""
        head = read(READ_BLOCK)
        name = display_path.replace("\\", "/").rsplit("/", 1)[-1]
        meta = extract_meta(real_path, name, head[:1 << 20])
        texty = is_texty(head[:8192]) and meta["kind"] not in PRECOMPRESSED
        params = TEXT_PARAMS if texty else BIN_PARAMS
        incompressible = meta["kind"] in PRECOMPRESSED
        file_hash = hashlib.sha256()
        shas: list = []
        seen_now: set = set()
        size = 0
        new_raw = new_stored = reused = 0
        batch: list = []
        batch_bytes = 0
        for raw in iter_chunks(read, params, head):
            file_hash.update(raw)
            size += len(raw)
            sha = hashlib.sha256(raw).hexdigest()
            shas.append(sha)
            batch.append((sha, raw))
            batch_bytes += len(raw)
            if batch_bytes >= READ_BLOCK:
                a, b, c = self._store_batch(batch, incompressible, seen_now)
                new_raw, new_stored, reused = new_raw + a, new_stored + b, reused + c
                batch, batch_bytes = [], 0
                self._maybe_commit()
        if batch:
            a, b, c = self._store_batch(batch, incompressible, seen_now)
            new_raw, new_stored, reused = new_raw + a, new_stored + b, reused + c
        file_sha = file_hash.hexdigest()
        conn = self.db()
        exists = conn.execute("SELECT 1 FROM files WHERE file_sha=?", (file_sha,)).fetchone()
        now = _now()
        if not exists:
            cue = build_cue(display_path, meta, keep=CUE_KEEP)
            conn.execute("INSERT OR IGNORE INTO files(file_sha, path, size, chunk_count, cue, ingested_at, kind, mime) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         (file_sha, display_path, size, len(shas), cue, now, meta["kind"], meta["mime"]))
            conn.executemany("INSERT OR IGNORE INTO file_chunks(file_sha, seq, chunk_sha) VALUES (?, ?, ?)",
                             [(file_sha, i, s) for i, s in enumerate(shas)])
            weights = self._index_terms(file_sha, display_path, build_cue(display_path, meta), meta["fields"])
            head_rec = {"t": "M", "ts": time.time_ns(), "file_sha": file_sha, "size": size, "path": display_path,
                        "cue": cue, "kind": meta["kind"], "mime": meta["mime"], "w": weights}
            self._write_meta_record(b"M", _manifest_payload(head_rec, shas))
        praw = praw if praw is not None else display_path.encode("utf-8", "surrogateescape")
        mtime_ns = st.st_mtime_ns if st is not None else None
        mode = stat_mod.S_IMODE(st.st_mode) if st is not None else None
        _retire_location(conn, praw, file_sha, now)
        conn.execute("INSERT OR REPLACE INTO locations(praw, path, file_sha, size, mtime_ns, mode, seen_at) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (sqlite3.Binary(praw), display_path, file_sha, size, mtime_ns, mode, now))
        self._write_meta_record(b"L", json.dumps(
            {"t": "L", "ts": time.time_ns(), "path": display_path, "praw": praw.hex(), "file_sha": file_sha,
             "size": size, "mtime_ns": mtime_ns, "mode": mode}, ensure_ascii=False).encode())
        self._maybe_commit()
        out = {"path": display_path, "file_sha": file_sha, "size": size, "kind": meta["kind"],
               "status": "alias" if exists else "folded"}
        if exists:
            out["note"] = "identical bytes already held — copy folded, location remembered"
        else:
            out.update(chunks=len(shas), chunks_reused=reused, new_unique_raw=new_raw, new_unique_stored=new_stored)
        if st is not None and st.st_size != size:
            out["warning"] = "file changed while reading; the bytes that were read are what is held"
        return out

    def ingest_bytes(self, data: bytes, name: str) -> dict:
        return self.ingest_stream(io.BytesIO(data).read, name)

    def ingest_file(self, path, commit: bool = True, rehash: bool = False,
                    allow_secret_names: bool = False, hydrate_cloud: bool = False) -> dict:
        path = Path(path)
        display = os.path.abspath(str(path))
        if not allow_secret_names and SECRET_NAME_RX.search(path.name):
            return {"path": display, "status": "skip", "reason": "secret-shaped name"}
        try:
            st = os.stat(str(path), follow_symlinks=False)
        except OSError as exc:
            return {"path": display, "status": "skip", "reason": "stat: %s" % exc.strerror}
        if stat_mod.S_ISLNK(st.st_mode):
            try:
                st = os.stat(str(path))
            except OSError:
                return {"path": display, "status": "skip", "reason": "broken link"}
        if not stat_mod.S_ISREG(st.st_mode):
            return {"path": display, "status": "skip", "reason": "not a regular file (device, pipe, socket)"}
        attrs = getattr(st, "st_file_attributes", 0)
        if attrs & 0x00440000 and not hydrate_cloud:  # windows cloud placeholder: reading downloads it
            return {"path": display, "status": "skip", "reason": "cloud placeholder not on this disk"}
        praw = os.fsencode(display)
        if not rehash:
            row = self.db().execute(
                "SELECT l.file_sha FROM locations l JOIN files f ON f.file_sha=l.file_sha "
                "WHERE l.praw=? AND l.size=? AND l.mtime_ns=?",
                (sqlite3.Binary(praw), st.st_size, st.st_mtime_ns)).fetchone()
            if row:
                return {"path": display, "file_sha": row[0], "size": st.st_size, "status": "unchanged"}
        try:
            fh = open(str(path), "rb")
        except OSError as exc:
            return {"path": display, "status": "skip", "reason": "open: %s" % (exc.strerror or exc)}
        try:
            text_display = display if display.encode("utf-8", "surrogateescape").decode("utf-8", "replace") == display \
                else display.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
            res = self.ingest_stream(fh.read, text_display, praw=praw, real_path=path, st=st)
        except OSError as exc:
            return {"path": display, "status": "skip", "reason": "read: %s" % (exc.strerror or exc)}
        finally:
            fh.close()
        if commit:
            self._commit()
        return res

    def ingest_tree(self, root, excludes: list | None = None, follow_links: bool = False,
                    progress=None, **kw) -> list:
        return list(self.iter_ingest(root, excludes, follow_links, progress, **kw))

    def iter_ingest(self, root, excludes: list | None = None, follow_links: bool = False,
                    progress=None, **kw):
        root = Path(root)
        excludes = list(excludes or [])
        store_real = os.path.realpath(str(self.store))
        if root.is_file() or not root.exists():
            yield self.ingest_file(root, **kw)
            return
        seen_dirs = set()
        for dirpath, dirnames, filenames in os.walk(str(root), followlinks=follow_links):
            if follow_links:
                try:
                    st = os.stat(dirpath)
                    key = (st.st_dev, st.st_ino)
                    if key in seen_dirs:
                        dirnames[:] = []
                        continue
                    seen_dirs.add(key)
                except OSError:
                    continue
            keep = []
            for d in dirnames:
                full = os.path.join(dirpath, d)
                if d in DEFAULT_EXCLUDE_DIRS or os.path.realpath(full) == store_real:
                    continue
                if any(fnmatch.fnmatch(d, pat) or fnmatch.fnmatch(full, pat) for pat in excludes):
                    continue
                keep.append(d)
            dirnames[:] = keep
            for name in filenames:
                full = os.path.join(dirpath, name)
                if any(fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(full, pat) for pat in excludes):
                    yield {"path": full, "status": "skip", "reason": "excluded"}
                    continue
                res = self.ingest_file(full, commit=False, **kw)
                if progress:
                    progress(res)
                yield res
        self._commit()

    # ------------------------------------------------ reading

    def _chunk_row(self, sha: str):
        return self.db().execute("SELECT sha, size, pack, off, stored_size FROM chunks WHERE sha=?", (sha,)).fetchone()

    def _read_stored(self, row) -> bytes:
        if row["pack"] is None:
            p = self.legacy_dir / row["sha"][:2] / row["sha"]
            with open(p, "rb") as fh:
                return fh.read()
        fh = self._readers.get(row["pack"])
        if fh is None:
            fh = open(self.packs_dir / row["pack"], "rb")
            self._readers[row["pack"]] = fh
            if len(self._readers) > 64:
                _, old = self._readers.popitem(last=False)
                old.close()
        if self._pack_fh is not None and row["pack"] == self._pack_name:
            self._pack_fh.flush()
        fh.seek(row["off"])
        data = fh.read(row["stored_size"])
        if len(data) != row["stored_size"]:
            raise ValueError("pack truncated")
        return data

    def get_chunk(self, sha: str) -> bytes:
        hit = self._cache.get(sha)
        if hit is not None:
            return hit
        for attempt in (0, 1):
            row = self._chunk_row(sha)
            if row is None:
                raise Refused("missing chunk %s" % sha[:16])
            try:
                raw = unpack_chunk(self._read_stored(row), self.prior)
                break
            except OSError:
                if attempt:
                    raise Refused("chunk %s unreadable" % sha[:16])
                self._readers.pop(row["pack"], None)  # a gc may have moved it; look again
            except CodecMissing as exc:
                raise Refused("chunk %s not readable here (not damaged): %s" % (sha[:16], exc))
            except (ValueError, zlib.error, lzma.LZMAError) as exc:
                raise Refused("chunk %s damaged: %s" % (sha[:16], exc))
        if hashlib.sha256(raw).hexdigest() != sha:
            raise Refused("chunk %s hash mismatch" % sha[:16])
        self._cache.put(sha, raw)
        return raw

    def resolve(self, ref: str) -> str:
        """full sha, sha prefix (>=6 hex), or a remembered path."""
        conn = self.db()
        ref = ref.strip()
        if re.fullmatch(r"[0-9a-fA-F]{6,64}", ref):
            rows = conn.execute("SELECT file_sha FROM files WHERE file_sha >= ? AND file_sha < ? LIMIT 2",
                                (ref.lower(), ref.lower() + "g")).fetchall()
            if len(rows) == 1:
                return rows[0][0]
            if len(rows) > 1:
                raise LookupError("fingerprint prefix %s is ambiguous" % ref)
        for candidate in (os.path.abspath(ref), ref):
            row = conn.execute("SELECT file_sha FROM locations WHERE praw=? OR path=?",
                               (sqlite3.Binary(os.fsencode(candidate)), candidate)).fetchone()
            if row:
                return row[0]
        raise LookupError("nothing held for %s" % ref)

    def iter_unfold(self, file_sha: str):
        """yield the file's bytes chunk by chunk. raise Refused at the end if the whole-file hash misses."""
        conn = self.db()
        row = conn.execute("SELECT size FROM files WHERE file_sha=?", (file_sha,)).fetchone()
        if not row:
            raise Refused("unknown fingerprint %s" % file_sha)
        h = hashlib.sha256()
        n = 0
        cur = conn.execute("SELECT chunk_sha FROM file_chunks WHERE file_sha=? ORDER BY seq", (file_sha,))
        shas = [r[0] for r in cur]
        for sha in shas:
            raw = self.get_chunk(sha)
            h.update(raw)
            n += len(raw)
            yield raw
        if h.hexdigest() != file_sha or n != row["size"]:
            raise Refused("file fingerprint mismatch")

    def read(self, ref: str) -> bytes:
        return b"".join(self.iter_unfold(self.resolve(ref)))

    def unfold(self, ref: str, dest=None, version: int | None = None) -> dict:
        """exact bits to dest (file, dir, '-' for stdout, None to only verify) or refuse. nothing half-written.
        version=N picks the Nth newest version held at that path (1 = newest)."""
        try:
            file_sha = self.resolve_version(ref, version) if version else self.resolve(ref)
        except LookupError as exc:
            return {"ok": False, "error": str(exc), "ref": ref}
        conn = self.db()
        loc = conn.execute("SELECT path, mtime_ns, mode FROM locations WHERE file_sha=? ORDER BY seen_at LIMIT 1",
                           (file_sha,)).fetchone()
        if loc is None:  # an old version: no current location, but history knows its path and date
            loc = conn.execute("SELECT path, mtime_ns, NULL AS mode FROM history WHERE file_sha=? "
                               "ORDER BY last_seen DESC LIMIT 1", (file_sha,)).fetchone()
        frow = conn.execute("SELECT path, size FROM files WHERE file_sha=?", (file_sha,)).fetchone()
        src = loc["path"] if loc else (frow["path"] if frow else "")
        try:
            if dest is None:
                size = sum(len(b) for b in self.iter_unfold(file_sha))
                return {"ok": True, "file_sha": file_sha, "size": size, "source_path": src, "written": None,
                        "note": "bits match the fingerprint"}
            if str(dest) == "-":
                out = sys.stdout.buffer
                # stdout cannot be rolled back, so verify before the first byte leaves. 2.0 held
                # the whole file in ram here (a 4 gb dump needed 4 gb); spool past 32 mb to disk.
                total = 0
                with tempfile.SpooledTemporaryFile(max_size=32 << 20, dir=str(self.store)) as spool:
                    for part in self.iter_unfold(file_sha):
                        spool.write(part)
                        total += len(part)
                    spool.seek(0)
                    while True:
                        block = spool.read(READ_BLOCK)
                        if not block:
                            break
                        out.write(block)
                out.flush()
                return {"ok": True, "file_sha": file_sha, "size": total, "written": "-"}
            dest = Path(dest)
            if dest.is_dir() or str(dest).endswith(("/", "\\")):
                dest = dest / (_safe_name(src) or file_sha)
            written = self._write_verified(file_sha, dest, loc)
        except Refused as exc:
            return {"ok": False, "error": "unfold refused — %s" % exc, "file_sha": file_sha}
        return {"ok": True, "file_sha": file_sha, "size": frow["size"], "source_path": src,
                "written": str(written), "note": "bits match the fingerprint"}

    def _write_verified(self, file_sha: str, dest: Path, loc=None) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".fold-", dir=str(dest.parent))
        try:
            with os.fdopen(fd, "wb") as fh:
                for part in self.iter_unfold(file_sha):
                    fh.write(part)
                fh.flush()
                if self.fsync:
                    os.fsync(fh.fileno())
            if loc is not None and loc["mode"] is not None:
                try:
                    os.chmod(tmp, loc["mode"])
                except OSError:
                    pass
            os.replace(tmp, str(dest))
            if loc is not None and loc["mtime_ns"]:
                try:
                    os.utime(str(dest), ns=(loc["mtime_ns"], loc["mtime_ns"]))
                except OSError:
                    pass
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return dest

    def restore(self, prefix: str, out_dir, dry_run: bool = False) -> dict:
        """rebuild every remembered location under prefix inside out_dir, keeping relative layout."""
        out_dir = Path(out_dir)
        norm = prefix.replace("\\", "/").rstrip("/")
        conn = self.db()
        rows = conn.execute("SELECT path, file_sha, mtime_ns, mode FROM locations ORDER BY path").fetchall()
        done, refused = [], []
        claimed: dict = {}
        for r in rows:
            p = r["path"].replace("\\", "/")
            if norm and not (p == norm or p.startswith(norm + "/")):
                continue
            # 2.0 used only the file name when the prefix was empty or "/", so restore / put
            # every same-named file on top of the last one and still reported them all restored.
            if norm and p == norm:
                rel = p.rsplit("/", 1)[-1]
            else:
                rel = p[len(norm):]
            parts = [x for x in re.split(r"/+", rel) if x not in ("", ".", "..")]
            if parts and re.fullmatch(r"[A-Za-z]:", parts[0]):
                parts = parts[1:]
            if not parts:
                continue
            target = out_dir.joinpath(*parts)
            key = str(target) if os.name != "nt" and sys.platform != "darwin" else str(target).lower()
            if key in claimed:
                if claimed[key] != r["file_sha"]:
                    refused.append({"path": r["path"], "error": "target collision with %s" % target})
                continue
            claimed[key] = r["file_sha"]
            if dry_run:
                done.append(str(target))
                continue
            try:
                self._write_verified(r["file_sha"], target, r)
                done.append(str(target))
            except Refused as exc:
                refused.append({"path": r["path"], "error": str(exc)})
        return {"ok": not refused, "restored": len(done), "refused": refused, "out": str(out_dir),
                "sample": done[:20]}

    # ------------------------------------------------ recall

    def _index_terms(self, file_sha: str, path: str, cue: str, fields: dict,
                     weights: dict | None = None) -> dict:
        if weights is None:
            weights = term_weights(path, cue, fields)
        fid = fid_of(file_sha)
        conn = self.db()
        conn.execute("UPDATE files SET fid=? WHERE file_sha=?", (fid, file_sha))
        conn.execute("DELETE FROM words WHERE fid=?", (fid,))
        conn.executemany("INSERT OR REPLACE INTO words(term, fid, w) VALUES (?, ?, ?)",
                         [(t, fid, float(w)) for t, w in weights.items()])
        return weights

    def cue(self, query: str, trance: bool = False, limit: int = 12) -> list:
        """recall by words. trance widens: prefix matches, any-word matches, pair bonus. no extra storage."""
        conn = self.db()
        tokens = list(dict.fromkeys(tokenize(query)))
        if not tokens:
            return []
        core = [t for t in tokens if t not in STOP] or tokens
        n_files = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0] or 1
        scores: dict = {}
        matched: dict = {}
        for t in core:
            if trance and len(t) >= 3:
                rows = conn.execute("SELECT fid, MAX(w) FROM words WHERE term >= ? AND term < ? "
                                    "GROUP BY fid LIMIT 50000", (t, t + "\uffff")).fetchall()
            else:
                rows = conn.execute("SELECT fid, w FROM words WHERE term=? LIMIT 50000", (t,)).fetchall()
            if not rows:
                continue
            idf = math.log(1.0 + n_files / len(rows))
            for sha, w in rows:
                scores[sha] = scores.get(sha, 0.0) + w * idf
                matched.setdefault(sha, set()).add(t)
        if not scores:
            return []
        if trance:
            for a, b in zip(core, core[1:]):
                for sha, m in matched.items():
                    if a in m and b in m:
                        scores[sha] *= 1.25
            ranked = sorted(scores, key=lambda s: (-len(matched[s]), -scores[s]))
        else:
            full = [s for s in scores if len(matched[s]) == len(core)]
            pool = full if full else list(scores)
            ranked = sorted(pool, key=lambda s: (-len(matched[s]), -scores[s]))
        out = []
        for sha in ranked[:limit]:
            fid = sha
            f = conn.execute("SELECT file_sha, size, kind, cue, path FROM files WHERE fid=?", (fid,)).fetchone()
            if f is None:
                continue
            sha = f["file_sha"]
            paths = [r[0] for r in conn.execute(
                "SELECT path FROM locations WHERE file_sha=? ORDER BY seen_at DESC LIMIT 5", (sha,))]
            cue_body = (f["cue"] or "").split("\n", 1)[-1]
            out.append({
                "file_sha": sha,
                "path": paths[0] if paths else f["path"],
                "copies": len(paths),
                "other_paths": paths[1:],
                "size": f["size"],
                "kind": f["kind"],
                "score": round(scores[fid], 3),
                "matched": "%d/%d" % (len(matched[fid]), len(core)),
                "cue_preview": re.sub(r"\s+", " ", cue_body)[:160],
            })
        return out

    def ls(self, prefix: str = "", limit: int = 200) -> list:
        norm = prefix.replace("\\", "/").rstrip("/")
        rows = self.db().execute(
            "SELECT l.path, l.file_sha, l.size, f.kind, l.seen_at FROM locations l "
            "LEFT JOIN files f ON f.file_sha=l.file_sha ORDER BY l.path").fetchall()
        out = []
        for r in rows:
            p = r["path"].replace("\\", "/")
            if norm and not (p == norm or p.startswith(norm + "/")):
                continue
            out.append({"path": r["path"], "file_sha": r["file_sha"], "size": r["size"], "kind": r["kind"],
                        "seen_at": r["seen_at"]})
            if len(out) >= limit:
                break
        return out

    # ------------------------------------------------ accounting and health

    def _checkpoint(self) -> None:
        try:
            self.db().execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass

    def stats(self) -> dict:
        self._commit()
        self._checkpoint()
        conn = self.db()
        q = lambda sql: conn.execute(sql).fetchone()[0] or 0  # noqa: E731
        logical = q("SELECT SUM(size) FROM locations")
        unique_files = q("SELECT SUM(size) FROM files")
        unique_raw = q("SELECT SUM(size) FROM chunks")
        stored = q("SELECT SUM(stored_size) FROM chunks")
        disk = 0
        for dirpath, _, filenames in os.walk(str(self.store)):
            for fn in filenames:
                try:
                    disk += os.path.getsize(os.path.join(dirpath, fn))
                except OSError:
                    pass
        iv = conn.execute("SELECT v FROM meta WHERE k='index_version'").fetchone()
        extra = {}
        if (iv[0] if iv else 1) < INDEX_VERSION and q("SELECT COUNT(*) FROM files"):
            extra["reindex_recommended"] = ("this index was built by 2.0, which indexed metadata fields "
                                            "(titles, subjects, csv headers) without masking secrets. run: reindex")
        return dict({
            "store": str(self.store),
            "files_held": q("SELECT COUNT(*) FROM files"),
            "old_versions_held": q("SELECT COUNT(*) FROM history"),
            "locations": q("SELECT COUNT(*) FROM locations"),
            "unique_chunks": q("SELECT COUNT(*) FROM chunks"),
            "logical_bytes": logical,
            "unique_file_bytes": unique_files,
            "unique_chunk_bytes": unique_raw,
            "stored_chunk_bytes": stored,
            "disk_bytes": disk,
            "saved_by_copies": max(0, logical - unique_raw),
            "saved_by_squeeze": max(0, unique_raw - stored),
            "fold_ratio": round(1 - disk / logical, 4) if logical else 0.0,
            "floor_note": "disk_bytes is everything on disk: packs, index, prior. unique bits do not shrink.",
            "wifi": False,
            "version": __version__,
        }, **extra)

    def verify(self, full: bool = False, progress=None) -> dict:
        """read every chunk and check its fingerprint. full also re-checks every whole file."""
        self._commit()
        conn = self.db()
        bad_chunks = []
        n = unreadable = 0
        for (sha,) in conn.execute("SELECT sha FROM chunks").fetchall():
            n += 1
            self._cache = _LRU(0)
            try:
                self.get_chunk(sha)
            except Refused as exc:
                if "not readable here" in str(exc):
                    unreadable += 1
                else:
                    bad_chunks.append({"chunk": sha, "error": str(exc)})
            if progress and n % 1000 == 0:
                progress(n)
        self._cache = _LRU(CACHE_BYTES)
        missing = [r[0] for r in conn.execute(
            "SELECT DISTINCT fc.chunk_sha FROM file_chunks fc LEFT JOIN chunks c ON c.sha=fc.chunk_sha "
            "WHERE c.sha IS NULL LIMIT 1000")]
        bad_set = set(b["chunk"] for b in bad_chunks) | set(missing)
        affected = []
        if bad_set:
            for (fsha,) in conn.execute("SELECT DISTINCT file_sha FROM file_chunks WHERE chunk_sha IN (%s)" %
                                        ",".join("?" * len(bad_set)), tuple(bad_set)):
                affected.append(fsha)
        bad_files = []
        if full:
            for (fsha,) in conn.execute("SELECT file_sha FROM files").fetchall():
                try:
                    for _ in self.iter_unfold(fsha):
                        pass
                except Refused as exc:
                    if "not readable here" not in str(exc):
                        bad_files.append({"file_sha": fsha, "error": str(exc)})
        # ok means "every chunk checked and fine". chunks this python can't decode were not checked.
        ok = not bad_chunks and not missing and not bad_files and not unreadable
        self._log("verify", {"ok": ok, "chunks": n, "bad": len(bad_chunks), "missing": len(missing)})
        self._commit()
        out = {"ok": ok, "chunks_checked": n - unreadable, "bad_chunks": bad_chunks[:100], "missing_chunks": missing[:100],
               "files_affected": affected[:100], "bad_files": bad_files[:100]}
        if unreadable:
            out["not_checked"] = unreadable
            out["note"] = "%d chunks use zstd and this python can't decode them. not damage. verify with python 3.14+." % unreadable
        return out

    # ------------------------------------------------ forgetting and garbage

    def forget(self, ref: str, everywhere: bool = False) -> dict:
        """drop one remembered location (a path), or a whole file (a fingerprint) with every location."""
        conn = self.db()
        dropped_paths = []
        targets = []
        is_sha = bool(re.fullmatch(r"[0-9a-fA-F]{6,64}", ref))
        if is_sha:
            targets = [self.resolve(ref)]
        else:
            for candidate in (os.path.abspath(ref), ref):
                row = conn.execute("SELECT praw, path, file_sha FROM locations WHERE praw=? OR path=?",
                                   (sqlite3.Binary(os.fsencode(candidate)), candidate)).fetchone()
                if row is None:  # a path that only has old versions left
                    row = conn.execute("SELECT praw, path, file_sha FROM history WHERE praw=? OR path=? "
                                       "ORDER BY last_seen DESC LIMIT 1",
                                       (sqlite3.Binary(os.fsencode(candidate)), candidate)).fetchone()
                if row:
                    praw = row["praw"]
                    touched = set(r[0] for r in conn.execute("SELECT file_sha FROM history WHERE praw=?", (praw,)))
                    touched.add(row["file_sha"])
                    conn.execute("DELETE FROM locations WHERE praw=?", (praw,))
                    conn.execute("DELETE FROM history WHERE praw=?", (praw,))
                    dropped_paths.append(row["path"])
                    self._write_meta_record(b"D", json.dumps({"t": "D", "ts": time.time_ns(),
                                                              "praw": bytes(praw).hex()}).encode())
                    if everywhere:
                        targets.append(row["file_sha"])
                    targets.extend(s for s in sorted(touched) if s not in targets and not self._is_referenced(s))
                    break
            else:
                raise LookupError("nothing held for %s" % ref)
        for target in targets:
            dropped_paths.extend(self._drop_file(target))
        self._log("forget", {"ref": ref, "files": len(targets), "paths": len(dropped_paths)})
        self._commit()
        return {"ok": True, "forgot_file": targets[0] if targets else None, "forgot_files": targets[:50],
                "forgot_paths": dropped_paths[:50], "note": "run gc to give the space back"}

    def _is_referenced(self, file_sha: str) -> bool:
        conn = self.db()
        return bool(conn.execute("SELECT 1 FROM locations WHERE file_sha=? LIMIT 1", (file_sha,)).fetchone()
                    or conn.execute("SELECT 1 FROM history WHERE file_sha=? LIMIT 1", (file_sha,)).fetchone())

    def _drop_file(self, target: str) -> list:
        conn = self.db()
        paths = [r[0] for r in conn.execute("SELECT path FROM locations WHERE file_sha=?", (target,))]
        for t in ("locations", "history", "file_chunks", "files"):
            conn.execute("DELETE FROM %s WHERE file_sha=?" % t, (target,))
        conn.execute("DELETE FROM words WHERE fid=?", (fid_of(target),))
        self._write_meta_record(b"D", json.dumps({"t": "D", "ts": time.time_ns(), "file_sha": target}).encode())
        return paths

    def reindex(self, progress=None) -> dict:
        """re-read every held file from its own chunks and rebuild its words and cue.
        a 2.0 store indexed metadata fields unmasked; this scrubs that without the originals."""
        self._commit()
        conn = self.db()
        need_path = {"pdf", "zip", "tar", "gzip", "sqlite", "mp4", "mov", "m4a", "heic", "avif"}
        done = refused = 0
        rows = conn.execute("SELECT file_sha, path, size FROM files ORDER BY file_sha").fetchall()
        for r in rows:
            fsha, path = r["file_sha"], r["path"]
            name = path.replace("\\", "/").rsplit("/", 1)[-1]
            chunk_list = [x[0] for x in conn.execute(
                "SELECT chunk_sha FROM file_chunks WHERE file_sha=? ORDER BY seq", (fsha,))]
            try:
                head = bytearray()
                for sha in chunk_list:
                    head += self.get_chunk(sha)
                    if len(head) >= 1 << 20:
                        break
                head = bytes(head)
                tmp = None
                if sniff_kind(head, name) in need_path:
                    fd, tmp = tempfile.mkstemp(prefix=".reindex-", dir=str(self.store))
                    with os.fdopen(fd, "wb") as fh:
                        for part in self.iter_unfold(fsha):
                            fh.write(part)
                try:
                    meta = extract_meta(Path(tmp) if tmp else None, name, head)
                finally:
                    if tmp:
                        os.unlink(tmp)
            except Refused:
                refused += 1
                continue
            cue = build_cue(path, meta, keep=CUE_KEEP)
            weights = self._index_terms(fsha, path, build_cue(path, meta), meta["fields"])
            conn.execute("UPDATE files SET cue=?, kind=?, mime=? WHERE file_sha=?",
                         (cue, meta["kind"], meta["mime"], fsha))
            head_rec = {"t": "M", "ts": time.time_ns(), "file_sha": fsha, "size": r["size"], "path": path,
                        "cue": cue, "kind": meta["kind"], "mime": meta["mime"], "w": weights}
            self._write_meta_record(b"M", _manifest_payload(head_rec, chunk_list))
            done += 1
            if progress:
                progress(done)
            self._maybe_commit()
        if not refused:
            conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('index_version', ?)", (INDEX_VERSION,))
        self._log("reindex", {"files": done, "refused": refused})
        self._commit()
        return {"ok": refused == 0, "reindexed": done, "refused": refused}

    # ------------------------------------------------ versions, pruning, duplicates (2.1)

    def versions(self, ref: str) -> dict:
        """every version held at one path, newest first. the bytes of each are still exact."""
        conn = self.db()
        cur = None
        old = []
        for candidate in (os.path.abspath(ref), ref):
            args = (sqlite3.Binary(os.fsencode(candidate)), candidate)
            cur = conn.execute("SELECT praw, path, file_sha, size, mtime_ns, seen_at FROM locations "
                               "WHERE praw=? OR path=? LIMIT 1", args).fetchone()
            praw = cur["praw"] if cur is not None else None
            if praw is None:
                r = conn.execute("SELECT praw FROM history WHERE praw=? OR path=? LIMIT 1", args).fetchone()
                praw = r[0] if r else None
            if praw is not None:
                old = conn.execute("SELECT path, file_sha, size, mtime_ns, first_seen, last_seen FROM history "
                                   "WHERE praw=? ORDER BY last_seen DESC, first_seen DESC", (praw,)).fetchall()
                break
        if cur is None and not old:
            raise LookupError("no versions held for %s" % ref)
        out = []
        if cur is not None:
            out.append({"file_sha": cur["file_sha"], "size": cur["size"], "current": True,
                        "held_since": cur["seen_at"], "replaced_at": None,
                        "mtime": _iso(cur["mtime_ns"]) if cur["mtime_ns"] else None})
        for r in old:
            out.append({"file_sha": r["file_sha"], "size": r["size"], "current": False,
                        "held_since": r["first_seen"], "replaced_at": r["last_seen"],
                        "mtime": _iso(r["mtime_ns"]) if r["mtime_ns"] else None})
        for i, v in enumerate(out):
            v["n"] = i + 1
        return {"path": (cur["path"] if cur is not None else old[0]["path"]), "versions": out,
                "note": "unfold <path> --version N, or unfold <file_sha>"}

    def resolve_version(self, ref: str, n: int) -> str:
        vs = self.versions(ref)["versions"]
        if not 1 <= n <= len(vs):
            raise LookupError("%s has %d versions; asked for %d" % (ref, len(vs), n))
        return vs[n - 1]["file_sha"]

    def prune(self, keep: int, prefix: str = "", dry_run: bool = False) -> dict:
        """keep the newest `keep` versions at each path; drop older ones. the current one always stays."""
        if keep < 1:
            raise ValueError("keep must be at least 1")
        conn = self.db()
        norm = prefix.replace("\\", "/").rstrip("/")
        rows = conn.execute(
            "SELECT h.praw, h.path, h.file_sha, h.size, (l.praw IS NOT NULL) AS has_current FROM history h "
            "LEFT JOIN locations l ON l.praw=h.praw "
            "ORDER BY h.praw, h.last_seen DESC, h.first_seen DESC").fetchall()
        drop = []
        seen: dict = {}
        for r in rows:
            p = r["path"].replace("\\", "/")
            if norm and not (p == norm or p.startswith(norm + "/")):
                continue
            k = bytes(r["praw"])
            if k not in seen:
                seen[k] = 1 if r["has_current"] else 0  # the current version counts toward keep
            seen[k] += 1
            if seen[k] > keep:
                drop.append(r)
        if dry_run:
            return {"ok": True, "dry_run": True, "versions_to_drop": len(drop),
                    "bytes_if_unshared": sum(r["size"] for r in drop),
                    "sample": [{"path": r["path"], "file_sha": r["file_sha"]} for r in drop[:20]]}
        touched = set()
        for r in drop:
            conn.execute("DELETE FROM history WHERE praw=? AND file_sha=?", (r["praw"], r["file_sha"]))
            self._write_meta_record(b"D", json.dumps({"t": "D", "ts": time.time_ns(), "hist": {
                "praw": bytes(r["praw"]).hex(), "file_sha": r["file_sha"]}}).encode())
            touched.add(r["file_sha"])
        files = [s for s in sorted(touched) if not self._is_referenced(s)]
        for s in files:
            self._drop_file(s)
        self._log("prune", {"keep": keep, "versions": len(drop), "files": len(files)})
        self._commit()
        return {"ok": True, "versions_dropped": len(drop), "files_dropped": len(files),
                "note": "run gc to give the space back"}

    def dupes(self, prefix: str = "", limit: int = 50) -> dict:
        """files held at more than one path right now, biggest waste first. the copies worth deleting."""
        conn = self.db()
        norm = prefix.replace("\\", "/").rstrip("/")
        groups: dict = {}
        for r in conn.execute("SELECT l.file_sha, l.path, l.size FROM locations l WHERE l.file_sha IN "
                              "(SELECT file_sha FROM locations GROUP BY file_sha HAVING COUNT(*) > 1) "
                              "ORDER BY l.file_sha, l.path"):
            p = r["path"].replace("\\", "/")
            if norm and not (p == norm or p.startswith(norm + "/")):
                continue
            g = groups.setdefault(r["file_sha"], {"file_sha": r["file_sha"], "size": r["size"], "paths": []})
            g["paths"].append(r["path"])
        dup = [g for g in groups.values() if len(g["paths"]) > 1]
        for g in dup:
            g["copies"] = len(g["paths"])
            g["wasted_bytes"] = g["size"] * (g["copies"] - 1)
        dup.sort(key=lambda g: (-g["wasted_bytes"], g["file_sha"]))
        return {"groups": len(dup), "extra_copies": sum(g["copies"] - 1 for g in dup),
                "wasted_bytes_on_source_disks": sum(g["wasted_bytes"] for g in dup),
                "top": dup[:limit],
                "note": "these bytes are stored once here already; this is what the source disks still pay for"}

    def gc(self, dry_run: bool = False, force: bool = False, deep: bool = False,
           live_ratio: float = 0.8) -> dict:
        """drop chunks nothing points at, then repack packs that are mostly dead. crash-safe order."""
        self._commit()
        conn = self.db()
        now = time.time_ns()
        others = conn.execute("SELECT COUNT(*) FROM writers WHERE id IS NOT ? AND heartbeat_ns > ?",
                              (self._writer_id, now - WRITER_STALE_NS)).fetchone()[0]
        if others and not force:
            return {"ok": False, "error": "another writer is active; gc waits (or --force if it crashed)"}
        conn.execute("DELETE FROM writers WHERE heartbeat_ns <= ?", (now - WRITER_STALE_NS,))
        cutoff = now if force else now - GC_GRACE_NS
        dead = conn.execute(
            "SELECT sha, pack, stored_size FROM chunks c WHERE added_ns < ? AND NOT EXISTS "
            "(SELECT 1 FROM file_chunks fc WHERE fc.chunk_sha=c.sha)", (cutoff,)).fetchall()
        dead_bytes = sum(r["stored_size"] for r in dead)
        if dry_run:
            return {"ok": True, "dry_run": True, "dead_chunks": len(dead), "dead_bytes": dead_bytes}
        conn.executemany("DELETE FROM chunks WHERE sha=?", [(r["sha"],) for r in dead])
        self._commit()
        for r in dead:
            if r["pack"] is None:
                try:
                    (self.legacy_dir / r["sha"][:2] / r["sha"]).unlink()
                except OSError:
                    pass
        self._seal_pack()
        self._adopt_orphan_packs(cutoff)
        repacked, freed = self._compact(1.0 if deep else live_ratio)
        self._sweep_orphans()
        self._log("gc", {"dead_chunks": len(dead), "repacked": repacked, "freed": freed})
        self._commit()
        self._checkpoint()
        return {"ok": True, "dead_chunks": len(dead), "dead_bytes": dead_bytes, "packs_repacked": repacked,
                "disk_freed": freed}

    def _compact(self, live_ratio: float) -> tuple:
        conn = self.db()
        live_files = set(r[0] for r in conn.execute("SELECT file_sha FROM files"))
        # 2.0 kept only the L record of the current location, so after a repack a rebuild lost
        # every older version. 2.1 keeps any (path, file) pair that history still holds.
        live_locs = set()
        for r in conn.execute("SELECT praw, file_sha FROM locations UNION SELECT praw, file_sha FROM history"):
            live_locs.add((bytes(r[0]).hex(), r[1]))
        repacked = 0
        freed = 0
        legacy_rows = conn.execute("SELECT sha FROM chunks WHERE pack IS NULL").fetchall()
        if legacy_rows:
            for (sha,) in legacy_rows:
                row = self._chunk_row(sha)
                stored = self._read_stored(row)
                fh = self._open_pack()
                off = _write_record(fh, b"C", bytes.fromhex(sha), stored)
                conn.execute("UPDATE chunks SET pack=?, off=? WHERE sha=?", (self._pack_name, off, sha))
            self._commit()
            for (sha,) in legacy_rows:
                p = self.legacy_dir / sha[:2] / sha
                try:
                    freed += p.stat().st_size
                    p.unlink()
                except OSError:
                    pass
            repacked += 1
        for prow in conn.execute("SELECT name FROM packs WHERE state='sealed' ORDER BY name").fetchall():
            name = prow[0]
            path = self.packs_dir / name
            if not path.exists():
                conn.execute("DELETE FROM packs WHERE name=?", (name,))
                continue
            size = path.stat().st_size
            live = conn.execute("SELECT COALESCE(SUM(stored_size), 0) + COUNT(*) * ? FROM chunks WHERE pack=?",
                                (REC_HEAD.size, name)).fetchone()[0]
            live += conn.execute("SELECT meta_bytes FROM packs WHERE name=?", (name,)).fetchone()[0]
            dead_bytes = size - len(PACK_MAGIC) - live
            if dead_bytes <= 0 or (live_ratio < 1.0 and live / size >= live_ratio and dead_bytes < (64 << 20)):
                continue
            moved = []
            for kind, sha_raw, off, length, payload in scan_records(path):
                if kind == b"C":
                    sha = sha_raw.hex()
                    row = conn.execute("SELECT pack, off FROM chunks WHERE sha=?", (sha,)).fetchone()
                    if row is None or row["pack"] != name or row["off"] != off:
                        continue
                    fh = self._open_pack()
                    moved.append((self._pack_name, _write_record(fh, b"C", sha_raw, payload), sha))
                else:
                    keep = kind == b"D"
                    if kind == b"M":
                        keep = _parse_manifest(payload)[0].get("file_sha") in live_files
                    elif kind == b"L":
                        rec = json.loads(payload.decode())
                        keep = (rec.get("praw"), rec.get("file_sha")) in live_locs
                    if keep:
                        _write_record(self._open_pack(), kind, sha_raw, payload)
                        self._count_meta(REC_HEAD.size + len(payload))
            self._sync_pack()
            conn.executemany("UPDATE chunks SET pack=?, off=? WHERE sha=?", moved)
            conn.execute("UPDATE packs SET state='dead' WHERE name=?", (name,))
            self._commit()
            reader = self._readers.pop(name, None)
            if reader is not None:
                reader.close()
            try:
                path.unlink()
                freed += size
                conn.execute("DELETE FROM packs WHERE name=?", (name,))
            except OSError:
                pass
            repacked += 1
        self._seal_pack()
        _fsync_dir(self.packs_dir)
        return repacked, freed

    def _adopt_orphan_packs(self, cutoff_ns: int) -> None:
        conn = self.db()
        known = set(r[0] for r in conn.execute("SELECT name FROM packs"))
        for path in self.packs_dir.glob("*.pack"):
            if path.name in known:
                continue
            try:
                if path.stat().st_mtime_ns < cutoff_ns:
                    conn.execute("INSERT OR IGNORE INTO packs(name, state, created_ns) VALUES (?, 'sealed', ?)",
                                 (path.name, time.time_ns()))
            except OSError:
                pass
        # gc only gets here with no other live writer, so any 'open' pack is a crashed writer's
        conn.execute("UPDATE packs SET state='sealed' WHERE state='open' AND name IS NOT ?", (self._pack_name,))
        self._commit()

    def _sweep_orphans(self) -> None:
        conn = self.db()
        for (name,) in conn.execute("SELECT name FROM packs WHERE state='dead'").fetchall():
            try:
                (self.packs_dir / name).unlink()
            except OSError:
                pass
            conn.execute("DELETE FROM packs WHERE name=?", (name,))
        if self.legacy_dir.exists():
            for d in list(self.legacy_dir.iterdir()):
                try:
                    d.rmdir()
                except OSError:
                    pass
            try:
                self.legacy_dir.rmdir()
            except OSError:
                pass

    # ------------------------------------------------ rebuild, export, import

    def rebuild(self) -> dict:
        """rebuild the whole index from the packs alone. the packs are the truth; fold.sqlite is a cache."""
        self._commit()
        self._seal_pack()
        try:
            return self._rebuild()
        except BaseException:
            # first cut of this committed the DELETEs on close when rebuild died half way (zstd store
            # on python 3.12) and left an empty index. roll the whole thing back instead.
            self.db().rollback()
            raise

    def _rebuild(self) -> dict:
        conn = self.db()
        for t in ("chunks", "files", "file_chunks", "locations", "words", "history"):
            conn.execute("DELETE FROM %s" % t)
        conn.execute("DELETE FROM packs")
        events = []
        n_chunks = bad = 0
        now = time.time_ns()
        for path in sorted(self.packs_dir.glob("*.pack")):
            conn.execute("INSERT OR IGNORE INTO packs(name, state, created_ns) VALUES (?, 'sealed', ?)", (path.name, now))
            for kind, sha_raw, off, length, payload in scan_records(path):
                if kind == b"C":
                    try:
                        raw = unpack_chunk(payload, self.prior)
                    except CodecMissing as exc:
                        # dropping these would lose good data on the next gc. stop instead.
                        raise Refused("rebuild stopped: %s. run rebuild with a python that can read it." % exc)
                    except (ValueError, zlib.error, lzma.LZMAError):
                        bad += 1
                        continue
                    if hashlib.sha256(raw).digest() != sha_raw:
                        bad += 1
                        continue
                    conn.execute("INSERT OR IGNORE INTO chunks(sha, size, stored_size, refs, pack, off, added_ns) "
                                 "VALUES (?, ?, ?, 0, ?, ?, ?)", (sha_raw.hex(), len(raw), length, path.name, off, now))
                    n_chunks += 1
                elif hashlib.sha256(payload).digest() == sha_raw:
                    conn.execute("UPDATE packs SET meta_bytes = meta_bytes + ? WHERE name=?",
                                 (REC_HEAD.size + length, path.name))
                    if kind == b"M":
                        head, shas = _parse_manifest(payload)
                        events.append((head.get("ts", 0), "M", head, shas))
                    else:
                        rec = json.loads(payload.decode())
                        events.append((rec.get("ts", 0), kind.decode(), rec, None))
        if self.legacy_dir.exists():
            for sub in self.legacy_dir.iterdir():
                for blob in sub.iterdir():
                    stored = blob.read_bytes()
                    try:
                        raw = unpack_chunk(stored, self.prior)
                    except (ValueError, zlib.error, CodecMissing):
                        continue  # v1 blobs are only ever zlib; anything else is junk in that dir
                    if hashlib.sha256(raw).hexdigest() == blob.name:
                        conn.execute("INSERT OR IGNORE INTO chunks(sha, size, stored_size, refs, pack, off, added_ns) "
                                     "VALUES (?, ?, ?, 0, NULL, NULL, ?)", (blob.name, len(raw), len(stored), now))
        events.sort(key=lambda e: e[0])
        wmap: dict = {}
        for ts, kind, rec, shas in events:
            if kind == "M":
                fsha = rec["file_sha"]
                if isinstance(rec.get("w"), dict):
                    wmap[fsha] = rec["w"]
                conn.execute("INSERT OR REPLACE INTO files(file_sha, path, size, chunk_count, cue, ingested_at, kind, mime) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                             (fsha, rec["path"], rec["size"], len(shas), rec.get("cue", ""),
                              datetime.fromtimestamp(ts / 1e9, timezone.utc).isoformat(timespec="seconds"),
                              rec.get("kind"), rec.get("mime")))
                conn.execute("DELETE FROM file_chunks WHERE file_sha=?", (fsha,))
                conn.executemany("INSERT INTO file_chunks(file_sha, seq, chunk_sha) VALUES (?, ?, ?)",
                                 [(fsha, i, s) for i, s in enumerate(shas)])
            elif kind == "L":
                self._apply_history_event(conn, "L", rec)
                conn.execute("INSERT OR REPLACE INTO locations(praw, path, file_sha, size, mtime_ns, mode, seen_at) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?)",
                             (sqlite3.Binary(bytes.fromhex(rec["praw"])), rec["path"], rec["file_sha"], rec["size"],
                              rec.get("mtime_ns"), rec.get("mode"),
                              datetime.fromtimestamp(ts / 1e9, timezone.utc).isoformat(timespec="seconds")))
            elif kind == "D":
                if rec.get("praw"):
                    conn.execute("DELETE FROM locations WHERE praw=?", (sqlite3.Binary(bytes.fromhex(rec["praw"])),))
                if rec.get("file_sha"):
                    for t in ("files", "file_chunks", "locations"):
                        conn.execute("DELETE FROM %s WHERE file_sha=?" % t, (rec["file_sha"],))
                self._apply_history_event(conn, "D", rec)
        conn.execute("DELETE FROM locations WHERE file_sha NOT IN (SELECT file_sha FROM files)")
        conn.execute("DELETE FROM history WHERE file_sha NOT IN (SELECT file_sha FROM files)")
        conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('history', 1)")
        for r in conn.execute("SELECT file_sha, path, cue FROM files").fetchall():
            self._index_terms(r["file_sha"], r["path"], r["cue"] or "", {}, weights=wmap.get(r["file_sha"]))
        incomplete = conn.execute(
            "SELECT COUNT(DISTINCT fc.file_sha) FROM file_chunks fc LEFT JOIN chunks c ON c.sha=fc.chunk_sha "
            "WHERE c.sha IS NULL").fetchone()[0]
        self._log("rebuild", {"chunks": n_chunks, "bad": bad})
        self._commit()
        return {"ok": bad == 0 and incomplete == 0, "chunks": n_chunks, "bad_records": bad,
                "files": conn.execute("SELECT COUNT(*) FROM files").fetchone()[0],
                "locations": conn.execute("SELECT COUNT(*) FROM locations").fetchone()[0],
                "files_missing_chunks": incomplete}

    def have(self) -> list:
        return [r[0] for r in self.db().execute("SELECT sha FROM chunks ORDER BY sha")]

    def export(self, out_path, refs: list | None = None, have: set | None = None) -> dict:
        """one portable pack: manifests + locations + only the chunks the other side lacks."""
        conn = self.db()
        self._commit()
        have = have or set()
        if refs:
            shas = [self.resolve(r) for r in refs]
        else:
            shas = [r[0] for r in conn.execute("SELECT file_sha FROM files ORDER BY file_sha")]
        out_path = Path(out_path)
        tmp = out_path.with_name(out_path.name + ".part")
        sent_chunks = sent_bytes = skipped = 0
        written = set()
        with open(tmp, "wb") as fh:
            fh.write(PACK_MAGIC)
            # the chunks below are deflated against this store's prior. 2.0 did not send it, so a
            # store with a different prior (every upgraded 1.0 store) refused every text chunk.
            # older importers see an unknown record kind and skip it.
            _write_record(fh, b"P", hashlib.sha256(self.prior).digest(), self.prior)
            for fsha in shas:
                f = conn.execute("SELECT * FROM files WHERE file_sha=?", (fsha,)).fetchone()
                chunk_list = [r[0] for r in conn.execute(
                    "SELECT chunk_sha FROM file_chunks WHERE file_sha=? ORDER BY seq", (fsha,))]
                for c in chunk_list:
                    if c in have or c in written:
                        skipped += c in have
                        continue
                    row = self._chunk_row(c)
                    if row is None:
                        raise Refused("cannot export %s: chunk %s missing" % (fsha[:12], c[:12]))
                    stored = self._read_stored(row)
                    _write_record(fh, b"C", bytes.fromhex(c), stored)
                    written.add(c)
                    sent_chunks += 1
                    sent_bytes += len(stored)
                words = {r[0]: r[1] for r in conn.execute("SELECT term, w FROM words WHERE fid=?", (fid_of(fsha),))}
                head = {"t": "M", "ts": time.time_ns(), "file_sha": fsha, "size": f["size"], "path": f["path"],
                        "cue": f["cue"] or "", "kind": f["kind"], "mime": f["mime"], "w": words}
                payload = _manifest_payload(head, chunk_list)
                _write_record(fh, b"M", hashlib.sha256(payload).digest(), payload)
                for loc in conn.execute("SELECT * FROM locations WHERE file_sha=?", (fsha,)).fetchall():
                    payload = json.dumps({"t": "L", "ts": time.time_ns(), "path": loc["path"],
                                          "praw": bytes(loc["praw"]).hex(), "file_sha": fsha, "size": loc["size"],
                                          "mtime_ns": loc["mtime_ns"], "mode": loc["mode"]}, ensure_ascii=False).encode()
                    _write_record(fh, b"L", hashlib.sha256(payload).digest(), payload)
            fh.flush()
            if self.fsync:
                os.fsync(fh.fileno())
        os.replace(str(tmp), str(out_path))
        prior_note = "zdict prior sha %s" % sha256_hex(self.prior)[:16]
        return {"ok": True, "out": str(out_path), "files": len(shas), "chunks_sent": sent_chunks,
                "chunk_bytes_sent": sent_bytes, "chunks_already_there": skipped,
                "pack_bytes": out_path.stat().st_size, "note": prior_note}

    def import_pack(self, pack_path) -> dict:
        """take a pack from export. every chunk is re-verified before it is trusted."""
        conn = self.db()
        new_chunks = bad = files = locs = recoded = 0
        manifests = []
        loc_recs = []
        # dictionaries to try, in order: the sender's (from a 2.1 pack), ours, the stock seed.
        priors = [self.prior] + ([_PRIOR_SEED] if _PRIOR_SEED != self.prior else [])
        for kind, sha_raw, off, length, payload in scan_records(Path(pack_path)):
            if kind == b"P":
                if hashlib.sha256(payload).digest() == sha_raw and payload not in priors:
                    priors.insert(0, payload)
                continue
            if kind == b"C":
                sha = sha_raw.hex()
                if conn.execute("SELECT 1 FROM chunks WHERE sha=?", (sha,)).fetchone():
                    continue
                raw = None
                for pr in priors:
                    try:
                        cand = unpack_chunk(payload, pr)
                    except CodecMissing as exc:
                        raise Refused("import stopped: %s" % exc)
                    except (ValueError, zlib.error, lzma.LZMAError):
                        continue
                    if hashlib.sha256(cand).digest() == sha_raw:
                        raw = cand
                        break
                if raw is None:
                    bad += 1
                    continue
                stored = payload
                if payload[:1] == b"Z" and pr != self.prior:
                    # deflated against the sender's dictionary: re-squeeze against ours so this
                    # store can read it with only its own prior.
                    stored = pack_chunk(raw, self.prior, self.level, "zlib")
                    recoded += 1
                fh = self._open_pack()
                noff = _write_record(fh, b"C", sha_raw, stored)
                conn.execute("INSERT OR IGNORE INTO chunks(sha, size, stored_size, refs, pack, off, added_ns) "
                             "VALUES (?, ?, ?, 0, ?, ?, ?)",
                             (sha, len(raw), len(stored), self._pack_name, noff, time.time_ns()))
                new_chunks += 1
                self._pending_bytes += len(stored)
                self._maybe_commit()
            elif hashlib.sha256(payload).digest() != sha_raw:
                bad += 1
            elif kind == b"M":
                manifests.append(payload)
            elif kind == b"L":
                loc_recs.append(payload)
        for payload in manifests:
            head, shas = _parse_manifest(payload)
            missing = [s for s in set(shas) if not conn.execute("SELECT 1 FROM chunks WHERE sha=?", (s,)).fetchone()]
            if missing:
                bad += 1
                continue
            fsha = head["file_sha"]
            if not conn.execute("SELECT 1 FROM files WHERE file_sha=?", (fsha,)).fetchone():
                conn.execute("INSERT INTO files(file_sha, path, size, chunk_count, cue, ingested_at, kind, mime) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                             (fsha, head["path"], head["size"], len(shas), head.get("cue", ""), _now(),
                              head.get("kind"), head.get("mime")))
                conn.executemany("INSERT OR IGNORE INTO file_chunks(file_sha, seq, chunk_sha) VALUES (?, ?, ?)",
                                 [(fsha, i, s) for i, s in enumerate(shas)])
                w = head.get("w") if isinstance(head.get("w"), dict) else None
                self._index_terms(fsha, head["path"], head.get("cue", ""), {}, weights=w)
                self._write_meta_record(b"M", payload)
                files += 1
        # locations last, and only for files that are really here now. 2.0 counted locations
        # whose file was then refused, so "locations: 1" could mean nothing was imported.
        for payload in loc_recs:
            rec = json.loads(payload.decode())
            if not conn.execute("SELECT 1 FROM files WHERE file_sha=?", (rec["file_sha"],)).fetchone():
                continue
            praw = bytes.fromhex(rec["praw"])
            _retire_location(conn, praw, rec["file_sha"], _now())
            conn.execute("INSERT OR REPLACE INTO locations(praw, path, file_sha, size, mtime_ns, mode, seen_at) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (sqlite3.Binary(praw), rec["path"], rec["file_sha"], rec["size"],
                          rec.get("mtime_ns"), rec.get("mode"), _now()))
            self._write_meta_record(b"L", payload)
            locs += 1
        self._log("import", {"pack": str(pack_path), "chunks": new_chunks, "files": files, "bad": bad})
        self._commit()
        return {"ok": bad == 0, "new_chunks": new_chunks, "chunks_recoded": recoded, "new_files": files,
                "locations": locs, "bad_records": bad}

    def _log(self, verb: str, note: dict) -> None:
        self.db().execute("INSERT INTO log(at, verb, note) VALUES (?, ?, ?)", (_now(), verb, json.dumps(note)))


def _safe_name(path: str) -> str:
    name = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return "" if name in ("", ".", "..") else name


# ---------------------------------------------------------------- selftest

def _words(rng, n: int) -> bytes:
    vocab = [bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(2, 9))) for _ in range(3000)]
    out = []
    for i in range(n):
        out.append(rng.choice(vocab))
        if i % 13 == 12:
            out.append(b".\n")
    return b" ".join(out)


def cmd_selftest(args=None) -> int:
    import random
    rng = random.Random(7)
    tmp = Path(tempfile.mkdtemp(prefix="fold-mem-"))
    store = tmp / "store"
    src = tmp / "src"
    src.mkdir()
    checks = {}
    measures = {}

    shared = _words(rng, 40000)  # ~250 kb of non-repeating prose: zlib cannot fake the dedupe
    a = b"alpha head\n" + shared + b"\nalpha tail 111\n"
    b = b"beta head, a different first line\n" + shared + b"\nbeta tail 222\n"
    (src / "mem-a.txt").write_bytes(a)
    (src / "mem-b.txt").write_bytes(b)
    unique = os.urandom(3 << 20)
    (src / "unique.bin").write_bytes(unique)
    big = os.urandom(9 << 20)
    (src / "big.bin").write_bytes(big)
    edited = big[:4 << 20] + b"INSERTED-BYTES" * 7 + big[4 << 20:]
    (src / "big-edited.bin").write_bytes(edited)
    (src / "sub").mkdir()
    (src / "sub" / "mem-a-copy.txt").write_bytes(a)
    (src / "empty.txt").write_bytes(b"")
    (src / "notes-cjk.txt").write_bytes("会议记录：预算报告 第三季度\n".encode())
    docx = io.BytesIO()
    with zipfile.ZipFile(docx, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:t>quarterly zeppelin budget</w:t></w:p></w:body></w:document>")
        zf.writestr("docProps/core.xml", "<cp:coreProperties><dc:title>Airship plan</dc:title></cp:coreProperties>")
    (src / "plan.docx").write_bytes(docx.getvalue())
    png = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(">IIBBBBB", 640, 480, 8, 2, 0, 0, 0) + b"\x00" * 4
    (src / "photo.png").write_bytes(png + os.urandom(2048))
    (src / ".env").write_bytes(b"API_KEY=sk_live_abcdefghijklmnop1234\n")
    if hasattr(os, "mkfifo"):
        os.mkfifo(str(src / "a-pipe"))

    t0 = time.monotonic()
    with FoldMemory(store) as fm:
        rows = {Path(r["path"]).name: r for r in fm.ingest_tree(src)}
        measures["ingest_seconds"] = round(time.monotonic() - t0, 2)
        checks["secret name skipped"] = rows[".env"]["status"] == "skip"
        if hasattr(os, "mkfifo"):
            checks["pipe skipped, no hang"] = rows["a-pipe"]["status"] == "skip"
        checks["copy at a new path is an alias"] = rows["mem-a-copy.txt"]["status"] == "alias"
        shared_saved = len(a) + len(b) - (rows["mem-a.txt"]["new_unique_raw"] + rows["mem-b.txt"]["new_unique_raw"])
        measures["near_duplicate_text_dedupe"] = round(shared_saved / (len(a) + len(b)), 3)
        checks["shared middle stored once"] = rows["mem-b.txt"]["new_unique_raw"] < len(b) * 0.1
        edit_new = min(rows["big-edited.bin"]["new_unique_raw"], rows["big.bin"]["new_unique_raw"])
        measures["9mb_file_with_insert_new_bytes"] = edit_new
        checks["insert in big file costs < 1% new bytes"] = edit_new < len(edited) * 0.01
        measures["random_bytes_stored_ratio"] = round(rows["unique.bin"]["new_unique_stored"] / len(unique), 4)
        checks["random bytes stay the floor"] = rows["unique.bin"]["new_unique_stored"] >= len(unique) * 0.99
        again = {Path(r["path"]).name: r for r in fm.ingest_tree(src)}
        checks["re-ingest is a no-op"] = again["mem-a.txt"]["status"] == "unchanged"

        for name, data in (("mem-a.txt", a), ("big-edited.bin", edited), ("empty.txt", b""), ("plan.docx", docx.getvalue())):
            checks["unfold exact: " + name] = fm.read(rows[name]["file_sha"]) == data
        out = fm.unfold(rows["mem-b.txt"]["file_sha"][:10], tmp / "restored" / "")
        checks["unfold by prefix to a folder"] = out["ok"] and Path(out["written"]).read_bytes() == b

        hits = fm.cue("zeppelin budget")
        checks["cue finds words inside a docx"] = bool(hits) and hits[0]["path"].endswith("plan.docx")
        checks["cue reads cjk text"] = any(h["path"].endswith("notes-cjk.txt") for h in fm.cue("预算"))
        checks["cue remembers every copy"] = any(h["copies"] == 2 for h in fm.cue("mem"))
        checks["trance widens by prefix"] = any(h["path"].endswith("plan.docx") for h in fm.cue("zepp", trance=True))
        checks["png size read"] = "640" in (fm.db().execute("SELECT cue FROM files WHERE file_sha=?",
                                                              (rows["photo.png"]["file_sha"],)).fetchone()[0])
        st = fm.stats()
        measures["logical_bytes"] = st["logical_bytes"]
        measures["disk_bytes"] = st["disk_bytes"]
        measures["disk_vs_logical"] = round(st["disk_bytes"] / st["logical_bytes"], 3)

        restored = fm.restore(str(src), tmp / "tree")
        checks["restore whole tree"] = restored["ok"] and (tmp / "tree" / "sub" / "mem-a-copy.txt").read_bytes() == a

        fm.export(tmp / "all.fmpack")
        have = set(fm.have())

    with FoldMemory(tmp / "store2") as other:
        imp = other.import_pack(tmp / "all.fmpack")
        checks["import to a second store"] = imp["ok"] and other.read(rows["big.bin"]["file_sha"]) == big
    with FoldMemory(store) as fm:
        delta = fm.export(tmp / "delta.fmpack", have=have)
        checks["delta export sends no held chunks"] = delta["chunks_sent"] == 0
        measures["delta_pack_bytes"] = delta["pack_bytes"]

        before = fm.stats()["disk_bytes"]
        fm.forget(rows["big.bin"]["file_sha"])
        fm.forget(rows["unique.bin"]["file_sha"])
        fm.gc(force=True, deep=True)
        after = fm.stats()["disk_bytes"]
        measures["gc_freed_bytes"] = before - after
        checks["gc gives space back"] = after < before - (3 << 20)
        checks["others survive gc"] = fm.read(rows["big-edited.bin"]["file_sha"]) == edited

        rb = fm.rebuild()
        checks["rebuild index from packs"] = rb["ok"] and fm.read(rows["mem-b.txt"]["file_sha"]) == b \
            and fm.stats()["locations"] >= 8

        victim = fm.db().execute("SELECT c.pack, c.off, c.stored_size FROM file_chunks fc JOIN chunks c "
                                 "ON c.sha=fc.chunk_sha WHERE fc.file_sha=? LIMIT 1",
                                 (rows["mem-a.txt"]["file_sha"],)).fetchone()
        fm.close()
    with open(store / "packs" / victim["pack"], "r+b") as fh:
        fh.seek(victim["off"] + victim["stored_size"] // 2)
        byte = fh.read(1)
        fh.seek(-1, 1)
        fh.write(bytes([byte[0] ^ 0xFF]))
    with FoldMemory(store) as fm:
        bad = fm.unfold(rows["mem-a.txt"]["file_sha"], tmp / "corrupt-out.txt")
        checks["corrupt bits refused"] = not bad["ok"] and not (tmp / "corrupt-out.txt").exists()
        v = fm.verify()
        checks["verify names the damaged file"] = not v["ok"] and rows["mem-a.txt"]["file_sha"] in v["files_affected"]

    fails = [k for k, ok in checks.items() if not ok]
    report = {"ok": not fails, "fails": fails, "checks": len(checks), "measured": measures,
              "note": "near-duplicate text is non-repeating prose, so the dedupe number is not zlib"}
    _print(report)
    if args is None or not getattr(args, "keep", False):
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    return 0 if not fails else 1


def cmd_sample(args) -> int:
    """estimate savings on a real folder without keeping anything."""
    import shutil
    tmp = Path(tempfile.mkdtemp(prefix="fold-sample-"))
    try:
        with FoldMemory(tmp / "store", level=args.level, fsync=False) as fm:
            n = 0
            t0 = time.monotonic()
            for root in args.paths:
                for r in fm.iter_ingest(root, excludes=args.exclude):
                    n += 1
                    _progress_line(n, t0, r)
            st = fm.stats()
        _clear_progress()
        st["store"] = "(temporary, deleted)"
        st["seconds"] = round(time.monotonic() - t0, 1)
        _print(st)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


# ---------------------------------------------------------------- cli

def _print(obj) -> None:
    try:
        print(json.dumps(obj, indent=2, ensure_ascii=False))
        sys.stdout.flush()
    except BrokenPipeError:
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass


_last_progress = [0.0]


def _progress_line(n: int, t0: float, res: dict) -> None:
    if not sys.stderr.isatty():
        return
    now = time.monotonic()
    if now - _last_progress[0] < 0.5:
        return
    _last_progress[0] = now
    name = str(res.get("path", ""))[-60:]
    sys.stderr.write("\r  %d files  %.0fs  %s\033[K" % (n, now - t0, name))
    sys.stderr.flush()


def _clear_progress() -> None:
    if sys.stderr.isatty():
        sys.stderr.write("\r\033[K")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fold_memory",
        description="leftover-memory: identical copies share one box, unique bits stay the floor, "
                    "unfold only if the fingerprint matches.")
    p.add_argument("--store", help="store folder (default: $FOLD_MEMORY_STORE, ./fold-memory-store, or your data dir)")
    p.add_argument("--version", action="version", version="fold-memory " + __version__)
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("ingest", help="fold files, folders, or '-' for stdin")
    s.add_argument("paths", nargs="+")
    s.add_argument("--name", help="name for stdin input (e.g. nightly.sql)")
    s.add_argument("--exclude", action="append", default=[], help="glob to skip (repeatable)")
    s.add_argument("--follow-links", action="store_true")
    s.add_argument("--rehash", action="store_true", help="re-read files even if size+mtime are unchanged")
    s.add_argument("--include-secret-names", action="store_true")
    s.add_argument("--hydrate-cloud", action="store_true", help="read cloud placeholders (downloads them)")
    s.add_argument("--level", choices=["fast", "default", "max"], default="default")
    s.add_argument("--codec", choices=["zlib", "zstd"], default="zlib",
                   help="zstd needs python 3.14+ on every machine that reads this store")
    s.add_argument("--jobs", type=int, default=0)
    s.add_argument("--verbose", "-v", action="store_true", help="print every file")
    s.add_argument("--no-fsync", action="store_true")

    s = sub.add_parser("cue", help="recall by words")
    s.add_argument("words", nargs="+")
    s.add_argument("--trance", action="store_true", help="wider recall: prefixes, any word, pair bonus")
    s.add_argument("--limit", type=int, default=12)

    s = sub.add_parser("unfold", help="exact file back by fingerprint, prefix, or path — or refuse")
    s.add_argument("ref")
    s.add_argument("--out", help="file, folder/, or - for stdout. omit to only verify")
    s.add_argument("--version", type=int, dest="nth", help="Nth newest version held at that path (1 = newest)")

    s = sub.add_parser("versions", help="every version held at a path, newest first")
    s.add_argument("path")

    s = sub.add_parser("prune", help="keep the newest N versions per path; drop older ones")
    s.add_argument("--keep", type=int, required=True)
    s.add_argument("prefix", nargs="?", default="")
    s.add_argument("--dry-run", action="store_true")

    s = sub.add_parser("dupes", help="files held at more than one path: the copies worth deleting")
    s.add_argument("prefix", nargs="?", default="")
    s.add_argument("--limit", type=int, default=50)

    sub.add_parser("reindex", help="rebuild words and cues from the held bytes (scrubs a 2.0 index)")

    s = sub.add_parser("restore", help="rebuild everything held under a path prefix")
    s.add_argument("prefix")
    s.add_argument("--out", required=True)
    s.add_argument("--dry-run", action="store_true")

    s = sub.add_parser("ls", help="list remembered locations")
    s.add_argument("prefix", nargs="?", default="")
    s.add_argument("--limit", type=int, default=200)

    sub.add_parser("stats", help="sizes, honest: disk_bytes is real disk")
    s = sub.add_parser("verify", help="check every chunk fingerprint")
    s.add_argument("--full", action="store_true", help="also re-check every whole file")

    s = sub.add_parser("forget", help="drop a path, or a whole file by fingerprint")
    s.add_argument("refs", nargs="+")
    s.add_argument("--everywhere", action="store_true", help="with a path: drop the file at all its locations")

    s = sub.add_parser("gc", help="give back space from forgotten files")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--force", action="store_true", help="ignore other writers and the 1h grace window")
    s.add_argument("--deep", action="store_true", help="repack every pack with any dead bytes")

    sub.add_parser("rebuild", help="rebuild the index from packs (if fold.sqlite is lost or damaged)")

    s = sub.add_parser("export", help="write a portable pack (for another device, disk, or a thin link)")
    s.add_argument("out")
    s.add_argument("refs", nargs="*")
    s.add_argument("--have", help="file from 'have' on the receiving side: skip chunks it already holds")

    s = sub.add_parser("import", help="take a pack from export")
    s.add_argument("pack")

    s = sub.add_parser("have", help="list held chunk fingerprints (send this to the exporting side)")
    s.add_argument("out", nargs="?", default="-")

    s = sub.add_parser("sample", help="estimate savings on a folder; keeps nothing")
    s.add_argument("paths", nargs="+")
    s.add_argument("--exclude", action="append", default=[])
    s.add_argument("--level", choices=["fast", "default", "max"], default="default")

    s = sub.add_parser("selftest", help="prove it on this machine")
    s.add_argument("--keep", action="store_true")
    sub.add_parser("smoke", help="open the store and exit")
    return p


def main(argv: list | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "fold_memory.py":
        argv = argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help()
        return 0
    if args.cmd == "selftest":
        return cmd_selftest(args)
    if args.cmd == "sample":
        return cmd_sample(args)

    kw = {}
    if args.cmd == "ingest":
        kw = dict(level=args.level, codec=args.codec, jobs=args.jobs or None, fsync=not args.no_fsync)
        if args.codec == "zstd" and _zstd is None:
            print("zstd needs python 3.14+; use --codec zlib", file=sys.stderr)
            return 2
    fm = FoldMemory(args.store, **kw)
    try:
        fm.open()
    except sqlite3.DatabaseError as exc:
        print("store unreadable: %s — try: fold_memory rebuild" % exc, file=sys.stderr)
        return 1
    try:
        if args.cmd == "smoke":
            print("fold-memory smoke pass  store=%s" % fm.store)
            return 0
        if args.cmd == "ingest":
            counts: dict = {}
            shown = []
            t0 = time.monotonic()
            n = 0
            for path in args.paths:
                if path == "-":
                    name = "stdin/" + (args.name or datetime.now().strftime("stdin-%Y%m%d-%H%M%S"))
                    results = [fm.ingest_stream(sys.stdin.buffer.read, name)]
                    fm.flush()
                else:
                    results = fm.iter_ingest(path, excludes=args.exclude, follow_links=args.follow_links,
                                             rehash=args.rehash, allow_secret_names=args.include_secret_names,
                                             hydrate_cloud=args.hydrate_cloud)
                for r in results:
                    n += 1
                    key = r["status"] if r["status"] != "skip" else "skip: " + r.get("reason", "")
                    counts[key] = counts.get(key, 0) + 1
                    if args.verbose:
                        _clear_progress()
                        _print(r)
                    elif len(shown) < 50 and r["status"] != "unchanged":
                        shown.append(r)
                    _progress_line(n, t0, r)
            _clear_progress()
            out = {"seen": n, "counts": counts, "seconds": round(time.monotonic() - t0, 2),
                   "stats": fm.stats()}
            if not args.verbose:
                out["results"] = shown
            _print(out)
            return 0
        if args.cmd == "cue":
            q = " ".join(args.words)
            _print({"query": q, "trance": args.trance, "hits": fm.cue(q, trance=args.trance, limit=args.limit)})
            return 0
        if args.cmd == "unfold":
            res = fm.unfold(args.ref, args.out, version=args.nth)
            if args.out != "-":
                _print(res)
            elif not res["ok"]:
                print(json.dumps(res), file=sys.stderr)
            return 0 if res["ok"] else 1
        if args.cmd == "versions":
            _print(fm.versions(args.path))
            return 0
        if args.cmd == "prune":
            try:
                res = fm.prune(args.keep, args.prefix, dry_run=args.dry_run)
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            _print(res)
            return 0
        if args.cmd == "dupes":
            _print(fm.dupes(args.prefix, args.limit))
            return 0
        if args.cmd == "reindex":
            t0 = time.monotonic()
            res = fm.reindex(progress=lambda n: _progress_line(n, t0, {"path": "%d files" % n}))
            _clear_progress()
            _print(res)
            return 0 if res["ok"] else 1
        if args.cmd == "restore":
            res = fm.restore(args.prefix, args.out, dry_run=args.dry_run)
            _print(res)
            return 0 if res["ok"] else 1
        if args.cmd == "ls":
            _print(fm.ls(args.prefix, args.limit))
            return 0
        if args.cmd == "stats":
            _print(fm.stats())
            return 0
        if args.cmd == "verify":
            res = fm.verify(full=args.full)
            _print(res)
            return 0 if res["ok"] else 1
        if args.cmd == "forget":
            out = []
            for ref in args.refs:
                try:
                    out.append(fm.forget(ref, everywhere=args.everywhere))
                except LookupError as exc:
                    out.append({"ok": False, "ref": ref, "error": str(exc)})
            _print(out)
            return 0 if all(o["ok"] for o in out) else 1
        if args.cmd == "gc":
            res = fm.gc(dry_run=args.dry_run, force=args.force, deep=args.deep)
            _print(res)
            return 0 if res["ok"] else 1
        if args.cmd == "rebuild":
            try:
                res = fm.rebuild()
            except Refused as exc:
                _print({"ok": False, "error": str(exc), "index": "untouched"})
                return 1
            _print(res)
            return 0 if res["ok"] else 1
        if args.cmd == "export":
            have = set()
            if args.have:
                with open(args.have, "r", encoding="ascii") as fh:
                    have = set(line.strip() for line in fh if line.strip())
            try:
                _print(fm.export(args.out, args.refs or None, have))
            except Refused as exc:
                _print({"ok": False, "error": str(exc)})
                return 1
            return 0
        if args.cmd == "import":
            res = fm.import_pack(args.pack)
            _print(res)
            return 0 if res["ok"] else 1
        if args.cmd == "have":
            shas = fm.have()
            if args.out == "-":
                sys.stdout.write("\n".join(shas) + ("\n" if shas else ""))
            else:
                Path(args.out).write_text("\n".join(shas) + "\n", encoding="ascii")
                _print({"ok": True, "chunks": len(shas), "out": args.out})
            return 0
    except LookupError as exc:
        print(str(exc).strip("'\""), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted — everything up to the last commit is held", file=sys.stderr)
        return 130
    finally:
        fm.close()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
