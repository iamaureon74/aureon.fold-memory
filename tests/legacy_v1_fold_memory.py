#!/usr/bin/env python3
"""
asher.fold-memory — leftover-memory.

identical leftover copies share one box. unique bits stay the floor.
unfold only if the file fingerprint matches, else refuse.
local disk + python stdlib (hashlib, zlib, sqlite3). no extra packages. no wifi
for what is already held.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import zlib
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
DEFAULT_STORE = HERE / "fold-memory-store"
STORE = Path(os.environ.get("FOLD_MEMORY_STORE", str(DEFAULT_STORE)))

TEXT_MIN, TEXT_AVG, TEXT_MAX = 256, 1024, 8192
BIN_MIN, BIN_AVG, BIN_MAX = 2048, 8192, 65536
SDM_ADDRS = 4096
SDM_K = 8
SDM_TRANCE_K = 16
PRIOR_MAX = 32768

SECRET_RX = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]
WORD_RX = re.compile(r"[a-z0-9]{3,}", re.I)
STOP = {
    "the", "and", "for", "with", "from", "this", "that", "are", "was", "not",
    "file", "files", "into", "when", "then", "than",
}
SKIP_DIR = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "fold-memory-store",
    "AppData", "Application Data", "$Recycle.Bin", "System Volume Information",
    ".ssh", ".gnupg", "Cookies",
}
_SKIP_INGEST_NAME = re.compile(
    r"(?i)(?:\.env(?:$|\.)|id_rsa|id_ed25519|cookies|login data|web data|"
    r"wallet\.dat|keystore|\.pem$|\.p12$|2fa|bank.?statement|secret)"
)

_PRIOR_SEED = (
    b"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><script>function"
    b"</script></head><body>{\"id\":null,\"type\":\"\",\"status\":true,"
    b"false}function(){return};const let var import from def class self"
    b"None True False http https www.com.json.xml.csv.txt.log.error.warn"
    b"abcdefghijklmnopqrstuvwxyz0123456789 \t\r\n"
)[:PRIOR_MAX]

def _gear() -> list[int]:
    out: list[int] = []
    for i in range(256):
        h = hashlib.sha256(bytes([i, 0xA5, 0x5A])).digest()
        out.append(int.from_bytes(h[:8], "little"))
    return out


GEAR = _gear()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mask_cue(text: str) -> str:
    s = text
    for rx in SECRET_RX:
        s = rx.sub("[masked]", s)
    return s


def tokenize(text: str) -> list[str]:
    return [w.lower() for w in WORD_RX.findall(text or "") if len(w) >= 3]


def query_core(tokens: list[str]) -> list[str]:
    core = [t for t in tokens if t not in STOP]
    return core or tokens


def sdm_addrs(token: str, k: int) -> list[int]:
    addrs: list[int] = []
    raw = token.encode("utf-8", errors="replace")
    for i in range(k):
        h = hashlib.blake2s(raw + bytes([i]), digest_size=8).digest()
        addrs.append(int.from_bytes(h, "little") % SDM_ADDRS)
    return addrs


def is_texty(data: bytes) -> bool:
    sample = data[:1024] or data
    if not sample:
        return True
    good = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return (good / len(sample)) >= 0.85


def _is_cloud_placeholder(path: Path) -> bool:
    try:
        import ctypes

        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        if attrs == -1:
            return False
        return bool(attrs & (0x00400000 | 0x00040000))
    except Exception:
        return False


def classify_holder(path: Path, data: bytes) -> dict:
    """Map a blob to a data-holder class used by humans, corporations, governments."""
    suf = path.suffix.lower()
    head = (data or b"")[:32]
    name = path.name.lower()
    by_suf = {
        ".jpg": ("media_jpeg", "human", "jpeg"),
        ".jpeg": ("media_jpeg", "human", "jpeg"),
        ".png": ("media_png", "human", "png"),
        ".gif": ("media_gif", "human", "gif"),
        ".webp": ("media_webp", "human", "webp"),
        ".heic": ("media_heic", "human", "heic"),
        ".mp4": ("media_video", "human", "mp4"),
        ".mov": ("media_video", "human", "mp4"),
        ".docx": ("office_ooxml", "corp", "docx"),
        ".xlsx": ("office_ooxml", "corp", "xlsx"),
        ".pptx": ("office_ooxml", "corp", "pptx"),
        ".pdf": ("doc_pdf", "gov", "pdf"),
        ".csv": ("table_csv", "corp", "csv"),
        ".tsv": ("table_csv", "corp", "tsv"),
        ".xml": ("markup_xml", "gov", "xml"),
        ".kml": ("geo_xml", "gov", "kml"),
        ".gpx": ("geo_xml", "gov", "gpx"),
        ".gml": ("geo_xml", "gov", "gml"),
        ".geojson": ("geo_json", "gov", "geojson"),
        ".json": ("struct_json", "corp", "json"),
        ".eml": ("mail_rfc822", "human", "eml"),
        ".mbox": ("mail_rfc822", "human", "mbox"),
        ".sql": ("db_sql", "corp", "sql"),
        ".sqlite": ("db_sqlite", "corp", "sqlite"),
        ".db": ("db_sqlite", "corp", "sqlite"),
        ".log": ("ops_log", "corp", "log"),
        ".vcf": ("human_card", "human", "vcf"),
        ".ics": ("human_card", "human", "ics"),
        ".md": ("human_text", "human", "md"),
        ".txt": ("human_text", "human", "txt"),
        ".zip": ("archive_zip", "corp", "zip"),
    }
    if suf in by_suf:
        c, a, t = by_suf[suf]
        return {"class": c, "audience": a, "tech": t}
    if head.startswith(b"SQLite format 3"):
        return {"class": "db_sqlite", "audience": "corp", "tech": "sqlite"}
    if head.startswith(b"%PDF"):
        return {"class": "doc_pdf", "audience": "gov", "tech": "pdf"}
    if head.startswith(b"\xff\xd8\xff"):
        return {"class": "media_jpeg", "audience": "human", "tech": "jpeg"}
    if head.startswith(b"\x89PNG"):
        return {"class": "media_png", "audience": "human", "tech": "png"}
    if head.startswith(b"PK"):
        return {"class": "archive_zip", "audience": "corp", "tech": "zip"}
    if suf in {".exe", ".dll", ".sys", ".iso", ".msi"}:
        return {"class": "blob_unique", "audience": "corp", "tech": suf[1:]}
    if data and is_texty(data):
        return {"class": "human_text", "audience": "human", "tech": suf[1:] or "text"}
    return {"class": "blob_unique", "audience": "corp", "tech": suf[1:] or "bin"}


def cdc_chunks(data: bytes) -> list[bytes]:
    n = len(data)
    if n == 0:
        return []
    if is_texty(data):
        min_c, avg_c, max_c = TEXT_MIN, TEXT_AVG, TEXT_MAX
    else:
        min_c, avg_c, max_c = BIN_MIN, BIN_AVG, BIN_MAX
    mask = avg_c - 1
    if n <= min_c:
        return [data]
    chunks: list[bytes] = []
    offset = 0
    while offset < n:
        remain = n - offset
        if remain <= min_c:
            chunks.append(data[offset:])
            break
        end = min(offset + max_c, n)
        i = offset + min_c
        h = 0
        cut = end
        while i < end:
            h = ((h << 1) + GEAR[data[i]]) & 0xFFFFFFFFFFFFFFFF
            if (h & mask) == 0:
                cut = i + 1
                break
            i += 1
        chunks.append(data[offset:cut])
        offset = cut
    return chunks


def build_prior_from_paths(paths: list[Path]) -> bytes:
    grams: Counter[bytes] = Counter()
    seen = 0
    for p in paths:
        if p.suffix.lower() not in {".md", ".mdc", ".py", ".json"}:
            continue
        try:
            data = p.read_bytes()[:8192]
        except OSError:
            continue
        if not is_texty(data):
            continue
        seen += 1
        if seen > 120:
            break
        lim = max(0, len(data) - 24)
        for i in range(0, lim, 4):
            grams[data[i : i + 24]] += 1
    parts = [g for g, k in grams.most_common(2400) if k >= 2]
    blob = _PRIOR_SEED + b"".join(parts)
    return blob[:PRIOR_MAX]


def blob_path(store: Path, sha: str) -> Path:
    return store / "blobs" / sha[:2] / sha


class FoldMemory:
    def __init__(self, store: Path | None = None) -> None:
        self.store = Path(store or STORE)
        self.blobs = self.store / "blobs"
        self.db_path = self.store / "fold.sqlite"
        self.prior_path = self.store / "prior.bin"
        self._conn: sqlite3.Connection | None = None
        self.prior = b""
        self._chunk_sz: dict[str, int] = {}
        self._raw_cache: dict[str, bytes] = {}
        self._dirty = 0

    def init(self) -> None:
        self.store.mkdir(parents=True, exist_ok=True)
        self.blobs.mkdir(parents=True, exist_ok=True)
        if not self.prior_path.exists():
            self.prior_path.write_bytes(_PRIOR_SEED)
        self.prior = self.prior_path.read_bytes()[:PRIOR_MAX]
        conn = self.db()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS files (
                file_sha TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                size INTEGER NOT NULL,
                chunk_count INTEGER NOT NULL,
                cue TEXT,
                ingested_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chunks (
                sha TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                stored_size INTEGER NOT NULL,
                refs INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS file_chunks (
                file_sha TEXT NOT NULL,
                seq INTEGER NOT NULL,
                chunk_sha TEXT NOT NULL,
                PRIMARY KEY (file_sha, seq)
            );
            CREATE TABLE IF NOT EXISTS sdm (
                addr INTEGER NOT NULL,
                file_sha TEXT NOT NULL,
                weight REAL NOT NULL,
                PRIMARY KEY (addr, file_sha)
            );
            CREATE TABLE IF NOT EXISTS stats (
                k TEXT PRIMARY KEY,
                v INTEGER NOT NULL
            );
            """
        )
        try:
            conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(file_sha, cue)"
            )
        except sqlite3.OperationalError:
            pass
        for k in ("bytes_in", "unique_raw", "unique_stored", "files", "copies_folded"):
            conn.execute("INSERT OR IGNORE INTO stats(k, v) VALUES (?, 0)", (k,))
        conn.commit()
        for r in conn.execute("SELECT sha, stored_size FROM chunks"):
            self._chunk_sz[r["sha"]] = int(r["stored_size"])

    def install_prior(self, blob: bytes) -> None:
        conn = self.db()
        n = conn.execute("SELECT COUNT(*) c FROM chunks").fetchone()["c"]
        if n:
            return
        blob = (blob or _PRIOR_SEED)[:PRIOR_MAX]
        self.prior_path.write_bytes(blob)
        self.prior = blob

    def db(self) -> sqlite3.Connection:
        if self._conn is None:
            self.store.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path), timeout=30)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA temp_store=MEMORY")
            self._conn.execute("PRAGMA cache_size=-8000")
        return self._conn

    def flush(self) -> None:
        if self._conn is not None:
            self._conn.commit()
            self._dirty = 0

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.commit()
            except sqlite3.Error:
                pass
            self._conn.close()
            self._conn = None

    def _pack_chunk(self, raw: bytes) -> bytes:
        try:
            c = zlib.compressobj(
                6, zlib.DEFLATED, 15, 8, zlib.Z_DEFAULT_STRATEGY, zdict=self.prior
            )
            packed = c.compress(raw) + c.flush()
        except zlib.error:
            packed = zlib.compress(raw, 6)
        if len(packed) + 1 < len(raw):
            return b"Z" + packed
        return b"R" + raw

    def _unpack_chunk(self, stored: bytes) -> bytes:
        if not stored:
            return b""
        kind, payload = stored[:1], stored[1:]
        if kind == b"R":
            return payload
        if kind == b"Z":
            try:
                d = zlib.decompressobj(15, zdict=self.prior)
                return d.decompress(payload) + d.flush()
            except zlib.error:
                return zlib.decompress(payload)
        raise ValueError("unknown blob header")

    def put_chunk(self, raw: bytes) -> tuple[str, int, bool]:
        sha = sha256_bytes(raw)
        conn = self.db()
        if sha in self._chunk_sz:
            return sha, self._chunk_sz[sha], True
        path = blob_path(self.store, sha)
        path.parent.mkdir(parents=True, exist_ok=True)
        packed = self._pack_chunk(raw)
        path.write_bytes(packed)
        stored = len(packed)
        conn.execute(
            "INSERT INTO chunks(sha, size, stored_size, refs) VALUES (?, ?, ?, 1)",
            (sha, len(raw), stored),
        )
        self._chunk_sz[sha] = stored
        if len(self._raw_cache) < 8000:
            self._raw_cache[sha] = raw
        return sha, stored, False

    def get_chunk(self, sha: str) -> bytes:
        hit = self._raw_cache.get(sha)
        if hit is not None:
            return hit
        path = blob_path(self.store, sha)
        if not path.is_file():
            raise FileNotFoundError(sha)
        raw = self._unpack_chunk(path.read_bytes())
        if sha256_bytes(raw) != sha:
            raise ValueError("chunk hash mismatch")
        if len(self._raw_cache) < 8000:
            self._raw_cache[sha] = raw
        return raw

    def _cue_text(self, path: Path, data: bytes) -> str:
        holder = classify_holder(path, data)
        name = (
            path.name
            + " "
            + path.stem.replace("_", " ").replace("-", " ")
            + " "
            + holder["class"]
            + " "
            + holder["audience"]
            + " holder"
        )
        if is_texty(data) and len(data) > 8192:
            mid = len(data) // 2
            sample = data[:4096] + b"\n" + data[mid : mid + 2048] + b"\n" + data[-2048:]
        else:
            sample = data[:8192]
        text = sample.decode("utf-8", errors="ignore")
        printable = "".join(ch if ch.isprintable() or ch in "\n\t" else " " for ch in text)
        if len(printable) > 2800:
            printable = (
                printable[:1600] + "\n" + printable[len(printable) // 2 : len(printable) // 2 + 700] + "\n" + printable[-700:]
            )
        return mask_cue((name + "\n" + printable)[:4000])

    def _index_cue(self, file_sha: str, cue: str, name: str) -> None:
        conn = self.db()
        name_toks = tokenize(name)[:24]
        body = [t for t in tokenize(cue)[:80] if t not in STOP][:24]
        weights: dict[int, float] = {}
        for tok in name_toks:
            w0 = 8.0 if tok not in STOP else 0.4
            for addr in sdm_addrs(tok, SDM_K):
                weights[addr] = weights.get(addr, 0.0) + w0
        for tok in body:
            for addr in sdm_addrs(tok, SDM_K):
                weights[addr] = weights.get(addr, 0.0) + 1.0
        if weights:
            conn.executemany(
                """
                INSERT INTO sdm(addr, file_sha, weight) VALUES (?, ?, ?)
                ON CONFLICT(addr, file_sha) DO UPDATE SET weight = weight + excluded.weight
                """,
                [(addr, file_sha, w) for addr, w in weights.items()],
            )

    def ingest_file(self, path: Path, commit: bool = True) -> dict:
        path = path.resolve()
        if _SKIP_INGEST_NAME.search(path.name):
            return {
                "path": "(skipped)",
                "status": "skip",
                "error": "secret-shaped name",
            }
        data = path.read_bytes()
        file_sha = sha256_bytes(data)
        conn = self.db()
        existing = conn.execute(
            "SELECT path, size FROM files WHERE file_sha=?", (file_sha,)
        ).fetchone()
        if existing:
            conn.execute("UPDATE stats SET v = v + 1 WHERE k='copies_folded'")
            conn.execute("UPDATE stats SET v = v + ? WHERE k='bytes_in'", (len(data),))
            self._dirty += 1
            if commit:
                self.flush()
            return {
                "path": str(path),
                "file_sha": file_sha,
                "size": len(data),
                "status": "alias",
                "note": "identical bytes already held — copy folded, quality kept",
            }
        chunks = cdc_chunks(data)
        shas: list[str] = []
        new_raw = 0
        new_stored = 0
        reused = 0
        for raw in chunks:
            sha, stored_size, was_copy = self.put_chunk(raw)
            shas.append(sha)
            if was_copy:
                reused += 1
            else:
                new_raw += len(raw)
                new_stored += stored_size
        cue = self._cue_text(path, data)
        conn.execute(
            """
            INSERT INTO files(file_sha, path, size, chunk_count, cue, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (file_sha, str(path), len(data), len(shas), cue, _now()),
        )
        conn.executemany(
            "INSERT INTO file_chunks(file_sha, seq, chunk_sha) VALUES (?, ?, ?)",
            [(file_sha, i, sha) for i, sha in enumerate(shas)],
        )
        self._index_cue(file_sha, cue, path.name)
        conn.execute("UPDATE stats SET v = v + ? WHERE k='bytes_in'", (len(data),))
        conn.execute("UPDATE stats SET v = v + ? WHERE k='unique_raw'", (new_raw,))
        conn.execute("UPDATE stats SET v = v + ? WHERE k='unique_stored'", (new_stored,))
        conn.execute("UPDATE stats SET v = v + 1 WHERE k='files'")
        self._dirty += 1
        if commit:
            self.flush()
        return {
            "path": str(path),
            "file_sha": file_sha,
            "size": len(data),
            "chunks": len(shas),
            "new_unique_raw": new_raw,
            "new_unique_stored": new_stored,
            "chunks_reused": reused,
            "status": "folded",
        }

    def ingest_tree(self, root: Path) -> list[dict]:
        root = root.resolve()
        out: list[dict] = []
        if root.is_file():
            return [self.ingest_file(root)]
        n = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR]
            for name in filenames:
                p = Path(dirpath) / name
                try:
                    if p.resolve() == self.store.resolve() or self.store.resolve() in p.resolve().parents:
                        continue
                except OSError:
                    continue
                try:
                    n += 1
                    out.append(self.ingest_file(p, commit=(n % 50 == 0)))
                except (OSError, PermissionError) as exc:
                    out.append({"path": str(p), "status": "skip", "error": str(exc)})
        self.flush()
        return out

    def unfold(self, file_sha: str, dest: Path | None = None) -> dict:
        conn = self.db()
        row = conn.execute(
            "SELECT path, size FROM files WHERE file_sha=?", (file_sha,)
        ).fetchone()
        if not row:
            return {"ok": False, "error": "unknown file_sha", "file_sha": file_sha}
        parts = conn.execute(
            "SELECT chunk_sha FROM file_chunks WHERE file_sha=? ORDER BY seq",
            (file_sha,),
        ).fetchall()
        buf = bytearray()
        try:
            for part in parts:
                buf.extend(self.get_chunk(part["chunk_sha"]))
        except (FileNotFoundError, ValueError) as exc:
            return {
                "ok": False,
                "error": "unfold refused — residue failed hash/missing chunk",
                "detail": str(exc),
                "file_sha": file_sha,
            }
        data = bytes(buf)
        got = sha256_bytes(data)
        if got != file_sha or len(data) != int(row["size"]):
            return {
                "ok": False,
                "error": "unfold refused — file fingerprint mismatch",
                "file_sha": file_sha,
                "got": got,
            }
        written = None
        if dest is not None:
            dest = Path(dest)
            if dest.is_dir() or str(dest).endswith(os.sep):
                dest = dest / Path(row["path"]).name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            written = str(dest)
        return {
            "ok": True,
            "file_sha": file_sha,
            "size": len(data),
            "source_path": row["path"],
            "written": written,
            "note": "bits match founded fingerprint",
        }

    def cue(self, query: str, trance: bool = False, limit: int = 12) -> list[dict]:
        conn = self.db()
        tokens = tokenize(query)
        if not tokens:
            return []
        core = query_core(tokens)
        k = SDM_TRANCE_K if trance else SDM_K
        addrs: set[int] = set()
        for tok in core + (tokens if trance else []):
            addrs.update(sdm_addrs(tok, k))
        if trance:
            for a, b in zip(core, core[1:]):
                addrs.update(sdm_addrs(f"{a}_{b}", k))
        scores: dict[str, float] = {}
        if addrs:
            qmarks = ",".join("?" * len(addrs))
            rows = conn.execute(
                f"SELECT file_sha, SUM(weight) AS w FROM sdm WHERE addr IN ({qmarks}) GROUP BY file_sha",
                tuple(addrs),
            ).fetchall()
            for r in rows:
                scores[r["file_sha"]] = float(r["w"])
        core_set = set(core)
        qjoin = "-".join(core)
        need = 2 if len(core) >= 2 else 1
        bonus = 90.0 if trance else 55.0
        for f in conn.execute("SELECT file_sha, path FROM files"):
            stem = Path(f["path"]).stem.lower().replace("_", "-")
            stem_toks = set(tokenize(stem.replace("-", " ")))
            overlap = len(core_set & stem_toks)
            if overlap >= need:
                scores[f["file_sha"]] = scores.get(f["file_sha"], 0.0) + bonus * overlap
            elif overlap == 1 and not trance:
                scores[f["file_sha"]] = scores.get(f["file_sha"], 0.0) + 4.0
            if qjoin and qjoin in stem:
                scores[f["file_sha"]] = scores.get(f["file_sha"], 0.0) + (140.0 if trance else 80.0)
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[: max(limit * 8, 80)]
        out: list[dict] = []
        for sha, score in ranked:
            f = conn.execute(
                "SELECT path, size, cue FROM files WHERE file_sha=?", (sha,)
            ).fetchone()
            if not f:
                continue
            out.append(
                {
                    "file_sha": sha,
                    "path": f["path"],
                    "size": int(f["size"]),
                    "score": round(score, 3),
                    "cue_preview": (f["cue"] or "")[:160],
                    "cue": f["cue"] or "",
                }
            )
        if len(core) >= 2:
            pair_fold = "fold" in core_set and "memory" in core_set
            kept: list[dict] = []
            for h in out:
                if pair_fold and _is_single_fold_name(h["path"]):
                    continue
                if _covers_core(h["path"], h.get("cue") or "", core):
                    kept.append(h)
            if kept:
                out = kept
        if out:
            floor = max(8.0, float(out[0]["score"]) * 0.15)
            out = [h for h in out if float(h["score"]) >= floor]
        for h in out:
            h.pop("cue", None)
        return out[:limit]

    def stats(self) -> dict:
        self.flush()
        conn = self.db()
        kv = {r["k"]: int(r["v"]) for r in conn.execute("SELECT k, v FROM stats")}
        n_chunks = conn.execute("SELECT COUNT(*) c FROM chunks").fetchone()["c"]
        n_files = conn.execute("SELECT COUNT(*) c FROM files").fetchone()["c"]
        bytes_in = kv.get("bytes_in", 0)
        unique_stored = kv.get("unique_stored", 0)
        saved = max(0, bytes_in - unique_stored)
        ratio = (saved / bytes_in) if bytes_in else 0.0
        return {
            "store": str(self.store),
            "files_held": n_files,
            "unique_chunks": n_chunks,
            "bytes_in": bytes_in,
            "unique_raw": kv.get("unique_raw", 0),
            "unique_stored": unique_stored,
            "copies_folded": kv.get("copies_folded", 0),
            "bytes_saved": saved,
            "fold_ratio": round(ratio, 4),
            "floor_note": "unique_stored is the information floor for this snapshot — uniqueness does not shrink",
            "wifi": False,
            "prior_bytes": len(self.prior),
        }


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def cmd_smoke() -> int:
    fm = FoldMemory()
    fm.init()
    fm.close()
    print("fold-memory smoke pass")
    return 0


def cmd_selftest() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="fold-mem-"))
    store = tmp / "store"
    shared = ("the leftover was never deleted. " * 400).encode("utf-8")
    a = b"alpha-head " + shared + b" alpha-tail-unique-111"
    b = b"beta-head " + shared + b" beta-tail-unique-222"
    fa = tmp / "mem-a.txt"
    fb = tmp / "mem-b.txt"
    fc = tmp / "mem-c.txt"
    fa.write_bytes(a)
    fb.write_bytes(b)
    fc.write_bytes(os.urandom(8192))
    os.environ["FOLD_MEMORY_STORE"] = str(store)
    fm = FoldMemory(store)
    fm.init()
    ra = fm.ingest_file(fa)
    rb = fm.ingest_file(fb)
    rc = fm.ingest_file(fc)
    ra2 = fm.ingest_file(fa)
    st = fm.stats()
    ua = fm.unfold(ra["file_sha"])
    ub = fm.unfold(rb["file_sha"])
    hits = fm.cue("leftover never deleted", trance=False)
    trance = fm.cue("leftover never deleted alpha", trance=True)
    c_sha = rc["file_sha"]
    row = fm.db().execute(
        "SELECT chunk_sha FROM file_chunks WHERE file_sha=? ORDER BY seq LIMIT 1",
        (c_sha,),
    ).fetchone()
    blob = blob_path(store, row["chunk_sha"])
    blob.write_bytes(b"R" + b"\x00" * 32)
    fm._raw_cache.clear()
    bad = fm.unfold(c_sha)
    fm.close()

    fails: list[str] = []
    if ra["status"] != "folded" or rb["status"] != "folded":
        fails.append("ingest")
    if ra2.get("status") != "alias":
        fails.append("copy-fold")
    if not ua.get("ok") or not ub.get("ok"):
        fails.append("unfold-good")
    if st["unique_stored"] >= (len(a) + len(b)):
        fails.append("shared-tissue-not-saved")
    if not any(h["file_sha"] == ra["file_sha"] for h in hits):
        fails.append("cue-miss")
    if not trance:
        fails.append("trance-empty")
    if bad.get("ok"):
        fails.append("corrupt-not-refused")
    if rc["new_unique_raw"] < 7000:
        fails.append("unique-floor-too-small")

    report = {
        "ok": not fails,
        "fails": fails,
        "stats": st,
        "alias": ra2.get("status"),
        "cue_hits": len(hits),
        "trance_hits": len(trance),
        "corrupt_refused": not bad.get("ok"),
    }
    _print(report)
    return 0 if not fails else 1


def _is_single_fold_name(path: str) -> bool:
    stem = Path(path).stem.lower()
    toks = set(tokenize(stem.replace("-", " ").replace("_", " ")))
    return "fold" in toks and "memory" not in toks and "fold-memory" not in stem


def _covers_core(path: str, cue: str, core: list[str]) -> bool:
    blob = f"{Path(path).stem} {cue or ''}".lower().replace("_", "-")
    toks = set(tokenize(blob.replace("-", " ")))
    core_set = set(core)
    if len(core) >= 2:
        return core_set.issubset(toks) or "-".join(core) in blob.replace(" ", "-")
    return bool(core_set & toks)



def cmd_help() -> int:
    print(
        """asher.fold-memory — leftover-memory

  python fold_memory.py ingest <path>
  python fold_memory.py cue <text> [--trance]
  python fold_memory.py unfold <file_sha> [--out <path>]
  python fold_memory.py stats
  python fold_memory.py smoke
  python fold_memory.py selftest

identical leftover copies share one box. unique bits stay the floor.
unfold is refused unless the file fingerprint matches.
cue = recall. --trance = a richer cue, not extra storage.
no wifi. store: ./fold-memory-store/ next to this runner
"""
    )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] in {"help", "-h", "--help"}:
        return cmd_help()
    cmd = argv[1]
    if cmd == "smoke":
        return cmd_smoke()
    if cmd == "selftest":
        return cmd_selftest()
    fm = FoldMemory()
    fm.init()
    try:
        if cmd == "ingest":
            if len(argv) < 3:
                print("usage: ingest <path>", file=sys.stderr)
                return 2
            rows = fm.ingest_tree(Path(argv[2]))
            _print({"ingested": len(rows), "results": rows[:50], "stats": fm.stats()})
            return 0
        if cmd == "cue":
            trance = "--trance" in argv
            words = [a for a in argv[2:] if not a.startswith("-")]
            if not words:
                print("usage: cue <text> [--trance]", file=sys.stderr)
                return 2
            hits = fm.cue(" ".join(words), trance=trance)
            _print({"query": " ".join(words), "trance": trance, "hits": hits})
            return 0
        if cmd == "unfold":
            if len(argv) < 3:
                print("usage: unfold <file_sha> [--out path]", file=sys.stderr)
                return 2
            dest = None
            if "--out" in argv:
                dest = Path(argv[argv.index("--out") + 1])
            _print(fm.unfold(argv[2], dest))
            return 0
        if cmd == "stats":
            _print(fm.stats())
            return 0
        print(f"unknown command: {cmd}", file=sys.stderr)
        return 2
    finally:
        fm.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
