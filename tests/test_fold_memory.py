"""adversarial tests. run: python -m unittest discover -s tests -v"""
import hashlib
import io
import json
import os
import random
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import fold_memory as fmod  # noqa: E402
from fold_memory import FoldMemory, Refused  # noqa: E402

RUNNER = str(ROOT / "fold_memory.py")
LEGACY = str(Path(__file__).resolve().parent / "legacy_v1_fold_memory.py")


def run(*args, store, stdin=None, check=True):
    env = dict(os.environ, FOLD_MEMORY_STORE=str(store))
    p = subprocess.run([sys.executable, RUNNER] + list(args), input=stdin, capture_output=True, env=env, timeout=600)
    if check and p.returncode != 0:
        raise AssertionError("exit %d: %s" % (p.returncode, p.stderr.decode(errors="replace")))
    return p


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fm-test-"))
        self.store = self.tmp / "store"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


class ChunkerTests(unittest.TestCase):
    def test_streaming_equals_whole_buffer_for_any_read_size(self):
        rng = random.Random(1)
        data = bytes(rng.getrandbits(8) for _ in range(3_000_000))
        whole = fmod.chunk_bytes(data, texty=False)
        self.assertEqual(b"".join(whole), data)
        old = fmod.READ_BLOCK
        try:
            for block in (1, 7, 4096, 65537, 1 << 20):
                fmod.READ_BLOCK = block
                got = list(fmod.iter_chunks(io.BytesIO(data).read, fmod.BIN_PARAMS))
                self.assertEqual([hashlib.sha256(c).digest() for c in got],
                                 [hashlib.sha256(c).digest() for c in whole], "block %d" % block)
        finally:
            fmod.READ_BLOCK = old

    def test_bounds_hold(self):
        data = os.urandom(5_000_000)
        mn, avg, mx = fmod.BIN_CHUNK
        chunks = fmod.chunk_bytes(data, texty=False)
        for c in chunks[:-1]:
            self.assertGreaterEqual(len(c), mn)
            self.assertLessEqual(len(c), mx)
        zeros = fmod.chunk_bytes(b"\x00" * 1_000_000, texty=False)
        self.assertEqual(b"".join(zeros), b"\x00" * 1_000_000)
        self.assertTrue(all(len(c) <= mx for c in zeros))

    def test_insert_resyncs(self):
        data = os.urandom(4_000_000)
        edited = data[:2_000_000] + b"x" + data[2_000_000:]
        a = set(hashlib.sha256(c).digest() for c in fmod.chunk_bytes(data, False))
        b = fmod.chunk_bytes(edited, False)
        new = sum(len(c) for c in b if hashlib.sha256(c).digest() not in a)
        self.assertLess(new, 600_000)

    def test_text_detection(self):
        self.assertTrue(fmod.is_texty("会议记录 预算".encode() * 100))
        self.assertTrue(fmod.is_texty(b"plain ascii\n" * 100))
        self.assertTrue(fmod.is_texty("ok \u00e9".encode()[:-1]))  # cut multibyte tail
        self.assertFalse(fmod.is_texty(os.urandom(4096)))
        self.assertTrue(fmod.is_texty(b""))


class CodecTests(unittest.TestCase):
    def test_roundtrip_all_codecs(self):
        text = b"the quick brown fox " * 500
        for level in ("fast", "default", "max"):
            packed = fmod.pack_chunk(text, fmod._PRIOR_SEED, level)
            self.assertLess(len(packed), len(text))
            self.assertEqual(fmod.unpack_chunk(packed, fmod._PRIOR_SEED), text)
        rnd = os.urandom(50000)
        self.assertEqual(fmod.pack_chunk(rnd, fmod._PRIOR_SEED)[:1], b"R")
        if fmod._zstd is not None:
            packed = fmod.pack_chunk(text, fmod._PRIOR_SEED, codec="zstd")
            self.assertEqual(packed[:1], b"S")
            self.assertEqual(fmod.unpack_chunk(packed, fmod._PRIOR_SEED), text)

    def test_unknown_codec_refuses(self):
        with self.assertRaises(ValueError):
            fmod.unpack_chunk(b"Q123", b"")


class MediaTests(Base):
    def meta(self, name, data):
        p = self.tmp / name
        p.write_bytes(data)
        return fmod.extract_meta(p, name, data[:1 << 20])

    def test_pdf_text(self):
        content = zlib.compress(b"BT /F1 12 Tf 72 712 Td (hydrogen invoice march) Tj ET")
        pdf = (b"%%PDF-1.4\n1 0 obj << /Title (Moon Report) >> endobj\n2 0 obj << /Type /Page >> endobj\n"
               b"3 0 obj << /Length %d /Filter /FlateDecode >>\nstream\n" % len(content)
               + content + b"\nendstream\nendobj\n%EOF")
        m = self.meta("r.pdf", pdf)
        self.assertEqual(m["kind"], "pdf")
        self.assertIn("hydrogen invoice march", m["text"])
        self.assertEqual(m["fields"]["title"], "Moon Report")

    def test_office_and_epub(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("xl/workbook.xml", "<workbook/>")
            z.writestr("xl/sharedStrings.xml", "<sst><si><t>revenue forecast</t></si></sst>")
        m = self.meta("b.xlsx", buf.getvalue())
        self.assertEqual(m["kind"], "xlsx")
        self.assertIn("revenue forecast", m["text"])
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("mimetype", "application/epub+zip")
            z.writestr("ch1.xhtml", "<html><body><p>lighthouse keeper</p></body></html>")
        m = self.meta("b.epub", buf.getvalue())
        self.assertEqual(m["kind"], "epub")
        self.assertIn("lighthouse keeper", m["text"])

    def test_zip_bomb_is_bounded(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("word/document.xml", b"<w:t>a</w:t>" * 30_000_000)  # 330 mb inflated
        t0 = time.monotonic()
        m = self.meta("bomb.docx", buf.getvalue())
        self.assertEqual(m["kind"], "docx")
        self.assertLess(time.monotonic() - t0, 10)
        self.assertLessEqual(len(m["text"]), fmod.MAX_META_TEXT)

    def test_images_audio_video(self):
        exif = b"MM\x00*\x00\x00\x00\x08\x00\x01" + struct.pack(">HHII", 0x0110, 2, 12, 26) + b"\x00\x00\x00\x00" + b"PiCam Mark2\x00"
        app1 = b"\xff\xe1" + struct.pack(">H", 2 + 6 + len(exif)) + b"Exif\x00\x00" + exif
        sof = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, 1080, 1920, 1) + b"\x01\x11\x00"
        m = self.meta("p.jpg", b"\xff\xd8" + app1 + sof + b"\xff\xd9")
        self.assertEqual((m["kind"], m["fields"].get("width"), m["fields"].get("model")), ("jpeg", 1920, "PiCam Mark2"))
        title = b"\x03Night Drive"
        frame = b"TIT2" + struct.pack(">I", len(title)) + b"\x00\x00" + title
        id3 = b"ID3\x03\x00\x00" + bytes([0, 0, (len(frame) >> 7) & 0x7F, len(frame) & 0x7F]) + frame
        m = self.meta("s.mp3", id3 + b"\xff\xfb" + b"\x00" * 100)
        self.assertEqual(m["fields"].get("title"), "Night Drive")
        wav = (b"RIFF" + struct.pack("<I", 36 + 8000) + b"WAVEfmt " + struct.pack("<IHHIIHH", 16, 1, 1, 8000, 16000, 2, 16)
               + b"data" + struct.pack("<I", 8000) + b"\x00" * 8000)
        m = self.meta("a.wav", wav)
        self.assertEqual(m["fields"].get("seconds"), 0.5)
        mvhd = b"mvhd" + b"\x00" * 4 + b"\x00" * 8 + struct.pack(">II", 1000, 93500) + b"\x00" * 80
        moov = struct.pack(">I", 8 + 4 + len(mvhd)) + b"moov" + struct.pack(">I", 4 + len(mvhd)) + mvhd
        mp4 = struct.pack(">I", 16) + b"ftypisom" + b"\x00" * 4 + moov
        m = self.meta("v.mp4", mp4)
        self.assertEqual((m["kind"], m["fields"].get("seconds")), ("mp4", 93.5))

    def test_science_and_mail(self):
        card = lambda k, v: ("%-8s= %-70s" % (k, v)).encode()  # noqa: E731
        fits = card("SIMPLE", "T") + card("TELESCOP", "'HUBBLE'") + card("OBJECT", "'M31'") + b"END".ljust(80) + b" " * 2560
        m = self.meta("x.fits", fits)
        self.assertEqual((m["kind"], m["fields"].get("telescop"), m["fields"].get("object")), ("fits", "HUBBLE", "M31"))
        self.assertEqual(self.meta("g.h5", b"\x89HDF\r\n\x1a\n" + b"\x00" * 100)["kind"], "hdf5")
        mail = b"From: ops@example.com\r\nTo: a@b.c\r\nSubject: orbit window moved\r\n\r\ntelemetry body text\r\n"
        m = self.meta("m.eml", mail)
        self.assertEqual(m["fields"].get("subject"), "orbit window moved")
        self.assertIn("telemetry", m["text"])

    def test_garbage_never_raises(self):
        for name in ("x.pdf", "x.docx", "x.mp4", "x.jpg", "x.png", "x.mp3", "x.tar", "x.gz", "x.sqlite", "x.eml"):
            for blob in (b"", b"\x00", os.urandom(3000), b"%PDF" + os.urandom(500), b"PK\x03\x04" + os.urandom(500),
                         b"\xff\xd8\xff" + os.urandom(200), b"\x00\x00\x00\x20ftyp" + os.urandom(500)):
                self.meta(name, blob)

    def test_secrets_masked_in_cue(self):
        with FoldMemory(self.store) as fm:
            fm.ingest_bytes(b"deploy notes\npassword = hunter2\nkey AKIAABCDEFGHIJKLMNOP\n", "notes.txt")
            cue = fm.db().execute("SELECT cue FROM files").fetchone()[0]
        self.assertNotIn("hunter2", cue)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", cue)


class StoreTests(Base):
    def test_every_byte_value_and_sizes_roundtrip(self):
        rng = random.Random(3)
        with FoldMemory(self.store) as fm:
            cases = [b"", b"\x00", bytes(range(256)) * 300, b"a" * 10_000_000]
            cases += [bytes(rng.getrandbits(8) for _ in range(n)) for n in (1, 511, 512, 513, 8191, 8192, 8193, 262145)]
            shas = [fm.ingest_bytes(c, "case%d.bin" % i)["file_sha"] for i, c in enumerate(cases)]
            fm.flush()
            for c, s in zip(cases, shas):
                self.assertEqual(fm.read(s), c)

    def test_sparse_zero_file_folds_to_almost_nothing(self):
        p = self.tmp / "zeros.img"
        with open(p, "wb") as fh:
            fh.truncate(200 << 20)
        with FoldMemory(self.store) as fm:
            fm.ingest_file(p)
            st = fm.stats()
            self.assertLess(st["disk_bytes"], 2 << 20)
            self.assertEqual(fm.unfold(str(p))["size"], 200 << 20)

    def test_non_utf8_path_and_restore(self):
        if os.name == "nt" or sys.platform == "darwin":
            self.skipTest("posix byte paths")
        src = self.tmp / "src"
        src.mkdir()
        bad = os.path.join(os.fsencode(str(src)), b"caf\xe9-\xff.txt")
        with open(bad, "wb") as fh:
            fh.write(b"latin-1 name body")
        with FoldMemory(self.store) as fm:
            rows = fm.ingest_tree(src)
            self.assertEqual(rows[0]["status"], "folded")
            res = fm.restore(str(src), self.tmp / "out")
            self.assertTrue(res["ok"])
            self.assertEqual(res["restored"], 1)

    def test_symlink_loop_with_follow(self):
        if not hasattr(os, "symlink"):
            self.skipTest("no symlinks")
        src = self.tmp / "src"
        (src / "a").mkdir(parents=True)
        (src / "a" / "f.txt").write_text("x")
        os.symlink(str(src), str(src / "a" / "loop"))
        with FoldMemory(self.store) as fm:
            rows = fm.ingest_tree(src, follow_links=True)
        self.assertLessEqual(len([r for r in rows if r["status"] in ("folded", "alias")]), 2)

    def test_changed_file_reingested(self):
        p = self.tmp / "log.txt"
        p.write_text("one\n")
        with FoldMemory(self.store) as fm:
            a = fm.ingest_file(p)
            time.sleep(0.01)
            p.write_text("one\ntwo\n")
            os.utime(p, ns=(time.time_ns(), time.time_ns() + 10**9))
            b = fm.ingest_file(p)
            self.assertNotEqual(a["file_sha"], b["file_sha"])
            self.assertEqual(fm.read(str(p)), b"one\ntwo\n")
            self.assertEqual(fm.read(a["file_sha"]), b"one\n")

    def test_lost_index_rebuilds_from_packs(self):
        src = self.tmp / "src"
        src.mkdir()
        for i in range(30):
            (src / ("doc%02d.txt" % i)).write_bytes(("record %d pelican " % i).encode() * (50 + i))
        (src / "copy.txt").write_bytes((src / "doc03.txt").read_bytes())
        with FoldMemory(self.store) as fm:
            fm.ingest_tree(src)
            before = {r["path"]: r["file_sha"] for r in fm.ls()}
            fm.forget(str(src / "doc07.txt"))
        for f in self.store.glob("fold.sqlite*"):
            f.unlink()
        with FoldMemory(self.store) as fm:
            res = fm.rebuild()
            self.assertTrue(res["ok"], res)
            after = {r["path"]: r["file_sha"] for r in fm.ls()}
            expect = dict(before)
            expect.pop(str(src / "doc07.txt"))
            self.assertEqual(after, expect)
            self.assertTrue(fm.cue("pelican"))
            for s in set(after.values()):
                fm.read(s)

    def test_torn_pack_tail_is_harmless(self):
        with FoldMemory(self.store) as fm:
            s = fm.ingest_bytes(os.urandom(100000), "a.bin")["file_sha"]
        pack = sorted((self.store / "packs").glob("*.pack"))[-1]
        with open(pack, "ab") as fh:
            fh.write(b"FMR1C" + os.urandom(20))
        with FoldMemory(self.store) as fm:
            self.assertTrue(fm.rebuild()["ok"])
            fm.read(s)
            fm.ingest_bytes(b"after the tear", "b.txt")

    def test_refuse_writes_nothing(self):
        with FoldMemory(self.store) as fm:
            s = fm.ingest_bytes(os.urandom(300000), "a.bin")["file_sha"]
            row = fm.db().execute("SELECT pack, off, stored_size FROM chunks LIMIT 1").fetchone()
        with open(self.store / "packs" / row["pack"], "r+b") as fh:
            fh.seek(row["off"] + 10)
            fh.write(b"\x00\x01\x02")
        out = self.tmp / "out.bin"
        with FoldMemory(self.store) as fm:
            res = fm.unfold(s, out)
            self.assertFalse(res["ok"])
            self.assertFalse(out.exists())
            self.assertEqual(list(self.tmp.glob(".fold-*")), [])
            with self.assertRaises(Refused):
                fm.read(s)


class ZstdOnOldPythonTests(Base):
    # found by hand on 3.12 against a store written by 3.14: verify called healthy chunks "damaged",
    # and rebuild wiped the index before dying. both must not happen.
    def test_store_written_with_zstd_read_without_it(self):
        if fmod._zstd is None:
            self.skipTest("needs python 3.14+ to write the zstd store")
        data = ("line %d of the zstd log\n" % i for i in range(60000))
        data = "".join(data).encode()
        with FoldMemory(self.store, codec="zstd") as fm:
            fm.ingest_bytes(data, "z.log")
        saved = fmod._zstd
        fmod._zstd = None
        try:
            with FoldMemory(self.store) as fm:
                v = fm.verify()
                self.assertFalse(v["ok"])
                self.assertEqual(v["bad_chunks"], [])
                self.assertGreater(v["not_checked"], 0)
                with self.assertRaises(Refused):
                    fm.read("z.log")
                with self.assertRaises(Refused):
                    fm.rebuild()
                fm.gc(force=True, deep=True)
        finally:
            fmod._zstd = saved
        with FoldMemory(self.store) as fm:
            self.assertEqual(fm.read("z.log"), data)
            self.assertTrue(fm.verify(full=True)["ok"])


class LegacyTests(Base):
    def test_v1_store_migrates_and_keeps_every_bit(self):
        src = self.tmp / "src"
        src.mkdir()
        files = {"a.txt": ("legacy pelican text " * 900).encode(), "b.bin": os.urandom(70000),
                 "c.json": b'{"k": "v"}' * 300}
        for n, d in files.items():
            (src / n).write_bytes(d)
        (src / "a-again.txt").write_bytes(files["a.txt"])
        env = dict(os.environ, FOLD_MEMORY_STORE=str(self.store))
        p = subprocess.run([sys.executable, LEGACY, "ingest", str(src)], capture_output=True, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue((self.store / "blobs").exists())
        with FoldMemory(self.store) as fm:
            for n, d in files.items():
                self.assertEqual(fm.read(hashlib.sha256(d).hexdigest()), d)
            self.assertTrue(fm.cue("pelican"))
            fm.ingest_tree(src)
            self.assertEqual(fm.read(str(src / "a-again.txt")), files["a.txt"])
            fm.gc(force=True)
            self.assertFalse((self.store / "blobs").exists())
            for n, d in files.items():
                self.assertEqual(fm.read(hashlib.sha256(d).hexdigest()), d)
            self.assertTrue(fm.verify(full=True)["ok"])
            self.assertTrue(fm.rebuild()["ok"])
            for n, d in files.items():
                self.assertEqual(fm.read(str(src / n)), d)


class CliTests(Base):
    def test_stdin_to_stdout_and_exit_codes(self):
        dump = os.urandom(2_000_000) + b"CREATE TABLE t (id int);\n" * 20000
        out = json.loads(run("ingest", "-", "--name", "nightly.sql", store=self.store, stdin=dump).stdout)
        self.assertEqual(out["counts"], {"folded": 1})
        sha = hashlib.sha256(dump).hexdigest()
        back = run("unfold", sha[:12], "--out", "-", store=self.store).stdout
        self.assertEqual(back, dump)
        self.assertEqual(run("unfold", "deadbeef00", store=self.store, check=False).returncode, 1)
        again = json.loads(run("ingest", "-", "--name", "nightly2.sql", store=self.store, stdin=dump).stdout)
        self.assertEqual(again["counts"], {"alias": 1})
        hits = json.loads(run("cue", "nightly", store=self.store).stdout)["hits"]
        self.assertEqual(hits[0]["copies"], 2)

    def test_export_have_import_delta(self):
        a, b = self.tmp / "a", self.tmp / "b"
        src = self.tmp / "src"
        src.mkdir()
        (src / "one.bin").write_bytes(os.urandom(500000))
        run("ingest", str(src), store=a)
        run("export", str(self.tmp / "p1.fmpack"), store=a)
        run("import", str(self.tmp / "p1.fmpack"), store=b)
        (src / "two.bin").write_bytes((src / "one.bin").read_bytes()[:400000] + os.urandom(1000))
        run("ingest", str(src), store=a)
        run("have", str(self.tmp / "have.txt"), store=b)
        res = json.loads(run("export", str(self.tmp / "p2.fmpack"), "--have", str(self.tmp / "have.txt"), store=a).stdout)
        self.assertLess(res["pack_bytes"], 200000)
        run("import", str(self.tmp / "p2.fmpack"), store=b)
        got = run("unfold", str(src / "two.bin"), "--out", "-", store=b).stdout
        self.assertEqual(got, (src / "two.bin").read_bytes())

    def test_fifo_does_not_hang(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no fifo")
        src = self.tmp / "src"
        src.mkdir()
        os.mkfifo(str(src / "pipe"))
        (src / "ok.txt").write_text("fine")
        out = json.loads(run("ingest", str(src), store=self.store).stdout)
        self.assertEqual(out["counts"].get("folded"), 1)

    def test_concurrent_writers(self):
        src = self.tmp / "src"
        src.mkdir()
        shared = os.urandom(40_000_000)
        for i in range(6):
            (src / ("f%d.bin" % i)).write_bytes(shared[: 10_000_000 + i * 5_000_000] + os.urandom(20000))
        env = dict(os.environ, FOLD_MEMORY_STORE=str(self.store))
        procs = [subprocess.Popen([sys.executable, RUNNER, "ingest", str(src), "--rehash"], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(4)]
        for p in procs:
            _, err = p.communicate(timeout=300)
            self.assertEqual(p.returncode, 0, err)
        with FoldMemory(self.store) as fm:
            self.assertTrue(fm.verify(full=True)["ok"])
            for f in src.iterdir():
                self.assertEqual(fm.read(str(f)), f.read_bytes())
            fm.gc(force=True, deep=True)
            for f in src.iterdir():
                self.assertEqual(fm.read(str(f)), f.read_bytes())

    def test_kill_mid_ingest_then_recover(self):
        if os.name == "nt":
            self.skipTest("posix kill")
        big = self.tmp / "big.bin"
        with open(big, "wb") as fh:
            for _ in range(400):
                fh.write(os.urandom(1 << 20))
        env = dict(os.environ, FOLD_MEMORY_STORE=str(self.store))
        p = subprocess.Popen([sys.executable, RUNNER, "ingest", str(big)], env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # a fixed sleep flaked under cpu contention (3.10 run, 3 suites in parallel). wait for bytes instead.
        deadline = time.time() + 120
        while time.time() < deadline and p.poll() is None:
            packs = list((self.store / "packs").glob("*.pack")) if (self.store / "packs").exists() else []
            if sum(x.stat().st_size for x in packs) > (24 << 20):
                break
            time.sleep(0.05)
        p.send_signal(signal.SIGKILL)
        self.assertEqual(p.wait(), -signal.SIGKILL, "ingest finished before the kill; test proves nothing")
        packs = list((self.store / "packs").glob("*.pack"))
        self.assertTrue(packs and sum(x.stat().st_size for x in packs) > (8 << 20), "kill landed too early")
        with FoldMemory(self.store) as fm:
            self.assertTrue(fm.verify()["ok"])
            fm.ingest_file(big)
            self.assertEqual(hashlib.sha256(fm.read(str(big))).digest(), hashlib.sha256(big.read_bytes()).digest())
            fm.gc(force=True, deep=True)
            self.assertTrue(fm.verify(full=True)["ok"])
            st = fm.stats()
            self.assertLess(st["disk_bytes"], (400 << 20) * 1.03)


class MemoryTests(Base):
    def test_big_file_ram_stays_bounded(self):
        big = self.tmp / "big.bin"
        block = os.urandom(8 << 20)
        with open(big, "wb") as fh:
            for i in range(96):  # 768 mb, mostly repeated so the disk stays small
                fh.write(block if i % 3 else os.urandom(8 << 20))
        if not os.path.exists("/proc/self/status"):
            self.skipTest("needs /proc")
        # ru_maxrss survives exec on linux, so read this process's own high-water mark
        code = ("import sys; sys.path.insert(0,%r); import fold_memory as f;"
                "m=f.FoldMemory(%r); m.open(); r=m.ingest_file(%r); m.close();"
                "print(open('/proc/self/status').read().split('VmHWM:')[1].split()[0])") % (
                    str(ROOT), str(self.store), str(big))
        p = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=600)
        self.assertEqual(p.returncode, 0, p.stderr)
        peak_mb = int(p.stdout.strip()) / 1024
        self.assertLess(peak_mb, 200, "peak rss %.0f mb" % peak_mb)


if __name__ == "__main__":
    unittest.main()
