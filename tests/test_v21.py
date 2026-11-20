"""regression tests for 2.1: each one failed on 2.0. run: python -m unittest discover -s tests -v"""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import fold_memory as fmod  # noqa: E402
from fold_memory import FoldMemory  # noqa: E402

RUNNER = str(ROOT / "fold_memory.py")


def run(*args, store, check=True):
    env = dict(os.environ, FOLD_MEMORY_STORE=str(store))
    p = subprocess.run([sys.executable, RUNNER] + list(args), capture_output=True, env=env, timeout=600)
    if check and p.returncode != 0:
        raise AssertionError("exit %d: %s" % (p.returncode, p.stderr.decode(errors="replace")))
    return p


def prose(seed: int, n: int) -> str:
    rng = random.Random(seed)
    words = ["ledger", "harbor", "copper", "meadow", "signal", "lantern", "orbit", "quartz", "willow", "ember"]
    return " ".join(rng.choice(words) + str(rng.randint(0, 99)) for _ in range(n))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fm21-"))
        self.src = self.tmp / "src"
        self.src.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class SecretFieldTests(Base):
    def test_secret_in_metadata_field_is_not_searchable(self):
        (self.src / "keys.csv").write_text("name,token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12\nbob,1\n")
        (self.src / "m.eml").write_text("Subject: password=hunter2xyz quarterly\nFrom: a@b.c\n\nhello\n")
        with FoldMemory(self.tmp / "s") as fm:
            fm.ingest_tree(self.src)
            terms = [r[0] for r in fm.db().execute("SELECT term FROM words")]
            self.assertFalse([t for t in terms if "hunter2" in t or "ghp" in t or "abcdefghij" in t], terms)
            self.assertEqual(fm.cue("hunter2xyz"), [])
            self.assertTrue(fm.cue("quarterly"), "the rest of the subject is still searchable")

    def test_reindex_scrubs_an_old_index(self):
        (self.src / "m.eml").write_text("Subject: password=hunter2xyz\nFrom: a@b.c\n\nhello\n")
        with FoldMemory(self.tmp / "s") as fm:
            fm.ingest_tree(self.src)
            sha = fm.db().execute("SELECT file_sha FROM files").fetchone()[0]
            # plant what 2.0 would have indexed, and mark the index as 2.0-built
            fm.db().execute("INSERT INTO words(term, fid, w) VALUES ('hunter2xyz', ?, 3.0)", (fmod.fid_of(sha),))
            fm.db().execute("UPDATE meta SET v=1 WHERE k='index_version'")
            fm.flush()
            self.assertTrue(fm.cue("hunter2xyz"))
            self.assertIn("reindex_recommended", fm.stats())
            res = fm.reindex()
            self.assertTrue(res["ok"])
            self.assertEqual(fm.cue("hunter2xyz"), [])
            self.assertNotIn("reindex_recommended", fm.stats())
            # and a rebuild from packs must not bring the old words back
            fm.rebuild()
            self.assertEqual(fm.cue("hunter2xyz"), [])
            self.assertTrue(fm.cue("hello"))


class PortablePackTests(Base):
    def test_export_import_between_stores_with_different_priors(self):
        a = self.tmp / "a"
        a.mkdir()
        (a / "prior.bin").write_bytes(b"a dictionary trained on some other store " * 400)  # like an upgraded 1.0 store
        (self.src / "x.txt").write_text(prose(1, 40000))
        with FoldMemory(a) as fm:
            fm.ingest_file(self.src / "x.txt")
            fm.export(self.tmp / "d.fmpack")
        with FoldMemory(self.tmp / "b") as fm:
            res = fm.import_pack(self.tmp / "d.fmpack")
            self.assertTrue(res["ok"], res)
            self.assertGreater(res["chunks_recoded"], 0)
            self.assertEqual(fm.read(str(self.src / "x.txt")), (self.src / "x.txt").read_bytes())
            self.assertTrue(fm.verify(full=True)["ok"])
            fm.rebuild()  # recoded chunks are readable with this store's prior alone
            self.assertEqual(fm.read(str(self.src / "x.txt")), (self.src / "x.txt").read_bytes())

    def test_import_counts_only_locations_that_landed(self):
        (self.src / "x.txt").write_text(prose(2, 5000))
        with FoldMemory(self.tmp / "a") as fm:
            fm.ingest_file(self.src / "x.txt")
            fm.export(self.tmp / "d.fmpack")
        raw = bytearray((self.tmp / "d.fmpack").read_bytes())
        # break the first chunk record's payload so the file can't be completed
        off = len(fmod.PACK_MAGIC)
        for _ in range(2):  # skip the P record, land on the first C record
            magic, kind, sha, length = fmod.REC_HEAD.unpack_from(raw, off)
            if kind == b"C":
                break
            off += fmod.REC_HEAD.size + length
        raw[off + fmod.REC_HEAD.size + 3] ^= 0xFF
        (self.tmp / "bad.fmpack").write_bytes(bytes(raw))
        with FoldMemory(self.tmp / "b") as fm:
            res = fm.import_pack(self.tmp / "bad.fmpack")
            self.assertFalse(res["ok"])
            self.assertEqual(res["locations"], 0)
            self.assertEqual(fm.ls(), [])


class RestoreTests(Base):
    def test_restore_root_keeps_layout_and_never_overwrites(self):
        (self.src / "d1").mkdir()
        (self.src / "d2").mkdir()
        (self.src / "d1" / "same.txt").write_text("one")
        (self.src / "d2" / "same.txt").write_text("two two")
        with FoldMemory(self.tmp / "s") as fm:
            fm.ingest_tree(self.src)
            out = self.tmp / "out"
            res = fm.restore("/", out)
            self.assertTrue(res["ok"], res)
            got = sorted(p.read_text() for p in out.rglob("same.txt"))
            self.assertEqual(got, ["one", "two two"])

    def test_restore_prefix_still_relative(self):
        (self.src / "a").mkdir()
        (self.src / "a" / "f.txt").write_text("x")
        with FoldMemory(self.tmp / "s") as fm:
            fm.ingest_tree(self.src)
            fm.restore(str(self.src), self.tmp / "out")
            self.assertEqual((self.tmp / "out" / "a" / "f.txt").read_text(), "x")


class VersionTests(Base):
    def _three_versions(self, fm, f: Path):
        for i in range(3):
            f.write_text("version %d\n%s" % (i, prose(i, 300)))
            os.utime(str(f), ns=(10**18 + i * 10**9, 10**18 + i * 10**9))
            fm.ingest_file(f)
            time.sleep(1.1)  # seen times are second resolution

    def test_versions_listed_and_unfoldable(self):
        f = self.src / "notes.txt"
        with FoldMemory(self.tmp / "s") as fm:
            self._three_versions(fm, f)
            vs = fm.versions(str(f))["versions"]
            self.assertEqual(len(vs), 3)
            self.assertTrue(vs[0]["current"])
            self.assertFalse(vs[2]["current"])
            oldest = fm.unfold(str(f), self.tmp / "old.txt", version=3)
            self.assertTrue(oldest["ok"], oldest)
            self.assertTrue((self.tmp / "old.txt").read_text().startswith("version 0"))
            self.assertFalse(fm.unfold(str(f), None, version=9)["ok"])

    def test_history_survives_gc_repack_and_rebuild(self):
        f = self.src / "notes.txt"
        with FoldMemory(self.tmp / "s") as fm:
            self._three_versions(fm, f)
            fm.gc(force=True, deep=True)
            fm.rebuild()
            self.assertEqual(len(fm.versions(str(f))["versions"]), 3)
            self.assertTrue(fm.read(fm.resolve_version(str(f), 3)).startswith(b"version 0"))

    def test_prune_keeps_newest_and_gc_frees(self):
        f = self.src / "notes.txt"
        with FoldMemory(self.tmp / "s") as fm:
            self._three_versions(fm, f)
            self.assertEqual(fm.prune(1, dry_run=True)["versions_to_drop"], 2)
            res = fm.prune(1)
            self.assertEqual(res["versions_dropped"], 2)
            self.assertEqual(res["files_dropped"], 2)
            self.assertEqual(len(fm.versions(str(f))["versions"]), 1)
            self.assertTrue(fm.read(str(f)).startswith(b"version 2"))
            self.assertGreater(fm.gc(force=True)["dead_chunks"], 0)
            fm.rebuild()
            self.assertEqual(len(fm.versions(str(f))["versions"]), 1)

    def test_prune_never_drops_a_version_current_elsewhere(self):
        f, g = self.src / "a.txt", self.src / "b.txt"
        with FoldMemory(self.tmp / "s") as fm:
            f.write_text("shared old")
            fm.ingest_file(f)
            g.write_text("shared old")  # same bytes, still current at b.txt
            fm.ingest_file(g)
            time.sleep(1.1)
            f.write_text("new")
            fm.ingest_file(f)
            fm.prune(1)
            self.assertEqual(fm.read(str(g)), b"shared old")

    def test_forget_path_drops_its_old_versions(self):
        f = self.src / "notes.txt"
        with FoldMemory(self.tmp / "s") as fm:
            self._three_versions(fm, f)
            res = fm.forget(str(f))
            self.assertEqual(len(res["forgot_files"]), 3)
            self.assertEqual(fm.db().execute("SELECT COUNT(*) FROM files").fetchone()[0], 0)
            fm.rebuild()
            self.assertEqual(fm.db().execute("SELECT COUNT(*) FROM files").fetchone()[0], 0)

    def test_old_store_history_backfilled_from_packs(self):
        f = self.src / "notes.txt"
        store = self.tmp / "s"
        with FoldMemory(store) as fm:
            self._three_versions(fm, f)
            fm.db().execute("DELETE FROM history")  # what a 2.0 store looks like
            fm.db().execute("DELETE FROM meta WHERE k='history'")
            fm.flush()
        with FoldMemory(store) as fm:
            self.assertEqual(len(fm.versions(str(f))["versions"]), 3)


class DupesTests(Base):
    def test_dupes_ranks_wasted_bytes(self):
        big = prose(5, 20000)
        for d in ("a", "b", "c"):
            (self.src / d).mkdir()
            (self.src / d / "big.txt").write_text(big)
        (self.src / "a" / "small.txt").write_text("tiny")
        (self.src / "b" / "small.txt").write_text("tiny")
        (self.src / "a" / "unique.txt").write_text("only one")
        with FoldMemory(self.tmp / "s") as fm:
            fm.ingest_tree(self.src)
            d = fm.dupes()
            self.assertEqual(d["groups"], 2)
            self.assertEqual(d["extra_copies"], 3)
            self.assertEqual(d["top"][0]["copies"], 3)
            self.assertEqual(d["top"][0]["wasted_bytes"], 2 * len(big))


class CliTests(Base):
    def test_new_commands_exit_codes(self):
        store = self.tmp / "s"
        f = self.src / "n.txt"
        f.write_text("one")
        run("ingest", str(self.src), store=store)
        time.sleep(1.1)
        f.write_text("two")
        run("ingest", str(self.src), store=store)
        vs = json.loads(run("versions", str(f), store=store).stdout)
        self.assertEqual(len(vs["versions"]), 2)
        p = run("unfold", str(f), "--version", "2", "--out", "-", store=store)
        self.assertEqual(p.stdout, b"one")
        self.assertEqual(run("unfold", str(f), "--version", "5", store=store, check=False).returncode, 1)
        self.assertEqual(json.loads(run("dupes", store=store).stdout)["groups"], 0)
        self.assertEqual(json.loads(run("prune", "--keep", "1", store=store).stdout)["versions_dropped"], 1)
        self.assertEqual(run("prune", "--keep", "0", store=store, check=False).returncode, 2)
        self.assertTrue(json.loads(run("reindex", store=store).stdout)["ok"])
        bad = run("export", str(self.tmp / "x.fmpack"), "ffffff", store=store, check=False)
        self.assertEqual(bad.returncode, 1)
        self.assertNotIn(b"Traceback", bad.stderr)

    def test_stdout_unfold_of_big_file_spools(self):
        store = self.tmp / "s"
        big = self.src / "big.bin"
        big.write_bytes(os.urandom(40 << 20))  # over the 32 mb spool threshold
        run("ingest", str(big), store=store)
        p = run("unfold", str(big), "--out", "-", store=store)
        self.assertEqual(p.stdout, big.read_bytes())


if __name__ == "__main__":
    unittest.main()
