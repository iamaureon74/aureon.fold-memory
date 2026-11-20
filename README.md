# asher.fold-memory 2.1.0

**Leftover-memory software.** Identical copies share one box, unique bits stay the floor, and a file is only handed back if its fingerprint still matches.

It doesn't make unique things smaller. It keeps one copy of anything identical, remembers where every copy came from, and gives back the exact original bytes or refuses. It never hands back a lookalike.

- Python 3.8+, standard library only. No dependencies, no network, ever.
- Works as a CLI, as a Python library, or inside PostgreSQL (`add-to-postgres.sql`).
- Open [`README.html`](README.html) in a browser for the illustrated guide with diagrams and every capability numbered (works offline).

---

## Quick start

```bash
python fold_memory.py selftest
```

```bash
python fold_memory.py ingest "/path/to/your/folder"
```

```bash
python fold_memory.py cue "leftover never deleted" --trance
```

```bash
python fold_memory.py unfold "/path/to/your/folder/report.pdf" --out restored/
```

```bash
python fold_memory.py stats
```

On Windows, use `py` if `python` isn't found.

### Install as a command

```bash
pip install .
```

```bash
fold-memory selftest
```

**Where the store lives:** `$FOLD_MEMORY_STORE` if set, else `fold-memory-store/` next to `fold_memory.py`, else your data folder (`~/.local/share/fold-memory`, `~/Library/Application Support/fold-memory`, or `%LOCALAPPDATA%\fold-memory`). `--store` picks any folder.

---

## How it works

1. Split each file into content-defined chunks ("bites"). The bytes decide where to cut, so an insert near the start only changes the nearby bites.
2. Name each bite by its SHA-256 fingerprint.
3. If that fingerprint is already stored, point at it instead of storing it again.
4. Compress what's left (zlib with a trained dictionary). Already-compressed media goes in as-is.
5. Keep a small recall index (`fold.sqlite`) so a cue can find the right files. The index is only a cache, and `rebuild` restores it from the packs.
6. On unfold, glue bites in order, check every bite, then check the whole-file fingerprint.
7. Match: you get the exact file. Mismatch: it refuses (exit 1) and leaves nothing half-written.

Bites live in a few large append-only pack files, not millions of tiny ones.

---

## Commands

| Command | What it does |
|---|---|
| `ingest <paths...>` | Fold files or folders (unchanged files are skipped fast) |
| `ingest - --name nightly.sql` | Fold whatever is piped in |
| `cue "words" [--trance]` | Recall what's held about something |
| `unfold <ref> --out file\|dir/\|-` | Exact file back, or refuse |
| `unfold <path> --version N` | An older version back, exact *(2.1)* |
| `restore <prefix> --out dir` | A whole folder back, with layout, dates, and permissions |
| `ls [prefix]` | Paths held |
| `versions <path>` | Every version held at a path *(2.1)* |
| `prune --keep N [prefix]` | Drop old versions beyond N per path *(2.1)* |
| `dupes [prefix]` | Identical files at several paths, biggest waste first *(2.1)* |
| `reindex` | Rebuild words and cues from held bytes *(2.1)* |
| `stats` | Honest sizes (`disk_bytes` is the real disk) |
| `verify [--full]` | Check every bite's fingerprint and name damaged files |
| `forget <ref> [--everywhere]` | Drop a path, or a file at every path |
| `gc [--dry-run]` | Give back space from forgotten files |
| `rebuild` | Recreate `fold.sqlite` from the packs |
| `sample <paths>` | Estimate savings on a folder without keeping anything |
| `export` / `have` / `import` | Move only missing bites between machines |

Useful `ingest` switches: `--exclude "*.tmp"`, `--level fast|default|max`, `--jobs N`, `-v`, `--follow-links`, `--hydrate-cloud`.

---

## Use it from Python

```python
from fold_memory import FoldMemory

with FoldMemory("/data/closet") as fm:
    fm.ingest_file("report.pdf")
    fm.ingest_bytes(b"...", "name.bin")
    hits = fm.cue("quarterly report")
    data = fm.read(hits[0]["file_sha"])   # exact bytes, or raises Refused
```

## Database dumps and PostgreSQL

Nightly dumps only add the changed bites:

```bash
pg_dump mydb | python fold_memory.py ingest - --name mydb-nightly.sql
```

Inside PostgreSQL 11+, run `add-to-postgres.sql` once (safe to re-run). It adds `fold_memory.fold_column(...)` / `restore_column(...)`, plus `get`, `verify`, `gc`, and `stats`, and refuses secret-shaped columns. A `pg_cron` example is at the bottom of the file.

## Syncing between machines (air-gapped or slow links)

```bash
python fold_memory.py have have.txt                        # on the receiver
```

```bash
python fold_memory.py export delta.fmpack --have have.txt  # on the sender
```

```bash
python fold_memory.py import delta.fmpack                  # on the receiver
```

The delta holds only the bites the other side lacks. Import checks every fingerprint.

---

## What's new in 2.1

**Fixes (each has a regression test that fails on 2.0):**
- Secrets in metadata fields (email subjects, CSV headers, titles) are now masked before indexing. For existing stores, run `reindex` once.
- Export/import now works between stores with different compression dictionaries.
- `restore` with an empty prefix keeps the full layout and refuses rather than overwrite on path collisions.
- `unfold --out -` spools files over 32 MB to disk instead of holding them in RAM.

**New:** `versions`, `unfold --version`, `prune`, `dupes`, `reindex`.

See `README FILE.txt` for the full changelog, including what was fixed from 1.0 to 2.0.

---

## Tested results

| | 1.0 | 2.0 |
|---|---|---|
| Said it saved | 63% | 56% |
| Real disk saved | 45% (63.4 MB) | 56% (50.3 MB) |
| Paths remembered | 627 | 1,281 |
| Time | 13.0 s | 4.9 s |

*Test pile: 114.6 MB, made of a Python source tree, its backup copy, and 30 MB of random bytes.* See [`TESTED RESULTS GRAPHS.svg`](TESTED%20RESULTS%20GRAPHS.svg).

Run the tests:

```bash
python -m unittest discover -s tests
```

The suite has 44 tests (29 from 2.0 + 15 in `tests/test_v21.py`). The 2.1 tests were run on Python 3.8 and 3.13. The zstd test needs Python 3.14 and is skipped on older versions.

---

## Honest limits

- **No encryption.** The store is as private as its disk, so use disk encryption for private files. Secret masking protects the search index, not the stored bytes. Don't point it at password stores.
- No direct S3/blob backend. Run it on the machine that has the disk.
- Don't put the store on a network share (SMB/NFS) with multiple writers. Use export/import instead.
- Stores made with `--codec zstd` need Python 3.14+ to read.
- Unique data (photos, encrypted vaults, random bytes) saves ~0%. That's the floor. Savings come from copies.
- The index costs about 10 KB per unique file.

---

## Files

| File | Purpose |
|---|---|
| `fold_memory.py` | The runner and Python library |
| `add-to-postgres.sql` | Store inside PostgreSQL, with working functions |
| `pyproject.toml` | `pip install .` provides the `fold-memory` command |
| `README.html` | Illustrated offline guide |
| `README FILE.txt` | Full plain-text guide and changelog |
| `TESTED RESULTS GRAPHS.svg` / `.html` | Measured results, drawn |
| `tests/` | Python tests, Postgres test, and the 1.0 runner kept for upgrade tests |

## License

All rights reserved by the author unless they say otherwise.
