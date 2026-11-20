asher.fold-memory 2.1.0
read me

(open README.html in any browser for the illustrated guide: diagrams, workflows, and every capability numbered. it works offline.)

this is leftover-memory software. it does not make unique things smaller. it keeps one copy of anything that is identical, and it only hands a file back if the fingerprint still matches.

---

what it is for (purpose)

people, companies, and governments keep paying to store the same leftover copies again and again:

- the same log line written every minute
- the same backup of a backup
- the same spreadsheet emailed five times
- the same json config copied into twenty folders

unique things (one photo, one encrypted vault, one original file) are the floor. they stay the size they are. that is not a bug.

the purpose is:

1. store shared leftover copies once
2. remember where they were by a cue (a hint), not by stuffing extra copies
3. give the exact original bits back, or refuse — never a lookalike
4. run on a laptop with no wifi for what is already held, or inside a company database on a clock

it is not a cloud warehouse. it is not a zip that "shrinks everything."

---

what changed in 2.1 (and what was wrong in 2.0)

2.0 had four real problems. each was reproduced first, then fixed, then given a test that fails on 2.0:

- secrets in metadata were searchable. the cue text was masked, but the fields beside it (an email subject, a csv header, a document title) went into the word index raw. an email with "Subject: password=..." could be found by typing the password. 2.1 masks fields too. existing stores: run reindex once (stats will tell you).
- export / import broke between stores with different squeeze dictionaries. every upgraded 1.0 store has its own; importing its export into a fresh store refused every text chunk (measured: 28 bad, 0 files). 2.1 sends the dictionary in the export and re-squeezes on arrival. a 2.0 importer simply skips the extra record.
- restore / (or an empty prefix) used only file names, so d1/same.txt and d2/same.txt landed on top of each other, and it still said "restored 3". 2.1 keeps the full layout, and refuses (never overwrites) if two paths would land in one place.
- unfold --out - held the whole file in ram before writing. 2.1 spools anything over 32 mb to a temp file in the store, still checked before the first byte leaves.
- smaller: import said "locations: 1" for a file it had refused; export with an unknown fingerprint printed a python traceback.

new in 2.1:

- versions. 2.0 quietly kept the old bytes when a file changed, but forgot which path they came from, so they could not be found and could never be freed. 2.1 remembers every version at every path:
    python fold_memory.py versions report.docx
    python fold_memory.py unfold report.docx --version 3 --out old.docx
  a 2.0 store opened by 2.1 gets its history back from the packs it already has (the records were always there).
  history only holds replaced versions, so a folder that never changes costs nothing extra (measured: +8 kb on a 642-file store).
- prune. keep the newest N versions per path, drop the rest, then gc gives the space back. the current version always stays, and a version still current at another path is never dropped.
    python fold_memory.py prune --keep 5 --dry-run
- dupes. the copies still sitting on your source disks, biggest waste first. this is the list to hand to a person deciding what to delete:
    python fold_memory.py dupes /home/me/Documents
- reindex. rebuild every file's words and cue from the bytes already held, no originals needed.

---

what changed in 2.0 (and what was wrong in 1.0)

1.0 had real problems. they were measured, not guessed:

- the old graph said 82%. in that selftest, 0 bites were shared between the two files. the saving was zlib squeezing one repeated sentence (12,833 bytes → 111), plus counting the same file twice.
- one file on disk per bite. stats said 169 kb stored for a text test; the disk said 2,012 kb — more than the 786 kb that went in.
- whole files were read into ram, and bites were cut in pure python at about 10 mb/s.
- the same file at a second path was forgotten. only the first path was kept.
- a pipe (fifo) inside a folder hung it forever. refused unfolds still said "exit 0".
- chinese / japanese / korean text could not be found by cue.
- nothing could be deleted, checked, or given back. add-to-postgres.sql only made tables.

2.0 fixes all of that. same idea, same words, rebuilt underneath:

- bites are cut at c speed (~460 mb/s cutting, ~100 mb/s end to end on one cpu). any file size. ram stays small (a 768 mb file peaked at 58 mb).
- bites live in a few big pack files, not millions of tiny ones. stats now report real disk, index included.
- the index (fold.sqlite) is only a cache. lose it, run rebuild, it comes back from the packs.
- every path is remembered, including every copy.
- a crash, a pulled plug, or kill -9 mid-write loses at most the last few seconds. what was committed is held.
- several ingests can run at once on the same store.
- verify, forget, gc (give space back), restore a whole folder, export / import deltas between machines.
- reads what is inside files for the cue: pdf, word/excel/powerpoint, epub, photos (exif camera + date), mp3/mp4/flac/wav tags, zip/tar members, email, sqlite, html/json/csv, science files (fits, hdf5, netcdf), and more. bounded, so a zip bomb can't blow it up.
- secrets are masked in the cue (api keys, tokens, private keys, password=...). secret-shaped files (.env, id_rsa, .pem, .kdbx...) are skipped unless you say otherwise.
- a 1.0 store upgrades itself the first time 2.0 opens it.
- add-to-postgres.sql now does the work inside the database (see below).

---

how it works (deep, then dumbed down)

nerdy word → plain word

- leftover copies = the same bytes sitting in more than one place
- unique leftover / the floor = the one original that has no twin; it cannot get smaller
- fingerprint = a long id made from the exact bits (sha-256). if one bit changes, the id changes
- closet = the store folder. it labels a box by what is inside, so two identical boxes share one shelf
- bite = a bite-sized piece of a file. identical bites across files share one shelf
- pack = a big box that holds many bites back to back, so the disk isn't full of tiny files
- ingest = put files into the closet
- unfold = put the exact file back together
- restore = unfold a whole folder, keeping names, layout, and dates
- cue = ask "what did we hold about x?" (recall)
- trance = a richer cue. it does not add storage. it only looks harder at what is already held
- refuse = if the fingerprint does not match, do not pretend you have the file
- forget = drop a path or a file from memory. gc = actually give the space back

the loop:

1. split a file into bites. where to cut is decided by the bytes themselves, so an insert near the start of a file only changes the bites around it — the rest still match
2. name each bite by its fingerprint
3. if that fingerprint is already on the shelf, do not store a second box — just point at the first
4. squeeze leftover air in the box (zlib, trained on shared leftover tissue). photos, video, and zips are already squeezed, so they go in as they are
5. keep a small recall index so a cue can find the right fingerprints
6. when you unfold, glue the bites in order, check every bite, then check the whole-file fingerprint
7. match → you get the exact file. miss → refuse, and nothing half-written is left behind. no dream file.

copies die. uniqueness stays.

---

how to add it

python 3.8 or newer. no extra packages. no wifi, ever.

a) quickest (any machine with python)

1. unzip this pack
2. open a terminal in this folder
3. prove it on this machine:
   python fold_memory.py selftest
4. put a folder in:
   python fold_memory.py ingest "/path/to/your/folder"
5. recall:
   python fold_memory.py cue "leftover never deleted"
   python fold_memory.py cue "leftover never deleted" --trance
6. get a file back (by fingerprint, the first few letters of it, or the path it came from):
   python fold_memory.py unfold "/path/to/your/folder/report.pdf" --out restored/
7. see sizes:
   python fold_memory.py stats

on windows, use py instead of python if python isn't found.

b) install it as a command

   pip install .            (or: pipx install .)
   fold-memory selftest

where the closet lives: $FOLD_MEMORY_STORE if you set it, else a fold-memory-store folder next to fold_memory.py (like 1.0), else your data folder (linux ~/.local/share/fold-memory, mac ~/Library/Application Support/fold-memory, windows %LOCALAPPDATA%\fold-memory). --store picks any folder.

c) by device

- windows / mac / linux laptop or pc: a) or b) above.
- raspberry pi, nas, any linux box: same. use --level fast on slow cpus.
- android: install termux, then: pkg install python, and run a).
- iphone / ipad: a-shell or pythonista can run fold_memory.py. apple limits what folders an app can see, so point it at files inside that app.
- a server with no internet: copy fold_memory.py over. it never reaches the network.

d) the everyday commands

   ingest <paths...>                fold files or folders (unchanged files are skipped fast)
   ingest - --name nightly.sql      fold whatever is piped in
   cue "words" [--trance]           recall
   unfold <ref> --out file|dir/|-   exact file back, or refuse (exit 1)
   restore <path prefix> --out dir  a whole folder back, with dates and permissions
   ls [prefix]                      what paths are held
   versions <path>                  every version held at that path (2.1)
   unfold <path> --version N        an older version back, exact (2.1)
   prune --keep N [prefix]          drop old versions beyond N per path; gc frees them (2.1)
   dupes [prefix]                   identical files at several paths, biggest waste first (2.1)
   reindex                          rebuild words and cues from held bytes (2.1)
   stats                            honest sizes (disk_bytes is the real disk)
   verify [--full]                  check every bite's fingerprint; names damaged files
   forget <ref> [--everywhere]      drop a path, or a file at every path
   gc [--dry-run]                   give back space from forgotten files
   rebuild                          if fold.sqlite is lost or damaged
   sample <paths>                   estimate savings on a folder; keeps nothing
   export / have / import           move only the missing bites between machines

useful switches on ingest: --exclude "*.tmp" (repeatable), --level fast|default|max, --jobs N, -v, --follow-links, --hydrate-cloud (download onedrive/icloud placeholders; off by default so nothing downloads by surprise).

skip secrets. the runner already skips .env, keys, cookies, wallets, and similar names, and masks key-shaped text in the cue. the bytes are still stored as they are — do not point it at password stores.

e) databases, big servers, and far-away machines

- any database dump, nightly:
    pg_dump mydb | python fold_memory.py ingest - --name mydb-nightly.sql
    mysqldump mydb | python fold_memory.py ingest - --name mydb-nightly.sql
  each night only the changed bites are new. unfold it back to replay it.

- inside postgres (11 or newer): run add-to-postgres.sql once. it is safe to run again, and it upgrades a 1.0 closet. then:
    select * from fold_memory.fold_column('public', 'app_logs', 'id', 'body',
        'created_at < now() - interval ''30 days''', true);
  that folds every old body into one box per unique value, and clears the cell only after the box is checked. get it back with fold_memory.restore_column(...), or fold_memory.get(sha) for one value. fold_memory.verify() lists any broken box. fold_memory.gc() drops boxes nothing points at. fold_memory.stats() shows the sizes. there's a pg_cron example at the bottom of the file for "on a clock". it refuses secret-shaped columns (password, token, secret, api_key...) and anything listed in fold_memory.skip_rel.

- cloud servers and big disks: run it on the machine that has the disk. packs are plain append-only files, so they back up and sync well.

- satellites, ships, air-gapped sites, bad links: keep a closet on each side and send only what's missing:
    receiver:  python fold_memory.py have have.txt
    sender:    python fold_memory.py export delta.fmpack --have have.txt
    receiver:  python fold_memory.py import delta.fmpack
  the delta holds only the bites the other side doesn't have, plus each file's list of fingerprints (32 bytes per bite). import checks every fingerprint and refuses broken ones. measured: two small edits to a 9.8 mb log → a 137 kb delta (the full closet was 5.8 mb), rebuilt exactly on the other side.

f) inside your own python software

    from fold_memory import FoldMemory
    with FoldMemory("/data/closet") as fm:
        fm.ingest_file("report.pdf")
        fm.ingest_bytes(b"...", "name.bin")
        hits = fm.cue("quarterly report")
        data = fm.read(hits[0]["file_sha"])   # exact bytes, or raises Refused

do not paste this into a homepage. this is backend leftover-memory, not a frontend widget.

---

tested results (this build, this machine — not a drawing of a wish)

a real pile: 114.6 mb = a python source tree + its monday backup copy + 30 mb of random bytes.

                          1.0                      2.0
  said it saved           63%                      56%
  real disk saved         45% (63.4 mb)            56% (50.3 mb)
  paths remembered        627                      1,281 (every file, both copies)
  time                    13.0 s                   4.9 s

the 2.0 number is lower on paper and higher on the disk. that's the honest one.

selftest (python fold_memory.py selftest — 25 checks):

- near-duplicate prose stored once: 49.6% saved (perfect would be 50%). the prose doesn't repeat, so this is real sharing, not zlib
- an insert into a 9 mb file costs only ~11–45 kb of new bites, not 9 mb
- unique random bytes: 0% saved. the floor
- broken box: unfold refused, nothing half-written, verify names the file
- lose the index: rebuild brings it all back from the packs
- export a delta, import on a second closet: exact files

the test suite (tests/, 44 tests: 29 from 2.0, plus 15 in tests/test_v21.py that each fail on 2.0) also does: every file size from 0 bytes up, a 200 mb sparse disk image (under 2 mb stored), names that aren't valid utf-8, a symlink loop, a fifo, a zip bomb, 4 writers at once, kill -9 in the middle of a 400 mb ingest then recovery, and a 768 mb file with ram checked. 2.0 passed on python 3.8, 3.10, 3.12, and 3.14. 2.1 was run on python 3.8 and 3.13: 43 pass, 1 skipped on each (the zstd test needs 3.14). the postgres file is unchanged from 2.0 and has its own test (tests/test_postgres.sql), which passed on postgres 16 for 2.0; it was not re-run for 2.1.

    python -m unittest discover -s tests

---

money % — honest estimate (not a slogan)

savings track leftover copies, not "all data."

the ice-cream law (why a cloud "4 gb" number often does not drop)

you buy an ice cream. the sun melts it. you cannot take the money back. the ice cream is gone — the cup is still in your hand.

- ice cream = leftover copies (the same log written again and again)
- melt = this software folds those twins and can delete the extra scoops
- cup = the database file size the cloud still shows
- freezer = the disk they rented you. they bill the freezer, not the melted scoops

leftover-memory can make leftover ice cream gone. it cannot un-buy the cup. postgres keeps the cup the same size after a delete (empty space inside; only vacuum full or a repack shrinks the file). the company bills the freezer you already rented. a smaller freezer is a later upgrade, not an automatic refund.

so: leftover copies can improve while the 4 gb status stays. that is not proof the leftover is still there. unique files were never ice cream — they stay the floor.

the estimate to tell a founder:

- if your bill is leftover copies (logs, backups of backups, duplicated exports): plan on saving most of *that copy slice* — often ~40–100% of the copy slice. this is unsure until you sample (python fold_memory.py sample /your/folder)
- if your bill is unique rows, unique photos, unique encrypted disks: plan on ~0–10%
- mixed office + logs + some photos: a working planning band is ~15–35% of the mixed pile. this is unsure
- do not sell "we will cut the whole cloud bill by 90%." that would only be true if almost everything was a twin
- do not sell "the 4 gb number must fall tonight." melted leftover and the cup on the bill are different.

industry backup closets (older software this idea shares roots with, not a promise of this zip): writeups have long said real-world backup copy ratios often land around 8:1 to 22:1, and that a large share of enterprise growth is copy data, not new unique data (~ idc / computerworld copy-data note; older, unsure on today's exact %). those numbers are why leftover-memory has a market. they are not a guarantee for unique database rows.

---

market research (who this can save, dumbed down)

people
- phone dumps, email attachments, "final_final_v3" folders
- savings: the twins. unique camera photos stay the floor

corporations
- nightly backups, vm clones, log pipelines, the same contract pdf in ten shares
- they already buy leftover-copy closets (backup appliances). the gap this software is built for: cue/trance recall + fingerprint-or-refuse as a memory law inside the product, local, no wifi for held bytes

governments
- records systems, place files, repeated xml/pdf packets
- same law: copies fold, unique records stay, unfold must match the fingerprint. do not claim classified networks from this zip

the market is leftover copies. other software already has: git-style closets, backup leftover-copy boxes, zip. the gap: memory (cue/trance) + refuse-on-mismatch + honest floor.

---

honest limits (what it does not do yet)

- no encryption. the closet is as private as the disk it sits on. use disk encryption (bitlocker, filevault, luks) if the files are private.
- no direct s3 / blob-storage backend. run it on the machine with the disk, or on a mounted bucket.
- sqlite on a network share (smb/nfs) can corrupt under two machines writing at once. keep the closet on a local disk, and use export/import to move it.
- a closet made with --codec zstd needs python 3.14+ to read it. older python refuses clearly and never calls it damage. the default (zlib) reads everywhere.
- tested on linux (python 3.8–3.14, postgres 16). windows, mac, android and ios paths are written for but were not run here.
- the index costs about 10 kb per unique file. for a pile of thousands of tiny files, that can be a real share of the disk.
- files are fingerprinted as they are read. a file that is changing while it is read is stored as whatever was read — the fingerprint still matches what was stored.

---

what this zip contains

- fold_memory.py  (the runner — laptop, phone, server; also a python library)
- add-to-postgres.sql  (the closet inside a postgres database, with working functions)
- pyproject.toml  (pip install . gives you the fold-memory command)
- TESTED RESULTS GRAPHS.svg / .html  (the numbers above, drawn)
- tests/  (python tests, the postgres test, and the 1.0 runner kept to test upgrades)
- this README FILE
