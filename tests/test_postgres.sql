-- run against a scratch database:
--   psql -v ON_ERROR_STOP=1 -d scratch -f add-to-postgres.sql -f tests/test_postgres.sql
-- every check raises on failure, so a clean exit means all passed.
\set ON_ERROR_STOP 1
SET client_min_messages = warning;

DROP TABLE IF EXISTS public.fm_logs;
CREATE TABLE public.fm_logs (id bigint PRIMARY KEY, payload text, raw bytea, doc jsonb, api_token text);
INSERT INTO public.fm_logs
SELECT g,
       CASE WHEN g % 10 = 0 THEN 'unique line ' || g ELSE 'disk full on node-7, retrying' END,
       CASE WHEN g % 2 = 0 THEN decode('00ff10', 'hex') ELSE decode(md5(g::text), 'hex') END,
       jsonb_build_object('k', g % 3),
       'tok_' || g
FROM generate_series(1, 1000) g;

DO $$
DECLARE r record; h text; n int;
BEGIN
  -- put / get / alias / refuse
  h := fold_memory.put('hello'::bytea);
  IF fold_memory.put('hello'::bytea) <> h THEN RAISE EXCEPTION 'alias fingerprint differs'; END IF;
  IF fold_memory.get(h) <> 'hello'::bytea THEN RAISE EXCEPTION 'get wrong bytes'; END IF;
  IF fold_memory.get(upper(h)) <> 'hello'::bytea THEN RAISE EXCEPTION 'get case'; END IF;
  BEGIN
    PERFORM fold_memory.get(repeat('0', 64));
    RAISE EXCEPTION 'unknown fingerprint not refused';
  EXCEPTION WHEN no_data_found THEN NULL;
  END;
  UPDATE fold_memory.blobs SET body = 'hellO'::bytea WHERE sha256 = h;
  BEGIN
    PERFORM fold_memory.get(h);
    RAISE EXCEPTION 'corrupt blob not refused';
  EXCEPTION WHEN data_corrupted THEN NULL;
  END;
  IF (SELECT count(*) FROM fold_memory.verify()) <> 1 THEN RAISE EXCEPTION 'verify missed corruption'; END IF;
  DELETE FROM fold_memory.blobs WHERE sha256 = h;

  -- text column: 1000 rows, 101 distinct values, cleared after verified copy
  SELECT * INTO r FROM fold_memory.fold_column('public', 'fm_logs', 'id', 'payload', NULL, true);
  IF r.rows_seen <> 1000 OR r.new_blobs <> 101 OR r.aliases <> 899 OR r.cleared <> 1000 THEN
    RAISE EXCEPTION 'fold_column text counts wrong: %', r;
  END IF;
  IF EXISTS (SELECT 1 FROM public.fm_logs WHERE payload IS NOT NULL) THEN RAISE EXCEPTION 'not cleared'; END IF;
  n := fold_memory.restore_column('public', 'fm_logs', 'id', 'payload');
  IF n <> 1000 THEN RAISE EXCEPTION 'restore count %', n; END IF;
  IF (SELECT payload FROM public.fm_logs WHERE id = 20) <> 'unique line 20'
     OR (SELECT payload FROM public.fm_logs WHERE id = 21) <> 'disk full on node-7, retrying' THEN
    RAISE EXCEPTION 'restore wrong text';
  END IF;

  -- bytea column with a where clause and limit
  SELECT * INTO r FROM fold_memory.fold_column('public', 'fm_logs', 'id', 'raw', 'id <= 100', false, 50);
  IF r.rows_seen <> 50 OR r.new_blobs <> 26 THEN RAISE EXCEPTION 'bytea counts wrong: %', r; END IF;

  -- jsonb round trip
  SELECT * INTO r FROM fold_memory.fold_column('public', 'fm_logs', 'id', 'doc', NULL, true);
  IF r.new_blobs <> 3 THEN RAISE EXCEPTION 'jsonb distinct wrong: %', r; END IF;
  PERFORM fold_memory.restore_column('public', 'fm_logs', 'id', 'doc');
  IF (SELECT doc FROM public.fm_logs WHERE id = 4) <> '{"k": 1}'::jsonb THEN RAISE EXCEPTION 'jsonb restore'; END IF;

  -- refusals
  BEGIN
    PERFORM fold_memory.fold_column('public', 'fm_logs', 'id', 'api_token');
    RAISE EXCEPTION 'secret column not refused';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM NOT LIKE '%secret-shaped%' THEN RAISE; END IF;
  END;
  BEGIN
    PERFORM fold_memory.fold_column('fold_memory', 'blobs', 'sha256', 'body');
    RAISE EXCEPTION 'skip_rel not honored';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM NOT LIKE '%skip_rel%' THEN RAISE; END IF;
  END;

  -- gc keeps linked blobs, drops unlinked ones
  PERFORM fold_memory.put('orphan'::bytea);
  PERFORM fold_memory.unlink('public', 'fm_logs', '4', 'doc');
  n := fold_memory.gc(interval '0 seconds');
  IF n <> 1 THEN RAISE EXCEPTION 'gc dropped % (want 1: the orphan)', n; END IF;
  IF (SELECT count(*) FROM fold_memory.objects o LEFT JOIN fold_memory.blobs b ON b.sha256 = o.blob_sha
      WHERE b.sha256 IS NULL) <> 0 THEN RAISE EXCEPTION 'gc broke a link'; END IF;
  IF (SELECT nrefs FROM fold_memory.blobs WHERE sha256 = encode(sha256(convert_to('disk full on node-7, retrying', 'UTF8')), 'hex')) <> 900 THEN
    RAISE EXCEPTION 'nrefs not refreshed';
  END IF;
  IF (SELECT ok FROM fold_memory.tick_log ORDER BY id DESC LIMIT 1) IS NOT TRUE THEN RAISE EXCEPTION 'tick_log'; END IF;
END $$;

SELECT 'postgres checks passed' AS result, * FROM fold_memory.stats();
DROP TABLE public.fm_logs;
