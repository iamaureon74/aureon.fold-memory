-- asher.fold-memory — closet for a company database (postgresql 11+)
-- leftover copies share one box. unique rows stay. get() refuses unless the fingerprint matches.
-- backend leftover-memory, not a homepage widget.
-- never fold password / token / vault / job-command columns; fold_column refuses the obvious ones.
--
-- install:   psql -v ON_ERROR_STOP=1 -d yourdb -f add-to-postgres.sql
-- re-running this file is safe; it upgrades the v1 starter closet in place.

CREATE SCHEMA IF NOT EXISTS fold_memory;

CREATE TABLE IF NOT EXISTS fold_memory.blobs (
  sha256 text PRIMARY KEY,
  body bytea NOT NULL,
  nbytes integer NOT NULL,
  nrefs integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);

DO $$
BEGIN
  ALTER TABLE fold_memory.blobs ALTER COLUMN body SET COMPRESSION lz4;
EXCEPTION WHEN others THEN
  RAISE NOTICE 'fold_memory: lz4 column compression unavailable here (needs pg14 built with lz4); default toast compression stays';
END $$;

CREATE TABLE IF NOT EXISTS fold_memory.objects (
  origin_schema text NOT NULL,
  origin_table text NOT NULL,
  origin_pk text NOT NULL,
  origin_column text NOT NULL,
  blob_sha text NOT NULL REFERENCES fold_memory.blobs(sha256),
  cue text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (origin_schema, origin_table, origin_pk, origin_column)
);
CREATE INDEX IF NOT EXISTS objects_blob ON fold_memory.objects(blob_sha);

CREATE TABLE IF NOT EXISTS fold_memory.tick_log (
  id bigserial PRIMARY KEY,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  ok boolean,
  note text,
  ingested integer DEFAULT 0,
  aliases integer DEFAULT 0,
  pruned integer DEFAULT 0
);

CREATE TABLE IF NOT EXISTS fold_memory.skip_rel (
  nsp text NOT NULL,
  rel text NOT NULL,
  reason text NOT NULL,
  PRIMARY KEY (nsp, rel)
);

INSERT INTO fold_memory.skip_rel(nsp, rel, reason) VALUES
  ('cron', 'job', 'commands can hold secrets'),
  ('vault', 'secrets', 'secrets'),
  ('auth', 'users', 'auth'),
  ('auth', 'refresh_tokens', 'auth'),
  ('auth', 'sessions', 'auth'),
  ('fold_memory', 'blobs', 'self'),
  ('fold_memory', 'objects', 'self')
ON CONFLICT DO NOTHING;


-- put: store bytes once, return the fingerprint. a second identical put is an alias.
CREATE OR REPLACE FUNCTION fold_memory.put(raw bytea) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  h text;
BEGIN
  IF raw IS NULL THEN
    RETURN NULL;
  END IF;
  h := encode(sha256(raw), 'hex');
  INSERT INTO fold_memory.blobs(sha256, body, nbytes, nrefs)
  VALUES (h, raw, length(raw), 0)
  ON CONFLICT (sha256) DO NOTHING;
  RETURN h;
END $$;


-- get: exact bytes, or an error. never a lookalike.
CREATE OR REPLACE FUNCTION fold_memory.get(h text) RETURNS bytea
LANGUAGE plpgsql STABLE AS $$
DECLARE
  b bytea;
BEGIN
  SELECT body INTO b FROM fold_memory.blobs WHERE sha256 = lower(h);
  IF NOT FOUND THEN
    RAISE EXCEPTION 'fold_memory: unfold refused — unknown fingerprint %', h USING ERRCODE = 'no_data_found';
  END IF;
  IF encode(sha256(b), 'hex') <> lower(h) THEN
    RAISE EXCEPTION 'fold_memory: unfold refused — fingerprint mismatch %', h USING ERRCODE = 'data_corrupted';
  END IF;
  RETURN b;
END $$;


-- link: remember that (schema.table, pk, column) held these bytes.
CREATE OR REPLACE FUNCTION fold_memory.link(p_schema text, p_table text, p_pk text, p_column text,
                                            p_sha text, p_cue text DEFAULT NULL) RETURNS void
LANGUAGE sql AS $$
  INSERT INTO fold_memory.objects(origin_schema, origin_table, origin_pk, origin_column, blob_sha, cue)
  VALUES (p_schema, p_table, p_pk, p_column, lower(p_sha), p_cue)
  ON CONFLICT (origin_schema, origin_table, origin_pk, origin_column)
  DO UPDATE SET blob_sha = excluded.blob_sha, cue = coalesce(excluded.cue, fold_memory.objects.cue),
                created_at = now();
$$;


CREATE OR REPLACE FUNCTION fold_memory.unlink(p_schema text, p_table text, p_pk text, p_column text) RETURNS boolean
LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM fold_memory.objects
  WHERE origin_schema = p_schema AND origin_table = p_table AND origin_pk = p_pk AND origin_column = p_column;
  RETURN FOUND;
END $$;


-- fold_column: walk one column, store each distinct value once, link every row to it.
-- with p_clear, the origin cell is set to NULL, but only after get() hands the exact bytes back.
-- p_where is a raw sql predicate you write yourself (e.g. 'created_at < now() - interval ''7 days''').
CREATE OR REPLACE FUNCTION fold_memory.fold_column(
  p_schema text, p_table text, p_pk text, p_column text,
  p_where text DEFAULT NULL, p_clear boolean DEFAULT false, p_limit integer DEFAULT NULL)
RETURNS TABLE (rows_seen integer, new_blobs integer, aliases integer, cleared integer)
LANGUAGE plpgsql AS $$
DECLARE
  typ text;
  r record;
  raw bytea;
  h text;
  existed boolean;
  log_id bigint;
BEGIN
  rows_seen := 0; new_blobs := 0; aliases := 0; cleared := 0;
  IF EXISTS (SELECT 1 FROM fold_memory.skip_rel WHERE nsp = p_schema AND rel = p_table) THEN
    RAISE EXCEPTION 'fold_memory: %.% is on skip_rel', p_schema, p_table;
  END IF;
  IF p_column ~* '(pass(word|wd)?|secret|token|api_?key|private_?key|credential|salt|otp|2fa|session)' THEN
    RAISE EXCEPTION 'fold_memory: column % looks secret-shaped; refusing', p_column;
  END IF;
  SELECT format_type(a.atttypid, a.atttypmod) INTO typ
  FROM pg_attribute a
  WHERE a.attrelid = format('%I.%I', p_schema, p_table)::regclass AND a.attname = p_column AND NOT a.attisdropped;
  IF typ IS NULL THEN
    RAISE EXCEPTION 'fold_memory: no column %.%.%', p_schema, p_table, p_column;
  END IF;
  IF typ <> 'bytea' AND typ NOT IN ('text', 'json', 'jsonb', 'xml') AND typ NOT LIKE 'character varying%' AND typ NOT LIKE 'character(%' THEN
    RAISE EXCEPTION 'fold_memory: column type % not supported (bytea, text, varchar, json, jsonb, xml)', typ;
  END IF;
  INSERT INTO fold_memory.tick_log(note) VALUES (format('fold_column %I.%I.%I', p_schema, p_table, p_column))
  RETURNING id INTO log_id;

  FOR r IN EXECUTE format(
      'SELECT %I::text AS pk, %s AS val FROM %I.%I WHERE %I IS NOT NULL %s ORDER BY 1 %s',
      p_pk,
      CASE WHEN typ = 'bytea' THEN quote_ident(p_column) ELSE format('convert_to(%I::text, ''UTF8'')', p_column) END,
      p_schema, p_table, p_column,
      CASE WHEN p_where IS NULL THEN '' ELSE 'AND (' || p_where || ')' END,
      CASE WHEN p_limit IS NULL THEN '' ELSE 'LIMIT ' || p_limit::int END)
  LOOP
    rows_seen := rows_seen + 1;
    raw := r.val;
    h := encode(sha256(raw), 'hex');
    existed := EXISTS (SELECT 1 FROM fold_memory.blobs WHERE sha256 = h);
    PERFORM fold_memory.put(raw);
    PERFORM fold_memory.link(p_schema, p_table, r.pk, p_column, h, NULL);
    IF existed THEN aliases := aliases + 1; ELSE new_blobs := new_blobs + 1; END IF;
    IF p_clear THEN
      IF fold_memory.get(h) = raw THEN
        EXECUTE format('UPDATE %I.%I SET %I = NULL WHERE %I::text = $1', p_schema, p_table, p_column, p_pk)
        USING r.pk;
        cleared := cleared + 1;
      END IF;
    END IF;
  END LOOP;

  UPDATE fold_memory.tick_log
  SET finished_at = now(), ok = true, ingested = new_blobs, aliases = fold_column.aliases, pruned = cleared
  WHERE id = log_id;
  RETURN NEXT;
END $$;


-- restore_column: put folded values back into cells that are NULL now. text types come back as text.
CREATE OR REPLACE FUNCTION fold_memory.restore_column(p_schema text, p_table text, p_pk text, p_column text)
RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
  typ text;
  o record;
  n integer := 0;
  k integer;
BEGIN
  SELECT format_type(a.atttypid, a.atttypmod) INTO typ
  FROM pg_attribute a
  WHERE a.attrelid = format('%I.%I', p_schema, p_table)::regclass AND a.attname = p_column AND NOT a.attisdropped;
  FOR o IN SELECT origin_pk, blob_sha FROM fold_memory.objects
           WHERE origin_schema = p_schema AND origin_table = p_table AND origin_column = p_column
  LOOP
    IF typ = 'bytea' THEN
      EXECUTE format('UPDATE %I.%I SET %I = $1 WHERE %I::text = $2 AND %I IS NULL',
                     p_schema, p_table, p_column, p_pk, p_column)
      USING fold_memory.get(o.blob_sha), o.origin_pk;
    ELSE
      EXECUTE format('UPDATE %I.%I SET %I = convert_from($1, ''UTF8'')::%s WHERE %I::text = $2 AND %I IS NULL',
                     p_schema, p_table, p_column, typ, p_pk, p_column)
      USING fold_memory.get(o.blob_sha), o.origin_pk;
    END IF;
    GET DIAGNOSTICS k = ROW_COUNT;
    n := n + k;
  END LOOP;
  RETURN n;
END $$;


-- gc: drop blobs nothing links to (older than the grace window) and refresh nrefs.
CREATE OR REPLACE FUNCTION fold_memory.gc(p_grace interval DEFAULT interval '1 hour') RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
  n integer;
BEGIN
  UPDATE fold_memory.blobs b SET nrefs = c.n
  FROM (SELECT blob_sha, count(*)::int AS n FROM fold_memory.objects GROUP BY blob_sha) c
  WHERE b.sha256 = c.blob_sha AND b.nrefs <> c.n;
  DELETE FROM fold_memory.blobs b
  WHERE b.created_at <= clock_timestamp() - p_grace
    AND NOT EXISTS (SELECT 1 FROM fold_memory.objects o WHERE o.blob_sha = b.sha256);
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;


-- verify: every blob against its fingerprint. returns the broken ones.
CREATE OR REPLACE FUNCTION fold_memory.verify() RETURNS TABLE (sha256 text, nbytes integer)
LANGUAGE sql STABLE AS $$
  SELECT b.sha256, b.nbytes FROM fold_memory.blobs b WHERE encode(sha256(b.body), 'hex') <> b.sha256;
$$;


CREATE OR REPLACE FUNCTION fold_memory.stats()
RETURNS TABLE (objects bigint, blobs bigint, logical_bytes numeric, unique_bytes numeric, on_disk_bytes bigint)
LANGUAGE sql STABLE AS $$
  SELECT (SELECT count(*) FROM fold_memory.objects),
         (SELECT count(*) FROM fold_memory.blobs),
         (SELECT coalesce(sum(b.nbytes), 0) FROM fold_memory.objects o JOIN fold_memory.blobs b ON b.sha256 = o.blob_sha),
         (SELECT coalesce(sum(nbytes), 0) FROM fold_memory.blobs),
         pg_total_relation_size('fold_memory.blobs');
$$;

-- run on a clock, e.g. with pg_cron:
--   SELECT cron.schedule('fold-app-logs', '*/15 * * * *',
--     $q$SELECT * FROM fold_memory.fold_column('public', 'app_logs', 'id', 'payload',
--        'created_at < now() - interval ''1 day''', true)$q$);
--   SELECT cron.schedule('fold-gc', '0 4 * * *', $q$SELECT fold_memory.gc()$q$);
-- a cleared cell leaves dead space inside the table until autovacuum reuses it;
-- the file on disk (the cup) only shrinks with VACUUM FULL or pg_repack.

REVOKE ALL ON SCHEMA fold_memory FROM PUBLIC;
