# Gav Task

**Category:** Web / Source Disclosure
**Flag:** `SAS{g1t_h1st0ry_1s_pr377y_g00d?}`

## Challenge

The challenge ships as a source archive and exposes a live DogNav instance:

```text
https://435127eb4e5c479dbe95.kit.sasc.tf/
```

The web application is a Go service backed by Postgres/PostGIS and Patroni.
After unpacking the archive, the important tree looks like this:

```text
sources/
├── .git/
├── docker-compose.yaml
├── deploy/
│   ├── Dockerfile-patroni
│   └── Dockerfile-web
├── patroni/
│   ├── entry.sh
│   ├── init.sql
│   ├── nuclear_explosion.c
│   └── patroni.yml
└── web/
    ├── cmd/main.go
    └── internal/
        ├── database/
        ├── server/
        └── waf/
```

The live page is a dog tracking dashboard with two API routes:

- `/api/nearby`
- `/api/chip`

## Recon

The `/api/chip` handler accepts a `chip` and an optional `pulse` value:

```go
func (srv *Server) chipHandler(w http.ResponseWriter, req *http.Request) {
    chipID := strings.TrimSpace(req.URL.Query().Get("chip"))
    if chipID == "" {
        writeJSONError(w, http.StatusBadRequest, "chip is required")
        return
    }

    pulse := strings.TrimSpace(req.URL.Query().Get("pulse"))
    report, err := srv.db.DogReport(chipID, pulse)
    if err != nil {
        writeJSONError(w, http.StatusInternalServerError, "failed to load chip report")
        return
    }

    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(report))
}
```

`pulse` flows into `signalQuality`:

```go
func (engine *DatabaseEngine) signalQuality(value string) (int, error) {
    value = strings.TrimSpace(value)
    if value == "" {
        return 0, nil
    }

    var quality int
    if err := engine.db.Raw("SELECT signal_quality(?)", value).Scan(&quality).Error; err != nil {
        return 0, err
    }

    return quality, nil
}
```

At first glance this looks parameterized, but the SQL function itself builds a
dynamic query unsafely:

```sql
CREATE FUNCTION signal_quality(sample TEXT)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    quality TEXT := '0';
BEGIN
    IF sample IS NULL OR length(btrim(sample)) = 0 THEN
        RETURN 0;
    END IF;

    EXECUTE 'SELECT quality::text
        FROM (VALUES
            (''fresh'', 84),
            (''stable'', 61),
            (''weak'', 27)
        ) AS signal_samples(token, quality)
        WHERE token = ''' || sample || '''' INTO quality;

    RETURN COALESCE(NULLIF(regexp_replace(quality, '[^0-9]', '', 'g'), '')::integer, 0);
END;
$$
```

The app also enables a small Coraza WAF rule:

```go
SecRule ARGS_NAMES|ARGS "@detectSQLi" \
  "id:9421,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,multiMatch,log,deny"
```

So the web surface intentionally points toward SQL injection, but obvious
payloads such as:

```text
' OR '1'='1
```

are blocked with `403`.

## Vulnerability

The shipped archive contains the full `.git` directory. That means redactions
in the working tree are not enough: previous commits can still contain secrets.

The current `docker-compose.yaml` has a redacted flag:

```yaml
pg-patroni:
  environment:
    FLAG: SAS{REDACTED}
```

But `git log` shows several deployment-history commits:

```text
8c1cea0 Redact compose flag
c161611 Update compose deployment values
d87027c Redact patroni credentials
1dc4fb5 Add initial deployment config
```

The commit immediately before the flag redaction still contains the real
environment variable.

## Exploitation

Unpack the archive and inspect the bundled repository:

```sh
mkdir -p /tmp/gav-task
tar -xzf gav-task-d062b20a609d88406428af565e738b99.tgz -C /tmp/gav-task
cd /tmp/gav-task/sources
git log --oneline --all
```

The suspicious commit is:

```text
c161611 Update compose deployment values
```

Reading `docker-compose.yaml` from that commit reveals the flag:

```sh
git show c161611:docker-compose.yaml
```

Relevant output:

```yaml
pg-patroni:
  depends_on:
  - etcd
  build:
    context: .
    dockerfile: ./deploy/Dockerfile-patroni
  hostname: pg-patroni
  environment:
    FLAG: SAS{g1t_h1st0ry_1s_pr377y_g00d?}
```

The later commit `8c1cea0` redacts the value in the working tree, but the
original value remains available in the git object database.

## Automated Solve

The included artifact extracts the challenge archive, walks historical
`docker-compose.yaml` versions, and prints the first unredacted `SAS{...}`
value it finds:

```sh
python3 artifacts/solve.py
```

Output:

```text
SAS{g1t_h1st0ry_1s_pr377y_g00d?}
```

## Flag

```text
SAS{g1t_h1st0ry_1s_pr377y_g00d?}
```

## Lessons / Defenses

- **Do not ship `.git` with source releases** — `git archive`, a clean export,
  or a CI packaging step should produce challenge/application bundles.
- **Treat git history as sensitive** — redacting a secret in a later commit
  does not remove it from existing objects.
- **Rotate leaked secrets** — once a flag, password, or token appears in a
  commit, assume it is compromised.
- **Fix decoy bugs too** — the SQL injection inside `signal_quality` is real,
  even though the fastest solve is the repository-history leak.

## Artifacts

- [`artifacts/solve.py`](artifacts/solve.py) — git-history flag extractor
- [`artifacts/gav-task-d062b20a609d88406428af565e738b99.tgz`](artifacts/gav-task-d062b20a609d88406428af565e738b99.tgz) — original challenge archive

Challenge archive SHA-256:

```text
9b9c4a55311131e36b3a142db64dd212f13c20205cff7f750ee6aecbf6791250
```
