"""Open Cloud deployer: the only component with the Docker socket.

Builds an app image, starts the container, stops it, rolls it back to an
earlier image, and deletes one app. The container name is oc-agent. It listens
on an internal-only network. Every request needs a generated token. It exposes
a fixed set of actions; it never runs caller-supplied commands.
"""
import calendar, copy, hashlib, hmac, json, os, re, secrets, shutil, socket, subprocess, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(os.environ.get("OC_ROOT", "/srv/opencloud"))
APPS_DOMAIN = os.environ.get("OC_APPS_DOMAIN", "localhost")
PUBLIC_IP = os.environ.get("OC_PUBLIC_IP", "")
EDGE = os.environ.get("OC_EDGE_CONTAINER", "oc-edge")
EDGE_MODE = os.environ.get("OC_EDGE_MODE", "internal")   # "external": another proxy fronts the console; no oc-edge
OBSERVE = os.environ.get("OC_OBSERVE", "0") == "1"       # read-only view of containers Open Cloud doesn't manage
OBSERVE_DIR = Path("/run/observe")                       # optional read-only file mounts (status.json, backup markers)
NAME = re.compile(r"^[a-z][a-z0-9-]{1,30}$")
KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
REPO = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+$")
REF = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
HEALTH_PATH = re.compile(r"^/[A-Za-z0-9._~/-]{0,100}$")
ENDPOINT = re.compile(r"^[a-z0-9][a-z0-9.-]{1,40}$")
MODEL_ID = re.compile(r"^[A-Za-z0-9._:/-]{1,120}$")
# Initiate AI: provider -> its OpenAI-compatible chat completions URL (the default when no URL is given).
PROVIDERS = {"openrouter": "https://openrouter.ai/api/v1/chat/completions",
             "openai": "https://api.openai.com/v1/chat/completions",
             "anthropic": "https://api.anthropic.com/v1/chat/completions"}
UPSTREAM = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$")
API_PATH = re.compile(r"^/[A-Za-z0-9._~/{}-]{0,200}$")
PROBE_PATH = re.compile(r"^/[A-Za-z0-9._~/-]{0,200}$")   # no templates or query strings
METHODS = ("get", "post", "put", "patch", "delete")
SPEC_MAX = 1_000_000
CONSOLE_HOST = os.environ.get("OC_CONSOLE_HOST", "console.localhost")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
STORAGE = os.environ.get("OC_STORAGE_CONTAINER", "oc-storage")
RESERVED = {"console", "s3", "storage", "llm-gateway"}
LOCK = threading.Lock()      # guards app locks, audit appends and the S3 identity file
BUSY = set()                 # apps with a running job
PROBE_LOCK = threading.Lock()  # serializes API health probes (kept apart from LOCK: probes are slow)


class Bad(Exception):
    pass


MUTATING = {"exec", "restart", "stop", "start", "kill", "rm", "update", "pause", "unpause", "rename", "cp", "commit"}


def guard(args):
    """Mutating docker verbs may only target Open Cloud's own (oc-*) containers."""
    if args[:1] == ["docker"] and len(args) > 1 and args[1] in MUTATING:
        names = [a for a in args[2:] if not a.startswith("-")]
        # exec/cp/commit/rename: the container comes first; update: it comes last (after option values)
        names = names[:1] if args[1] in ("exec", "cp", "commit", "rename") else names[-1:] if args[1] == "update" else names
        if not names or any(not n.startswith("oc-") for n in names):
            raise Bad(f"refusing docker {args[1]} on a container not managed by Open Cloud")


def run(args, timeout=900, check=True, **kw):
    guard(args)
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, **kw)
    if check and r.returncode:
        raise Bad(f"{args[0]} {args[1] if len(args) > 1 else ''} failed: {r.stderr.strip()[-600:]}")
    return r


def valid_app_name(name):
    """One path component. Names starting with `site-` are edge files, not apps."""
    if isinstance(name, str) and name.startswith("site-") and NAME.match(name):
        raise Bad("invalid app name: the site- prefix is reserved for edge files")
    if not NAME.match(name or "") or name in RESERVED:
        raise Bad("invalid app name")
    return name


def app_dir(name):
    valid_app_name(name)
    return ROOT / "apps" / name


def load(name):
    p = app_dir(name) / "app.json"
    if not p.exists():
        raise Bad("no such app")
    return json.loads(p.read_text())


def save(app):
    d = app_dir(app["name"])
    d.mkdir(parents=True, exist_ok=True)
    (d / "app.json").write_text(json.dumps(app, indent=2))


def secret_dir(name):
    d = ROOT / "secrets" / "apps" / name
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


# Container users that read secret files. Docker bind-mounts secrets with host
# ownership, so each file is 0400 and owned by the one user that consumes it.
GATEWAY_UID = 10002
POSTGRES_UID = 70  # postgres:17-alpine


def write_secret(path, value, owner=(0, 0)):
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
    with os.fdopen(fd, "w") as f:
        f.write(value)
    os.chown(tmp, *owner)
    tmp.replace(path)


def chown_secrets(name, owner):
    """App secrets belong to the user the app image runs as (root if unset)."""
    for p in secret_dir(name).iterdir():
        os.chown(p, *(owner or (0, 0)))
        os.chmod(p, 0o400)


HARDEN = {
    "restart": "unless-stopped",
    "cap_drop": ["ALL"],
    "cap_add": ["NET_BIND_SERVICE", "CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE"],
    "security_opt": ["no-new-privileges:true"],
    "pids_limit": 200,
    "logging": {"driver": "local", "options": {"max-size": "10m", "max-file": "3"}},
}


# ---- Host sources and mounts (opt-in, allowlisted in .env) -----------------------------------------
# OC_LOCAL_SOURCES: roots a "server folder" app source may come from (copied read-only into the build).
# OC_ALLOWED_EXTERNAL_NETWORKS: existing docker networks an app may join.
# OC_ALLOWED_DATA_ROOTS: folders (and their subfolders) an app may mount as data.
# OC_ALLOWED_SECRET_PATHS: secret files (or folders of them) an app may mount read-only at /run/secrets/<name>.
# The agent checks paths but never reads secret files.
ABS_PATH = re.compile(r"^/[A-Za-z0-9._/-]{0,250}$")
NET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
MOUNT_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
ENV_VALUE = re.compile(r"^[A-Za-z0-9 ._:/@+,=-]{0,500}$")
DOCKERFILE = re.compile(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
RESERVED_TARGETS = ("/run/secrets", "/proc", "/sys", "/dev", "/etc", "/usr", "/bin", "/sbin", "/lib")


def allow(var):
    return [Path(p) for p in os.environ.get(var, "").split() if ABS_PATH.match(p)]


def under_root(path, roots, kind):
    """Resolved path if it lies inside one of the allowlisted roots (after resolving symlinks), else Bad."""
    path = str(path or "")
    if not ABS_PATH.match(path) or ".." in path.split("/"):
        raise Bad(f"{kind} must be an absolute path without ..")
    real = Path(os.path.realpath(path))
    for r in roots:
        rr = Path(os.path.realpath(r))
        if real == rr or rr in real.parents:
            return real
    raise Bad(f"{kind} {path} is not under an allowed root")


def _lines(v):
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in str(v or "").replace("\r", "").split("\n") if x.strip()]


def parse_settings(body):
    """Validate the optional host settings of an app; returns only the keys that were given."""
    out = {}
    if "networks" in body:
        nets = sorted({n for n in str(body.get("networks") or "").replace(",", " ").split()})
        allowed = os.environ.get("OC_ALLOWED_EXTERNAL_NETWORKS", "").split()
        for n in nets:
            if not NET_NAME.match(n) or n not in allowed or n in ("host", "bridge", "none"):
                raise Bad(f"network {n} is not in OC_ALLOWED_EXTERNAL_NETWORKS")
        out["networks"] = nets
    if "secret_mounts" in body:
        mounts, seen = [], set()
        for ln in _lines(body.get("secret_mounts")):
            src, sep, target = ln.rpartition("=")
            if not sep or not MOUNT_NAME.match(target) or target in seen:
                raise Bad("secret mounts are lines of /host/file=name")
            real = under_root(src, allow("OC_ALLOWED_SECRET_PATHS"), "secret file")
            if not real.is_file():
                raise Bad(f"secret {src} is not a file")
            seen.add(target)
            mounts.append({"source": str(real), "target": target})
        out["secret_mounts"] = mounts
    if "data_mounts" in body:
        mounts = []
        for ln in _lines(body.get("data_mounts")):
            parts = ln.split(":")
            if len(parts) not in (2, 3) or (len(parts) == 3 and parts[2] != "ro"):
                raise Bad("data mounts are lines of /host/folder:/container/path[:ro]")
            real = under_root(parts[0], allow("OC_ALLOWED_DATA_ROOTS"), "data folder")
            t = parts[1]
            if not real.is_dir():
                raise Bad(f"data folder {parts[0]} is not a folder")
            if not ABS_PATH.match(t) or ".." in t.split("/") or t == "/" or any(t == r or t.startswith(r + "/") for r in RESERVED_TARGETS):
                raise Bad(f"invalid container path {t}")
            mounts.append({"source": str(real), "target": t, "ro": len(parts) == 3})
        out["data_mounts"] = mounts
    if "env" in body:
        env = {}
        for ln in _lines(body.get("env")):
            k, sep, v = ln.partition("=")
            if not sep or not KEY.match(k) or k == "PORT" or not ENV_VALUE.match(v):
                raise Bad("environment lines are KEY=value (A-Z, 0-9, _; simple values; not PORT)")
            env[k] = v
        out["env"] = env
    return out


def dockerfile_path(src, rel):
    rel = rel or "Dockerfile"
    if not DOCKERFILE.match(rel) or ".." in rel.split("/"):
        raise Bad("invalid Dockerfile path")
    p = Path(src) / rel
    real = Path(os.path.realpath(p))
    if Path(os.path.realpath(src)) not in real.parents:
        raise Bad("Dockerfile must be inside the source")
    return p


def snapshot_folder(folder, dst):
    """Copy a server folder (read-only mount in the agent) into the app's build dir; symlinks stay links."""
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(folder, dst, symlinks=True)


def recheck_host_settings(app):
    """Before every (re)start: the allowlists in .env may have shrunk since the app was created."""
    allowed = os.environ.get("OC_ALLOWED_EXTERNAL_NETWORKS", "").split()
    for n in app.get("networks") or []:
        if n not in allowed:
            raise Bad(f"network {n} is no longer allowed")
    for m in app.get("secret_mounts") or []:
        under_root(m["source"], allow("OC_ALLOWED_SECRET_PATHS"), "secret file")
    for m in app.get("data_mounts") or []:
        under_root(m["source"], allow("OC_ALLOWED_DATA_ROOTS"), "data folder")


def net_key(n):
    return "ext_" + re.sub(r"[^A-Za-z0-9_]", "_", n)


# ---- Managed Postgres roles ------------------------------------------------------------------------
# "app" is the owner/admin role (the image's superuser): it runs schema setup and migrations by hand
# (docker exec ... psql -U app). Apps connect as "app_runtime": no superuser, no CREATEDB/CREATEROLE,
# only CONNECT, schema USAGE, DML on tables and USAGE/SELECT on sequences, plus default privileges
# so tables "app" creates later are covered.
RUNTIME_ROLE = "app_runtime"
RUNTIME_ROLE_SQL = r"""\set ON_ERROR_STOP on
\set pw `cat /run/secrets/DB_RUNTIME_PASSWORD`
SELECT format('CREATE ROLE app_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L', :'pw')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_runtime') \gexec
SELECT format('ALTER ROLE app_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L', :'pw') \gexec
GRANT CONNECT ON DATABASE app TO app_runtime;
GRANT USAGE ON SCHEMA public TO app_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE app IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE app IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app_runtime;
"""


def runtime_pw_file(name):
    return ROOT / "secrets" / "db" / f"{name}-runtime"


def ensure_db_runtime(app):
    """Give a managed DB its non-superuser runtime role. Returns True when the app's DATABASE_URL changed."""
    n, changed = app["name"], False
    if not runtime_pw_file(n).exists():
        # Existing DB from before the split: create the credential and move DATABASE_URL to it.
        pw = secrets.token_urlsafe(24)
        write_secret(runtime_pw_file(n), pw, (POSTGRES_UID, POSTGRES_UID))
        write_secret(secret_dir(n) / "DATABASE_URL", f"postgresql://{RUNTIME_ROLE}:{pw}@db:5432/app")
        changed = True
    return changed


def apply_db_runtime_role(app, compose_file):
    """Start the DB alone, then create/refresh the runtime role before the web service connects."""
    run(["docker", "compose", "-f", str(compose_file), "up", "-d", "--wait", "--wait-timeout", "120", "db"])
    run(["docker", "exec", "-i", f"oc-app-{app['name']}-db-1", "psql", "-q", "-U", "app", "-d", "app", "-f", "-"],
        input=RUNTIME_ROLE_SQL, timeout=60)


# ---- Per-app health and containment (app.json, or opencloud.json shipped in the app's source) --------
# {"health": {"path": "/api/health", "tool": "python|node|wget"}, "read_only": true, "tmpfs": ["/tmp"]}
HEALTH_PATH = re.compile(r"^/[A-Za-z0-9._~/-]{0,100}$")
HEALTH_TOOLS = ("python", "node", "wget")


def app_manifest(app):
    """Containment settings: the app's own opencloud.json (if shipped in its source), then app.json on top."""
    m = {}
    f = app_dir(app["name"]) / "src" / "opencloud.json"
    try:
        if f.is_file() and f.stat().st_size < 4096:
            m = {k: v for k, v in json.loads(f.read_text()).items() if k in ("health", "read_only", "tmpfs")}
    except (OSError, ValueError):
        m = {}
    m.update({k: app[k] for k in ("health", "read_only", "tmpfs") if k in app})
    return m


def healthcheck(health, port):
    if not isinstance(health, dict) or not HEALTH_PATH.match(str(health.get("path", ""))) or health.get("tool") not in HEALTH_TOOLS:
        raise Bad("health needs a path like /api/health and a tool: python, node or wget")
    url = f"http://127.0.0.1:{int(port)}{health['path']}"
    test = {"python": ["CMD", "python3", "-c", f"import urllib.request;urllib.request.urlopen('{url}',timeout=4)"],
            "node": ["CMD", "node", "-e", f"fetch('{url}').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"],
            "wget": ["CMD", "wget", "-q", "-O", "/dev/null", url]}[health["tool"]]
    return {"test": test, "interval": "15s", "timeout": "5s", "retries": 4, "start_period": "30s"}


def tmpfs_mounts(paths):
    out = []
    for t in paths or []:
        if not isinstance(t, str) or not ABS_PATH.match(t) or ".." in t.split("/") or t == "/" or any(t == r or t.startswith(r + "/") for r in RESERVED_TARGETS):
            raise Bad(f"invalid tmpfs path {t}")
        out.append(f"{t}:size=64m,mode=1777")
    return out


def compose(app):
    """Build the app's compose file. JSON is valid YAML, so no YAML library is needed."""
    n = app["name"]
    sdir = secret_dir(n)
    names = sorted(p.name for p in sdir.iterdir())
    web = dict(HARDEN, image=f"oc-app-{n}:{app['image_tag']}", pull_policy="never",
               environment={**app.get("env", {}), "PORT": str(app["port"])}, mem_limit=f"{app.get('memory_mb', 512)}m", cpus=float(app.get("cpus", 1.0)),
               volumes=[f"{ROOT}/data/{n}:/data"],
               networks={"edge": {"aliases": [f"app-{n}"]}},
               secrets=names)
    doc = {"name": f"oc-app-{n}", "services": {"web": web},
           "networks": {"edge": {"external": True, "name": "oc_edge"}},
           "secrets": {s: {"file": str(sdir / s)} for s in names}}
    m = app_manifest(app)
    if m.get("health"):
        web["healthcheck"] = healthcheck(m["health"], app["port"])
    if m.get("read_only") is True:
        web["read_only"] = True
    if m.get("tmpfs"):
        web["tmpfs"] = tmpfs_mounts(m["tmpfs"])
    dm = app.get("data_mounts") or []
    if any(m["target"] == "/data" for m in dm):
        web["volumes"] = []
    web["volumes"] += [f"{m['source']}:{m['target']}" + (":ro" if m.get("ro") else "") for m in dm]
    web["volumes"] += [f"{m['source']}:/run/secrets/{m['target']}:ro" for m in app.get("secret_mounts") or []]
    for net in app.get("networks") or []:
        web["networks"][net_key(net)] = {"aliases": [f"app-{n}"]}
        doc["networks"][net_key(net)] = {"external": True, "name": net}
    if app.get("db"):
        web["networks"]["db"] = {}
        web["depends_on"] = {"db": {"condition": "service_healthy"}}
        doc["services"]["db"] = dict(HARDEN, image="postgres:17-alpine",
            cap_add=["CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER"],
            labels={"opencloud.backup": "postgres"},
            environment={"POSTGRES_USER": "app", "POSTGRES_DB": "app",
                         "POSTGRES_PASSWORD_FILE": "/run/secrets/DB_PASSWORD"},
            secrets=["DB_PASSWORD"], volumes=[f"{ROOT}/pgdata/{n}:/var/lib/postgresql/data"],
            networks=["db"], mem_limit="512m", cpus=0.5,
            healthcheck={"test": ["CMD-SHELL", "pg_isready -U app -d app"],
                         "interval": "5s", "timeout": "5s", "retries": 20})
        doc["networks"]["db"] = {"internal": True}
        doc["secrets"]["DB_PASSWORD"] = {"file": str(ROOT / "secrets" / "db" / n)}
        if runtime_pw_file(n).exists():
            doc["services"]["db"]["secrets"].append("DB_RUNTIME_PASSWORD")
            doc["secrets"]["DB_RUNTIME_PASSWORD"] = {"file": str(runtime_pw_file(n))}
    if route_cfg(app)["canary_weight"] and app.get("previous_tag"):
        # Canary: the previous release keeps serving a share of traffic beside the current one.
        prev = copy.deepcopy(web)
        prev["image"] = f"oc-app-{n}:{app['previous_tag']}"
        prev["networks"]["edge"] = {"aliases": [f"app-{n}-prev"]}
        doc["services"]["prev"] = prev
    return doc


def check_policy(path):
    """Refuse a compose file that publishes host ports, uses the host network, or is privileged."""
    cfg = json.loads(run(["docker", "compose", "-f", str(path), "config", "--format", "json"]).stdout)
    for s in cfg["services"].values():
        if s.get("ports") or s.get("network_mode") == "host" or s.get("privileged"):
            raise Bad("refusing host ports, host networking or privileged mode")


def up(app, build, recreate=False):
    d = app_dir(app["name"])
    f = d / "compose.yaml"
    recheck_host_settings(app)
    inject_provider_key(app)
    if app.get("db") and ensure_db_runtime(app):
        recreate = True  # DATABASE_URL is a bind-mounted secret: new value needs a new container
    f.write_text(json.dumps(compose(app), indent=2))
    check_policy(f)
    if build:
        log = d / "build.log"
        # Build in the rootless BuildKit sandbox (no host socket), then load the image.
        r = run(["docker", "buildx", "build", "--builder", ensure_builder(), "--pull", "--load",
                 "-f", str(dockerfile_path(d / "src", app.get("dockerfile"))),
                 "-t", f"oc-app-{app['name']}:{app['image_tag']}", str(d / "src")], check=False, timeout=1800)
        log.write_text(r.stdout + r.stderr)
        if r.returncode:
            raise Bad("build failed: " + (r.stdout + r.stderr).strip()[-800:])
    chown_secrets(app["name"], fix_data_owner(app))
    if app.get("db"):
        apply_db_runtime_role(app, f)
    # recreate: secret files are bind mounts, so a replaced value reaches a running container only on a new container.
    run(["docker", "compose", "-f", str(f), "up", "-d", "--remove-orphans", "--wait", "--wait-timeout", "120"] + (["--force-recreate"] if recreate else []))
    route(app)


def ensure_builder():
    """Register the sandboxed BuildKit (remote driver) with buildx once."""
    if run(["docker", "buildx", "inspect", "oc-sandbox"], check=False).returncode:
        run(["docker", "buildx", "create", "--name", "oc-sandbox", "--driver", "remote",
             os.environ.get("OC_BUILDKIT_ADDR", "tcp://oc-builder:1234")])
    return "oc-sandbox"


def image_owner(image):
    """uid:gid the image runs as, or None for root/unset."""
    user = run(["docker", "image", "inspect", "-f", "{{.Config.User}}", image]).stdout.strip()
    if user in ("", "root", "0", "0:0"):
        return None
    if re.fullmatch(r"[0-9]+(:[0-9]+)?", user):
        uid, _, gid = user.partition(":")
        return int(uid), int(gid or uid)
    ids = []
    for flag in ("-u", "-g"):
        r = run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "id", image, flag, user.split(":")[0]], check=False, timeout=60)
        if r.returncode or not r.stdout.strip().isdigit():
            return None
        ids.append(int(r.stdout.strip()))
    return tuple(ids)


def fix_data_owner(app):
    """Non-root images must be able to write /data: hand it (recursively) to the image user."""
    owner = image_owner(f"oc-app-{app['name']}:{app['image_tag']}")
    d = ROOT / "data" / app["name"]
    st = d.stat()
    if owner and (st.st_uid, st.st_gid) != owner:
        # Owner changed (first deploy, new image user, or restored files): hand over everything.
        for root, dirs, files in os.walk(d):
            for x in [root] + [os.path.join(root, f) for f in dirs + files]:
                os.lchown(x, *owner)
    return owner


def route_cfg(app):
    return {"domains": [], "redirect": True, "health_path": "", "health_interval": 30,
            "canary_weight": 0, **app.get("route", {})}


def hosts(app):
    return [f"{app['name']}.{APPS_DOMAIN}"] + route_cfg(app)["domains"]


def render_site_body(app):
    """Caddy site block, built only from validated structured fields. No ownership line."""
    n, r, port = app["name"], route_cfg(app), app["port"]
    hs = hosts(app)
    addrs = hs + ([] if r["redirect"] else [f"http://{h}" for h in hs])
    canary = r["canary_weight"] if app.get("previous_tag") else 0
    # Canary as 20 weighted slots picked at random (5 % steps). Stock weighted_round_robin was seen to stick to
    # one upstream for long stretches with 50/50, so random selection over repeated upstreams is used instead.
    slots = round(canary / 5)
    ups = [f"app-{n}:{port}"] * (20 - slots) + [f"app-{n}-prev:{port}"] * slots if canary else [f"app-{n}:{port}"]
    lines = [", ".join(addrs) + " {", "\timport security_headers", f"\treverse_proxy {' '.join(ups)} {{"]
    if canary:
        lines.append("\t\tlb_policy random")
    if r["health_path"]:
        lines += [f"\t\thealth_uri {r['health_path']}", f"\t\thealth_interval {r['health_interval']}s"]
    return "\n".join(lines + ["\t}", "}", ""])


def route_marker(name):
    """First line of an edge file this deployer wrote for this app."""
    return f"# opencloud:app={name}"


def render_site(app):
    return route_marker(app["name"]) + "\n" + render_site_body(app)


def visibility(app):
    """Apps saved before this setting existed keep their route."""
    return app.get("visibility", "external")


def parse_visibility(v):
    """New apps are internal unless asked: no edge route, reachable only on private networks."""
    v = str(v or "internal").strip()
    if v not in ("internal", "external"):
        raise Bad("visibility must be internal or external")
    return v


def set_visibility(body, name):
    app = load(name)
    app["visibility"] = parse_visibility(body.get("visibility"))
    save(app)
    route(app)
    return {"ok": True, "visibility": app["visibility"]}


def route(app):
    """Write the site, `caddy validate`, reload; restore the previous file on any failure.
    Internal apps get no site file. Only a file this deployer wrote is removed."""
    if EDGE_MODE == "external":
        return  # the external proxy owns routing; Open Cloud writes no Caddy config
    valid_app_name(app["name"])
    site = route_path(app["name"])
    if visibility(app) == "internal":
        remove_route(app["name"], app)
        return
    if site.is_symlink() or (site.exists() and not site.is_file()):
        raise Bad("refusing unexpected route path")
    old = site.read_text() if site.exists() else None
    site.write_text(render_site(app))
    try:
        run(["docker", "exec", EDGE, "caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"], timeout=60)
        run(["docker", "exec", EDGE, "caddy", "reload", "--config", "/etc/caddy/Caddyfile"], timeout=60)
    except Bad as err:
        if old is None:
            site.unlink()
        else:
            site.write_text(old)
        run(["docker", "exec", EDGE, "caddy", "reload", "--config", "/etc/caddy/Caddyfile"], check=False)
        raise Bad("route change rejected by Caddy and rolled back: " + str(err)[-300:])


def set_route(body, name):
    if EDGE_MODE == "external":
        raise Bad("routes are managed by the external proxy in this install (OC_EDGE_MODE=external)")
    app = load(name)
    if visibility(app) == "internal":
        raise Bad("this app is internal (no edge route); set it to external first")
    taken = {CONSOLE_HOST, os.environ.get("OC_S3_HOST", "s3." + APPS_DOMAIN)}
    for other in app_list():
        if other["name"] != name:
            taken.update(hosts(other))
    domains = [d.strip().lower() for d in str(body.get("domains", "")).replace(",", " ").split() if d.strip()]
    if len(domains) > 10 or len(set(domains)) != len(domains):
        raise Bad("up to 10 distinct custom domains")
    for d in domains:
        if not HOST.match(d) or d in taken or d == f"{name}.{APPS_DOMAIN}":
            raise Bad(f"invalid or already used domain: {d}")
    path = str(body.get("health_path") or "")
    if path and not HEALTH_PATH.match(path):
        raise Bad("health check path must look like /health")
    try:
        interval, canary = int(body.get("health_interval") or 30), int(body.get("canary_weight") or 0)
    except ValueError:
        raise Bad("interval and canary weight must be integers")
    if not 5 <= interval <= 300:
        raise Bad("health check interval 5-300 seconds")
    if not 0 <= canary <= 50:
        raise Bad("canary weight 0-50 percent")
    canary = round(canary / 5) * 5
    if canary and not app.get("previous_tag"):
        raise Bad("canary needs a previous release (deploy twice first)")
    old_canary = route_cfg(app)["canary_weight"]
    app["route"] = {"domains": domains, "redirect": bool(body.get("redirect")), "health_path": path,
                    "health_interval": interval, "canary_weight": canary}
    if bool(canary) != bool(old_canary):
        up(app, build=False)  # start or stop the previous-version container, then route
    else:
        route(app)
    save(app)
    return {"ok": True, "route": app["route"]}


def parse_openapi(raw):
    """Untrusted spec -> list of {method, path, summary}. Strings are kept as plain text, capped."""
    if len(raw) > SPEC_MAX:
        raise Bad("spec larger than 1 MB")
    try:
        spec = json.loads(raw)
    except ValueError:
        raise Bad("spec is not JSON")
    paths = spec.get("paths") if isinstance(spec, dict) else None
    if not isinstance(paths, dict):
        raise Bad("spec has no paths object")
    out = []
    for path, ops in list(paths.items())[:300]:
        if not isinstance(ops, dict):
            continue
        for m in METHODS:
            op = ops.get(m)
            if isinstance(op, dict):
                summary = op.get("summary") or op.get("operationId") or ""
                out.append({"method": m.upper(), "path": str(path)[:200], "summary": str(summary)[:200]})
    return out


def api_cfg(app):
    return {"spec_path": "/openapi.json", "source": None, "endpoints": [], "checks": {}, **app.get("api", {})}


def discover_api(body, name):
    app = load(name)
    spec_path = str(body.get("spec_path") or "/openapi.json")
    if not PROBE_PATH.match(spec_path):
        raise Bad("spec path must look like /openapi.json")
    # Fetched from the edge over the internal network only, with a timeout and a size cap.
    r = edge(f"wget -q -O - -T 5 http://app-{name}:{app['port']}{spec_path} | head -c {SPEC_MAX + 1}", timeout=15)
    if not r.stdout:
        raise Bad("could not fetch the spec from the app")
    api = api_cfg(app)
    manual = [x for x in api["endpoints"] if x.get("manual")]
    api.update(spec_path=spec_path, source="openapi", endpoints=parse_openapi(r.stdout) + manual)
    app["api"] = api
    save(app)
    return {"ok": True, "count": len(api["endpoints"])}


def add_api_endpoint(body, name):
    app = load(name)
    method, path = str(body.get("method", "GET")).upper(), str(body.get("path", ""))
    if method.lower() not in METHODS or not API_PATH.match(path):
        raise Bad("method GET/POST/PUT/PATCH/DELETE and a path like /items/{id}")
    api = api_cfg(app)
    api["endpoints"].append({"method": method, "path": path, "summary": str(body.get("summary", ""))[:200], "manual": True})
    api["source"] = api["source"] or "manual"
    app["api"] = api
    save(app)
    return {"ok": True}


def set_api_check(body, name):
    """Only plain GET paths the admin marks are ever probed."""
    app = load(name)
    path, on = str(body.get("path", "")), bool(body.get("enabled"))
    api = api_cfg(app)
    if on and not (PROBE_PATH.match(path) and any(x["method"] == "GET" and x["path"] == path for x in api["endpoints"])):
        raise Bad("only listed GET endpoints without parameters can be health checks")
    if on:
        api["checks"][path] = api["checks"].get(path) or {"code": None, "ms": None, "checked": None}
    else:
        api["checks"].pop(path, None)
    app["api"] = api
    save(app)
    probe_app(name)
    return {"ok": True}


def probe_app(name):
    with PROBE_LOCK:
        app = load(name)
        api = api_cfg(app)
        for path in api["checks"]:
            r = edge(f"time wget -S -q -O /dev/null -T 5 http://app-{name}:{app['port']}{path} 2>&1", timeout=15)
            code = re.search(r"HTTP/[0-9.]+ ([0-9]{3})", r.stdout)
            t = re.search(r"real\s+([0-9]+)m\s*([0-9.]+)s", r.stdout)
            api["checks"][path] = {"code": int(code.group(1)) if code else None,
                                   "ms": round((int(t.group(1)) * 60 + float(t.group(2))) * 1000) if t else None,
                                   "checked": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        app["api"] = api
        save(app)


def probe_loop():
    while True:
        time.sleep(int(os.environ.get("OC_API_PROBE_INTERVAL", "60")))
        for p in (ROOT / "apps").glob("*/app.json"):
            try:
                if json.loads(p.read_text()).get("api", {}).get("checks"):
                    probe_app(p.parent.name)
            except (Bad, OSError, ValueError, subprocess.TimeoutExpired):
                pass


def probe_now(body, name):
    probe_app(name)
    return {"ok": True}


def app_map(body, name):
    app = load(name)
    fmt = '{{.Name}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}'
    states = {}
    for line in run(["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project=oc-app-{name}", "--format", "{{.Names}}"]).stdout.split():
        n, st, h = run(["docker", "inspect", "--format", fmt, line]).stdout.strip().split("|")
        states[n.lstrip("/").rsplit("-", 2)[-2]] = {"status": st, "health": h}
    rt = next((r for r in routes() if r["app"] == name), None)
    gw = gw_config()
    return {"app": name, "commit": app.get("commit"), "services": states, "route": rt,
            "db": app.get("db", False),
            "buckets": [b["bucket"] for b in buckets() if b["app"] == name],
            "endpoints": sorted(n for n, e in gw["endpoints"].items() if name in e["apps"]),
            "gateway_key": (secret_dir(name) / "LLM_GATEWAY_KEY").exists(),
            "api": api_cfg(app)}


def edge(cmd, timeout=10):
    return run(["docker", "exec", EDGE, "sh", "-c", cmd], check=False, timeout=timeout)


def routes(body=None):
    if EDGE_MODE == "external":
        return []
    out = []
    for a in app_list():
        if visibility(a) == "internal":
            continue  # no edge route, so no domain or certificate to show
        r = route_cfg(a)
        probe = edge(f"wget -q -O /dev/null -T 3 http://app-{a['name']}:{a['port']}{r['health_path'] or '/'} && echo ok")
        tls = {h: ("issued" if edge(f"ls -d /data/caddy/certificates/*/{h}").returncode == 0 else "pending") for h in hosts(a)}
        out.append({"app": a["name"], "hosts": hosts(a), "commit": a.get("commit"), "image_tag": a.get("image_tag"),
                    "previous_tag": a.get("previous_tag"), "route": r, "tls": tls,
                    "health": "healthy" if probe.stdout.strip() == "ok" else "unhealthy"})
    return out


def record(app, action):
    d = ROOT / "releases" / app["name"]
    d.mkdir(parents=True, exist_ok=True)
    rel = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "action": action,
           "image_tag": app["image_tag"], "commit": app.get("commit"), "repo": app["repo"]}
    (d / f"{time.time_ns()}.json").write_text(json.dumps(rel))
    return rel


# ---- actions ---------------------------------------------------------------

def start_job(kind, name, fn, *args):
    with LOCK:
        if name in BUSY:
            raise Bad("a job is already running for this app")
        BUSY.add(name)
    jid = f"{time.time_ns():x}"
    job = {"id": jid, "kind": kind, "app": name, "status": "running",
           "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    path = ROOT / "jobs" / f"{jid}.json"
    path.write_text(json.dumps(job))

    def work():
        try:
            job["result"] = fn(*args)
            job["status"] = "succeeded"
        except Exception as e:  # report every failure on the job page
            job["status"], job["error"] = "failed", str(e)[-1500:]
        finally:
            job["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            # Publish the final status before releasing the app, so a delete cannot
            # mark the job and then lose that mark to this write.
            with LOCK:
                path.write_text(json.dumps(job))
                BUSY.discard(name)
    threading.Thread(target=work, daemon=True).start()
    return job


def jobs(body=None):
    return [json.loads(p.read_text()) for p in sorted((ROOT / "jobs").glob("*.json"), reverse=True)[:50]]


def job(body, jid):
    p = ROOT / "jobs" / f"{jid}.json"
    if not re.fullmatch(r"[0-9a-f]{1,20}", jid) or not p.exists():
        raise Bad("no such job")
    return json.loads(p.read_text())


def deploy(body, name=None):
    if name:  # redeploy existing app from its repo or server folder
        app = load(name)
    else:
        name = body.get("name", "")
        app_dir(name)
        if (app_dir(name) / "app.json").exists():
            raise Bad("app already exists")
        app = {"name": name, "repo": "", "ref": "", "db": False, "image_tag": None}
        if body.get("source") == "folder":
            folder = under_root(body.get("folder"), allow("OC_LOCAL_SOURCES"), "source folder")
            if not folder.is_dir():
                raise Bad("source folder is not a folder")
            app["folder"] = str(folder)
        else:
            repo = body.get("repo", "")
            if not REPO.match(repo) or ".." in repo:
                raise Bad("repo must be a public https Git URL")
            ref = body.get("ref") or ""
            if ref and not REF.match(ref):
                raise Bad("invalid ref")
            app["repo"], app["ref"] = repo, ref
        if body.get("dockerfile"):
            if not DOCKERFILE.match(body["dockerfile"]) or ".." in body["dockerfile"].split("/"):
                raise Bad("invalid Dockerfile path")
            app["dockerfile"] = body["dockerfile"]
        port = int(body.get("port") or 8080)
        if not 1 <= port <= 65535:
            raise Bad("invalid port")
        app["port"] = port
        app["visibility"] = parse_visibility(body.get("visibility"))
        app.update(parse_settings({k: body[k] for k in ("networks", "secret_mounts", "data_mounts", "env") if body.get(k)}))
        for net in app.get("networks", []):
            if run(["docker", "network", "inspect", net], check=False).returncode:
                raise Bad(f"network {net} doesn't exist")
        save(app)
    return start_job("deploy", name, build_release, app)


def build_release(app):
    name = app["name"]
    d = app_dir(name)
    src = d / "src"
    shutil.rmtree(src, ignore_errors=True)
    if app.get("folder"):  # re-checked on every build: the allowlist may have changed
        snapshot_folder(under_root(app["folder"], allow("OC_LOCAL_SOURCES"), "source folder"), src)
    else:
        args = ["git", "clone", "--depth", "1"] + (["--branch", app["ref"]] if app["ref"] else []) + ["--", app["repo"], str(src)]
        genv = {"GIT_TERMINAL_PROMPT": "0", "PATH": os.environ["PATH"]}
        ca = os.environ.get("OC_GIT_SSL_CAINFO", "")
        if ca and Path(ca).exists():  # optional private CA for an internal HTTPS git server
            genv["GIT_SSL_CAINFO"] = ca
        run(args, timeout=300, env=genv)
    if not dockerfile_path(src, app.get("dockerfile")).exists():
        raise Bad(f"no {app.get('dockerfile') or 'Dockerfile'} in the source")
    r = run(["git", "-c", "safe.directory=*", "-C", str(src), "rev-parse", "--short", "HEAD"], check=False)
    commit = r.stdout.strip() if not r.returncode and r.stdout.strip() else "local"
    (ROOT / "data" / name).mkdir(parents=True, exist_ok=True)
    secret_dir(name)
    app["previous_tag"], app["image_tag"], app["commit"] = app.get("image_tag"), f"{commit}-{int(time.time())}", commit
    save(app)
    up(app, build=True)
    return record(app, "deploy")


def rollback(body, name):
    app = load(name)
    if not app.get("previous_tag"):
        raise Bad("no previous release to roll back to")
    return start_job("rollback", name, do_rollback, app)


def do_rollback(app):
    app["image_tag"], app["previous_tag"] = app["previous_tag"], app["image_tag"]
    save(app)
    up(app, build=False)
    return record(app, "rollback")


def create_db(body, name):
    app = load(name)
    if app.get("db"):
        raise Bad("database already exists")
    pw = secrets.token_urlsafe(24)
    ddir = ROOT / "secrets" / "db"
    ddir.mkdir(parents=True, exist_ok=True, mode=0o700)
    write_secret(ddir / name, pw, (POSTGRES_UID, POSTGRES_UID))
    rpw = secrets.token_urlsafe(24)
    write_secret(runtime_pw_file(name), rpw, (POSTGRES_UID, POSTGRES_UID))
    # The app gets only the runtime role; the admin password stays with the DB container.
    write_secret(secret_dir(name) / "DATABASE_URL", f"postgresql://{RUNTIME_ROLE}:{rpw}@db:5432/app")
    (ROOT / "pgdata" / name).mkdir(parents=True, exist_ok=True)
    app["db"] = True
    save(app)
    up(app, build=False)
    return {"ok": True, "secret": "DATABASE_URL"}


def set_limits(body, name):
    app = load(name)
    try:
        mem, cpus = int(body.get("memory_mb", 0)), round(float(body.get("cpus", 0)), 2)
    except (TypeError, ValueError):
        raise Bad("memory_mb must be an integer and cpus a number")
    if not 64 <= mem <= 65536 or not 0.1 <= cpus <= (os.cpu_count() or 1):
        raise Bad(f"memory 64-65536 MB, CPUs 0.1-{os.cpu_count()}")
    app["memory_mb"], app["cpus"] = mem, cpus
    save(app)
    up(app, build=False)
    return {"ok": True, "memory_mb": mem, "cpus": cpus}


def set_secret(body, name):
    load(name)
    key, value = body.get("key", ""), body.get("value", "")
    if not KEY.match(key) or not value or len(value) > 65536:
        raise Bad("secret name must be UPPER_SNAKE_CASE and value non-empty")
    write_secret(secret_dir(name) / key, value)
    up(load(name), build=False)
    return {"ok": True, "key": key}


GENERIC_GATEWAY = os.environ.get("OC_GENERIC_GATEWAY", "0") == "1"


def enable_ai(body, name):
    if not GENERIC_GATEWAY:
        raise Bad("the generic gateway is turned off (OC_GENERIC_GATEWAY=0); give the app the provider key instead")
    load(name)
    key = "ocg_" + secrets.token_urlsafe(32)
    gdir = ROOT / "secrets" / "gateway-clients"
    gdir.mkdir(parents=True, exist_ok=True)
    write_secret(gdir / name, key, (GATEWAY_UID, GATEWAY_UID))
    write_secret(secret_dir(name) / "LLM_GATEWAY_KEY", key)
    write_secret(secret_dir(name) / "LLM_GATEWAY_URL", "http://llm-gateway:8000/v1")
    up(load(name), build=False)
    return {"ok": True}


def s3_config_path():
    return ROOT / "secrets" / "storage" / "s3.json"


def s3_config():
    return json.loads(s3_config_path().read_text())


def restart_storage():
    run(["docker", "restart", STORAGE], timeout=120)
    for _ in range(60):
        h = run(["docker", "inspect", "-f", "{{.State.Health.Status}}", STORAGE]).stdout.strip()
        if h == "healthy":
            return
        time.sleep(1)
    raise Bad("object storage did not become healthy")


def create_bucket(body, name):
    app = load(name)
    bucket = body.get("bucket", "")
    if not BUCKET.match(bucket) or bucket == SITE_BUCKET:
        raise Bad("bucket names: 3-63 chars, a-z, 0-9 and -")
    with LOCK:
        cfg = s3_config()
        if any(a.endswith(":" + bucket) for i in cfg["identities"] for a in i["actions"]):
            raise Bad("bucket already exists")
        r = run(["docker", "exec", "-i", STORAGE, "weed", "shell"], input=f"s3.bucket.create -name {bucket}\n", timeout=60)
        if "created bucket" not in r.stdout + r.stderr:
            raise Bad("bucket create failed")
        ident = next((i for i in cfg["identities"] if i["name"] == "app-" + name), None)
        if not ident:
            ident = {"name": "app-" + name, "actions": [],
                     "credentials": [{"accessKey": "OC" + secrets.token_hex(9).upper(), "secretKey": secrets.token_urlsafe(30)}]}
            cfg["identities"].append(ident)
        ident["actions"] += [f"{a}:{bucket}" for a in ("Read", "Write", "List", "Tagging")]
        tmp = s3_config_path().with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, indent=2))
        os.chmod(tmp, 0o600)
        os.chown(tmp, 1000, 1000)  # SeaweedFS image user
        tmp.replace(s3_config_path())
    cred = ident["credentials"][0]
    sd = secret_dir(name)
    for k, v in {"S3_ACCESS_KEY_ID": cred["accessKey"], "S3_SECRET_ACCESS_KEY": cred["secretKey"],
                 "S3_ENDPOINT": "http://storage:8333", "S3_PUBLIC_ENDPOINT": "https://" + os.environ.get("OC_S3_HOST", "s3." + APPS_DOMAIN)}.items():
        write_secret(sd / k, v)
    restart_storage()
    up(app, build=False)
    return {"ok": True, "bucket": bucket}


def buckets(body=None):
    out = []
    for i in s3_config()["identities"]:
        if i["name"].startswith("app-"):
            out += [{"bucket": a.split(":", 1)[1], "app": i["name"][4:]} for a in i["actions"] if a.startswith("Read:")]
    return out


def audit_path():
    return ROOT / "audit" / "audit.log"


def audit_append(body):
    """Append-only, hash-chained log: a local consistency check, not tamper-proof (root can rewrite it). No API edits or deletes."""
    entry = {k: str(body.get(k, ""))[:300] for k in ("event", "ip", "target", "outcome")}
    entry["time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with LOCK:
        p = audit_path()
        last = p.read_text().splitlines()[-1] if p.exists() and p.stat().st_size else ""
        entry["prev"] = hashlib.sha256(last.encode()).hexdigest()
        fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
    return {"ok": True}


def audit_read(body=None):
    p = audit_path()
    lines = p.read_text().splitlines() if p.exists() else []
    prev, intact = "", True
    for line in lines:
        intact &= json.loads(line)["prev"] == hashlib.sha256(prev.encode()).hexdigest()
        prev = line
    return {"intact": intact, "count": len(lines), "entries": [json.loads(x) for x in lines[-200:]][::-1]}


def gw_dir():
    return ROOT / "gateway"


def gw_config():
    p = gw_dir() / "config.json"
    return json.loads(p.read_text()) if p.exists() else {"upstream_url": "", "endpoints": {}}


def gw_save(cfg):
    tmp = gw_dir() / "config.json.tmp"
    tmp.write_text(json.dumps(cfg, indent=2))
    os.chown(tmp, GATEWAY_UID, GATEWAY_UID)
    tmp.replace(gw_dir() / "config.json")


def upstream_key_file():
    return ROOT / "secrets" / "platform" / "llm-upstream-key"


def provider_key():
    kf = upstream_key_file()
    return kf.read_text().strip() if kf.exists() else ""


def inject_provider_key(app):
    """Apps that declare provider_key_env get the Open Bedrock provider key as /run/secrets/<ENV> (removed when unset)."""
    env = app.get("provider_key_env")
    if not env:
        return
    f, key = secret_dir(app["name"]) / env, provider_key()
    if key:
        write_secret(f, key)
    else:
        f.unlink(missing_ok=True)


def set_provider_key_env(body, name):
    app = load(name)
    env, old = str(body.get("env", "")).strip(), app.get("provider_key_env")
    if env and not KEY.match(env):
        raise Bad("env name must be UPPER_SNAKE_CASE")
    if env and env != old and (secret_dir(name) / env).exists():
        raise Bad(f"{env} is already one of this app's own secrets")
    if old and old != env:
        (secret_dir(name) / old).unlink(missing_ok=True)
    if env:
        app["provider_key_env"] = env
    else:
        app.pop("provider_key_env", None)
    save(app)
    up(app, build=False)
    return {"ok": True, "env": env}


def gateway_state(body=None):
    usage_file = gw_dir() / "usage.json"
    kf = upstream_key_file()
    return {**gw_config(), "provider_key_set": kf.exists() and kf.stat().st_size > 0,
            "provider_key_apps": [a["name"] for a in app_list() if a.get("provider_key_env")],
            "usage": json.loads(usage_file.read_text()) if usage_file.exists() else {},
            "apps": [a["name"] for a in app_list() if "LLM_GATEWAY_KEY" in a["secrets"]]}


def set_provider(body):
    provider = str(body.get("provider", "")).strip()
    if provider and provider not in PROVIDERS:
        raise Bad("provider must be one of: " + ", ".join(PROVIDERS))
    url = str(body.get("upstream_url", "")).strip() or PROVIDERS.get(provider, "")
    if url and not UPSTREAM.match(url):
        raise Bad("provider URL must be http(s)://host[:port]/path")
    key = str(body.get("key", ""))
    if len(key) > 500 or any(c.isspace() for c in key):
        raise Bad("invalid provider key")
    with LOCK:
        cfg = gw_config()
        cfg["upstream_url"] = url
        if provider:
            cfg["provider"] = provider
        changed = bool(key or body.get("clear_key"))
        if changed:
            cfg["key_updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        gw_save(cfg)
        if changed:
            # Rewrite in place: the gateway bind-mounts this one file, and an atomic rename would leave it
            # reading the old inode until restarted.
            kf = upstream_key_file()
            fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
            with os.fdopen(fd, "w") as f:
                f.write(key)
            os.chown(kf, GATEWAY_UID, GATEWAY_UID)
            os.chmod(kf, 0o400)
    if changed:  # apps that consume the key restart with the new value
        for a in app_list():
            if a.get("provider_key_env"):
                up(load(a["name"]), build=False, recreate=True)
    return {"ok": True, "provider_key_set": gateway_state()["provider_key_set"]}


def set_endpoint(body):
    name = str(body.get("name", ""))
    if not ENDPOINT.match(name):
        raise Bad("endpoint names: 2-41 chars, a-z, 0-9, . and -")
    with LOCK:
        cfg = gw_config()
        if body.get("delete"):
            cfg["endpoints"].pop(name, None)
        else:
            model = str(body.get("model", ""))
            if not MODEL_ID.match(model):
                raise Bad("invalid provider model id")
            try:
                rpm = int(body.get("rpm") or 60)
            except ValueError:
                raise Bad("rate limit must be an integer")
            if not 1 <= rpm <= 10000:
                raise Bad("rate limit 1-10000 requests/minute per app")
            apps = sorted({a.strip() for a in str(body.get("apps", "")).replace(",", " ").split() if a.strip()})
            known = {a["name"] for a in app_list()}
            if any(a not in known for a in apps):
                raise Bad("unknown app in list")
            cfg["endpoints"][name] = {"model": model, "rpm": rpm, "apps": apps}
        gw_save(cfg)
    return {"ok": True}


def site_domains():
    """Domains served by hand-written site-*.caddy files, per app (from `reverse_proxy app-<name>:<port>`)."""
    out = {}
    for f in sorted((ROOT / "caddy" / "sites").glob("site-*.caddy")):
        hosts = []
        for ln in f.read_text().splitlines():
            if ln and not ln[0].isspace() and ln.rstrip().endswith("{") and not ln.startswith(("(", "#")):
                hosts = [h.strip() for h in ln.rstrip()[:-1].split(",") if h.strip()]
            m = re.search(r"reverse_proxy\s+app-([a-z][a-z0-9-]{1,30}):", ln)
            if m and hosts:
                out.setdefault(m.group(1), [])
                out[m.group(1)] += [h for h in hosts if h not in out[m.group(1)]]
    return out


REDACT_BLOCKS = ("basic_auth", "basicauth", "forward_auth")
SECRET_WORDS = re.compile(r"auth|token|secret|passw|api[-_]?key|cookie|bearer", re.I)
SECRET_LIKE = re.compile(r"\$2[aby]\$\S+|(?<![\w/])(?!/)(?=[A-Za-z0-9+/_=-]*\d)[A-Za-z0-9+/_=-]{32,}")  # hashes, long keys (not paths)


def redact_caddy(text):
    """Caddy config safe to show: auth blocks, auth/token lines, {env.*} and long secret-like strings removed."""
    out, skip = [], 0
    for ln in text.splitlines():
        if skip:
            skip += ln.count("{") - ln.count("}")
            continue
        body = ln.strip()
        word = body.split()[0] if body else ""
        indent = ln[:len(ln) - len(ln.lstrip())]
        if word in REDACT_BLOCKS or (SECRET_WORDS.search(body) and not body.endswith("{")):
            out.append(f"{indent}{word} [redacted]")
            skip = ln.count("{") - ln.count("}") if word in REDACT_BLOCKS else 0
            continue
        out.append(SECRET_LIKE.sub("[redacted]", re.sub(r"\{env\.[^}]*\}", "{env.[redacted]}", ln)))
    return "\n".join(out) + "\n"


def edge_config(body=None):
    """Every edge site file, redacted. `managed` files are written by Open Cloud; the rest are hand-written."""
    out = []
    for f in sorted((ROOT / "caddy" / "sites").glob("*.caddy")):
        text, targets = f.read_text(), []
        for ln in text.splitlines():
            w = ln.split()
            if w and w[0] == "reverse_proxy":
                targets += [t for t in w[1:] if t != "{" and t not in targets]
            elif w and w[0] in ("file_server", "redir") and w[0] not in targets:
                targets.append(w[0])
        site = f.stem.removeprefix("site-static-")
        out.append({"file": f.name, "hosts": caddy_hosts(f), "targets": targets, "config": redact_caddy(text),
                    "app": f.stem if (ROOT / "apps" / f.stem / "app.json").exists() else "",
                    "site": site if f.stem != site and (ROOT / "sites" / site / "site.json").exists() else ""})
        out[-1]["managed"] = bool(out[-1]["app"] or out[-1]["site"])
    return out


def app_list(body=None):
    out, sites = [], site_domains()
    for p in sorted((ROOT / "apps").glob("*/app.json")):
        a = json.loads(p.read_text())
        a["site_domains"] = sites.get(a["name"], [])
        a["url"] = (f"https://{a['site_domains'][0]}" if a["site_domains"] else
                    "" if visibility(a) == "internal" else f"https://{a['name']}.{APPS_DOMAIN}")
        a["secrets"] = sorted(x.name for x in secret_dir(a["name"]).iterdir())
        out.append(a)
    return out


def releases(body, name):
    d = ROOT / "releases" / name
    load(name)
    return [json.loads(p.read_text()) for p in sorted(d.glob("*.json"), reverse=True)[:20]]


def logs(body, name):
    load(name)
    r = run(["docker", "compose", "-f", str(app_dir(name) / "compose.yaml"), "logs", "--no-color", "--tail", "200"], check=False)
    return {"logs": (r.stdout + r.stderr)[-60000:]}


def status(body=None):
    fmt = '{{json .Name}}|{{json .State.Status}}|{{if .State.Health}}{{json .State.Health.Status}}{{else}}"none"{{end}}|{{json .RestartCount}}'
    ids = run(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project"]).stdout.split()
    containers = []
    if ids:
        for line in run(["docker", "inspect", "--format", fmt, *ids]).stdout.splitlines():
            n, s, h, r = [json.loads(x) for x in line.split("|")]
            if n.lstrip("/").startswith("oc-"):
                containers.append(dict(name=n.lstrip("/"), status=s, health=h, restarts=r))
    disk = shutil.disk_usage(ROOT)
    mem = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        k, v = line.split(":", 1)
        mem[k] = int(v.split()[0]) * 1024
    last = ROOT / "backups" / "last-success"
    return {"containers": containers, "disk_used": disk.used, "disk_total": disk.total,
            "mem_total": mem["MemTotal"], "mem_available": mem["MemAvailable"],
            "load": os.getloadavg(), "last_backup": last.read_text().strip() if last.exists() else None}


def observed_containers():
    """Read-only: containers Open Cloud doesn't manage, via `docker ps/inspect/stats` only."""
    fmt = ('{{json .Name}}|{{json (index .Config.Labels "com.docker.compose.project")}}|{{json .Config.Image}}|{{json .State.Status}}|'
           '{{if .State.Health}}{{json .State.Health.Status}}{{else}}"none"{{end}}|{{json .RestartCount}}|{{json .HostConfig.Memory}}')
    ids = run(["docker", "ps", "-aq"]).stdout.split()
    out = {}
    if ids:
        for line in run(["docker", "inspect", "--format", fmt, *ids]).stdout.splitlines():
            n, proj, img, st, h, rc, mem = [json.loads(x) for x in line.split("|")]
            n = n.lstrip("/")
            if not n.startswith("oc-"):
                out[n] = dict(name=n, project=proj or "", image=img, status=st, health=h, restarts=int(rc), mem_limit=mem, cpu=0.0, mem=0.0)
    running = [n for n, c in out.items() if c["status"] == "running"]
    if running:
        for line in run(["docker", "stats", "--no-stream", "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemPerc}}", *running], timeout=60).stdout.splitlines():
            n, c, m = line.split("|")
            if n in out:
                out[n].update(cpu=float(c.rstrip("%") or 0), mem=float(m.rstrip("%") or 0))
    return [out[n] for n in sorted(out)]


STATUS_KEYS = ("updated", "backup_last_success", "backup_last_download", "backup_last_restore", "backup_last_check",
               "backup_mode", "warnings", "alerts_email_configured")


def platform_status():
    """Optional read-only mounts: status.json (known keys only) and backup marker files (first line only)."""
    st = None
    p = OBSERVE_DIR / "status.json"
    if p.is_file():
        try:
            raw = json.loads(p.read_text()[:200000])
            st = {k: raw[k] for k in STATUS_KEYS if k in raw}
        except ValueError:
            st = {"error": "status.json is not valid JSON"}
    markers = {}
    if OBSERVE_DIR.is_dir():
        for m in sorted(OBSERVE_DIR.glob("backup-*")):
            if m.is_file():
                markers[m.name] = (m.read_text()[:200].splitlines() or [""])[0].strip()
    return {"status": st, "markers": markers}


def observed(body=None):
    return {"containers": observed_containers(), "platform": platform_status()}


def restic(*args, timeout=1800):
    env = {"PATH": os.environ["PATH"], "RESTIC_REPOSITORY": str(ROOT / "backups" / "restic"),
           "RESTIC_PASSWORD_FILE": str(ROOT / "secrets" / "platform" / "restic-password"),
           "RESTIC_CACHE_DIR": str(ROOT / "backups" / ".cache")}
    return run(["restic", *args], timeout=timeout, env=env)


def backup(body=None):
    try:
        return do_backup()
    except Exception:
        (ROOT / "backups" / "last-failure").write_text(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        raise


def do_backup():
    repo = ROOT / "backups" / "restic"
    if not (repo / "config").exists():
        restic("init")
    pg = ROOT / "backups" / "postgres"
    pg.mkdir(parents=True, exist_ok=True, mode=0o700)
    names = run(["docker", "ps", "--filter", "label=opencloud.backup=postgres", "--format", "{{.Names}}"]).stdout.split()
    for c in names:
        if not c.startswith("oc-"):
            raise Bad(f"refusing to back up {c}: not an Open Cloud container")
        dump = run(["docker", "exec", c, "sh", "-c", 'exec pg_dumpall -U "$POSTGRES_USER"']).stdout
        tmp = pg / f"{c}.sql.tmp"
        tmp.write_text(dump)
        tmp.replace(pg / f"{c}.sql")
    # Raw live PGDATA is excluded; the logical dumps above are backed up instead.
    restic("backup", "--tag", "opencloud", str(ROOT / "apps"), str(ROOT / "data"), str(ROOT / "secrets"),
           str(pg), str(ROOT / "caddy"), str(ROOT / "storage"), str(ROOT / "audit"), "--exclude", str(ROOT / "apps" / "*" / "src"))
    restic("forget", "--keep-daily", os.environ.get("OC_BACKUP_KEEP_DAILY", "7"), "--prune")
    (ROOT / "backups" / "last-success").write_text(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    return {"ok": True, "databases": len(names)}


def snapshots(body=None):
    if not (ROOT / "backups" / "restic" / "config").exists():
        return []
    return json.loads(restic("snapshots", "--json").stdout or "[]")


# ---- Open CloudWatch feed (read-only; the watch service's token can call only these) --------

WATCH_ALLOWED = {("GET", "/watch-stats"), ("POST", "/watch-logs"), ("GET", "/audit"), ("POST", "/audit"), ("GET", "/jobs")}


def watch_allowed(method, path):
    return (method, path.split("?")[0]) in WATCH_ALLOWED


def iso_ts(path):
    try:
        return calendar.timegm(time.strptime(path.read_text().strip(), "%Y-%m-%dT%H:%M:%SZ"))
    except (OSError, ValueError):
        return 0


def container_app(name):
    m = re.fullmatch(r"oc-app-([a-z][a-z0-9-]{1,30})-(web|db|prev)-[0-9]+", name)
    return m.group(1) if m else ""


def split_log_line(line):
    stamp, _, text = line.partition(" ")
    m = re.fullmatch(r"([0-9-]{10}T[0-9:]{8})(\.[0-9]+)?Z", stamp)
    if not m:
        return None, line
    return calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")) + float(m.group(2) or 0), text


def watch_stats(body=None):
    fmt = '{{.Name}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.RestartCount}}'
    info, stats = {}, {}
    ids = run(["docker", "ps", "-aq", "--filter", "name=^oc-app-"]).stdout.split()
    if ids:
        for line in run(["docker", "inspect", "--format", fmt, *ids]).stdout.splitlines():
            n, st, h, rc = line.split("|")
            info[n.lstrip("/")] = (st, h, int(rc))
    running = [n for n, v in info.items() if v[0] == "running"]
    if running:
        for line in run(["docker", "stats", "--no-stream", "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemPerc}}", *running], timeout=60).stdout.splitlines():
            n, c, m = line.split("|")
            stats[n] = (float(c.rstrip("%") or 0), float(m.rstrip("%") or 0))
    apps = {}
    for a in app_list():
        n, web = a["name"], f"oc-app-{a['name']}-web-1"
        st, h, rc = info.get(web, ("missing", "none", 0))
        checks = [c for c in api_cfg(a)["checks"].values() if c.get("checked")]
        cpu, mem = stats.get(web, (0.0, 0.0))
        apps[n] = {"status": st, "health": h, "restarts": rc, "cpu": round(cpu / float(a.get("cpus", 1.0)), 2), "mem": mem,
                   "latency_ms": max((c["ms"] for c in checks if c.get("ms") is not None), default=None),
                   "probe_code": checks[0]["code"] if checks else None,
                   "healthy": st == "running" and h in ("healthy", "none") and all(c["code"] and c["code"] < 400 for c in checks)}
    disk = shutil.disk_usage(ROOT)
    usage = gw_dir() / "usage.json"
    extra = {"observed": observed_containers()} if OBSERVE else {}
    return {**extra, "apps": apps, "disk_pct": round(disk.used / disk.total * 100, 2), "disk_used": disk.used, "disk_total": disk.total,
            "backup": {"last_success": iso_ts(ROOT / "backups" / "last-success"), "last_failure": iso_ts(ROOT / "backups" / "last-failure")},
            "usage": json.loads(usage.read_text()) if usage.exists() else {}}


def watch_logs(body):
    """Container log lines since a unix time, at most 2000 per container. The watch service redacts before storing."""
    since = float(body.get("since") or 0)
    out = []
    names = run(["docker", "ps", "-a", "--format", "{{.Names}}"] + ([] if OBSERVE else ["--filter", "name=^oc-"])).stdout.split()
    for name in names:
        r = run(["docker", "logs", "--timestamps", "--since", f"{since:.6f}", name], check=False, timeout=30)
        lines = [ln for ln in (r.stdout + r.stderr).splitlines() if ln.strip()][-2000:]
        for ln in lines:
            ts, text = split_log_line(ln)
            if ts and ts > since:
                out.append({"ts": ts, "container": name, "app": container_app(name), "text": text[:4000]})
    return {"lines": sorted(out, key=lambda x: x["ts"])}


# ---- Static sites ----------------------------------------------------------------------------------
# Files live in the private `sites` bucket (prefix <name>/<release>/, only the admin identity can read it).
# The agent also unpacks each release to ROOT/sites/<name>/releases/<id> and swaps the `current` symlink;
# the edge serves that folder read-only with file_server. The edge never talks to S3, so no bucket listing,
# other prefix or S3 API is reachable through a site.
SITE_BUCKET = "sites"
SITE_MAX_UPLOAD = 10 * 1024 * 1024        # upload (file or zip) as sent
SITE_MAX_EXTRACTED = 50 * 1024 * 1024     # total unpacked size
SITE_MAX_FILES = 2000
SITE_BODY_MAX = SITE_MAX_UPLOAD * 4 // 3 + 4096   # base64 in JSON
SITE_KEEP = 3
SITE_PATH = re.compile(r"^[A-Za-z0-9._ ~@+-]+(/[A-Za-z0-9._ ~@+-]+)*$")
SINGLE_FILE = (".html", ".htm")
DEFAULT_404 = "<!doctype html><meta charset=utf-8><title>Not found</title><h1>Not found</h1><p>This page doesn't exist.</p>\n"


def body_limit(path):
    return SITE_BODY_MAX if re.fullmatch(r"/sites/[a-z][a-z0-9-]{1,30}/upload", path.split("?")[0]) else 200000


def site_dir(name):
    if not NAME.match(name or ""):
        raise Bad("site names: 2-31 chars, a-z, 0-9 and -, starting with a letter")
    return ROOT / "sites" / name


def site_load(name):
    p = site_dir(name) / "site.json"
    if not p.exists():
        raise LookupError
    return json.loads(p.read_text())


def site_save(s):
    p = site_dir(s["name"]) / "site.json"
    p.with_suffix(".tmp").write_text(json.dumps(s, indent=2))
    p.with_suffix(".tmp").replace(p)


def site_audit(event, name, outcome="ok"):
    audit_append({"event": event, "ip": "agent", "target": f"site={name}", "outcome": outcome})


def site_list(body=None):
    out = []
    for p in sorted((ROOT / "sites").glob("*/site.json")):
        s = json.loads(p.read_text())
        cur = p.parent / "current"
        s["release"] = os.readlink(cur).split("/")[-1] if cur.is_symlink() else ""
        out.append(s)
    return out


def site_create(body):
    name = str(body.get("name", "")).strip()
    d = site_dir(name)
    if d.exists() or name in RESERVED:
        raise Bad("a site with that name already exists")
    (d / "releases").mkdir(parents=True)
    os.chmod(d, 0o755)
    os.chmod(d / "releases", 0o755)
    site_save({"name": name, "domains": [], "tls_internal": False, "visibility": "external",
               "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    site_audit("site-create", name)
    return {"ok": True, "name": name}


def site_files(filename, data):
    """Upload -> {relative path: bytes}. Rejects traversal, absolute paths, symlinks and oversize content."""
    import io, stat, zipfile
    if len(data) > SITE_MAX_UPLOAD:
        raise Bad(f"upload is larger than {SITE_MAX_UPLOAD // 1048576} MB")
    low = filename.lower()
    if low.endswith(SINGLE_FILE):
        return {"index.html": data}
    if not low.endswith(".zip"):
        raise Bad("upload an .html file or a .zip of the site")
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        infos = z.infolist()
    except zipfile.BadZipFile:
        raise Bad("not a valid zip file")
    files, total = {}, 0
    for i in infos:
        n = i.filename
        if stat.S_ISLNK(i.external_attr >> 16):
            raise Bad(f"zip contains a symlink: {n[:80]}")
        if n.endswith("/"):
            continue
        parts = n.split("/")
        if "\\" in n or n.startswith("/") or ":" in n or any(p in ("", ".", "..") for p in parts) or not SITE_PATH.match(n):
            raise Bad(f"unsafe path in zip: {n[:80]}")
        if parts[0] == "__MACOSX" or parts[-1] == ".DS_Store":
            continue
        total += i.file_size
        if total > SITE_MAX_EXTRACTED or len(files) >= SITE_MAX_FILES:
            raise Bad(f"site is larger than {SITE_MAX_EXTRACTED // 1048576} MB or {SITE_MAX_FILES} files")
        with z.open(i) as f:
            content = f.read(SITE_MAX_EXTRACTED + 1)
        if len(content) != i.file_size:
            raise Bad("zip entry size mismatch")
        files[n] = content
    tops = {k.split("/")[0] for k in files}
    if len(tops) == 1 and all("/" in k for k in files):   # one wrapping folder: serve its contents
        files = {k.split("/", 1)[1]: v for k, v in files.items()}
    if "index.html" not in files:
        raise Bad("the site needs an index.html at its top level")
    return files


def site_s3_push(name, rel, src):
    """Copy a release folder into the private bucket at sites/<name>/<rel>/ via the storage container's filer."""
    import io, tarfile
    run(["docker", "exec", "-i", STORAGE, "weed", "shell"], input=f"s3.bucket.create -name {SITE_BUCKET}\n", timeout=60, check=False)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        t.add(src, arcname=rel)
    tmp = f"/tmp/site-{name}-{rel}"
    args = ["docker", "exec", "-i", STORAGE, "sh", "-c",
            f"rm -rf {tmp} && mkdir -p {tmp} && tar -x -C {tmp} && weed filer.copy {tmp}/{rel} "
            f"http://127.0.0.1:8888/buckets/{SITE_BUCKET}/{name}/; rc=$?; rm -rf {tmp}; exit $rc"]
    guard(args)
    r = subprocess.run(args, input=buf.getvalue(), capture_output=True, timeout=300)
    if r.returncode:
        raise Bad("storing the site in object storage failed")


def site_s3_remove(name, rel=None):
    path = f"/buckets/{SITE_BUCKET}/{name}" + (f"/{rel}" if rel else "")
    run(["docker", "exec", "-i", STORAGE, "weed", "shell"], input=f"fs.rm -r {path}\n", timeout=120, check=False)


def site_upload(body, name):
    import base64, binascii
    s = site_load(name)
    filename = os.path.basename(str(body.get("filename", "")))
    try:
        data = base64.b64decode(str(body.get("data", "")), validate=True)
    except (binascii.Error, ValueError):
        raise Bad("upload data must be base64")
    try:
        files = site_files(filename, data)
    except Bad as err:
        site_audit("site-upload", name, "rejected: " + str(err)[:200])
        raise
    files.setdefault("404.html", DEFAULT_404.encode())
    d = site_dir(name)
    rel = time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + f"-{time.time_ns() % 10**9:09d}"   # sorts by time
    staging = d / "releases" / (rel + ".tmp")
    staging.mkdir(mode=0o755)
    try:
        root = staging.resolve()
        for path, content in files.items():
            dst = (staging / path).resolve()
            if root not in dst.parents:
                raise Bad("unsafe path")
            dst.parent.mkdir(parents=True, exist_ok=True)
            for p in [dst.parent, *dst.parent.parents]:
                if p == root.parent:
                    break
                os.chmod(p, 0o755)
            dst.write_bytes(content)
            os.chmod(dst, 0o644)
        site_s3_push(name, rel, staging)
        final = d / "releases" / rel
        staging.rename(final)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        site_audit("site-upload", name, "error")
        raise
    link = d / "current.tmp"
    if link.is_symlink():
        link.unlink()
    os.symlink(f"releases/{rel}", link)
    link.replace(d / "current")            # atomic swap: readers see the old or the new site, never a mix
    for old in sorted(p for p in (d / "releases").iterdir() if not p.name.endswith(".tmp") and p.name != rel)[:-(SITE_KEEP - 1)]:
        shutil.rmtree(old, ignore_errors=True)
        site_s3_remove(name, old.name)
    s["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    site_save(s)
    site_audit("site-upload", name, f"ok release={rel} files={len(files)} bytes={sum(map(len, files.values()))}")
    return {"ok": True, "release": rel, "files": len(files)}


def render_static_site(name, domains, tls_internal=False, www_redirect=False):
    """Caddy block from validated fields only: files from the read-only mount, no listing, no dotfiles.
    www_redirect: www.<d> gets its own block that redirects to <d> when both are attached."""
    www = [d for d in domains if www_redirect and d.startswith("www.") and d[4:] in domains]
    lines = [", ".join(d for d in domains if d not in www) + " {", "\timport security_headers",
             '\theader Permissions-Policy "camera=(), microphone=(), geolocation=()"']
    if tls_internal:
        lines.append("\ttls internal  # preview certificate until DNS points here")
    lines += [f"\troot * /srv/sites/{name}/current", "\trequest_body {", "\t\tmax_size 1KB", "\t}",
              "\t@page path / */ *.html", '\theader @page Cache-Control "no-cache"',
              "\t@asset not path / */ *.html", '\theader @asset Cache-Control "public, max-age=3600"',
              "\tfile_server {", "\t\thide .*", "\t}",
              "\thandle_errors {", '\t\theader Cache-Control "no-cache"', "\t\trewrite * /404.html", "\t\tfile_server {", "\t\t\thide .*", "\t\t}", "\t}", "}", ""]
    for w in www:
        lines[-1:] = [w + " {"] + (["\ttls internal"] if tls_internal else []) + [f"\tredir https://{w[4:]}{{uri}} 301", "}", ""]
    return "\n".join(lines)


def caddy_hosts(path):
    out = []
    for ln in path.read_text().splitlines():
        if ln and not ln[0].isspace() and ln.rstrip().endswith("{") and not ln.startswith(("(", "#")):
            out += [h.strip().removeprefix("http://").removeprefix("https://") for h in ln.rstrip()[:-1].split(",") if h.strip()]
    return out


def edge_apply():
    run(["docker", "exec", EDGE, "caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"], timeout=60)
    run(["docker", "exec", EDGE, "caddy", "reload", "--config", "/etc/caddy/Caddyfile"], timeout=60)


def write_site_file(f, text):
    """Write (or remove, text=None) one edge file; validate and reload; restore the old file on failure."""
    old = f.read_text() if f.exists() else None
    if text is None:
        if old is not None:
            f.unlink()
    else:
        f.write_text(text)
        os.chmod(f, 0o644)
    if EDGE_MODE == "external" or old == text:
        return
    try:
        edge_apply()
    except Bad as err:
        if old is None:
            f.unlink(missing_ok=True)
        else:
            f.write_text(old)
        run(["docker", "exec", EDGE, "caddy", "reload", "--config", "/etc/caddy/Caddyfile"], check=False)
        raise Bad("edge rejected the change and it was rolled back: " + str(err)[-300:])


def site_domains_set(body, name):
    s = site_load(name)
    domains = [d.strip().lower() for d in str(body.get("domains", "")).replace(",", " ").split() if d.strip()]
    if len(domains) > 10 or len(set(domains)) != len(domains):
        raise Bad("up to 10 distinct domains")
    f = ROOT / "caddy" / "sites" / f"site-static-{name}.caddy"
    taken = {CONSOLE_HOST, os.environ.get("OC_S3_HOST", "s3." + APPS_DOMAIN)}
    for other in (ROOT / "caddy" / "sites").glob("*.caddy"):
        if other != f:
            taken.update(caddy_hosts(other))
    for a in app_list():
        taken.update(hosts(a))
    for d in domains:
        if not HOST.match(d) or d in taken:
            raise Bad(f"invalid or already used domain: {d}")
    if domains and not (site_dir(name) / "current").is_symlink():
        raise Bad("upload the site before attaching a domain")
    tls_internal = bool(body.get("tls_internal")) and bool(domains)
    www_redirect = bool(body.get("www_redirect", s.get("www_redirect")))
    write_site_file(f, render_static_site(name, domains, tls_internal, www_redirect) if domains else None)
    s["domains"], s["tls_internal"], s["www_redirect"] = domains, tls_internal, www_redirect
    site_save(s)
    site_audit("site-domains", name, f"ok domains={' '.join(domains) or '-'} tls={'internal' if tls_internal else 'acme'} www_redirect={www_redirect}")
    return {"ok": True, "domains": domains}


def resolve(host):
    """Addresses the name resolves to, looked up from this server (empty if it doesn't resolve)."""
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, 443)})
    except OSError:
        return []


def dns_rows(body=None):
    """One row per domain: DNS (from this server), where the edge routes it, certificate, redacted config, problems."""
    if EDGE_MODE == "external":
        return []  # the external proxy owns routing and certificates
    certs = set(edge("ls /data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/").stdout.split())
    console = {"file": "Caddyfile", "hosts": [CONSOLE_HOST], "app": "", "site": "", "targets": ["console"], "config": ""}
    rows = []
    for c in [console] + edge_config():
        preview = "tls internal" in c["config"]
        for h in c["hosts"]:
            ips = resolve(h)
            here = bool(ips) and (not PUBLIC_IP or PUBLIC_IP in ips)
            cert = "preview" if preview else "issued" if h in certs else "pending"
            problems = (["no DNS record"] if not ips else [] if here else ["DNS points elsewhere"]) + \
                       (["certificate pending or failed"] if here and cert == "pending" else []) + \
                       (["preview certificate on, DNS is ready"] if here and preview else [])
            rows.append({"domain": h, "resolves": ips, "app": c["app"], "site": c["site"], "file": c["file"],
                         "targets": c["targets"], "cert": cert, "problems": problems, "config": c["config"]})
    return sorted(rows, key=lambda r: (r["domain"].removeprefix("www."), r["domain"]))


def domain_add(body):
    """Guided: attach one more domain to an app route or a static site (same checks, validate, rollback)."""
    kind, _, name = str(body.get("target", "")).partition(":")
    d = str(body.get("domain", "")).strip().lower()
    if kind == "site":
        s = site_load(name)
        return site_domains_set({"domains": " ".join(s["domains"] + [d]), "tls_internal": s.get("tls_internal")}, name)
    if kind == "app":
        r = route_cfg(load(name))
        return set_route({**r, "domains": " ".join(r["domains"] + [d])}, name)
    raise Bad("pick an app or a static site")


def site_real_cert(body, name):
    """Guided: drop the preview certificate once every domain resolves to this server."""
    s = site_load(name)
    waiting = [d for d in s["domains"] if not (ips := resolve(d)) or (PUBLIC_IP and PUBLIC_IP not in ips)]
    if waiting:
        raise Bad("DNS doesn't point at this server yet: " + " ".join(waiting))
    return site_domains_set({"domains": " ".join(s["domains"]), "tls_internal": False}, name)


def site_www_redirect(body, name):
    """Guided: www.<domain> redirects to <domain> (needs both attached)."""
    s, on = site_load(name), bool(body.get("on"))
    if on and not any(d.startswith("www.") and d[4:] in s["domains"] for d in s["domains"]):
        raise Bad("attach both example.com and www.example.com first")
    return site_domains_set({"domains": " ".join(s["domains"]), "tls_internal": s.get("tls_internal"), "www_redirect": on}, name)


def site_delete(body, name):
    site_load(name)
    write_site_file(ROOT / "caddy" / "sites" / f"site-static-{name}.caddy", None)
    site_s3_remove(name)
    shutil.rmtree(site_dir(name))
    site_audit("site-delete", name)
    return {"ok": True}


# ---- Delete one app -------------------------------------------------------------------------------
# The console asks; this is the only place that removes anything. Every path is one validated app
# name under OC_ROOT. External data mounts and hand-written edge files are reported and left alone.
# Safe to run again after a partial failure: each step treats "already gone" as success.


def want_backup(body):
    if "backup" not in body:
        return True
    v = body.get("backup")
    if isinstance(v, str):
        return v.strip().lower() not in ("0", "false", "off", "no", "")
    return bool(v)


def assert_under_root(path):
    """Refuse a path that resolves outside OC_ROOT (symlink escape or traversal)."""
    root = ROOT.resolve()
    if path.exists() or path.is_symlink():
        real = path.resolve()
    else:
        real = path.parent.resolve() / path.name
    if real != root and root not in real.parents:
        raise Bad("refusing path outside Open Cloud")
    return path


def managed_child(kind, name):
    """ROOT/<kind>/<name> for this app only. `name` is a single path component."""
    if kind not in ("apps", "data", "pgdata", "releases"):
        raise Bad("refusing unmanaged path")
    valid_app_name(name)
    parent = ROOT / kind
    path = parent / name
    if path.parent != parent:
        raise Bad("refusing path outside Open Cloud")
    assert_under_root(parent)
    if path.is_symlink():
        return path
    if path.exists():
        assert_under_root(path)
        if path.resolve().parent != parent.resolve():
            raise Bad("refusing path outside Open Cloud")
    return path


def remove_managed(kind, name):
    """Remove a managed directory. A symlink is unlinked and its target is not followed."""
    path = managed_child(kind, name)
    if not path.exists() and not path.is_symlink():
        return "absent", ""
    if path.is_symlink():
        target = os.readlink(path)
        path.unlink()
        return "removed", f"symlink unlinked; left in place: {target}"
    if path.is_file():
        path.unlink()
        return "removed", ""
    shutil.rmtree(path)
    return "removed", ""


def db_secret_path(filename):
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,40}", filename or ""):
        raise Bad("invalid database credential name")
    parent = ROOT / "secrets" / "db"
    path = parent / filename
    if path.parent != parent:
        raise Bad("refusing path outside Open Cloud")
    assert_under_root(parent)
    if path.is_symlink():
        return path
    if path.exists():
        assert_under_root(path)
        if path.resolve().parent != parent.resolve():
            raise Bad("refusing path outside Open Cloud")
    return path


def other_db_secret_users(filename, deleting):
    """Other apps that still use this secrets/db file (owner password, or a runtime password)."""
    users = []
    if filename != deleting and NAME.match(filename) and filename not in RESERVED:
        if (ROOT / "apps" / filename / "app.json").exists():
            users.append(filename)
    if filename.endswith("-runtime"):
        base = filename[:-len("-runtime")]
        if base != deleting and NAME.match(base) and base not in RESERVED and (ROOT / "apps" / base / "app.json").exists():
            users.append(base)
    return users


def load_optional(name):
    p = app_dir(name) / "app.json"
    if not p.is_file():
        return None
    return json.loads(p.read_text())


def lock_down(path):
    """0700 directories and 0600 files. Symlinks are left unchanged so their targets are not chmod'd."""
    if path.is_symlink():
        return
    os.chmod(path, 0o700 if path.is_dir() else 0o600)
    if path.is_dir():
        for child in path.rglob("*"):
            if child.is_symlink():
                continue
            os.chmod(child, 0o700 if child.is_dir() else 0o600)


def new_backup_dir(name):
    parent = ROOT / "backups" / "deleted"
    assert_under_root(ROOT / "backups")
    parent.mkdir(parents=True, exist_ok=True)
    os.chmod(parent, 0o700)
    assert_under_root(parent)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    dest = parent / f"{name}-{stamp}"
    if dest.exists():
        dest = parent / f"{name}-{stamp}-{time.time_ns()}"
    assert_under_root(dest)
    dest.mkdir(mode=0o700)
    os.chmod(dest, 0o700)
    marker = dest / "INCOMPLETE"
    marker.write_text("backup did not finish\n")
    os.chmod(marker, 0o600)
    return dest


def mark_incomplete(dest, err):
    """A failed backup must not look like a finished one. The app is still on the server."""
    marker = dest / "INCOMPLETE"
    marker.write_text("backup did not finish\n" + str(err).replace("\n", " ")[:300] + "\n")
    os.chmod(marker, 0o600)
    renamed = dest.with_name(dest.name + "-incomplete")
    if renamed.exists() or renamed.is_symlink():
        return dest
    dest.rename(renamed)
    return renamed


def database_dump(name):
    """pg_dump of this app's database only, as the owner role `app`.

    None when that container does not exist. A container is used only when its name,
    compose project, backup label, image, and POSTGRES_USER all belong to this app.
    """
    valid_app_name(name)
    container = f"oc-app-{name}-db-1"
    if not re.fullmatch(rf"oc-app-{re.escape(name)}-db-1", container):
        raise Bad("refusing database container")
    fmt = ("{{.Name}}\t{{.State.Status}}\t{{index .Config.Labels \"com.docker.compose.project\"}}\t"
           "{{index .Config.Labels \"opencloud.backup\"}}\t{{.Config.Image}}\n"
           "{{range .Config.Env}}{{println .}}{{end}}")
    state = run(["docker", "inspect", "-f", fmt, container], check=False)
    if state.returncode:
        return None
    lines = state.stdout.splitlines()
    fields = lines[0].split("\t") if lines else []
    if len(fields) != 5:
        raise Bad("refusing database container")
    cname, status, project, label, image = fields
    if cname.startswith("/"):
        cname = cname[1:]
    image_name = image.rsplit("/", 1)[-1]
    if (cname != container or project != f"oc-app-{name}" or label != "postgres"
            or not (image_name.startswith("postgres:") or image_name.startswith("postgres@"))
            or "POSTGRES_USER=app" not in lines[1:]):
        raise Bad("refusing database container")
    if status != "running":
        run(["docker", "start", container], timeout=120)
    return run(["docker", "exec", container, "pg_dump", "-U", "app", "--no-password", "-d", "app"], timeout=600).stdout


def action_bucket(action):
    """Bucket named by Read, Write, List, Tagging, or Admin on that bucket. Bare Admin is not a bucket."""
    kind, sep, bucket = str(action).partition(":")
    if sep != ":" or kind not in ("Read", "Write", "List", "Tagging", "Admin"):
        return None
    if not BUCKET.match(bucket) or bucket == SITE_BUCKET:
        return None
    return bucket


def identity_buckets(ident):
    out = []
    for action in ident.get("actions") or []:
        bucket = action_bucket(action)
        if bucket and bucket not in out:
            out.append(bucket)
    return out


def app_identity(cfg, name):
    return next((i for i in cfg.get("identities", []) if i.get("name") == "app-" + name), None)


def shared_bucket_names(cfg, name):
    """Buckets this app shares with another identity. Bare Admin and the `sites` bucket do not count."""
    ident = app_identity(cfg, name)
    if not ident:
        return []
    mine = set(identity_buckets(ident))
    others = set()
    for i in cfg.get("identities", []):
        if i.get("name") == "app-" + name:
            continue
        others.update(identity_buckets(i))
    return sorted(mine & others)


def shared_buckets(name):
    path = s3_config_path()
    if not path.is_file():
        return []
    return shared_bucket_names(s3_config(), name)


def publish_s3(cfg):
    tmp = s3_config_path().with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2))
    os.chmod(tmp, 0o600)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(tmp, 1000, 1000)  # SeaweedFS image user
    tmp.replace(s3_config_path())


def bucket_shell(bucket, script):
    if not BUCKET.match(bucket) or bucket == SITE_BUCKET or "/" in bucket or ".." in bucket:
        raise Bad("refusing to touch this bucket")
    return ["docker", "exec", "-i", STORAGE, "weed", "shell"], script


FILER_LIST_LIMIT = 1000
FILER_MODE_DIR = 1 << 31
FILER_MODE_SYMLINK = 1 << 27


def storage_run(argv, timeout=600):
    """Run a command inside the storage container. The filer there is only on loopback."""
    cmd = ["docker", "exec", STORAGE, *argv]
    guard(cmd)
    return subprocess.run(cmd, capture_output=True, timeout=timeout)


def filer_http_url(path, query=None):
    """Filer URL for one absolute path. Each component is encoded; the path is not a shell string."""
    from urllib.parse import quote, urlencode
    if not path.startswith("/") or "\x00" in path:
        raise Bad("refusing unexpected object path")
    parts = path.split("/")
    if any(p in (".", "..") for p in parts):
        raise Bad("refusing unexpected object path")
    url = "http://127.0.0.1:8888" + "/".join(quote(p, safe="") for p in parts)
    if query:
        url += "?" + urlencode(query)
    return url


def filer_request(path, query=None):
    """GET one filer path. Directory listings ask for JSON; file bodies come back as bytes."""
    # -q would hide the 404 text, and a missing bucket must be told apart from any other failure.
    argv = ["wget", "-O", "-", "--header", "Accept: application/json"]
    if not query:
        argv = ["wget", "-O", "-"]
    return storage_run([*argv, filer_http_url(path, query)])


def filer_missing(proc):
    blob = ((proc.stderr or b"") + (proc.stdout or b"")).decode(errors="replace").lower()
    return proc.returncode != 0 and any(s in blob for s in ("404", "not found", "no such", "no entry"))


def list_filer_dir(path):
    """Every direct child of a filer directory. None when the directory does not exist."""
    entries, last, seen = [], "", set()
    while True:
        query = {"limit": str(FILER_LIST_LIMIT)}
        if last:
            query["lastFileName"] = last
        proc = filer_request(path, query)
        if proc.returncode:
            if not entries and filer_missing(proc):
                return None
            err = (proc.stderr or b"").decode(errors="replace")
            raise Bad("bucket list failed: " + err[-300:])
        try:
            data = json.loads(proc.stdout.decode())
        except ValueError:
            raise Bad("bucket list was not JSON")
        entries.extend(data.get("Entries") or [])
        if not data.get("ShouldDisplayLoadMore"):
            return entries
        last = str(data.get("LastFileName") or "")
        if not last or last in seen:
            raise Bad("bucket listing did not advance")
        seen.add(last)


def object_key(bucket, full):
    """Key relative to /buckets/<bucket>. Rejects anything that could leave that tree."""
    root = f"/buckets/{bucket}"
    if not isinstance(full, str) or full == root or not full.startswith(root + "/") or "\x00" in full:
        raise Bad("refusing unexpected object path")
    key = full[len(root) + 1:]
    parts = key.split("/")
    if not parts or any(p in ("", ".", "..") for p in parts):
        raise Bad("refusing unsafe object key")
    return key


def object_dest(dest, bucket, key, directory):
    """dest/<bucket>/<key>, created only under dest. A symlink is never followed."""
    root = dest.resolve()
    path = dest / bucket
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.resolve() != root and root not in path.resolve().parents:
        raise Bad("refusing path outside the backup")
    for i, part in enumerate(key.split("/")):
        path = path / part
        if path.is_symlink():
            raise Bad("refusing unsafe object key")
        real = path.resolve() if path.exists() else path.parent.resolve() / path.name
        if root not in real.parents:
            raise Bad("refusing path outside the backup")
        last = i == key.count("/")
        if directory or not last:
            path.mkdir(exist_ok=True)
            if path.is_symlink() or not path.is_dir():
                raise Bad("refusing unsafe object key")
    return path


def save_object(dest, bucket, key, body, size):
    path = object_dest(dest, bucket, key, directory=False)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(body)
    if path.is_symlink() or path.stat().st_size != size or len(body) != size:
        path.unlink(missing_ok=True)
        raise Bad("bucket object size did not match")
    return path


def export_bucket(bucket, dest):
    """Download every object in one bucket. Never the shared sites bucket.

    `weed filer.copy` only uploads into the filer, so this reads the filer over its
    loopback HTTP port inside the storage container. Keys stay under dest/<bucket>/.
    """
    bucket_shell(bucket, "")
    root = f"/buckets/{bucket}"
    entries = list_filer_dir(root)
    if entries is None:
        return "absent"

    def walk(directory, children):
        for entry in children:
            full = entry.get("FullPath")
            key = object_key(bucket, full)
            if not full.startswith(directory.rstrip("/") + "/"):
                raise Bad("refusing unexpected object path")
            mode = int(entry.get("Mode") or 0)
            if mode & FILER_MODE_SYMLINK or entry.get("SymlinkTarget"):
                raise Bad("refusing symlink in bucket")
            if mode & FILER_MODE_DIR:
                object_dest(dest, bucket, key, directory=True)
                nested = list_filer_dir(full)
                if nested is None:
                    raise Bad("bucket folder disappeared during backup")
                walk(full, nested)
                continue
            proc = filer_request(full)
            if proc.returncode:
                err = (proc.stderr or b"").decode(errors="replace")
                raise Bad("bucket object download failed: " + err[-300:])
            save_object(dest, bucket, key, proc.stdout, int(entry.get("FileSize") or 0))

    walk(root, entries)
    (dest / bucket).mkdir(parents=True, exist_ok=True)
    return "ok"


def safe_extract_tar(blob, bucket, dest):
    """Unpack a bucket archive. Members must stay inside dest/<bucket>."""
    import io, tarfile
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    try:
        tar = tarfile.open(fileobj=io.BytesIO(blob), mode="r:")
    except tarfile.TarError:
        raise Bad("bucket export was not a tar archive")
    with tar:
        for member in tar.getmembers():
            name = member.name
            if member.issym() or member.islnk() or name.startswith("/") or ".." in name.split("/"):
                raise Bad("refusing unsafe path in bucket export")
            if name != bucket and not name.startswith(bucket + "/"):
                raise Bad("refusing unexpected path in bucket export")
            target = (dest / name).resolve()
            if target != root and root not in target.parents:
                raise Bad("refusing path outside the backup")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise Bad("refusing special file in bucket export")
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tar.extractfile(member)
            if src is None:
                raise Bad("bucket export entry is unreadable")
            target.write_bytes(src.read())
    return "ok"


def remove_bucket(bucket):
    args, script = bucket_shell(bucket, f"fs.rm -r /buckets/{bucket}\ns3.bucket.delete -name {bucket}\n")
    result = run(args, input=script, timeout=120, check=False)
    if result.returncode:
        err = (result.stdout + result.stderr).lower()
        if not any(s in err for s in ("no such", "not found", "no entry", "not exist", "does not exist")):
            raise Bad("bucket delete failed: " + (result.stderr or result.stdout)[-300:])
    return "removed"


def copy_managed_data(name, dest):
    src = managed_child("data", name)
    if not src.exists() and not src.is_symlink():
        return "absent"
    if src.is_symlink():
        (dest / "data-symlink.txt").write_text(f"symlink left unfollowed: {os.readlink(src)}\n")
        return "symlink"
    shutil.copytree(src, dest / "data", symlinks=True, dirs_exist_ok=True)
    return "ok"


def take_backup(name, app):
    """Final copy: app definition, database dump, bucket objects, and managed /data. No secret files."""
    pg = managed_child("pgdata", name)
    data = managed_child("data", name)
    has_db_files = pg.exists() or db_secret_path(name).exists() or db_secret_path(f"{name}-runtime").exists()
    buckets = []
    if s3_config_path().is_file() and app_identity(s3_config(), name):
        buckets = [b for b in identity_buckets(app_identity(s3_config(), name)) if b != SITE_BUCKET and BUCKET.match(b)]
    has_data = data.exists() or data.is_symlink()
    if not app and not has_db_files and not buckets and not has_data:
        return None, [{"step": "backup", "status": "absent", "detail": "nothing left to back up"}]
    dest = new_backup_dir(name)
    final = dest
    try:
        try:
            if app:
                (dest / "app.json").write_text(json.dumps({k: v for k, v in app.items() if k != "secrets"}, indent=2))
            if (app and app.get("db")) or has_db_files:
                dump = database_dump(name)
                if dump is None and has_db_files:
                    raise Bad("database files exist but the database container could not be dumped")
                if dump is not None:
                    (dest / "database.sql").write_text(dump)
            for bucket in buckets:
                export_bucket(bucket, dest / "buckets")
            if has_data:
                copy_managed_data(name, dest)
            (dest / "INCOMPLETE").unlink()
            return str(dest), [{"step": "backup", "status": "ok", "detail": str(dest)}]
        except Exception as err:
            final = mark_incomplete(dest, err)
            detail = str(err).replace("\n", " ")[:200]
            raise Bad(f"partial backup kept at {final}: {detail}")
    finally:
        if final.exists():
            lock_down(final)


def route_path(name):
    """caddy/sites/<name>.caddy. `name` is one path component; the file may be hand-written."""
    if not NAME.match(name or ""):
        raise Bad("invalid app name")
    sites = ROOT / "caddy" / "sites"
    site = sites / f"{name}.caddy"
    if site.parent != sites:
        raise Bad("refusing path outside Open Cloud")
    assert_under_root(sites)
    return site


def route_owned(name, site, app):
    """True when this regular file was written for this app. A `site-*` file is never owned."""
    if name.startswith("site-") or name in RESERVED or site.is_symlink() or not site.is_file():
        return False
    try:
        text = site.read_text()
    except OSError:
        return False
    lines = text.splitlines()
    if lines and lines[0] == route_marker(name):
        return True
    # Apps deployed before the marker: the file is owned only when it is still the generated route.
    return bool(app) and app.get("name") == name and text == render_site_body(app)


def remove_route(name, app=None):
    """Remove the edge file only when this deployer wrote it for this app. Anything else stays."""
    site = route_path(name)
    if not site.exists() and not site.is_symlink():
        return "absent", ""
    if not route_owned(name, site, app):
        return "kept", site.name
    old = site.read_text()
    site.unlink()
    if EDGE_MODE == "external":
        return "removed", site.name
    try:
        run(["docker", "exec", EDGE, "caddy", "reload", "--config", "/etc/caddy/Caddyfile"], timeout=60)
    except Bad as err:
        site.write_text(old)
        raise Bad("route removal rejected by Caddy and restored: " + str(err)[-200:])
    return "removed", site.name


def hand_routes(name):
    """Hand-written edge files that still proxy to this app. Listed, never edited."""
    found = []
    sites = ROOT / "caddy" / "sites"
    if not sites.is_dir():
        return found
    for f in sorted(sites.glob("site-*.caddy")):
        try:
            text = f.read_text()
        except OSError:
            continue
        if re.search(rf"(^|\s)app-{re.escape(name)}(:|\s|$)", text):
            found.append(f.name)
    return found


def compose_down(name):
    """Stop this app's compose project only. External networks joined by the app are not removed."""
    project = f"oc-app-{name}"
    if not re.fullmatch(rf"oc-app-{re.escape(name)}", project):
        raise Bad("refusing compose project")
    compose_file = managed_child("apps", name) / "compose.yaml"
    if compose_file.is_file() and not compose_file.is_symlink():
        run(["docker", "compose", "-f", str(compose_file), "-p", project, "down", "-v", "--remove-orphans"], timeout=300)
        return "removed", project
    listed = run(["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={project}", "--format", "{{.Names}}"], check=False)
    if listed.returncode:
        raise Bad("listing app containers failed: " + (listed.stderr or "")[-200:])
    names = [n for n in listed.stdout.split() if n]
    for n in names:
        if not re.fullmatch(rf"oc-app-{re.escape(name)}-(web|db|prev)-[0-9]+", n):
            raise Bad(f"refusing to remove unexpected container {n}")
    if names:
        run(["docker", "rm", "-f", *names], timeout=180)
    net = run(["docker", "network", "rm", f"{project}_db"], check=False)
    blob = ((net.stdout or "") + (net.stderr or "")).lower()
    missing = net.returncode != 0 and any(s in blob for s in ("not found", "no such", "not exist"))
    if net.returncode and not missing:
        raise Bad("removing the app network failed: " + (net.stderr or net.stdout or "")[-200:])
    if names or net.returncode == 0:
        return "removed", project
    return "absent", project


def remove_images(name):
    """Remove images whose repository is exactly oc-app-<name>. Other repositories are left alone."""
    repo = f"oc-app-{name}"
    listed = run(["docker", "image", "ls", "--format", "{{.Repository}}\t{{.Tag}}\t{{.ID}}"], check=False)
    if listed.returncode:
        raise Bad("listing images failed: " + (listed.stderr or "")[-200:])
    targets = []
    for line in listed.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or parts[0] != repo:
            continue
        if parts[1] == "<none>":
            if not re.fullmatch(r"(sha256:)?[0-9a-f]{12,64}", parts[2]):
                raise Bad("refusing to remove image")
            ref = parts[2]
        else:
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", parts[1]):
                raise Bad("refusing to remove image")
            ref = f"{repo}:{parts[1]}"
        if ref not in targets:
            targets.append(ref)
    for ref in targets:
        run(["docker", "image", "rm", "-f", ref], timeout=180)
    return ("removed" if targets else "absent"), " ".join(targets)


def remove_database_files(name):
    removed, kept = [], []
    for filename in (name, f"{name}-runtime"):
        others = other_db_secret_users(filename, name)
        path = db_secret_path(filename)
        if others:
            kept.append(f"{filename} (also used by {', '.join(others)})")
            continue
        if path.is_symlink() or path.is_file():
            path.unlink()
            removed.append(filename)
        elif path.exists():
            raise Bad("refusing unexpected database credential path")
    data, data_detail = remove_managed("pgdata", name)
    detail = " ".join(removed)
    if data == "removed":
        detail = (detail + " pgdata").strip()
    if data_detail:
        kept.append(data_detail)
    status = "removed" if removed or data == "removed" else "absent"
    return status, detail, kept


def storage_restart_flag():
    return ROOT / "secrets" / "storage" / "restart-required"


def remove_app_buckets(name):
    """Delete buckets only this app's key can use, then drop that identity. `sites` and other keys stay."""
    path = s3_config_path()
    if not path.is_file():
        return "absent", ""
    with LOCK:
        cfg = s3_config()
        ident = app_identity(cfg, name)
        if not ident:
            return "absent", ""
        buckets = identity_buckets(ident)
        shared = shared_bucket_names(cfg, name)
        if shared:
            raise Bad("refusing to delete buckets still used by another identity: " + " ".join(shared))
    for bucket in buckets:
        remove_bucket(bucket)
    with LOCK:
        cfg = s3_config()
        ident = app_identity(cfg, name)
        if ident:
            extra = [b for b in identity_buckets(ident) if b not in buckets]
            if extra or shared_bucket_names(cfg, name):
                raise Bad("storage config changed during delete; run delete again")
        before = len(cfg.get("identities", []))
        cfg["identities"] = [i for i in cfg.get("identities", []) if i.get("name") != "app-" + name]
        changed = len(cfg["identities"]) != before
        if changed:
            publish_s3(cfg)
            flag = storage_restart_flag()
            flag.parent.mkdir(parents=True, exist_ok=True)
            flag.write_text(name)
    return ("removed" if buckets or changed else "absent"), " ".join(buckets)


def restart_storage_if_needed():
    """Finish an identity change, including one whose restart failed on an earlier attempt."""
    flag = storage_restart_flag()
    if not flag.exists():
        return "absent", ""
    restart_storage()
    flag.unlink(missing_ok=True)
    return "restarted", STORAGE


def forget_gateway_app(name):
    """Drop this app's gateway client file and its name on endpoints. Endpoints themselves stay."""
    removed = False
    parent = ROOT / "secrets" / "gateway-clients"
    path = parent / name
    if parent.is_dir() and path.parent == parent:
        assert_under_root(parent)
        if path.is_symlink() or path.is_file():
            if path.is_symlink():
                path.unlink()
            else:
                assert_under_root(path)
                path.unlink()
            removed = True
        elif path.exists():
            raise Bad("refusing unexpected gateway client path")
    cfg_path = gw_dir() / "config.json"
    if cfg_path.is_file():
        with LOCK:
            cfg = gw_config()
            changed = False
            for ep in cfg.get("endpoints", {}).values():
                apps = ep.get("apps") or []
                if name in apps:
                    ep["apps"] = [a for a in apps if a != name]
                    changed = True
            if changed:
                try:
                    gw_save(cfg)
                except PermissionError:  # not root: tests, and a deployer that cannot chown
                    (gw_dir() / "config.json.tmp").unlink(missing_ok=True)
                    cfg_path.write_text(json.dumps(cfg, indent=2))
                removed = True
    return ("removed" if removed else "absent"), ""


def outside_mounts(app):
    """Host paths this app mounted. They are not under the app's managed directories and are not deleted."""
    if not app:
        return []
    kept = []
    for mount in app.get("data_mounts") or []:
        src, tgt = mount.get("source", ""), mount.get("target", "")
        if src:
            kept.append({"step": "data_mount", "status": "kept", "detail": f"{src}:{tgt}" if tgt else src})
    for mount in app.get("secret_mounts") or []:
        src = mount.get("source", "")
        if src:
            kept.append({"step": "secret_mount", "status": "kept", "detail": src})
    return kept


def delete_marker(name, filename):
    """releases/<name>/<filename> when that directory is a real directory. Symlinks do not count."""
    rel = managed_child("releases", name)
    if rel.is_symlink() or not rel.is_dir():
        return None
    path = rel / filename
    if path.parent != rel or path.is_symlink() or not path.is_file():
        return None
    return path


def recorded_delete(name):
    """True when this deployer already started or finished deleting this app."""
    return delete_marker(name, "DELETING") is not None or delete_marker(name, "DELETED") is not None


def delete_target_exists(name):
    """An app definition, an app folder, or a delete this deployer already recorded."""
    d = app_dir(name)
    if (d / "app.json").is_file() or d.exists() or d.is_symlink():
        return True
    return recorded_delete(name)


def begin_delete(name):
    """Remember that a delete has started, so a later run can finish after the app folder is gone."""
    if delete_marker(name, "DELETED"):
        return
    rel = managed_child("releases", name)
    if rel.is_symlink():
        raise Bad("refusing unexpected releases path")
    rel.mkdir(parents=True, exist_ok=True)
    marker = rel / "DELETING"
    if marker.is_symlink() or (marker.exists() and not marker.is_file()):
        raise Bad("refusing unexpected delete marker")
    if marker.is_file():
        return
    marker.write_text(json.dumps({"deleting": True, "app": name,
                                   "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}))
    os.chmod(marker, 0o600)


def mark_deleted(name, app, backup_path):
    """Keep release records and jobs. Mark them so the console can show the app is gone."""
    rel = managed_child("releases", name)
    if rel.is_symlink():
        raise Bad("refusing unexpected releases path")
    rel.mkdir(parents=True, exist_ok=True)
    when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    marker = rel / "DELETED"
    if marker.is_symlink():
        raise Bad("refusing unexpected delete marker")
    already = marker.is_file()
    marker.write_text(json.dumps({"deleted": True, "app": name, "time": when, "backup": backup_path or ""}))
    os.chmod(marker, 0o600)
    deleting = rel / "DELETING"
    if deleting.is_file() and not deleting.is_symlink():
        deleting.unlink()
    if not already:
        record_app = {"name": name, "image_tag": (app or {}).get("image_tag") or "", "commit": (app or {}).get("commit") or "",
                      "repo": (app or {}).get("repo") or (app or {}).get("folder") or ""}
        record(record_app, "delete")
    jobs_dir = ROOT / "jobs"
    with LOCK:
        if jobs_dir.is_dir():
            for p in jobs_dir.glob("*.json"):
                try:
                    job = json.loads(p.read_text())
                except ValueError:
                    continue
                if job.get("app") == name and not job.get("app_deleted"):
                    job["app_deleted"] = True
                    p.write_text(json.dumps(job))
    return "kept", "jobs and release records marked deleted" if not already else "already marked deleted"


def perform(steps, step, fn):
    try:
        status, detail = fn()
    except Bad as err:
        steps.append({"step": step, "status": "failed", "detail": str(err)[:300]})
        raise
    steps.append({"step": step, "status": status, "detail": detail or ""})
    return status


def delete_app(body, name):
    app_dir(name)  # validates the name; no traversal, no reserved names
    if str(body.get("confirm", "")) != name:
        raise Bad("type the app name to confirm")
    with LOCK:
        if name in BUSY:
            raise Bad("a build or deploy is already running for this app")
        BUSY.add(name)
    try:
        return do_delete(name, want_backup(body))
    finally:
        with LOCK:
            BUSY.discard(name)


def do_delete(name, backup):
    if not delete_target_exists(name):
        raise Bad("no such app")
    app = load_optional(name)
    shared = shared_buckets(name)
    if shared:
        raise Bad("refusing to delete buckets still used by another identity: " + " ".join(shared))
    steps = []
    backup_path = None
    try:
        if backup:
            backup_path, bsteps = take_backup(name, app)
            steps.extend(bsteps)
        else:
            steps.append({"step": "backup", "status": "skipped", "detail": "backup off"})
    except Bad as err:
        if not any(s["step"] == "backup" and s["status"] == "failed" for s in steps):
            steps.append({"step": "backup", "status": "failed", "detail": str(err)[:300]})
        audit_append({"event": "app-delete", "ip": "agent", "target": f"app={name}", "outcome": "error: " + str(err)[:200]})
        raise Bad("backup failed, app was not deleted: " + str(err)[:300])
    try:
        begin_delete(name)
        perform(steps, "route", lambda: remove_route(name, app))
        for filename in hand_routes(name):
            steps.append({"step": "hand_route", "status": "kept", "detail": filename})
        steps.extend(outside_mounts(app))
        perform(steps, "compose", lambda: compose_down(name))
        perform(steps, "images", lambda: remove_images(name))
        try:
            status, detail, kept = remove_database_files(name)
        except Bad as err:
            steps.append({"step": "database", "status": "failed", "detail": str(err)[:300]})
            raise
        steps.append({"step": "database", "status": status, "detail": detail})
        for item in kept:
            steps.append({"step": "database_credential", "status": "kept", "detail": item})
        try:
            status, detail = remove_app_buckets(name)
        except Bad as err:
            steps.append({"step": "buckets", "status": "failed", "detail": str(err)[:300]})
            raise
        steps.append({"step": "buckets", "status": status, "detail": detail})
        perform(steps, "storage", restart_storage_if_needed)
        perform(steps, "gateway", lambda: forget_gateway_app(name))
        perform(steps, "secrets", lambda: (remove_managed_secrets(name), ""))
        perform(steps, "data", lambda: remove_managed("data", name))
        perform(steps, "files", lambda: remove_managed("apps", name))
        if app or managed_child("releases", name).exists() or any(s["status"] in ("removed", "restarted") for s in steps):
            perform(steps, "history", lambda: mark_deleted(name, app, backup_path))
        else:
            steps.append({"step": "history", "status": "absent", "detail": ""})
    except Bad as err:
        summary = ", ".join(f"{s['step']}={s['status']}" for s in steps)
        audit_append({"event": "app-delete", "ip": "agent", "target": f"app={name}", "outcome": "error: " + str(err)[:200]})
        raise Bad(str(err)[:300] + (f" [{summary[:300]}]" if summary else ""))
    outcome = "ok backup=" + (backup_path or ("off" if not backup else "none"))
    audit_append({"event": "app-delete", "ip": "agent", "target": f"app={name}", "outcome": outcome})
    return {"ok": True, "app": name, "deleted": True, "backup_path": backup_path, "steps": steps}


def remove_managed_secrets(name):
    parent = ROOT / "secrets" / "apps"
    path = parent / name
    valid_app_name(name)
    if path.parent != parent:
        raise Bad("refusing path outside Open Cloud")
    assert_under_root(parent)
    if not path.exists() and not path.is_symlink():
        return "absent"
    if path.is_symlink() or path.is_file():
        path.unlink()
        return "removed"
    if path.resolve().parent != parent.resolve():
        raise Bad("refusing path outside Open Cloud")
    shutil.rmtree(path)
    return "removed"


SITE_ROUTES = {"upload": site_upload, "domains": site_domains_set, "delete": site_delete,
               "real-cert": site_real_cert, "www-redirect": site_www_redirect}


ROUTES = {
    ("GET", "host-options"): lambda b: {"local_sources": [str(p) for p in allow("OC_LOCAL_SOURCES")],
                                        "networks": os.environ.get("OC_ALLOWED_EXTERNAL_NETWORKS", "").split(),
                                        "data_roots": [str(p) for p in allow("OC_ALLOWED_DATA_ROOTS")],
                                        "secret_paths": [str(p) for p in allow("OC_ALLOWED_SECRET_PATHS")]},
    ("GET", "status"): status, ("GET", "apps"): app_list, ("POST", "apps"): deploy,
    ("POST", "backup"): backup, ("GET", "backups"): snapshots,
    ("POST", "redeploy"): lambda b, n: deploy(b, n), ("POST", "rollback"): rollback,
    ("POST", "db"): create_db, ("POST", "secrets"): set_secret, ("POST", "ai"): enable_ai, ("POST", "provider-key"): set_provider_key_env, ("POST", "visibility"): set_visibility,
    ("GET", "logs"): logs, ("GET", "releases"): releases, ("POST", "delete"): delete_app,
    ("POST", "buckets"): create_bucket, ("POST", "limits"): set_limits, ("GET", "buckets"): buckets,
    ("GET", "map"): app_map, ("POST", "api-discover"): discover_api, ("POST", "api-endpoint"): add_api_endpoint,
    ("POST", "api-check"): set_api_check, ("POST", "api-probe"): probe_now,
    ("GET", "routes"): routes, ("POST", "route"): set_route, ("GET", "edge-config"): edge_config,
    ("GET", "dns"): dns_rows, ("POST", "domain-add"): domain_add,
    ("GET", "gateway"): gateway_state, ("POST", "gateway-provider"): set_provider, ("POST", "gateway-endpoint"): set_endpoint,
    ("GET", "jobs"): jobs, ("POST", "audit"): audit_append, ("GET", "audit"): audit_read,
    ("GET", "sites"): site_list, ("POST", "sites"): site_create,
    ("GET", "watch-stats"): watch_stats, ("POST", "watch-logs"): watch_logs,
}


def dispatch(method, path, body):
    parts = [p for p in path.split("?")[0].split("/") if p]
    if parts == ["observed"] and method == "GET":
        if not OBSERVE:
            raise LookupError
        return observed(body)
    if len(parts) == 1 and (method, parts[0]) in ROUTES:
        return ROUTES[(method, parts[0])](body)
    if len(parts) == 3 and parts[0] == "sites" and method == "POST" and parts[2] in SITE_ROUTES:
        site_load(parts[1])
        return SITE_ROUTES[parts[2]](body, parts[1])
    if len(parts) == 2 and method == "GET" and parts[0] == "jobs":
        return job(body, parts[1])
    if len(parts) == 3 and parts[0] == "apps" and (method, parts[2]) in ROUTES:
        app_dir(parts[1])
        return ROUTES[(method, parts[2])](body, parts[1])
    raise LookupError


def bind_address(retries=30):
    """OC_AGENT_BIND: listen only on this name's address (oc-agent.oc_control), so the builder on the egress
    network can't open a connection to the management API. Unset: all interfaces."""
    host = os.environ.get("OC_AGENT_BIND", "")
    if not host:
        return "0.0.0.0"
    for _ in range(retries):
        try:
            return socket.gethostbyname(host)
        except OSError:
            time.sleep(1)
    raise SystemExit(f"cannot resolve OC_AGENT_BIND={host}")


class Handler(BaseHTTPRequestHandler):
    token = ""
    watch_token = ""

    def handle_one(self, method):
        auth = self.headers.get("Authorization", "")
        full = hmac.compare_digest(auth, "Bearer " + self.token)
        ro = bool(self.watch_token) and hmac.compare_digest(auth, "Bearer " + self.watch_token) and watch_allowed(method, self.path)
        if not (full or ro):
            return self.reply(401, {"error": "unauthorized"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(n, body_limit(self.path))) or b"{}") if method == "POST" else {}
            self.reply(200, dispatch(method, self.path, body))
        except LookupError:
            self.reply(404, {"error": "not found"})
        except (Bad, ValueError) as e:
            self.reply(400, {"error": str(e)})
        except subprocess.TimeoutExpired:
            self.reply(504, {"error": "timed out"})

    def do_GET(self):
        self.handle_one("GET")

    def do_POST(self):
        self.handle_one("POST")

    def reply(self, code, data):
        b = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, fmt, *a):  # method and path only, never bodies
        print(f"{self.command} {self.path.split('?')[0]} {a[1] if len(a) > 1 else ''}", flush=True)


if __name__ == "__main__":
    Handler.token = Path(os.environ["OC_AGENT_TOKEN_FILE"]).read_text().strip()
    wt = Path(os.environ.get("OC_WATCH_TOKEN_FILE", ROOT / "secrets" / "platform" / "watch-token"))
    Handler.watch_token = wt.read_text().strip() if wt.exists() else ""
    for sub in ("apps", "data", "pgdata", "releases", "caddy/sites", "backups", "jobs", "audit"):
        (ROOT / sub).mkdir(parents=True, exist_ok=True)
    threading.Thread(target=probe_loop, daemon=True).start()
    for p in (ROOT / "jobs").glob("*.json"):  # jobs cannot survive an agent restart
        j = json.loads(p.read_text())
        if j["status"] == "running":
            j.update(status="failed", error="interrupted by agent restart")
            p.write_text(json.dumps(j))
    ThreadingHTTPServer((bind_address(), 7000), Handler).serve_forever()
