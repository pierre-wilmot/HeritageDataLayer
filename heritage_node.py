#!/usr/bin/env python3
"""Heritage hosting node: mirror, vet and pin heritage site repositories.

  heritage_node.py run  --config node.toml   sync loop + maintainer review UI
  heritage_node.py sync --config node.toml   one sync pass, then exit
  heritage_node.py rank --config node.toml   print this node's site ranking
  heritage_node.py hash-password             make an admin_password_hash for the config

The node reads a site index (sites.json: "<scheme>:<id>" -> repo URL) and ranks
the sites: the operator's favourites first, then everything else in an order
that is pseudo-random per node (seeded by its IPFS peer ID), so that across
many nodes hosting spreads evenly over all sites.

For each site, in rank order, it walks the commit graph from the last approved
commit. A commit is approved automatically when:

  - it is signed by a whitelisted key (allowed_signers, namespace "git");
  - it only changes photos.json, leaves the site record (name, location...)
    alone, and only adds photos or signatures;
  - every new signature is valid, and every new photo has an accepted license
    and is signed by a whitelisted key (namespace "heritage-photo").

Anything else stops that site and waits for the maintainer in the review UI.
Approving lets the walk continue; rejecting freezes the site at its last
approved commit (every later commit builds on the rejected one).

Approved history is mirrored (a separate git repo holding only approved
objects) and its photos are pinned on IPFS within max_storage. Sites are filled
in rank order; when space runs out, lower-ranked sites are unpinned first.
Photos are fetched with a hard byte cap, and must match their signed size and
look like an image before they are pinned.
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from heritage_add import FILE, TYPE, check_signature, license_problem  # noqa: E402

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib

SITE_KEY = re.compile(r"^[a-z0-9][a-z0-9-]*:[A-Za-z0-9._-]+$")
CID = re.compile(r"^b[a-z2-7]{50,100}$")
REPO_URL = re.compile(r"^(https://|ssh://|git@[A-Za-z0-9.-]+:|/)")
MAX_DOC_BYTES = 20_000_000
SIZE_MARGIN = 1.01  # IPFS block overhead on top of the file size
UNITS = {"": 1, "B": 1, "KB": 10**3, "MB": 10**6, "GB": 10**9, "TB": 10**12,
         "KIB": 2**10, "MIB": 2**20, "GIB": 2**30, "TIB": 2**40}
DEFAULTS = {
    "data_dir": "/var/lib/heritage-node",
    "favourites": [],
    "node_seed": "",
    "poll_interval": 900,
    "admin_listen": "127.0.0.1:8090",
    "admin_hosts": [],
    "admin_password_hash": "",
    "admin_https": False,
    "session_hours": 12,
    "public_listen": "",
    "max_photo_bytes": "50MB",
    "max_repo_bytes": "50MB",
    "ipfs_path": "",
    "ipfs_timeout": 300,
}


def log(*parts):
    print(datetime.now().isoformat(timespec="seconds"), *parts, flush=True)


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_size(value):
    if isinstance(value, int):
        return value
    m = re.fullmatch(r"\s*([\d.]+)\s*([A-Za-z]*)\s*", str(value))
    if not m or m.group(2).upper() not in UNITS:
        raise ValueError(f"bad size {value!r} (e.g. 500MB, 2GB)")
    return int(float(m.group(1)) * UNITS[m.group(2).upper()])


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000


SCRYPT = {"n": 2**15, "r": 8, "p": 1, "maxmem": 128 * 2**20, "dklen": 32}
LOGIN_FAILURES, LOGIN_WINDOW = 10, 600  # at most 10 failed logins per 10 minutes


def hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, **SCRYPT)
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return f"scrypt${SCRYPT['n']}${SCRYPT['r']}${SCRYPT['p']}${b64(salt)}${b64(dk)}"


def check_password(password, stored):
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        dk = base64.b64decode(dk)
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=SCRYPT["maxmem"], dklen=len(dk))
        return hmac.compare_digest(got, dk)
    except (ValueError, TypeError):
        return False


def load_config(path):
    path = Path(path).expanduser().resolve()
    raw = tomllib.loads(path.read_text())
    missing = [k for k in ("index", "allowed_signers", "max_storage") if k not in raw]
    if missing:
        sys.exit(f"{path}: missing {', '.join(missing)}")
    cfg = DEFAULTS | raw
    for k in ("max_storage", "max_photo_bytes", "max_repo_bytes"):
        cfg[k] = parse_size(cfg[k])

    def rel(p):  # relative paths are relative to the config file
        return (path.parent / Path(p).expanduser()).resolve()

    cfg["data_dir"] = rel(cfg["data_dir"])
    cfg["allowed_signers"] = rel(cfg["allowed_signers"])
    if not cfg["allowed_signers"].is_file():
        sys.exit(f"allowed_signers file {cfg['allowed_signers']} not found")
    if cfg["ipfs_path"]:
        cfg["ipfs_path"] = str(rel(cfg["ipfs_path"]))
    if not str(cfg["index"]).startswith(("https://", "ssh://", "git@")):
        cfg["index"] = str(rel(cfg["index"]))
    bad = [f for f in cfg["favourites"] if not SITE_KEY.match(f)]
    if bad:
        sys.exit(f"bad favourite site id(s): {bad} (expected <scheme>:<id>)")
    if cfg["admin_password_hash"] and not re.fullmatch(r"scrypt\$\d+\$\d+\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+",
                                                       cfg["admin_password_hash"]):
        sys.exit("admin_password_hash is malformed: generate one with  heritage_node.py hash-password")
    return cfg


def git(*args, cwd=None, check=True):
    cmd = ["git", "-c", "protocol.ext.allow=never", *map(str, args)]
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env, timeout=900)
    if not check:
        return r
    if r.returncode:
        raise RuntimeError(f"git {' '.join(map(str, args))}: {r.stderr.strip()}")
    return r.stdout.strip()


def image_type(head):
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "image/tiff"
    return None


def make_thumbnail(data, size=480):
    """Small JPEG preview. Needs Pillow (python3-pil); raises ImportError without it."""
    import io
    from PIL import Image, ImageOps

    Image.MAX_IMAGE_PIXELS = 150_000_000  # refuse decompression bombs
    with Image.open(io.BytesIO(data)) as im:
        im.draft("RGB", (size * 2, size * 2))  # fast downscale while decoding JPEGs
        im = ImageOps.exif_transpose(im)
        im.thumbnail((size, size))
        out = io.BytesIO()
        im.convert("RGB").save(out, "JPEG", quality=80)
    return out.getvalue()


def read_doc(work, sha):
    """photos.json at a commit: (doc, None) or (None, problem)."""
    entry = git("ls-tree", sha, "--", FILE, cwd=work)
    if not entry:
        return None, "no photos.json"
    mode, kind, oid = entry.split("\t")[0].split()
    if mode != "100644" or kind != "blob":
        return None, "photos.json is not a regular file"
    if int(git("cat-file", "-s", oid, cwd=work)) > MAX_DOC_BYTES:
        return None, "photos.json is too large"
    try:
        return json.loads(git("cat-file", "blob", oid, cwd=work)), None
    except ValueError:
        return None, "photos.json is not valid JSON"


def schema_problems(doc, key):
    if not isinstance(doc, dict):
        return ["photos.json is not an object"]
    problems = []
    if doc.get("type") != TYPE:
        problems.append(f"type is not {TYPE}")
    site = doc.get("site")
    if not isinstance(site, dict) or f"{site.get('scheme')}:{site.get('value')}" != key:
        problems.append(f"site does not match its index entry {key}")
    for k in ("lat", "lon"):
        if type(doc.get(k)) not in (int, float):
            problems.append(f"{k} missing or not a number")
    photos = doc.get("photos")
    if not isinstance(photos, list):
        return problems + ["photos is not a list"]
    seen = set()
    for e in photos:
        ok = (isinstance(e, dict) and isinstance(e.get("cid"), str) and CID.match(e["cid"])
              and isinstance(e.get("meta"), dict) and isinstance(e.get("signatures"), list)
              and all(isinstance(s, dict) and isinstance(s.get("key"), str) and isinstance(s.get("sig"), str)
                      for s in e["signatures"]))
        if not ok:
            return problems + ["malformed photo entry"]
        if e["cid"] in seen:
            problems.append(f"duplicate photo {e['cid']}")
        seen.add(e["cid"])
        size = e["meta"].get("bytes")
        if type(size) is not int or size <= 0:
            problems.append(f"{e['cid']}: bytes missing or invalid")
    return problems


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class State:
    """Node state in one JSON file, saved atomically."""

    KEYS = ("sites", "pins", "approved", "rejected", "pending", "bad_cids")

    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()
        self.data = json.loads(path.read_text()) if path.exists() else {}
        for k in self.KEYS:
            self.data.setdefault(k, {})

    def __getitem__(self, key):
        return self.data[key]

    def save(self):
        with self.lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=1))
            os.replace(tmp, self.path)


class Node:
    def __init__(self, cfg):
        self.cfg = cfg
        self.dir = cfg["data_dir"]
        (self.dir / "sites").mkdir(parents=True, exist_ok=True)
        self.state = State(self.dir / "state.json")
        self.wake = threading.Event()
        self.sync_lock = threading.Lock()
        self.index, self.ranked = {}, []
        self.last_sync = None
        self.gc_needed = False
        self.wanted = set()  # CIDs the last sync planned to host
        self.auth_lock = threading.Lock()
        self.sessions = {}  # token -> expiry (epoch seconds)
        self.failures = []  # times of recent failed logins

    # -- IPFS -------------------------------------------------------------

    def ipfs_env(self):
        env = dict(os.environ)
        if self.cfg["ipfs_path"]:
            env["IPFS_PATH"] = self.cfg["ipfs_path"]
        return env

    def ipfs(self, *args):
        r = subprocess.run(["ipfs", *args], capture_output=True, text=True, env=self.ipfs_env(),
                           timeout=self.cfg["ipfs_timeout"] + 60)
        if r.returncode:
            raise RuntimeError(f"ipfs {' '.join(args)}: {r.stderr.strip()}")
        return r.stdout.strip()

    def fetch_photo(self, cid, expected, keep=False):
        """Fetch with a hard cap. Returns (content type, data or None, problem, permanent)."""
        p = subprocess.Popen(["ipfs", f"--timeout={self.cfg['ipfs_timeout']}s", "cat", cid],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.ipfs_env())
        n, head, chunks = 0, b"", []
        try:
            while chunk := p.stdout.read(1 << 16):
                if len(head) < 16:
                    head += chunk[:16 - len(head)]
                n += len(chunk)
                if n > expected:
                    p.kill()
                    return None, None, "larger than its signed size", True
                if keep:
                    chunks.append(chunk)
        finally:
            p.stdout.close()
            err = p.stderr.read().decode(errors="replace").strip()
            p.stderr.close()
            p.wait()
        if p.returncode:
            return None, None, f"unavailable ({err or 'ipfs cat failed'})", False
        if n != expected:
            return None, None, f"is {n} bytes, signed size is {expected}", True
        kind = image_type(head)
        if not kind:
            return None, None, "is not a JPEG, PNG, WebP or TIFF image", True
        return kind, b"".join(chunks) if keep else None, None, False

    # -- index and ranking ------------------------------------------------

    def load_index(self):
        src = self.cfg["index"]
        if src.endswith(".json") and Path(src).is_file():
            text = Path(src).read_text()
        else:
            d = self.dir / "index"
            if not (d / ".git").exists():
                if not REPO_URL.match(src):
                    raise RuntimeError(f"index {src!r} is not an https/ssh URL or absolute path")
                git("clone", "-q", "--depth", "1", src, d)
            else:
                git("fetch", "-q", "--depth", "1", "origin", "HEAD", cwd=d)
                git("reset", "-q", "--hard", "FETCH_HEAD", cwd=d)
            text = (d / "sites.json").read_text()
        raw = json.loads(text)
        index = {k: v for k, v in raw.items()
                 if isinstance(k, str) and isinstance(v, str) and SITE_KEY.match(k) and REPO_URL.match(v)}
        if len(index) != len(raw):
            log(f"index: ignored {len(raw) - len(index)} malformed entr(y/ies)")
        return index

    def seed(self):
        return self.cfg["node_seed"] or self.ipfs("config", "Identity.PeerID")

    def ranking(self, index):
        favourites = [k for k in dict.fromkeys(self.cfg["favourites"]) if k in index]
        seed = self.seed()
        rest = sorted((k for k in index if k not in favourites),
                      key=lambda k: hashlib.sha256(f"{seed}\n{k}".encode()).hexdigest())
        return favourites + rest

    # -- git --------------------------------------------------------------

    def site_dir(self, key):
        return self.dir / "sites" / key.replace(":", "__")

    def fetch_site(self, key, url):
        work = self.site_dir(key) / "work.git"
        if not work.exists():
            work.mkdir(parents=True)
            git("init", "-q", "--bare", work)
        git("fetch", "-q", "--no-tags", url, "+HEAD:refs/upstream/head", cwd=work)
        counts = dict(line.split(": ") for line in git("count-objects", "-v", cwd=work).splitlines())
        size = (int(counts.get("size", 0)) + int(counts.get("size-pack", 0))) * 1024
        if size > self.cfg["max_repo_bytes"]:
            raise RuntimeError(f"repository is {human(size)}, over max_repo_bytes")
        return work, git("rev-parse", "refs/upstream/head", cwd=work)

    def commit_trusted(self, work, sha):
        status = git("-c", "gpg.format=ssh", "-c", f"gpg.ssh.allowedSignersFile={self.cfg['allowed_signers']}",
                     "log", "-1", "--format=%G?", sha, cwd=work)
        return status == "G"

    def check_commit(self, key, work, sha):
        """Return (problems, new photo entries, signature report {cid: [...]})."""
        problems = []
        parents = git("rev-list", "--parents", "-n1", sha, cwd=work).split()[1:]
        if parents:
            changed = git("diff", "--name-only", parents[0], sha, cwd=work).splitlines()
        else:
            changed = git("ls-tree", "-r", "--name-only", sha, cwd=work).splitlines()
        others = [f for f in changed if f != FILE]
        if others:
            problems.append("changes files other than photos.json: " + ", ".join(others[:5]))
        if not self.commit_trusted(work, sha):
            problems.append("commit is not signed by a whitelisted key")
        doc, err = read_doc(work, sha)
        if err:
            return problems + [err], [], {}
        schema = schema_problems(doc, key)
        if schema:
            return problems + schema, [], {}

        # Parents were processed first (topological order), so they are approved and valid.
        parent_docs = [read_doc(work, p)[0] for p in parents]
        if parent_docs:
            def top(d):
                return {k: v for k, v in d.items() if k != "photos"}
            if top(parent_docs[0]) != top(doc):
                problems.append("changes the site record (name, location or other top-level fields)")
        before = {}  # cid -> versions of that entry in the parents
        for d in parent_docs:
            for e in d["photos"]:
                before.setdefault(e["cid"], []).append(e)
        now_by_cid = {e["cid"]: e for e in doc["photos"]}
        removed = [c for c in (e["cid"] for e in parent_docs[0]["photos"]) if c not in now_by_cid] if parent_docs else []
        if removed:
            problems.append(f"removes {len(removed)} photo(s)")

        new_entries, report = [], {}
        for cid, e in now_by_cid.items():
            name = e["meta"].get("name", cid)
            old = before.get(cid)
            if old is None:
                added = e["signatures"]
                new_entries.append(e)
            else:
                if all(o["meta"] != e["meta"] for o in old):
                    problems.append(f"{name}: metadata changed")
                    continue
                kept = {canon(s) for s in e["signatures"]}
                if any(canon(s) not in kept for s in old[0]["signatures"]):
                    problems.append(f"{name}: signatures removed or altered")
                    continue
                previous = {canon(s) for o in old for s in o["signatures"]}
                added = [s for s in e["signatures"] if canon(s) not in previous]
            trusted = False
            for s in added:
                valid, principal = check_signature(doc["site"], e, s, self.cfg["allowed_signers"])
                report.setdefault(cid, []).append({"key": s["key"], "role": s.get("role", ""),
                                                   "valid": valid, "trusted_by": principal})
                if not valid:
                    problems.append(f"{name}: invalid signature")
                trusted = trusted or bool(principal)
            if old is None:
                if problem := license_problem(e["meta"]):
                    problems.append(f"{name}: {problem}")
                if not trusted:
                    problems.append(f"{name}: not signed by a whitelisted key")
        return problems, new_entries, report

    def advance(self, key, work, head):
        """Walk from the approved commit towards head. Returns the approved commit."""
        st = self.state["sites"].setdefault(key, {})
        approved = st.get("approved")
        if approved and git("merge-base", "--is-ancestor", approved, head, cwd=work, check=False).returncode:
            st["status"] = "blocked: upstream history was rewritten"
            return approved
        rng = [head] + ([f"^{approved}"] if approved else [])
        commits = [c for c in git("rev-list", "--reverse", "--topo-order", *rng, cwd=work).splitlines() if c]
        st["status"] = "up to date"
        blocker = None
        for sha in commits:
            if sha in self.state["rejected"]:
                st["status"] = f"frozen: commit {sha[:10]} was rejected"
                break
            if sha not in self.state["approved"]:
                problems, entries, report = self.check_commit(key, work, sha)
                if problems:
                    if sha not in self.state["pending"]:
                        info = git("log", "-1", "--format=%an%x00%aI%x00%s", sha, cwd=work).split("\x00")
                        self.state["pending"][sha] = {
                            "site": key, "author": info[0], "date": info[1], "subject": info[2],
                            "problems": problems, "entries": entries, "signatures": report, "since": now()}
                        log(f"{key}: commit {sha[:10]} needs review: {problems[0]}")
                    st["status"] = "waiting for review"
                    blocker = sha
                    break
            approved = sha
        for sha, p in list(self.state["pending"].items()):  # drop stale reviews for this site
            if p["site"] == key and sha != blocker:
                del self.state["pending"][sha]
        if approved and approved != st.get("approved"):
            log(f"{key}: approved up to {approved[:10]}")
            st["approved"] = approved
            self.publish(key, work, approved)
        return approved

    def publish(self, key, work, sha):
        """Mirror the approved history in a repo that holds only approved objects."""
        public = self.site_dir(key) / "public.git"
        if not public.exists():
            git("init", "-q", "--bare", public)
        git("push", "-q", "--force", public, f"{sha}:refs/heads/main", cwd=work)
        git("symbolic-ref", "HEAD", "refs/heads/main", cwd=public)
        git("update-server-info", cwd=public)

    # -- sync -------------------------------------------------------------

    def sync(self):
        with self.sync_lock:
            self._sync()

    def _sync(self):
        cfg, state = self.cfg, self.state
        index = self.load_index()
        ranked = self.ranking(index)
        self.index, self.ranked = index, ranked
        budget, planned = cfg["max_storage"], 0
        wanted = {}  # cid -> {site, bytes}, in rank order
        full = False
        for key in ranked:
            st = state["sites"].setdefault(key, {})
            if full:
                st["status"] = "not hosted: storage full"
                continue
            try:
                work, head = self.fetch_site(key, index[key])
                with state.lock:
                    approved = self.advance(key, work, head)
                    state.save()
            except Exception as e:  # one broken site must not stop the others
                st["status"] = f"error: {e}"
                log(f"{key}: {e}")
                continue
            if not approved:
                continue
            doc, _ = read_doc(work, approved)
            for e in sorted(doc["photos"], key=lambda e: (e["meta"].get("name", ""), e["cid"])):
                cid, size = e["cid"], e["meta"]["bytes"]
                if cid in wanted or cid in state["bad_cids"] or size > cfg["max_photo_bytes"]:
                    continue
                cost = int(size * SIZE_MARGIN) + 4096
                if planned + cost > budget:
                    full = True
                    break
                wanted[cid] = {"site": key, "bytes": size, "name": e["meta"].get("name", "")}
                planned += cost

        # Unpin first, so disk use never exceeds the cap: lowest-ranked sites lose out.
        dropped = [cid for cid in state["pins"] if cid not in wanted]
        for cid in dropped:
            try:
                self.ipfs("pin", "rm", cid)
            except RuntimeError as e:
                if "not pinned" not in str(e):
                    log(f"unpin {cid}: {e}")
                    continue
            with state.lock:
                del state["pins"][cid]
            self.drop_thumbs([cid])
        if dropped:
            log(f"unpinned {len(dropped)} photo(s)")
            state.save()
        self.wanted = set(wanted)
        if dropped or self.gc_needed:
            self.ipfs("repo", "gc", "--quiet")
            self.gc_needed = False

        unavailable = {}
        for cid, w in wanted.items():
            if cid in state["pins"]:
                state["pins"][cid]["site"] = w["site"]
                continue
            _, _, problem, permanent = self.fetch_photo(cid, w["bytes"])
            if problem:
                log(f"{w['site']}: {w['name']} {cid}: {problem}")
                if permanent:
                    state["bad_cids"][cid] = {"site": w["site"], "problem": problem, "at": now()}
                else:
                    unavailable[w["site"]] = unavailable.get(w["site"], 0) + 1
                continue
            self.ipfs("pin", "add", "--name=heritage-node", cid)
            size = int(self.ipfs("files", "stat", "--format=<cumulsize>", f"/ipfs/{cid}"))
            with state.lock:
                state["pins"][cid] = {"site": w["site"], "bytes": size, "file_bytes": w["bytes"], "since": now()}
            state.save()

        with state.lock:
            for key in ranked:
                st = state["sites"].get(key, {})
                pins = [p for p in state["pins"].values() if p["site"] == key]
                st["hosted_photos"], st["hosted_bytes"] = len(pins), sum(p["bytes"] for p in pins)
                st["unavailable"] = unavailable.get(key, 0)
        self.last_sync = now()
        state.save()
        log(f"sync done: {human(self.used())} of {human(budget)} used, {len(state['pins'])} photo(s) pinned")

    def used(self):
        with self.state.lock:
            return sum(p["bytes"] for p in self.state["pins"].values())

    # -- what the dashboard shows -----------------------------------------

    def thumb_path(self, cid):
        return self.dir / "thumbs" / f"{cid}.jpg"

    def drop_thumbs(self, cids):
        for cid in cids:
            self.thumb_path(cid).unlink(missing_ok=True)

    def expected_size(self, cid):
        """Signed size of a photo the dashboard may show (under review or hosted), else None."""
        with self.state.lock:
            for p in self.state["pending"].values():
                for e in p["entries"]:
                    if e["cid"] == cid:
                        return e["meta"]["bytes"]
            pin = self.state["pins"].get(cid)
            return pin.get("file_bytes") if pin else None

    def thumbnail(self, cid):
        """(content type, data, problem) for a small preview, cached on disk.

        Without Pillow (python3-pil) the full photo is returned instead."""
        path = self.thumb_path(cid)
        if path.is_file():
            return "image/jpeg", path.read_bytes(), None
        expected = self.expected_size(cid)
        if not expected or expected > self.cfg["max_photo_bytes"]:
            return None, None, "not a photo under review or hosted"
        kind, data, problem, _ = self.fetch_photo(cid, expected, keep=True)
        if problem:
            return None, None, f"photo {problem}"
        try:
            thumb = make_thumbnail(data)
        except ImportError:
            return kind, data, None
        except Exception as e:  # undecodable or oversized image: show nothing
            return None, None, f"cannot make a preview: {e}"
        path.parent.mkdir(exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(thumb)
        os.replace(tmp, path)
        return "image/jpeg", thumb, None

    def site_view(self, key):
        """(approved photos.json or None, rows) describing what is hosted for a site."""
        st = self.state["sites"].get(key, {})
        approved = st.get("approved")
        if not approved:
            return None, []
        doc, err = read_doc(self.site_dir(key) / "work.git", approved)
        if err:
            return None, []
        rows = []
        with self.state.lock:
            for e in sorted(doc["photos"], key=lambda e: (e["meta"].get("name", ""), e["cid"])):
                cid, meta = e["cid"], e["meta"]
                pin, bad = self.state["pins"].get(cid), self.state["bad_cids"].get(cid)
                if pin:
                    reason = None
                elif bad:
                    reason = f"rejected: {bad['problem']}"
                elif meta["bytes"] > self.cfg["max_photo_bytes"]:
                    reason = "larger than max_photo_bytes"
                elif cid in self.wanted:
                    reason = "not fetched yet (unavailable on IPFS)"
                else:
                    reason = "storage cap reached"
                rows.append({"cid": cid, "meta": meta, "pin": pin, "reason": reason})
        return doc, rows

    def review(self, sha, action):
        with self.state.lock:
            p = self.state["pending"].pop(sha, None)
            if not p:
                return False
            record = {"site": p["site"], "at": now()}
            if action == "approve":
                self.state["approved"][sha] = record
            else:
                self.state["rejected"][sha] = record
                self.gc_needed = True  # drop the cached blocks we fetched for review
                self.drop_thumbs(e["cid"] for e in p["entries"] if e["cid"] not in self.state["pins"])
            self.state.save()
        log(f"{p['site']}: commit {sha[:10]} {action}d by maintainer")
        self.wake.set()
        return True

    def loop(self):
        while True:
            try:
                self.sync()
            except Exception:
                log("sync failed:\n" + traceback.format_exc())
            self.wake.wait(self.cfg["poll_interval"])
            self.wake.clear()

    # -- web --------------------------------------------------------------

    def serve(self):
        if not self.cfg["admin_password_hash"]:
            sys.exit("set admin_password_hash in the config first: generate it with  heritage_node.py hash-password")
        token = secrets.token_urlsafe(24)
        host, port = self.cfg["admin_listen"].rsplit(":", 1)
        hosts = {f"{host}:{port}", f"localhost:{port}", f"127.0.0.1:{port}", *self.cfg["admin_hosts"]}
        admin = ThreadingHTTPServer((host, int(port)), type("Admin", (AdminHandler,), {"node": self, "token": token, "hosts": hosts}))
        threading.Thread(target=admin.serve_forever, daemon=True).start()
        log(f"review UI on http://{host}:{port}/")
        if self.cfg["public_listen"]:
            phost, pport = self.cfg["public_listen"].rsplit(":", 1)
            public = ThreadingHTTPServer((phost, int(pport)), type("Public", (PublicHandler,), {"node": self}))
            threading.Thread(target=public.serve_forever, daemon=True).start()
            log(f"public mirror on http://{phost}:{pport}/")
        self.loop()


def esc(value):
    return html.escape(str(value), quote=True)


PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title>
<style>
body{{font:15px/1.45 system-ui,sans-serif;margin:0 auto;max-width:1100px;padding:16px;color:#1d1d1f;background:#fafaf8}}
h1{{font-size:22px}} h2{{font-size:17px;margin-top:28px}} a{{color:#0b57d0}}
table{{border-collapse:collapse;width:100%}} td,th{{text-align:left;padding:6px 8px;border-bottom:1px solid #e3e3df;vertical-align:top}}
.muted{{color:#6b6b66}} .bad{{color:#b3261e}} .ok{{color:#146c2e}} code{{font-size:13px}}
.bar{{height:10px;background:#e3e3df;border-radius:5px;overflow:hidden}} .bar span{{display:block;height:100%;background:#146c2e}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:14px}}
.card{{background:#fff;border:1px solid #e3e3df;border-radius:8px;padding:10px;font-size:13px;overflow-wrap:anywhere}}
.card img{{width:100%;height:200px;object-fit:contain;background:#f0f0ec;border-radius:4px}}
button{{font:inherit;padding:8px 18px;border-radius:6px;border:1px solid #888;cursor:pointer}}
.approve{{background:#146c2e;color:#fff;border-color:#146c2e}} .reject{{background:#b3261e;color:#fff;border-color:#b3261e}}
@media (prefers-color-scheme:dark){{body{{background:#1b1b1a;color:#e8e8e3}} .card{{background:#262624;border-color:#3a3a37}}
td,th{{border-color:#3a3a37}} .muted{{color:#a3a39c}} a{{color:#8ab4f8}} .card img{{background:#30302d}}}}
</style></head><body>{body}</body></html>"""


class AdminHandler(BaseHTTPRequestHandler):
    node = token = hosts = None

    def log_message(self, fmt, *args):
        pass

    def send(self, code, body, ctype="text/html; charset=utf-8", extra=()):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def allowed(self):
        if self.headers.get("Host") not in self.hosts:  # blocks DNS rebinding
            self.send(403, "forbidden host", "text/plain")
            return False
        return True

    COOKIE = "hn_session"

    def session(self):
        """The caller's valid session token, or None."""
        try:
            morsel = SimpleCookie(self.headers.get("Cookie") or "").get(self.COOKIE)
        except CookieError:
            return None
        token = morsel.value if morsel else None
        node = self.node
        with node.auth_lock:
            expiry = node.sessions.get(token)
            if expiry and expiry > time.time():
                return token
            node.sessions.pop(token, None)
        return None

    def cookie(self, value, max_age):
        secure = "; Secure" if self.node.cfg["admin_https"] else ""
        return ("Set-Cookie", f"{self.COOKIE}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}")

    def login_page(self, code=200, error=""):
        msg = f"<p class=bad>{esc(error)}</p>" if error else ""
        body = ("<h1>Heritage node</h1><form method=post action='/login'>"
                "<p><label>Password<br><input type=password name=password autofocus autocomplete=current-password "
                "style='font:inherit;padding:8px;width:min(320px,100%)'></label></p>"
                f"{msg}<button class=approve>Log in</button></form>")
        self.send(code, PAGE.format(title="Log in", body=body))

    def login(self, form):
        node = self.node
        with node.auth_lock:
            cutoff = time.time() - LOGIN_WINDOW
            node.failures = [t for t in node.failures if t > cutoff]
            locked = len(node.failures) >= LOGIN_FAILURES
        if locked:
            return self.login_page(429, "Too many failed attempts. Try again in a few minutes.")
        if check_password(form.get("password", [""])[0], node.cfg["admin_password_hash"]):
            token = secrets.token_urlsafe(32)
            max_age = int(node.cfg["session_hours"] * 3600)
            with node.auth_lock:
                now_ts = time.time()
                node.sessions = {t: e for t, e in node.sessions.items() if e > now_ts}
                node.sessions[token] = now_ts + max_age
            log("admin login")
            return self.send(303, "", extra=[("Location", "/"), self.cookie(token, max_age)])
        with node.auth_lock:
            node.failures.append(time.time())
        log("failed admin login")
        time.sleep(1)
        self.login_page(401, "Wrong password.")

    def do_GET(self):
        if not self.allowed():
            return
        path = urlparse(self.path).path
        if path == "/login":
            return self.login_page()
        if not self.session():
            return self.send(303, "", extra=[("Location", "/login")])
        if path == "/":
            return self.send(200, self.status_page())
        if m := re.fullmatch(r"/review/([0-9a-f]{40})", path):
            return self.review_page(m.group(1))
        if m := re.fullmatch(r"/photo/(b[a-z2-7]{50,100})", path):
            return self.photo(m.group(1))
        if m := re.fullmatch(r"/thumb/(b[a-z2-7]{50,100})", path):
            kind, data, problem = self.node.thumbnail(m.group(1))
            if problem:
                return self.send(404, problem, "text/plain")
            return self.send(200, data, kind, extra=[("Cache-Control", "private, max-age=86400")])
        if m := re.fullmatch(r"/site/([a-z0-9][a-z0-9-]*:[A-Za-z0-9._-]+)", path):
            return self.site_page(m.group(1))
        self.send(404, "not found", "text/plain")

    def do_POST(self):
        if not self.allowed():
            return
        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 <= length <= 10_000:
            return self.send(400, "bad request", "text/plain")
        form = parse_qs(self.rfile.read(length).decode(errors="replace"))
        if path == "/login":
            return self.login(form)
        session = self.session()
        if not session:
            return self.send(303, "", extra=[("Location", "/login")])
        if not secrets.compare_digest(form.get("token", [""])[0], self.token):
            return self.send(403, "bad token: reload the page", "text/plain")
        if path == "/logout":
            with self.node.auth_lock:
                self.node.sessions.pop(session, None)
            return self.send(303, "", extra=[("Location", "/login"), self.cookie("", 0)])
        m = re.fullmatch(r"/review/([0-9a-f]{40})", path)
        if not m:
            return self.send(404, "not found", "text/plain")
        action = form.get("action", [""])[0]
        if action not in ("approve", "reject"):
            return self.send(400, "bad action", "text/plain")
        self.node.review(m.group(1), action)
        self.send(303, "", extra=[("Location", "/")])

    def photo(self, cid):
        expected = self.node.expected_size(cid)
        if not expected or expected > self.node.cfg["max_photo_bytes"]:
            return self.send(404, "not a photo under review or hosted", "text/plain")
        kind, data, problem, _ = self.node.fetch_photo(cid, expected, keep=True)
        if problem:
            return self.send(502, f"photo {problem}", "text/plain")
        self.send(200, data, kind, extra=[("Cache-Control", "private, max-age=3600")])

    def site_page(self, key):
        node = self.node
        s = node.state["sites"].get(key)
        doc, rows = node.site_view(key) if s else (None, [])
        if not doc:
            return self.send(404, PAGE.format(title="Not found", body="<p>Nothing approved for this site yet. <a href='/'>Back</a></p>"))
        hosted = [r for r in rows if r["pin"]]
        missing = [r for r in rows if not r["pin"]]
        lat, lon = doc["lat"], doc["lon"]
        cards = "".join(
            f"<div class=card><a href='/photo/{esc(r['cid'])}'><img loading=lazy src='/thumb/{esc(r['cid'])}' alt=''></a>"
            f"<b>{esc(r['meta'].get('name', ''))}</b> · {human(r['meta']['bytes'])}<br>"
            f"{esc(r['meta'].get('license', ''))} · {esc(r['meta'].get('author', ''))}"
            f"{'<br>source: ' + esc(r['meta']['source']) if r['meta'].get('source') else ''}"
            f"<br><code>{esc(r['cid'])}</code><br><span class=muted>pinned {esc(r['pin'].get('since', ''))}</span></div>"
            for r in hosted)
        missing_rows = "".join(
            f"<tr><td>{esc(r['meta'].get('name', ''))}</td><td>{human(r['meta']['bytes'])}</td>"
            f"<td>{esc(r['reason'])}</td><td><code>{esc(r['cid'])}</code></td></tr>" for r in missing)
        missing_html = (f"<h2>Approved but not hosted ({len(missing)})</h2><table><tr><th>Photo</th><th>Size</th>"
                        f"<th>Why</th><th>CID</th></tr>{missing_rows}</table>") if missing else ""
        body = (f"<p><a href='/'>← all sites</a></p><h1>{esc(doc.get('name', key))}</h1>"
                f"<p><code>{esc(key)}</code> · <a href='https://www.openstreetmap.org/?mlat={lat}&amp;mlon={lon}#map=17/{lat}/{lon}' "
                f"rel=noreferrer>{lat}, {lon}</a><br>repo {esc(node.index.get(key, ''))}<br>"
                f"approved up to <code>{esc(s['approved'][:10])}</code> · {esc(s.get('status', ''))}</p>"
                f"<p><b>Hosting {len(hosted)} of {len(rows)} photos</b>, {human(sum(r['pin']['bytes'] for r in hosted))}</p>"
                f"<div class=grid>{cards or '<p class=muted>No photos hosted.</p>'}</div>{missing_html}")
        self.send(200, PAGE.format(title=doc.get("name", key), body=body))

    def status_page(self):
        node, st = self.node, self.node.state
        cap = node.cfg["max_storage"]
        used = node.used()
        rows = []
        for i, key in enumerate(node.ranked, 1):
            s = st["sites"].get(key, {})
            fav = " ★" if key in node.cfg["favourites"] else ""
            status = s.get("status", "not synced yet")
            cls = "bad" if status.startswith(("error", "blocked", "frozen", "waiting")) else "muted"
            unavailable = f", {s['unavailable']} unavailable" if s.get("unavailable") else ""
            link = f"<a href='/site/{esc(key)}'><code>{esc(key)}</code></a>" if s.get("approved") else f"<code>{esc(key)}</code>"
            rows.append(f"<tr><td>{i}</td><td>{link}{fav}<br><span class=muted>{esc(node.index.get(key, ''))}</span></td>"
                        f"<td class={cls}>{esc(status)}</td><td>{s.get('hosted_photos', 0)} photos, {human(s.get('hosted_bytes', 0))}{unavailable}</td>"
                        f"<td><code>{esc((s.get('approved') or '')[:10])}</code></td></tr>")
        pending = "".join(
            f"<tr><td><a href='/review/{sha}'>{esc(p['subject'])}</a></td><td><code>{esc(p['site'])}</code></td>"
            f"<td>{esc(p['author'])}</td><td>{len(p['entries'])}</td><td class=bad>{esc(p['problems'][0])}</td></tr>"
            for sha, p in st["pending"].items()) or "<tr><td colspan=5 class=muted>Nothing to review.</td></tr>"
        pct = min(100, 100 * used / cap) if cap else 0
        logout = (f"<form method=post action='/logout' style='float:right'><input type=hidden name=token "
                  f"value='{esc(self.token)}'><button>Log out</button></form>")
        body = (f"{logout}<h1>Heritage node</h1><p>{human(used)} of {human(cap)} used · {len(st['pins'])} photos pinned · "
                f"last sync {esc(node.last_sync or 'not yet')}</p><div class=bar><span style='width:{pct:.1f}%'></span></div>"
                f"<h2>Waiting for review</h2><table><tr><th>Commit</th><th>Site</th><th>Author</th><th>New photos</th><th>Why</th></tr>{pending}</table>"
                f"<h2>Sites by preference</h2><table><tr><th>#</th><th>Site</th><th>Status</th><th>Hosted</th><th>Approved</th></tr>{''.join(rows)}</table>")
        return PAGE.format(title="Heritage node", body=body)

    def review_page(self, sha):
        st = self.node.state
        with st.lock:
            p = st["pending"].get(sha)
        if not p:
            return self.send(404, PAGE.format(title="Not found", body="<p>No such review. <a href='/'>Back</a></p>"))
        cards = []
        for e in p["entries"]:
            m = e["meta"]
            sigs = "".join(
                f"<div class={'ok' if s['trusted_by'] else ('bad' if not s['valid'] else 'muted')}>"
                f"{esc(s['role'])}: {'trusted (' + esc(s['trusted_by']) + ')' if s['trusted_by'] else ('INVALID' if not s['valid'] else 'valid, not whitelisted')}"
                f"<br><code>{esc(s['key'][:32])}…</code></div>"
                for s in p["signatures"].get(e["cid"], []))
            cards.append(f"<div class=card><a href='/photo/{esc(e['cid'])}'><img loading=lazy src='/thumb/{esc(e['cid'])}' alt=''></a>"
                         f"<b>{esc(m.get('name', ''))}</b> · {human(m.get('bytes', 0))}<br>{esc(m.get('license', 'no license'))} · {esc(m.get('author', ''))}"
                         f"{'<br>source: ' + esc(m['source']) if m.get('source') else ''}<br><code>{esc(e['cid'])}</code>{sigs}</div>")
        problems = "".join(f"<li>{esc(x)}</li>" for x in p["problems"])
        form = (f"<form method=post style='display:inline'><input type=hidden name=token value='{esc(self.token)}'>"
                f"<input type=hidden name=action value='{{a}}'><button class={{a}}>{{label}}</button></form> ")
        body = (f"<p><a href='/'>← all sites</a></p><h1>{esc(p['subject'])}</h1>"
                f"<p><code>{esc(p['site'])}</code> · commit <code>{esc(sha)}</code><br>by {esc(p['author'])} · {esc(p['date'])}</p>"
                f"<h2>Why it needs review</h2><ul class=bad>{problems}</ul>"
                f"<h2>New photos ({len(p['entries'])})</h2><div class=grid>{''.join(cards) or '<p class=muted>None.</p>'}</div>"
                f"<h2>Decision</h2><p class=muted>Approving lets this site continue from this commit. Rejecting freezes the site at its "
                f"last approved commit: every later commit builds on this one.</p>"
                + form.format(a="approve", label="Approve commit") + form.format(a="reject", label="Reject"))
        self.send(200, PAGE.format(title="Review", body=body))


class PublicHandler(BaseHTTPRequestHandler):
    """Read-only: the list of hosted sites, and their approved git history (dumb HTTP)."""
    node = None

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        path = urlparse(self.path).path
        st = self.node.state
        if path == "/sites.json":
            with st.lock:
                sites = {k: {"approved": s["approved"], "photos": s.get("hosted_photos", 0),
                             "git": f"/git/{k.replace(':', '__')}.git"}
                         for k, s in st["sites"].items() if s.get("approved")}
            data = json.dumps(sites, indent=1).encode()
            return self.reply(200, data, "application/json")
        m = re.fullmatch(r"/git/([a-z0-9-]+__[A-Za-z0-9._-]+)\.git/([A-Za-z0-9._/-]+)", path)
        if m and ".." not in m.group(2):
            key = m.group(1).replace("__", ":", 1)
            if st["sites"].get(key, {}).get("approved"):
                root = (self.node.site_dir(key) / "public.git").resolve()
                f = (root / m.group(2)).resolve()
                if f.is_file() and root in f.parents:
                    return self.reply(200, f.read_bytes(), "application/octet-stream")
        self.reply(404, b"not found", "text/plain")

    def reply(self, code, data, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", choices=["run", "sync", "rank", "hash-password"])
    p.add_argument("--config")
    args = p.parse_args()
    if args.command == "hash-password":
        password = getpass.getpass("New admin password: ")
        if len(password) < 12:
            sys.exit("use at least 12 characters")
        if getpass.getpass("Again: ") != password:
            sys.exit("passwords differ")
        print(f'admin_password_hash = "{hash_password(password)}"')
        return
    if not args.config:
        p.error("--config is required")
    node = Node(load_config(args.config))
    if args.command == "rank":
        index = node.load_index()
        for i, key in enumerate(node.ranking(index), 1):
            print(f"{i:4}  {key}{'  (favourite)' if key in node.cfg['favourites'] else ''}")
    elif args.command == "sync":
        node.sync()
    else:
        node.serve()


if __name__ == "__main__":
    main()
