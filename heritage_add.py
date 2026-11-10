#!/usr/bin/env python3
"""Add photos to a heritage site repo: pin on IPFS, sign, record in photos.json.

One git repo per site. photos.json at its root holds the site identity, its
location, and every photo CID with metadata and contributor signatures.

  heritage_add.py seed <scheme:id> --lat LAT --lon LON [--name NAME] [--dir DIR] FILE...
  heritage_add.py add <git-url-or-path> [--dir DIR] [--push] FILE...
  heritage_add.py verify <repo-dir> --allowed-signers FILE

<scheme:id> is e.g. historic-england-nhle:1322326 (a bare id means NHLE).

Each signature is an SSH signature (ssh-keygen -Y sign, namespace
"heritage-photo") over:

  heritage-photo/v1\\n<scheme>:<id>\\n<cid>\\n<meta as sorted compact JSON>\\n

so a vouch cannot be moved to another site, and the metadata cannot be edited
without breaking it. Trust is decided by the reader's allowed_signers file
(entries need namespaces="heritage-photo"), never by the repo itself.
Commits are signed with the same key.
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

TYPE = "heritage-photos/v1"
NAMESPACE = "heritage-photo"
FILE = "photos.json"
DEFAULT_KEY = Path.home() / ".ssh" / "heritage_signing_ed25519"


def run(*cmd, cwd=None):
    r = subprocess.run([str(c) for c in cmd], cwd=cwd, capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"{' '.join(map(str, cmd))} failed:\n{r.stderr.strip()}")
    return r.stdout.strip()


def _mdls(path, attr):
    value = run("mdls", "-raw", "-name", attr, path)
    return None if value == "(null)" else value


def _exif_metadata(path):
    """Read EXIF with Pillow (pip install Pillow) where Spotlight is unavailable."""
    from PIL import Image

    meta = {"name": path.name, "bytes": path.stat().st_size}
    with Image.open(path) as im:
        exif = im.getexif()
        meta["pixels"] = list(im.size)
    sub, gps = exif.get_ifd(0x8769), exif.get_ifd(0x8825)
    taken = sub.get(36867) or exif.get(306)
    if taken:  # EXIF time has no zone: recorded as camera local time
        meta["taken"] = datetime.strptime(taken, "%Y:%m:%d %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%S")
    if gps.get(2) and gps.get(4):
        def to_deg(dms, ref):
            return (-1 if ref in ("S", "W") else 1) * float(dms[0] + dms[1] / 60 + dms[2] / 3600)
        meta["gps"] = {"lat": round(to_deg(gps[2], gps.get(1)), 7), "lon": round(to_deg(gps[4], gps.get(3)), 7)}
    if exif.get(272):
        meta["camera"] = exif[272].strip()
    return meta


def metadata(path):
    """Photo metadata: macOS Spotlight (mdls) when available, else Pillow."""
    if shutil.which("mdls") is None:
        return _exif_metadata(path)
    meta = {"name": path.name, "bytes": path.stat().st_size}
    taken = _mdls(path, "kMDItemContentCreationDate")
    if taken:
        meta["taken"] = datetime.strptime(taken, "%Y-%m-%d %H:%M:%S %z").strftime("%Y-%m-%dT%H:%M:%SZ")
    lat, lon = _mdls(path, "kMDItemLatitude"), _mdls(path, "kMDItemLongitude")
    if lat and lon:
        meta["gps"] = {"lat": round(float(lat), 7), "lon": round(float(lon), 7)}
    camera = _mdls(path, "kMDItemAcquisitionModel")
    if camera:
        meta["camera"] = camera.strip('"')
    width, height = _mdls(path, "kMDItemPixelWidth"), _mdls(path, "kMDItemPixelHeight")
    if width and height:
        meta["pixels"] = [int(width), int(height)]
    return meta


def parse_site(text):
    scheme, sep, value = text.rpartition(":")
    if not sep:
        scheme = "historic-england-nhle"
    if not scheme or not value:
        sys.exit(f"bad site id {text!r}: expected <scheme>:<id>")
    return {"scheme": scheme, "value": value}


def payload(site, cid, meta):
    meta_json = json.dumps(meta, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{TYPE}\n{site['scheme']}:{site['value']}\n{cid}\n{meta_json}\n".encode()


def public_key(key):
    """'ssh-ed25519 AAAA...' without the comment (which is usually an email)."""
    return " ".join(Path(f"{key}.pub").read_text().split()[:2])


def sign(key, data):
    with tempfile.TemporaryDirectory() as d:
        msg = Path(d) / "msg"
        msg.write_bytes(data)
        run("ssh-keygen", "-q", "-Y", "sign", "-f", key, "-n", NAMESPACE, msg)
        lines = (Path(d) / "msg.sig").read_text().splitlines()
    return "".join(l for l in lines if not l.startswith("-----"))


def _ssh_verify(allowed_file, principal, sig, data):
    with tempfile.TemporaryDirectory() as d:
        sig_file = Path(d) / "sig"
        body = "\n".join(sig[i:i + 70] for i in range(0, len(sig), 70))
        sig_file.write_text(f"-----BEGIN SSH SIGNATURE-----\n{body}\n-----END SSH SIGNATURE-----\n")
        r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(allowed_file), "-I", principal,
                            "-n", NAMESPACE, "-s", str(sig_file)], input=data, capture_output=True)
        return r.returncode == 0, sig_file.read_text()


def check_signature(site, entry, signature, allowed_signers):
    """Return (valid for its claimed key, trusted principal or None)."""
    data = payload(site, entry["cid"], entry["meta"])
    with tempfile.TemporaryDirectory() as d:
        claimed = Path(d) / "claimed"
        claimed.write_text(f'claimed namespaces="{NAMESPACE}" {signature["key"]}\n')
        valid, armored = _ssh_verify(claimed, "claimed", signature["sig"], data)
        if not valid or not allowed_signers:
            return valid, None
        sig_file = Path(d) / "sig"
        sig_file.write_text(armored)
        r = subprocess.run(["ssh-keygen", "-Y", "find-principals", "-s", str(sig_file),
                            "-f", str(allowed_signers)], capture_output=True, text=True)
    for principal in r.stdout.split() if r.returncode == 0 else []:
        if _ssh_verify(allowed_signers, principal, signature["sig"], data)[0]:
            return True, principal
    return True, None


def load(repo):
    path = Path(repo) / FILE
    if not path.exists():
        sys.exit(f"{path} not found: not a heritage site repo")
    doc = json.loads(path.read_text())
    if doc.get("type") != TYPE:
        sys.exit(f"{path}: unsupported type {doc.get('type')!r}")
    return doc


def save(repo, doc):
    (Path(repo) / FILE).write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")


def add_photos(repo, files, key, omit=()):
    """Pin each file, sign it, record it. Returns [(status, name, cid)].

    Metadata fields named in omit (e.g. "taken" when the camera clock is
    wrong) are left out of new entries."""
    doc = load(repo)
    site, photos = doc["site"], doc["photos"]
    by_cid = {p["cid"]: p for p in photos}
    pub = public_key(key)
    results = []
    for path in map(Path, files):
        cid = run("ipfs", "add", "-Q", "--pin", "--cid-version=1", path)
        entry = by_cid.get(cid)
        if entry is None:
            meta = {k: v for k, v in metadata(path).items() if k not in omit}
            entry = {"cid": cid, "meta": meta, "signatures": []}
            photos.append(entry)
            by_cid[cid] = entry
            status, role = "added", "contributor"
        elif any(s["key"] == pub for s in entry["signatures"]):
            results.append(("skip", path.name, cid))
            continue
        else:  # someone else's photo: endorse the metadata already recorded
            status, role = "signed", "endorser"
        entry["signatures"].append({"key": pub, "role": role,
                                    "sig": sign(key, payload(site, cid, entry["meta"]))})
        results.append((status, path.name, cid))
    photos.sort(key=lambda p: (p["meta"].get("name", ""), p["cid"]))
    save(repo, doc)
    return results


def commit(repo, key, message):
    run("git", "add", FILE, cwd=repo)
    if not run("git", "status", "--porcelain", cwd=repo):
        return False
    run("git", "-c", "gpg.format=ssh", "-c", f"user.signingkey={key}.pub",
        "commit", "-S", "-q", "-m", message, cwd=repo)
    return True


def report(results):
    for status, name, cid in results:
        print(f"{status:6} {name} {cid}")
    return sum(s != "skip" for s, _, _ in results)


def cmd_seed(args):
    site = parse_site(args.site)
    if not -90 <= args.lat <= 90 or not -180 <= args.lon <= 180:
        sys.exit("lat must be in [-90, 90] and lon in [-180, 180]")
    repo = Path(args.dir or f"{site['scheme']}-{site['value']}")
    if repo.exists() and any(repo.iterdir()):
        sys.exit(f"{repo} already exists and is not empty")
    repo.mkdir(parents=True, exist_ok=True)
    run("git", "init", "-q", "-b", "main", cwd=repo)
    doc = {"type": TYPE, "site": site}
    if args.name:
        doc["name"] = args.name
    doc.update({"lat": args.lat, "lon": args.lon, "photos": []})
    save(repo, doc)
    commit(repo, args.key, f"Genesis: {args.name or site['value']} ({site['scheme']}:{site['value']})")
    n = report(add_photos(repo, args.files, args.key, args.omit))
    if n:
        commit(repo, args.key, f"Add {n} photo{'s' * (n != 1)}")
    print(f"seeded {repo}")


def cmd_add(args):
    repo = Path(args.dir or Path(args.url.rstrip("/")).name.removesuffix(".git"))
    if repo.exists():
        if run("git", "status", "--porcelain", cwd=repo):
            sys.exit(f"{repo} has uncommitted changes: commit or discard them first")
        run("git", "pull", "-q", "--ff-only", cwd=repo)
    else:
        run("git", "clone", "-q", args.url, repo)
    n = report(add_photos(repo, args.files, args.key, args.omit))
    if n and commit(repo, args.key, f"Add {n} photo{'s' * (n != 1)}") and args.push:
        run("git", "push", "-q", cwd=repo)
        print("pushed")
    print(f"{n} change{'s' * (n != 1)} in {repo}" + ("" if n == 0 or args.push else " (not pushed)"))


def cmd_verify(args):
    doc = load(args.repo)
    bad = untrusted = ok = 0
    for entry in doc["photos"]:
        trusted_by = []
        for s in entry["signatures"]:
            valid, principal = check_signature(doc["site"], entry, s, args.allowed_signers)
            if not valid:
                bad += 1
                print(f"BAD    {entry['cid']} signature by {s['key'][:40]}...")
            elif principal:
                trusted_by.append(principal)
        if trusted_by:
            ok += 1
        else:
            untrusted += 1
            print(f"UNTRUSTED {entry['cid']} {entry['meta'].get('name', '')}")
    print(f"{ok} trusted, {untrusted} untrusted, {bad} bad signature(s)")
    sys.exit(1 if bad else 0)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--key", type=Path, default=DEFAULT_KEY, help="SSH private key (default: %(default)s)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("seed", help="create a new site repo")
    s.add_argument("site", help="<scheme>:<id>, e.g. historic-england-nhle:1322326")
    s.add_argument("--lat", type=float, required=True)
    s.add_argument("--lon", type=float, required=True)
    s.add_argument("--name")
    s.add_argument("--dir")
    s.add_argument("--omit", action="append", default=[], metavar="FIELD",
                   help="leave a metadata field out, e.g. --omit taken (repeatable)")
    s.add_argument("files", nargs="+")
    s.set_defaults(func=cmd_seed)

    a = sub.add_parser("add", help="clone (or pull) a site repo and add photos")
    a.add_argument("url")
    a.add_argument("--dir")
    a.add_argument("--push", action="store_true")
    a.add_argument("--omit", action="append", default=[], metavar="FIELD",
                   help="leave a metadata field out, e.g. --omit taken (repeatable)")
    a.add_argument("files", nargs="+")
    a.set_defaults(func=cmd_add)

    v = sub.add_parser("verify", help="check every signature against an allowed_signers file")
    v.add_argument("repo")
    v.add_argument("--allowed-signers", required=True, type=Path)
    v.set_defaults(func=cmd_verify)

    args = p.parse_args()
    args.key = args.key.expanduser().resolve()  # git runs inside the repo dir
    if not args.key.exists() or not Path(f"{args.key}.pub").exists():
        sys.exit(f"need both {args.key} and {args.key}.pub")
    args.func(args)


if __name__ == "__main__":
    main()
