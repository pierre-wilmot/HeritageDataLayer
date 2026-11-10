# Heritage Data Layer

A distributed, ownerless record of photographs of heritage sites.

Anyone can photograph a listed building or monument and contribute the photos.
Nobody has to host them centrally, nobody can silently alter them, and every
reader decides for themselves whose contributions they trust.

## The idea

Three ingredients, each doing one job:

| Piece | Job |
|---|---|
| **IPFS** | Stores the photos. A photo is addressed by its CID, a hash of its content, so any copy from anywhere can be checked against the record. |
| **Git** | Stores the *record*: which photos belong to which site. The history is a hash-linked chain of commits, each one signed by its author. |
| **SSH signatures** | Each photo entry carries signatures from the people who vouch for it. Readers keep their own list of trusted keys and ignore everything else, *before* downloading anything from IPFS. |

### One repository per site

Each heritage site is its own git repository. There are roughly 500,000 listed
sites in England alone, more across the UK and beyond, and keeping them apart
means:

- a site whose history went wrong can be restarted without touching any other;
- you clone only the sites you care about;
- sites can be hosted, mirrored and forked independently.

Sites are identified by the register they are listed in plus their number in
that register, e.g. `historic-england-nhle:1322326`. Numbers from different
registers (Historic England, Historic Environment Scotland, Cadw, ...) can
collide, so the scheme is always part of the identity.

## `photos.json`

The root of every site repository holds a single file:

```json
{
  "type": "heritage-photos/v1",
  "site": {"scheme": "historic-england-nhle", "value": "1322326"},
  "name": "Church of St Clement",
  "lat": 51.5413,
  "lon": 0.6542,
  "photos": [
    {
      "cid": "bafybei...",
      "meta": {
        "name": "IMG_8912.JPG",
        "bytes": 4328580,
        "taken": "2025-01-12T14:03:11Z",
        "camera": "Canon EOS 60D",
        "pixels": [5184, 3456]
      },
      "signatures": [
        {"key": "ssh-ed25519 AAAAC3...", "role": "contributor", "sig": "U1NIU0lH..."},
        {"key": "ssh-ed25519 AAAAC3...", "role": "endorser",    "sig": "U1NIU0lH..."}
      ]
    }
  ]
}
```

- **One entry per CID.** The first person to add a photo is its `contributor`.
  Anyone else who adds the same file becomes an `endorser` on the same entry,
  not a duplicate.
- **`bytes` is signed**, so a reader can refuse to download anything larger
  than what was vouched for.
- **Public keys are stored without their comment**, which usually holds an email
  address.

### What a signature covers

Each signature is an SSH signature (`ssh-keygen -Y sign`, namespace
`heritage-photo`) over:

```
heritage-photo/v1
<scheme>:<id>
<cid>
<meta as sorted, compact JSON>
```

Because the site is part of the signed message, a vouch for a photo of one site
cannot be copied into another site's record. Because the metadata is signed, the
date, location or size cannot be edited without breaking the signature. The CID
already guarantees that the photo itself cannot be swapped.

### Trust

Trust is never decided by the repository: a repo listing its own trusted keys
would be vouching for itself. Each reader keeps a standard OpenSSH
`allowed_signers` file:

```
alice namespaces="git,heritage-photo" ssh-ed25519 AAAAC3...
bob   namespaces="heritage-photo"     ssh-ed25519 AAAAC3...
```

`namespaces="heritage-photo"` trusts a key to vouch for photos, and `git`
trusts it to sign commits. A photo is fetched from IPFS only if at least one
trusted key has signed it.

## `heritage_add.py`

A single script with no dependencies beyond Python 3, git, OpenSSH and a
[Kubo](https://github.com/ipfs/kubo) IPFS node (`ipfs`). On systems without
macOS Spotlight, photo metadata is read with Pillow (`pip install Pillow`).

```bash
# Start a new site: creates the repo and its first commit, then adds the photos
python3 heritage_add.py seed historic-england-nhle:1322326 \
    --lat 51.5413 --lon 0.6542 --name "Church of St Clement" photos/*.JPG

# Contribute to an existing site: clones it (or updates an existing copy)
python3 heritage_add.py add https://example.org/sites/1322326.git --push photos/*.JPG

# Check every signature against your own trust list
python3 heritage_add.py verify 1322326 --allowed-signers ~/.ssh/allowed_signers
```

For every file, `seed` and `add`:

1. add and pin it on the local IPFS node (CIDv1);
2. sign it, as the contributor if it is new or as an endorser if someone else
   already recorded it (files you have already signed are skipped);
3. write `photos.json` and make one signed commit for the batch.

`add` pushes only when given `--push`. It refuses to run on a working copy
with uncommitted changes.

`--omit FIELD` (repeatable, on `seed` and `add`) leaves a metadata field out of
new entries, e.g. `--omit taken` when the camera clock was never set, or
`--omit gps` to keep a location private. Because metadata is signed, a field
cannot be dropped later without re-signing, so decide before adding.

`verify` reports each photo as trusted, untrusted (no signature from a key in
your file) or bad (a signature that does not match its key, site, CID or
metadata), and exits non-zero if any signature is bad.

The signing key defaults to `~/.ssh/heritage_signing_ed25519`; use `--key` for
another. To create one:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/heritage_signing_ed25519
```

### Making photos reachable

`ipfs add` stores photos on your own node only. Other people can fetch them
while your node is running (`ipfs daemon`). To keep them available while your
machine is off, pin the CIDs on an always-on node or a pinning service.

IPFS is public: anyone with a CID can fetch the photo, and copies cannot
reliably be recalled. Check photos for location data or anything private before
adding them.
