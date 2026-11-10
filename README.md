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
        "pixels": [5184, 3456],
        "license": "CC-BY-SA-4.0",
        "author": "Jane Smith"
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
- **Every photo carries its own license**, inside the signed metadata (see
  [Licensing](#licensing)).

### Licensing

A site mixes photos from many people and sources, so the license belongs to
each photo, not to the site:

- `license`: an [SPDX identifier](https://spdx.org/licenses/), e.g. `CC-BY-SA-4.0`;
- `author`: the name to credit, which need not match the signing key (an
  importer signs, the original photographer is credited);
- `source`: for imported photos, where the original license is stated.

Because they sit in the signed metadata, the contributor's signature doubles as
the claim "I have the right to release this under this license", and nobody can
change the license afterwards.

**Accepted licenses** are those whose photos can be combined into a
CC BY-SA 4.0 work, such as a 3D model built from them:

| License | Notes |
|---|---|
| `CC0-1.0` | No conditions. |
| `CC-BY-2.0`, `CC-BY-2.5`, `CC-BY-3.0`, `CC-BY-4.0` | Credit required. |
| `CC-BY-SA-2.0`, `CC-BY-SA-2.5`, `CC-BY-SA-3.0`, `CC-BY-SA-4.0` | Credit and share-alike. Covers Wikimedia Commons and Wiki Loves Monuments uploads, and Geograph Britain and Ireland (CC BY-SA 2.0). Older versions allow adaptations under later ones. |
| `OGL-UK-3.0` | UK Open Government Licence, compatible with CC BY. |
| `LicenseRef-PublicDomain` | Copyright expired (e.g. historic photographs). `source` must say why. |

**Rejected:** NonCommercial (NC) licenses cannot be combined with BY-SA, and
NoDerivatives (ND) licenses forbid building a model at all. GFDL-only files
and anything without a license are rejected too.

`author` is required unless the license is CC0 or public domain. A model built
from a mix of these photos is CC BY-SA 4.0, and its credits can be generated from
each photo's `author`, `license` and `source`.

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
    --lat 51.5413 --lon 0.6542 --name "Church of St Clement" \
    --license CC-BY-SA-4.0 --author "Jane Smith" photos/*.JPG

# Contribute to an existing site: clones it (or updates an existing copy)
python3 heritage_add.py add https://example.org/sites/1322326.git --push \
    --license CC-BY-4.0 --author "Jane Smith" photos/*.JPG

# Import a photo from elsewhere, crediting its original author
python3 heritage_add.py add https://example.org/sites/1322326.git \
    --license CC-BY-SA-2.0 --author "John Doe" \
    --source https://www.geograph.org.uk/photo/1234567 photo.jpg

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

`--license` is required on `seed` and `add` and applies to every file in that
run; `--author` and `--source` likewise.

`verify` reports each photo as trusted, untrusted (no signature from a key in
your file) or bad (a signature that does not match its key, site, CID or
metadata), flags missing or disallowed licenses, and exits non-zero if it finds
any bad signature or license.

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

## Hosting nodes: `heritage_node.py`

A hosting node keeps an always-on copy of approved site histories and their
photos. It is meant to run anywhere from a VPS to a Raspberry Pi with an SSD
kept at home or in a site's ticket office.

**Configuration** (`node.example.toml`):

- `index`: the site index, a git repo holding `sites.json`
  (`"<scheme>:<id>"` → repo URL);
- `allowed_signers`: the keys this node trusts (`git` namespace for commits,
  `heritage-photo` for photos);
- `max_storage`: the most photo data the node will pin;
- `favourites`: sites the operator wants hosted first. Every other site follows
  in an order that is random but fixed per node (seeded by its IPFS peer ID), so
  across many nodes hosting spreads roughly evenly over all sites.

**What it does**, every `poll_interval` and after every review decision:

1. For each site in preference order, fetch its repo and walk the commits after
   the last approved one. A commit is approved automatically only if it is
   signed by a trusted key, changes nothing but `photos.json`, leaves the site
   record alone, only adds photos or signatures, and every new photo is validly
   signed by a trusted key with an accepted license.
2. Anything else stops that site and waits in the **review UI**, which shows the
   reasons and the photos. *Approve* lets the walk continue; *Reject* freezes
   the site at its last approved commit.
3. Mirror the approved history in a separate git repo that holds only approved
   objects (optionally served read-only over HTTP with `public_listen`).
4. Pin approved photos within `max_storage`, filling sites in preference order.
   When space runs out, lower-ranked sites are unpinned first and their blocks
   garbage-collected. Each photo is fetched with a hard byte cap and must match
   its signed size and look like an image before it is pinned.

The review UI listens on localhost only. Reach it through an SSH tunnel:
`ssh -L 8090:127.0.0.1:8090 <node>`, then open http://127.0.0.1:8090/.

**Install** on Debian, Ubuntu or Raspberry Pi OS:

```bash
sudo deploy/setup-node.sh my_allowed_signers
sudo nano /etc/heritage-node/node.toml     # max_storage, favourites
sudo systemctl restart heritage-node
journalctl -u heritage-node -f
```

The node needs IPFS port 4001 (tcp and udp) reachable for others to fetch the
photos it pins.

**Not yet covered:** known-CSAM hash matching and image classification before
review, a signed revocation list, and re-encoding photos to neutralise hidden
data. Until then, a maintainer sees every photo that is not signed by a trusted
key before deciding.
