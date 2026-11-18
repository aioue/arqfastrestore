# TODO

## Restore-time fallback to an intact copy of a damaged blob

**Why.** `verify` (since f255cc8) reports, for each damaged blob, whether another
location in the same plan holds an intact copy with the same identifier. On a
real repository (139 records, 9.81M blobs, 163,214 bad blobs / 162,653 distinct
identifiers) 151,386 of the distinct bad blobs (93%) had an intact copy in
another pack, and 2,744,174 of 2,764,698 affected paths (99.3%) could be restored
in full from those copies. Arq itself does not repoint a snapshot at another
copy, and `restore`, `restore-path` and `restore-from-csv` do not use the copies
yet, so today nothing is recovered from this data.

**Idea.**
- Build an identifier -> list of BlobLoc index (the `verify` interner already
  sees every BlobLoc referenced by a tree).
- When a read fails (missing file, out of range, not ARQO, HMAC mismatch, decrypt
  or decompress error, identifier mismatch), look up the identifier, read each
  alternate location in turn, and accept the first one that passes HMAC,
  decryption, decompression and the recomputed identifier
  (`sha256(salt || plaintext)`; refuse to run when the formula is not
  calibrated).
- Re-check the identifier at the moment of use. The index can go stale if the
  repository changes between verify and restore.
- Log every fallback (original loc, alternate loc) so a restore can be audited.
- Behind a flag at first (for example `--use-intact-copies`), since it changes
  what a restore reads. Make it work for both whole-snapshot restores and
  `restore-from-csv`.

**Rules.** Read-only against the repository: never rename, delete or rewrite
packs, BlobLocs, pack indexes or backup records. Quarantine renames and HMAC
patching stay out of scope.

**Limits to measure first.**
- Trees are deduplicated by identifier during the walk, so duplicate tree
  locations are not indexed yet. Only data-blob copies are reported today. The
  real repo's tree-pack losses (about 411 trees) are probably not recoverable
  this way.
- 11,267 distinct bad blobs (about 456 MB) had no copy. They stay lost.

**Tests.** Synthetic encrypted plan with a deleted pack and a second copy of the
same blob in another pack: restore must produce identical bytes. Also a corrupted
alternate (must be rejected by the identifier check) and an index entry that no
longer exists.

## Smaller items

- `Impact::collect` silently stops at depth 512, so deeper damaged files are
  never listed. Count them or raise the cap.
- Restore: apply directory modes in a final pass, deepest first, so a 0o555
  directory cannot block its own children.
- BlobReader pack cache eviction picks an arbitrary entry. Use LRU or oldest
  inserted.
- `restore --verify` hardcodes `sha256(salt || plaintext)`. Reuse the
  calibration from `verify`, or degrade to a warning.
- Classify HMAC-only damage (stored HMAC bytes damaged, ciphertext intact).
  Needs an HMAC-skipping decrypt path guarded by the identifier check.
