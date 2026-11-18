// SPDX-License-Identifier: MIT
//! Read-only integrity verification of an Arq 7 repository.
//!
//! `verify` never writes to the repository and never restores any file. It:
//!
//! 1. **Backup records** – reads every `.backuprecord`, checks that it decrypts
//!    (HMAC-SHA256) and parses, and reports `isComplete`, `errorCount` and
//!    `backupRecordErrors`.
//! 2. **Trees** – walks every record's tree (each distinct tree once, as trees
//!    are content-addressed) and collects every blob location referenced by
//!    every file (data, ACL and xattr blobs).
//! 3. **Blobs** – for each distinct blob location: the pack/object file must
//!    exist, `offset + length` must fit inside it, the ARQO HMAC-SHA256 must
//!    match, it must decrypt and decompress, and (when the formula can be
//!    established) the plaintext must hash to the stored blob identifier.
//!    Damaged blobs are also classified as zero-filled or containing zero runs,
//!    which is the signature of a bad sector that was replaced by zeros.
//! 4. **Impact** – maps every damaged blob back to the files (and the newest
//!    snapshot) that reference it, so damaged data can be re-backed up.
//!
//! Exit status (set by the caller): 0 = clean, 2 = damage found.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::crypto::{Arq7Keys, decrypt_arq7_object};
use crate::format::arq7::{BlobLoc, Tree, decompress_blob, decompress_lz4};
use crate::format::backup_record::parse_backup_record_bytes;

const ARQO_MAGIC: &[u8] = b"ARQO";
/// A run of at least this many zero bytes inside a damaged blob is reported.
const MIN_ZERO_RUN: usize = 512;
/// Largest single read when neighbouring blobs of one pack are read together.
const MAX_COALESCED_READ: u64 = 8 << 20;
/// Largest gap between neighbouring blobs that is read through rather than skipped.
const MAX_COALESCE_GAP: u64 = 64 << 10;
/// Trees of one pack handed to a single worker in the tree walk.
const TREE_BATCH: usize = 256;

// ---------------------------------------------------------------------------
// Failure model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailKind {
    /// The pack or object file does not exist.
    MissingFile,
    /// `offset + length` runs past the end of the file.
    OutOfRange,
    /// The OS returned an I/O error while reading.
    ReadError,
    /// The bytes do not start with the `ARQO` magic.
    NotArqo,
    /// The ARQO HMAC-SHA256 does not match (bit rot, zeros, truncation).
    HmacMismatch,
    /// HMAC matched but decryption/padding failed.
    DecryptError,
    /// Decrypted, but decompression failed.
    DecompressError,
    /// Decrypted and decompressed, but the plaintext does not hash to the identifier.
    IdentifierMismatch,
    /// A tree blob decoded but could not be parsed.
    TreeParseError,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlobFailure {
    pub kind: FailKind,
    pub detail: String,
    /// Every byte of the stored blob is zero.
    pub zero_filled: bool,
    /// Longest run of zero bytes in the stored blob (0 if the bytes were not readable).
    pub max_zero_run: u64,
}

impl BlobFailure {
    fn simple(kind: FailKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            zero_filled: false,
            max_zero_run: 0,
        }
    }

    fn with_raw(kind: FailKind, detail: impl Into<String>, raw: &[u8]) -> Self {
        let (zero_filled, max_zero_run) = zero_stats(raw);
        Self {
            kind,
            detail: detail.into(),
            zero_filled,
            max_zero_run,
        }
    }
}

/// `(all bytes zero, longest zero run)` of `raw`.
fn zero_stats(raw: &[u8]) -> (bool, u64) {
    if raw.is_empty() {
        return (false, 0);
    }
    let mut best = 0usize;
    let mut cur = 0usize;
    for &b in raw {
        if b == 0 {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    (
        best == raw.len(),
        if best >= MIN_ZERO_RUN { best as u64 } else { 0 },
    )
}

// ---------------------------------------------------------------------------
// Blob identifier formula (established empirically per repository)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdFormula {
    /// SHA256(plaintext)
    Plain,
    /// SHA256(salt || plaintext)
    SaltPrefix,
    /// SHA256(plaintext || salt)
    SaltSuffix,
    /// SHA256(salt || compressed-plaintext)
    CompSaltPrefix,
    /// SHA256(compressed-plaintext || salt)
    CompSaltSuffix,
}

const ID_FORMULAS: [IdFormula; 5] = [
    IdFormula::Plain,
    IdFormula::SaltPrefix,
    IdFormula::SaltSuffix,
    IdFormula::CompSaltPrefix,
    IdFormula::CompSaltSuffix,
];

impl IdFormula {
    fn name(self) -> &'static str {
        match self {
            IdFormula::Plain => "sha256(plaintext)",
            IdFormula::SaltPrefix => "sha256(salt||plaintext)",
            IdFormula::SaltSuffix => "sha256(plaintext||salt)",
            IdFormula::CompSaltPrefix => "sha256(salt||compressed plaintext)",
            IdFormula::CompSaltSuffix => "sha256(compressed plaintext||salt)",
        }
    }

    fn compute(self, salt: &[u8], comp: &[u8], plain: &[u8]) -> String {
        let mut h = Sha256::new();
        match self {
            IdFormula::Plain => h.update(plain),
            IdFormula::SaltPrefix => {
                h.update(salt);
                h.update(plain);
            }
            IdFormula::SaltSuffix => {
                h.update(plain);
                h.update(salt);
            }
            IdFormula::CompSaltPrefix => {
                h.update(salt);
                h.update(comp);
            }
            IdFormula::CompSaltSuffix => {
                h.update(comp);
                h.update(salt);
            }
        }
        hex::encode(h.finalize())
    }
}

// ---------------------------------------------------------------------------
// Reading and checking one blob
// ---------------------------------------------------------------------------

/// Storage-relative path of the file holding `loc`.
fn loc_path(loc: &BlobLoc) -> &str {
    loc.relative_path
        .as_deref()
        .unwrap_or(&loc.identifier)
        .trim_start_matches('/')
}

/// Decrypted (still compressed) and decompressed bytes of a blob.
struct Fetched {
    comp: Vec<u8>,
    plain: Vec<u8>,
}

fn file_size(file: &File, path: &str) -> Result<u64, BlobFailure> {
    file.metadata()
        .map(|m| m.len())
        .map_err(|e| BlobFailure::simple(FailKind::ReadError, format!("stat {path}: {e}")))
}

/// `(offset, length)` of the stored bytes of `loc` in a file of `size` bytes.
fn stored_range(loc: &BlobLoc, size: u64, path: &str) -> Result<(u64, u64), BlobFailure> {
    let (offset, length) = if loc.is_packed {
        (loc.offset, loc.length)
    } else {
        (0, size)
    };
    let end = offset.saturating_add(length);
    if end > size {
        return Err(BlobFailure::simple(
            FailKind::OutOfRange,
            format!("{path}: blob needs bytes {offset}..{end} but the file is {size} bytes"),
        ));
    }
    Ok((offset, length))
}

/// Fetch the stored bytes of `loc` from an already-open file of `size` bytes.
fn read_stored(file: &File, size: u64, loc: &BlobLoc, path: &str) -> Result<Vec<u8>, BlobFailure> {
    let (offset, length) = stored_range(loc, size, path)?;
    let mut buf = vec![0u8; length as usize];
    file.read_exact_at(&mut buf, offset).map_err(|e| {
        BlobFailure::simple(
            FailKind::ReadError,
            format!("{path}: read {length} bytes at {offset}: {e}"),
        )
    })?;
    Ok(buf)
}

/// Read the stored bytes of each of `locs` (all in `path`, sorted by offset)
/// and call `f(index, bytes)` for each, in order.
///
/// The file is opened and sized once. Neighbouring packed blobs are fetched
/// with one read of up to [`MAX_COALESCED_READ`] bytes; if that read fails,
/// each blob is re-read on its own so an I/O error is attributed only to the
/// blobs it really affects. Results are identical to calling [`read_stored`]
/// per blob.
fn for_each_stored(
    root: &Path,
    path: &str,
    locs: &[&BlobLoc],
    mut f: impl FnMut(usize, Result<&[u8], BlobFailure>),
) {
    let opened = open_pack(root, path).and_then(|file| {
        let size = file_size(&file, path)?;
        Ok((file, size))
    });
    let (file, size) = match opened {
        Ok(v) => v,
        Err(fail) => {
            for i in 0..locs.len() {
                f(i, Err(fail.clone()));
            }
            return;
        }
    };
    let single = |loc: &BlobLoc| read_stored(&file, size, loc, path);

    let mut i = 0;
    while i < locs.len() {
        let loc = locs[i];
        let (start, length) = match stored_range(loc, size, path) {
            Ok(r) => r,
            Err(fail) => {
                f(i, Err(fail));
                i += 1;
                continue;
            }
        };
        // Extend a run of in-range packed neighbours.
        let mut end = start + length;
        let mut j = i + 1;
        if loc.is_packed {
            while let Some(next) = locs.get(j) {
                let next_end = next.offset.saturating_add(next.length);
                if !next.is_packed
                    || next.offset < start
                    || next_end > size
                    || next.offset > end.saturating_add(MAX_COALESCE_GAP)
                    || next_end.max(end) - start > MAX_COALESCED_READ
                {
                    break;
                }
                end = end.max(next_end);
                j += 1;
            }
        }
        if j == i + 1 {
            match single(loc) {
                Ok(buf) => f(i, Ok(&buf)),
                Err(fail) => f(i, Err(fail)),
            }
            i += 1;
            continue;
        }
        let mut buf = vec![0u8; (end - start) as usize];
        if file.read_exact_at(&mut buf, start).is_ok() {
            for (k, l) in locs.iter().enumerate().take(j).skip(i) {
                let a = (l.offset - start) as usize;
                f(k, Ok(&buf[a..a + l.length as usize]));
            }
        } else {
            for (k, l) in locs.iter().enumerate().take(j).skip(i) {
                match single(l) {
                    Ok(buf) => f(k, Ok(&buf)),
                    Err(fail) => f(k, Err(fail)),
                }
            }
        }
        i = j;
    }
}

fn open_pack(root: &Path, path: &str) -> Result<File, BlobFailure> {
    File::open(root.join(path)).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            BlobFailure::simple(FailKind::MissingFile, format!("{path}: no such file"))
        } else {
            BlobFailure::simple(FailKind::ReadError, format!("{path}: open: {e}"))
        }
    })
}

/// Decrypt and decompress stored bytes. HMAC is checked before decryption.
fn decode_stored(raw: &[u8], loc: &BlobLoc, keys: &Arq7Keys) -> Result<Fetched, BlobFailure> {
    if !raw.starts_with(ARQO_MAGIC) {
        return Err(BlobFailure::with_raw(
            FailKind::NotArqo,
            "stored bytes do not start with ARQO",
            raw,
        ));
    }
    let comp = decrypt_arq7_object(raw, keys).map_err(|e| {
        let msg = format!("{e:#}");
        let kind = if msg.contains("HMAC") {
            FailKind::HmacMismatch
        } else {
            FailKind::DecryptError
        };
        BlobFailure::with_raw(kind, msg, raw)
    })?;
    let plain = decompress_blob(&comp, loc.compression_type).map_err(|e| {
        BlobFailure::simple(
            FailKind::DecompressError,
            format!("compression_type={}: {e:#}", loc.compression_type),
        )
    })?;
    Ok(Fetched { comp, plain })
}

fn check_identifier(
    f: &Fetched,
    loc: &BlobLoc,
    keys: &Arq7Keys,
    formula: Option<IdFormula>,
) -> Result<(), BlobFailure> {
    if let Some(formula) = formula {
        let got = formula.compute(&keys.keys[2], &f.comp, &f.plain);
        if !got.eq_ignore_ascii_case(&loc.identifier) {
            return Err(BlobFailure::simple(
                FailKind::IdentifierMismatch,
                format!("expected {}, computed {got}", loc.identifier),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Repository model
// ---------------------------------------------------------------------------

type BlobKey = (u32, u64, u64);

struct BlobRef {
    /// The blob's location with `relative_path` cleared: the path is held once,
    /// shared, in `path` (10M blobs would otherwise each carry a copy).
    loc: BlobLoc,
    path: Arc<str>,
}

/// Distinct blob locations. Interning a location already seen allocates nothing.
#[derive(Default)]
struct Interner {
    /// Storage-relative file path → path id.
    path_ids: HashMap<Arc<str>, u32>,
    paths: Vec<Arc<str>>,
    /// (path id, offset, length) → blob index.
    map: HashMap<BlobKey, u32>,
    blobs: Vec<BlobRef>,
}

impl Interner {
    fn intern(&mut self, loc: &BlobLoc) -> u32 {
        let path = loc_path(loc);
        let pid = match self.path_ids.get(path) {
            Some(&p) => p,
            None => {
                let p = self.paths.len() as u32;
                let shared: Arc<str> = Arc::from(path);
                self.paths.push(shared.clone());
                self.path_ids.insert(shared, p);
                p
            }
        };
        let key = (pid, loc.offset, loc.length);
        if let Some(&i) = self.map.get(&key) {
            return i;
        }
        let i = self.blobs.len() as u32;
        self.blobs.push(BlobRef {
            loc: BlobLoc {
                identifier: loc.identifier.clone(),
                relative_path: None,
                ..*loc
            },
            path: self.paths[pid as usize].clone(),
        });
        self.map.insert(key, i);
        i
    }
}

#[derive(Default)]
struct TreeInfo {
    /// File entries: name and the blobs holding its content/metadata.
    files: Vec<(String, Vec<u32>)>,
    /// Sub-directories: name and tree identifier.
    subtrees: Vec<(String, String)>,
    /// Blob holding this tree itself.
    self_blob: u32,
    /// The tree blob could not be read or parsed; children are unknown.
    broken: bool,
}

#[derive(Debug, Serialize)]
pub struct RecordReport {
    pub path: String,
    pub timestamp: u64,
    pub local_path: String,
    pub is_complete: bool,
    pub error_count: Option<u64>,
    pub record_errors: Option<u64>,
    pub problem: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PackReport {
    pub path: String,
    pub bad_blobs: usize,
    pub bad_bytes: u64,
    pub zero_filled_blobs: usize,
    pub kinds: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
pub struct AffectedFile {
    pub path: String,
    pub newest_record: u64,
    pub records_affected: u32,
    pub kinds: Vec<FailKind>,
    pub packs: Vec<String>,
    /// Every damaged blob of this file has an intact copy elsewhere.
    pub recoverable_from_copies: bool,
    #[serde(skip)]
    blobs: Vec<u32>,
}

#[derive(Debug, Serialize)]
pub struct VerifyReport {
    pub plan: String,
    pub identifier_formula: Option<String>,
    pub records_total: usize,
    pub records_unreadable: usize,
    pub records_incomplete: usize,
    pub records_with_errors: usize,
    pub trees_checked: usize,
    pub trees_broken: usize,
    pub blobs_checked: usize,
    pub blobs_bad: usize,
    /// Damaged blobs whose identifier is also stored at another location that
    /// passed every check, including the identifier check. Their content is
    /// recoverable from that copy. Counted only when the formula is known.
    pub blobs_bad_with_intact_copy: usize,
    pub bytes_checked: u64,
    pub failures_by_kind: BTreeMap<String, usize>,
    /// Up to three example failure messages per kind.
    pub failure_samples: BTreeMap<String, Vec<String>>,
    pub bad_packs: Vec<PackReport>,
    pub affected_files: Vec<AffectedFile>,
    pub records: Vec<RecordReport>,
}

impl VerifyReport {
    pub fn is_clean(&self) -> bool {
        self.blobs_bad == 0
            && self.trees_broken == 0
            && self.records_unreadable == 0
            && self.records_with_errors == 0
    }
}

pub struct VerifyOptions {
    /// Directory that relative blob paths are resolved against (parent of the plan dir).
    pub storage_root: PathBuf,
    /// The plan directory itself (`.../<plan-uuid>`).
    pub plan_dir: PathBuf,
    pub keys: Arq7Keys,
    pub check_identifier: bool,
    pub json: bool,
    pub report_csv: Option<PathBuf>,
    pub max_files_printed: usize,
    /// Verify only the newest N backup records (None = all).
    pub latest: Option<usize>,
}

// ---------------------------------------------------------------------------
// Phase 1: backup records
// ---------------------------------------------------------------------------

struct RecordInfo {
    report: RecordReport,
    root: Option<BlobLoc>,
}

fn decode_record_raw(data: &[u8], keys: &Arq7Keys) -> Result<Vec<u8>> {
    let dec;
    let body = if data.starts_with(ARQO_MAGIC) {
        dec = decrypt_arq7_object(data, keys).context("decrypt backup record")?;
        &dec[..]
    } else {
        data
    };
    decompress_lz4(body).context("LZ4 decompress backup record")
}

/// `(errorCount, number of backupRecordErrors)` from the decoded record.
fn record_error_counts(raw: &[u8]) -> (Option<u64>, Option<u64>) {
    if raw.first() == Some(&b'{') {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(raw) {
            let ec = v["errorCount"].as_u64();
            let re = v["backupRecordErrors"].as_array().map(|a| a.len() as u64);
            return (ec, re);
        }
    } else if let Ok(plist::Value::Dictionary(d)) =
        plist::Value::from_reader(std::io::Cursor::new(raw))
    {
        let ec = d.get("errorCount").and_then(|v| v.as_unsigned_integer());
        let re = d
            .get("backupRecordErrors")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as u64);
        return (ec, re);
    }
    (None, None)
}

fn collect_record_paths(plan_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(folders) = std::fs::read_dir(plan_dir.join("backupfolders")) else {
        return out;
    };
    for folder in folders.flatten() {
        let Ok(prefixes) = std::fs::read_dir(folder.path().join("backuprecords")) else {
            continue;
        };
        for prefix in prefixes.flatten() {
            let Ok(files) = std::fs::read_dir(prefix.path()) else {
                continue;
            };
            for f in files.flatten() {
                let p = f.path();
                if p.extension().is_some_and(|e| e == "backuprecord") {
                    out.push(p);
                }
            }
        }
    }
    out.sort();
    out
}

fn read_record(path: &Path, keys: &Arq7Keys) -> RecordInfo {
    let display = path.display().to_string();
    let fail = |msg: String| RecordInfo {
        report: RecordReport {
            path: display.clone(),
            timestamp: 0,
            local_path: String::new(),
            is_complete: false,
            error_count: None,
            record_errors: None,
            problem: Some(msg),
        },
        root: None,
    };
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return fail(format!("read: {e}")),
    };
    let raw = match decode_record_raw(&data, keys) {
        Ok(r) => r,
        Err(e) => return fail(format!("{e:#}")),
    };
    let (error_count, record_errors) = record_error_counts(&raw);
    match parse_backup_record_bytes(&data, Some(keys)) {
        Ok(rec) => RecordInfo {
            report: RecordReport {
                path: display,
                timestamp: rec.timestamp,
                local_path: rec.local_path,
                is_complete: rec.is_complete,
                error_count,
                record_errors,
                problem: if rec.root_tree_blob_loc.is_none() {
                    Some("record has no root tree".to_owned())
                } else {
                    None
                },
            },
            root: rec.root_tree_blob_loc,
        },
        Err(e) => fail(format!("{e:#}")),
    }
}

// ---------------------------------------------------------------------------
// Phase 2: trees
// ---------------------------------------------------------------------------

struct TreeRead {
    loc: BlobLoc,
    outcome: Result<Tree, BlobFailure>,
}

/// Check and parse one tree blob from its stored bytes.
fn decode_tree(
    raw: Result<&[u8], BlobFailure>,
    loc: &BlobLoc,
    keys: &Arq7Keys,
    formula: Option<IdFormula>,
) -> Result<Tree, BlobFailure> {
    let f = decode_stored(raw?, loc, keys)?;
    check_identifier(&f, loc, keys, formula)?;
    Tree::parse(&f.plain).map_err(|e| {
        let head = hex::encode(&f.plain[..f.plain.len().min(65536)]);
        BlobFailure::simple(
            FailKind::TreeParseError,
            format!("{e:#} (plaintext {} bytes, starts {head})", f.plain.len()),
        )
    })
}

/// Read, check and parse every tree in `frontier`.
///
/// Trees are sorted by (file, offset) and handed out in batches of up to
/// [`TREE_BATCH`] from one file, so each worker opens and sizes a pack once and
/// reads neighbouring trees together instead of one open+stat+read per tree.
fn read_trees(
    root: &Path,
    keys: &Arq7Keys,
    frontier: Vec<BlobLoc>,
    formula: Option<IdFormula>,
) -> Vec<TreeRead> {
    let mut frontier = frontier;
    frontier.sort_by(|a, b| loc_path(a).cmp(loc_path(b)).then(a.offset.cmp(&b.offset)));
    let mut batches: Vec<&[BlobLoc]> = Vec::new();
    let mut rest = &frontier[..];
    while let Some(first) = rest.first() {
        let p = loc_path(first);
        let n = rest
            .iter()
            .take(TREE_BATCH)
            .take_while(|l| loc_path(l) == p)
            .count();
        let (batch, tail) = rest.split_at(n);
        batches.push(batch);
        rest = tail;
    }
    batches
        .par_iter()
        .flat_map_iter(|batch| {
            let locs: Vec<&BlobLoc> = batch.iter().collect();
            let mut out = Vec::with_capacity(batch.len());
            for_each_stored(root, loc_path(&batch[0]), &locs, |i, raw| {
                out.push(TreeRead {
                    loc: batch[i].clone(),
                    outcome: decode_tree(raw, &batch[i], keys, formula),
                });
            });
            out
        })
        .collect()
}

struct Model {
    interner: Interner,
    trees: HashMap<String, TreeInfo>,
    /// Failures already established while reading trees.
    failures: HashMap<u32, BlobFailure>,
    /// Blobs whose check is already complete (tree blobs).
    checked: HashSet<u32>,
}

fn walk_trees(opts: &VerifyOptions, roots: &[BlobLoc], formula: Option<IdFormula>) -> Model {
    let mut model = Model {
        interner: Interner::default(),
        trees: HashMap::new(),
        failures: HashMap::new(),
        checked: HashSet::new(),
    };
    let mut frontier: Vec<BlobLoc> = Vec::new();
    let mut queued: HashSet<String> = HashSet::new();
    for r in roots {
        if queued.insert(r.identifier.clone()) {
            frontier.push(r.clone());
        }
    }

    let mut level = 0usize;
    while !frontier.is_empty() {
        level += 1;
        eprintln!(
            "verify: tree level {level}: {} trees ({} done)",
            frontier.len(),
            model.trees.len()
        );
        let reads = read_trees(
            &opts.storage_root,
            &opts.keys,
            std::mem::take(&mut frontier),
            formula,
        );

        let mut next: Vec<BlobLoc> = Vec::new();
        for tr in reads {
            let self_blob = model.interner.intern(&tr.loc);
            model.checked.insert(self_blob);
            let mut info = TreeInfo {
                self_blob,
                ..TreeInfo::default()
            };
            match tr.outcome {
                Err(fail) => {
                    info.broken = true;
                    model.failures.insert(self_blob, fail);
                }
                Ok(tree) => {
                    for (name, node) in tree.nodes {
                        if node.deleted {
                            continue;
                        }
                        if node.is_tree
                            && let Some(sub) = &node.tree_blob_loc
                        {
                            info.subtrees.push((name.clone(), sub.identifier.clone()));
                            // Most subtree references are to trees already queued;
                            // check before cloning the identifier.
                            if !queued.contains(&sub.identifier) {
                                queued.insert(sub.identifier.clone());
                                next.push(sub.clone());
                            }
                        }
                        let mut blobs = Vec::new();
                        let locs = node
                            .data_blob_locs
                            .iter()
                            .chain(node.acl_blob_loc.iter())
                            .chain(node.xattrs_blob_locs.iter());
                        for l in locs {
                            if l.identifier.is_empty() {
                                continue;
                            }
                            blobs.push(model.interner.intern(l));
                        }
                        if !node.is_tree {
                            info.files.push((name, blobs));
                        } else if !blobs.is_empty() {
                            // ACL/xattrs on a directory: attribute to "<dir>/." entry.
                            info.files.push((format!("{name}/."), blobs));
                        }
                    }
                }
            }
            model.trees.insert(tr.loc.identifier.clone(), info);
        }
        frontier = next;
    }
    model
}

/// Pick the identifier formula that reproduces the identifiers of the root trees.
///
/// arq_restore never recomputes identifiers, so the formula is established
/// empirically: the first formula that reproduces every readable root tree wins.
fn calibrate_formula(opts: &VerifyOptions, roots: &[BlobLoc]) -> Option<IdFormula> {
    let mut seen = HashSet::new();
    let samples: Vec<(&BlobLoc, Fetched)> = roots
        .iter()
        .filter(|l| seen.insert(l.identifier.clone()))
        .take(64)
        .filter_map(|loc| {
            let path = loc_path(loc);
            let file = open_pack(&opts.storage_root, path).ok()?;
            let size = file_size(&file, path).ok()?;
            let raw = read_stored(&file, size, loc, path).ok()?;
            let f = decode_stored(&raw, loc, &opts.keys).ok()?;
            Some((loc, f))
        })
        .collect();
    if samples.is_empty() {
        return None;
    }
    ID_FORMULAS.into_iter().find(|f| {
        samples.iter().all(|(loc, fetched)| {
            f.compute(&opts.keys.keys[2], &fetched.comp, &fetched.plain)
                .eq_ignore_ascii_case(&loc.identifier)
        })
    })
}

// ---------------------------------------------------------------------------
// Phase 3: blobs
// ---------------------------------------------------------------------------

fn verify_blobs(
    opts: &VerifyOptions,
    model: &Model,
    formula: Option<IdFormula>,
) -> (HashMap<u32, BlobFailure>, u64) {
    // Group the remaining blobs by file so each pack is opened once and read in offset order.
    let mut by_path: BTreeMap<&str, Vec<u32>> = BTreeMap::new();
    for (i, b) in model.interner.blobs.iter().enumerate() {
        let i = i as u32;
        if model.checked.contains(&i) {
            continue;
        }
        by_path.entry(&b.path).or_default().push(i);
    }
    let total: usize = by_path.values().map(Vec::len).sum();
    eprintln!("verify: checking {total} blobs in {} files", by_path.len());

    let done = AtomicUsize::new(0);
    let bytes = std::sync::atomic::AtomicU64::new(0);
    let groups: Vec<(&str, Vec<u32>)> = by_path.into_iter().collect();

    let results: Vec<(u32, BlobFailure)> = groups
        .par_iter()
        .flat_map_iter(|(path, idxs)| {
            let mut idxs = idxs.clone();
            idxs.sort_by_key(|&i| model.interner.blobs[i as usize].loc.offset);
            let locs: Vec<&BlobLoc> = idxs
                .iter()
                .map(|&i| &model.interner.blobs[i as usize].loc)
                .collect();
            let mut out = Vec::new();
            for_each_stored(&opts.storage_root, path, &locs, |k, raw| {
                let loc = locs[k];
                let res = raw.and_then(|raw| {
                    bytes.fetch_add(raw.len() as u64, Ordering::Relaxed);
                    let f = decode_stored(raw, loc, &opts.keys)?;
                    check_identifier(&f, loc, &opts.keys, formula)
                });
                if let Err(f) = res {
                    out.push((idxs[k], f));
                }
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_multiple_of(25_000) {
                    eprintln!("verify: {n}/{total} blobs checked");
                }
            });
            out
        })
        .collect();

    (results.into_iter().collect(), bytes.load(Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
// Phase 4: impact
// ---------------------------------------------------------------------------

/// Maps damaged blobs back to the files that use them.
///
/// Two steps: `mark_bad` classifies every tree once (sequential, memoised), then
/// `collect` walks only the damaged subtrees of one record against that read-only
/// memo, so records can be processed in parallel.
struct Impact<'a> {
    model: &'a Model,
    failures: &'a HashMap<u32, BlobFailure>,
    /// damaged blob -> an intact copy of it
    copies: &'a HashMap<u32, u32>,
    /// tree identifier -> the tree or something below it is damaged
    bad: HashMap<String, bool>,
}

impl Impact<'_> {
    fn mark_bad(&mut self, id: &str) -> bool {
        if let Some(&b) = self.bad.get(id) {
            return b;
        }
        // Guard against cycles (corrupt data) by pre-seeding.
        self.bad.insert(id.to_owned(), false);
        let Some(info) = self.model.trees.get(id) else {
            self.bad.insert(id.to_owned(), true);
            return true;
        };
        let mut bad = info.broken || self.failures.contains_key(&info.self_blob);
        bad |= info
            .files
            .iter()
            .any(|(_, bl)| bl.iter().any(|b| self.failures.contains_key(b)));
        // Visit every child (no early exit) so all of them end up in the memo.
        for (_, sub) in &info.subtrees {
            bad |= self.mark_bad(sub);
        }
        self.bad.insert(id.to_owned(), bad);
        bad
    }

    fn collect(
        &self,
        id: &str,
        prefix: &str,
        record_ts: u64,
        out: &mut HashMap<String, AffectedFile>,
        depth: usize,
    ) {
        if depth > 512 || !self.bad.get(id).copied().unwrap_or(false) {
            return;
        }
        let Some(info) = self.model.trees.get(id) else {
            return;
        };
        if info.broken {
            self.note(out, format!("{prefix}/"), &[info.self_blob], record_ts);
            return;
        }
        for (name, blobs) in &info.files {
            if blobs.iter().any(|b| self.failures.contains_key(b)) {
                self.note(out, format!("{prefix}/{name}"), blobs, record_ts);
            }
        }
        for (name, sub) in &info.subtrees {
            let p = format!("{prefix}/{name}");
            self.collect(sub, &p, record_ts, out, depth + 1);
        }
    }

    fn note(
        &self,
        out: &mut HashMap<String, AffectedFile>,
        path: String,
        blobs: &[u32],
        record_ts: u64,
    ) {
        let bad_blobs: Vec<u32> = blobs
            .iter()
            .copied()
            .filter(|b| self.failures.contains_key(b))
            .collect();
        let mut kinds: Vec<FailKind> = Vec::new();
        let mut packs: Vec<String> = Vec::new();
        for b in &bad_blobs {
            let f = &self.failures[b];
            if !kinds.contains(&f.kind) {
                kinds.push(f.kind);
            }
            let p: &str = &self.model.interner.blobs[*b as usize].path;
            if !packs.iter().any(|x| x == p) {
                packs.push(p.to_owned());
            }
        }
        let recoverable_from_copies = bad_blobs.iter().all(|b| self.copies.contains_key(b));
        out.entry(path.clone()).or_insert_with(|| AffectedFile {
            path,
            newest_record: record_ts,
            records_affected: 1,
            kinds,
            packs,
            recoverable_from_copies,
            blobs: bad_blobs,
        });
    }
}

/// For each damaged blob, another interned location with the same identifier
/// that passed every check, if any.
///
/// Every interned location is checked, so a location absent from `failures`
/// decrypted, decompressed and hashed to its identifier; with the identifier
/// formula known that proves it holds the same content. Trees are walked once
/// per identifier, so in practice only data blobs can have copies.
fn intact_copies(model: &Model, failures: &HashMap<u32, BlobFailure>) -> HashMap<u32, u32> {
    let blobs = &model.interner.blobs;
    let wanted: HashSet<&str> = failures
        .keys()
        .map(|i| blobs[*i as usize].loc.identifier.as_str())
        .collect();
    let mut good: HashMap<&str, u32> = HashMap::new();
    for (i, b) in blobs.iter().enumerate() {
        let id = b.loc.identifier.as_str();
        if wanted.contains(id) && !failures.contains_key(&(i as u32)) {
            good.entry(id).or_insert(i as u32);
        }
    }
    failures
        .keys()
        .filter_map(|i| {
            let id = blobs[*i as usize].loc.identifier.as_str();
            good.get(id).map(|g| (*i, *g))
        })
        .collect()
}

/// Merge `from` into `into`: counts add up, the newest record wins.
fn merge_affected(
    mut into: HashMap<String, AffectedFile>,
    mut from: HashMap<String, AffectedFile>,
) -> HashMap<String, AffectedFile> {
    if into.len() < from.len() {
        std::mem::swap(&mut into, &mut from);
    }
    for (k, v) in from {
        match into.get_mut(&k) {
            Some(e) => {
                e.records_affected += v.records_affected;
                e.newest_record = e.newest_record.max(v.newest_record);
            }
            None => {
                into.insert(k, v);
            }
        }
    }
    into
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run(opts: &VerifyOptions) -> Result<VerifyReport> {
    let plan = opts
        .plan_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    // blobIdentifierType: only SHA256 (2) is handled.
    let id_type = std::fs::read(opts.plan_dir.join("backupconfig.json"))
        .ok()
        .and_then(|d| serde_json::from_slice::<serde_json::Value>(&d).ok())
        .and_then(|v| v["blobIdentifierType"].as_u64());
    let want_id_check = opts.check_identifier && id_type.is_none_or(|t| t == 2);

    // Phase 1
    let record_paths = collect_record_paths(&opts.plan_dir);
    eprintln!("verify: reading {} backup records", record_paths.len());
    let mut records: Vec<RecordInfo> = record_paths
        .par_iter()
        .map(|p| read_record(p, &opts.keys))
        .collect();
    records.sort_by_key(|r| r.report.timestamp);
    if let Some(n) = opts.latest {
        let skip = records.len().saturating_sub(n);
        records.drain(..skip);
        eprintln!("verify: limited to the newest {} records", records.len());
    }

    let roots: Vec<BlobLoc> = records.iter().filter_map(|r| r.root.clone()).collect();

    // Identifier formula (calibrated on the root trees), then Phase 2.
    let formula = if want_id_check {
        let f = calibrate_formula(opts, &roots);
        match f {
            Some(f) => eprintln!("verify: blob identifier = {}", f.name()),
            None => eprintln!(
                "verify: could not reproduce blob identifiers from root trees; identifier check disabled"
            ),
        }
        f
    } else {
        None
    };
    let model = walk_trees(opts, &roots, formula);
    eprintln!(
        "verify: {} distinct trees, {} distinct blobs referenced",
        model.trees.len(),
        model.interner.blobs.len()
    );
    let mut failures: HashMap<u32, BlobFailure> = model.failures.clone();

    // Phase 3
    let (blob_failures, bytes_checked) = verify_blobs(opts, &model, formula);
    failures.extend(blob_failures);

    // Damaged blobs with an intact copy elsewhere (read-only; nothing is repaired).
    let copies = if formula.is_some() {
        intact_copies(&model, &failures)
    } else {
        HashMap::new()
    };

    // Report assembly
    let mut failures_by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut packs: BTreeMap<String, PackReport> = BTreeMap::new();
    let mut failure_samples: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut sorted_failures: Vec<(&u32, &BlobFailure)> = failures.iter().collect();
    sorted_failures.sort_by_key(|(i, _)| **i);
    for (i, f) in sorted_failures {
        let v = failure_samples.entry(format!("{:?}", f.kind)).or_default();
        if v.len() < 3 {
            v.push(f.detail.clone());
        }
        let b = &model.interner.blobs[*i as usize];
        *failures_by_kind.entry(format!("{:?}", f.kind)).or_default() += 1;
        let p = packs
            .entry(b.path.to_string())
            .or_insert_with(|| PackReport {
                path: b.path.to_string(),
                bad_blobs: 0,
                bad_bytes: 0,
                zero_filled_blobs: 0,
                kinds: BTreeMap::new(),
            });
        p.bad_blobs += 1;
        p.bad_bytes += b.loc.length;
        if f.zero_filled {
            p.zero_filled_blobs += 1;
        }
        *p.kinds.entry(format!("{:?}", f.kind)).or_default() += 1;
    }

    // Impact: newest record first so `newest_record` is right and counts cover every record.
    let mut affected: BTreeMap<String, AffectedFile> = BTreeMap::new();
    if !failures.is_empty() {
        eprintln!(
            "verify: {} bad blobs; mapping them to files in {} records",
            failures.len(),
            records.len()
        );
        let mut impact = Impact {
            model: &model,
            failures: &failures,
            copies: &copies,
            bad: HashMap::new(),
        };
        for r in &records {
            if let Some(root) = &r.root {
                impact.mark_bad(&root.identifier);
            }
        }
        let impact = &impact;
        let merged = records
            .par_iter()
            .filter_map(|r| {
                let root = r.root.as_ref()?;
                let mut local = HashMap::new();
                let prefix = r.report.local_path.trim_end_matches('/');
                impact.collect(&root.identifier, prefix, r.report.timestamp, &mut local, 0);
                Some(local)
            })
            .reduce(HashMap::new, merge_affected);
        affected = merged.into_iter().collect();
    }

    if let Some(csv) = &opts.report_csv {
        write_csv(csv, &model, &failures, &copies, &affected)?;
    }

    let records_unreadable = records
        .iter()
        .filter(|r| r.report.problem.is_some())
        .count();
    let records_incomplete = records
        .iter()
        .filter(|r| r.report.problem.is_none() && !r.report.is_complete)
        .count();
    let records_with_errors = records
        .iter()
        .filter(|r| {
            r.report.error_count.unwrap_or(0) > 0 || r.report.record_errors.unwrap_or(0) > 0
        })
        .count();

    let mut bad_packs: Vec<PackReport> = packs.into_values().collect();
    bad_packs.sort_by(|a, b| b.bad_blobs.cmp(&a.bad_blobs).then(a.path.cmp(&b.path)));

    Ok(VerifyReport {
        plan,
        identifier_formula: formula.map(|f| f.name().to_owned()),
        records_total: records.len(),
        records_unreadable,
        records_incomplete,
        records_with_errors,
        trees_checked: model.trees.len(),
        trees_broken: model.trees.values().filter(|t| t.broken).count(),
        blobs_checked: model.interner.blobs.len(),
        blobs_bad: failures.len(),
        blobs_bad_with_intact_copy: copies.len(),
        bytes_checked,
        failures_by_kind,
        failure_samples,
        bad_packs,
        affected_files: affected.into_values().collect(),
        records: records.into_iter().map(|r| r.report).collect(),
    })
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

fn write_csv(
    path: &Path,
    model: &Model,
    failures: &HashMap<u32, BlobFailure>,
    copies: &HashMap<u32, u32>,
    affected: &BTreeMap<String, AffectedFile>,
) -> Result<()> {
    let mut f = std::io::BufWriter::new(
        File::create(path).with_context(|| format!("create {}", path.display()))?,
    );
    writeln!(
        f,
        "kind,pack,offset,length,identifier,zero_filled,max_zero_run,newest_record,records_affected,path,intact_copy"
    )?;
    for a in affected.values() {
        for i in &a.blobs {
            let b = &model.interner.blobs[*i as usize];
            let fail = &failures[i];
            let copy = copies.get(i).map_or(String::new(), |c| {
                let c = &model.interner.blobs[*c as usize];
                format!("{}@{}", c.path, c.loc.offset)
            });
            writeln!(
                f,
                "{:?},{},{},{},{},{},{},{},{},{},{}",
                fail.kind,
                csv_escape(&b.path),
                b.loc.offset,
                b.loc.length,
                b.loc.identifier,
                fail.zero_filled,
                fail.max_zero_run,
                a.newest_record,
                a.records_affected,
                csv_escape(&a.path),
                csv_escape(&copy),
            )?;
        }
    }
    f.flush()?;
    Ok(())
}

/// Human-readable summary on stdout.
pub fn print_text(r: &VerifyReport, max_files: usize) {
    println!("Plan {}", r.plan);
    println!(
        "  records:  {} total, {} unreadable, {} incomplete, {} with errors",
        r.records_total, r.records_unreadable, r.records_incomplete, r.records_with_errors
    );
    for rec in &r.records {
        if rec.problem.is_some()
            || !rec.is_complete
            || rec.error_count.unwrap_or(0) > 0
            || rec.record_errors.unwrap_or(0) > 0
        {
            println!(
                "    ! {} ts={} complete={} errorCount={:?} recordErrors={:?} {}",
                rec.path,
                rec.timestamp,
                rec.is_complete,
                rec.error_count,
                rec.record_errors,
                rec.problem.as_deref().unwrap_or("")
            );
        }
    }
    println!(
        "  trees:    {} checked, {} broken",
        r.trees_checked, r.trees_broken
    );
    println!(
        "  blobs:    {} checked ({:.1} GiB read), {} bad",
        r.blobs_checked,
        r.bytes_checked as f64 / 1_073_741_824.0,
        r.blobs_bad
    );
    println!(
        "  identity: {}",
        r.identifier_formula
            .as_deref()
            .unwrap_or("not checked (formula unknown or disabled)")
    );
    for (k, n) in &r.failures_by_kind {
        println!("    {k}: {n}");
    }
    if r.blobs_bad > 0 && r.identifier_formula.is_some() {
        println!(
            "  bad blobs with an intact copy elsewhere in the plan: {}",
            r.blobs_bad_with_intact_copy
        );
    }
    if !r.bad_packs.is_empty() {
        println!(
            "  damaged pack/object files: {} (showing {})",
            r.bad_packs.len(),
            max_files.min(r.bad_packs.len())
        );
        for p in r.bad_packs.iter().take(max_files) {
            println!(
                "    {}  bad_blobs={} bytes={} zero_filled={} {:?}",
                p.path, p.bad_blobs, p.bad_bytes, p.zero_filled_blobs, p.kinds
            );
        }
    }
    if !r.affected_files.is_empty() {
        println!(
            "  affected files ({} total, showing {}):",
            r.affected_files.len(),
            max_files.min(r.affected_files.len())
        );
        for a in r.affected_files.iter().take(max_files) {
            println!(
                "    {}  newest_record={} records={} {:?}",
                a.path, a.newest_record, a.records_affected, a.kinds
            );
        }
    }
    println!(
        "RESULT: {}",
        if r.is_clean() {
            "clean"
        } else {
            "DAMAGE FOUND"
        }
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encrypt_arqo, test_keys};

    const PLAN: &str = "PLAN-1";

    fn put_str(out: &mut Vec<u8>, v: &str) {
        out.push(1);
        out.extend_from_slice(&(v.len() as u64).to_be_bytes());
        out.extend_from_slice(v.as_bytes());
    }

    fn put_loc(out: &mut Vec<u8>, l: &BlobLoc) {
        put_str(out, &l.identifier);
        out.push(u8::from(l.is_packed));
        out.push(0); // isLargePack
        match &l.relative_path {
            Some(p) => put_str(out, p),
            None => out.push(0),
        }
        out.extend_from_slice(&l.offset.to_be_bytes());
        out.extend_from_slice(&l.length.to_be_bytes());
        out.push(1); // stretchEncryptionKey
        out.extend_from_slice(&l.compression_type.to_be_bytes());
    }

    /// A tree-version-3 tree of `(name, subtree, data blobs)` entries.
    fn tree_bytes(entries: &[(&str, Option<&BlobLoc>, &[BlobLoc])]) -> Vec<u8> {
        let mut out = 3u32.to_be_bytes().to_vec();
        out.extend_from_slice(&(entries.len() as u64).to_be_bytes());
        for (name, sub, data) in entries {
            put_str(&mut out, name);
            out.push(u8::from(sub.is_some()));
            if let Some(s) = sub {
                put_loc(&mut out, s);
            }
            out.extend_from_slice(&1u32.to_be_bytes()); // computerOSType
            out.extend_from_slice(&(data.len() as u64).to_be_bytes());
            for d in *data {
                put_loc(&mut out, d);
            }
            out.push(0); // no ACL
            out.extend_from_slice(&0u64.to_be_bytes()); // xattrs
            out.extend_from_slice(&5u64.to_be_bytes()); // itemSize
            out.extend_from_slice(&1u64.to_be_bytes()); // containedFilesCount
            out.extend_from_slice(&[0u8; 48]); // six timestamps
            put_str(&mut out, "user");
            put_str(&mut out, "group");
            out.push(0); // deleted
            out.extend_from_slice(&[0u8; 40]); // dev, ino, mode, nlink, uid, gid, rdev, flags, win_attrs
            out.extend_from_slice(&[0u8; 5]); // reparse tag + is-directory flag
        }
        out
    }

    fn lz4_frame(plain: &[u8]) -> Vec<u8> {
        let mut out = (plain.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&lz4_flex::compress(plain));
        out
    }

    /// A synthetic encrypted Arq 7 plan in a temp directory.
    struct Repo {
        dir: tempfile::TempDir,
        keys: Arq7Keys,
        files: BTreeMap<String, Vec<u8>>,
    }

    impl Repo {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
                keys: test_keys(),
                files: BTreeMap::new(),
            }
        }

        fn stored(&self, plain: &[u8]) -> (String, Vec<u8>) {
            let id = IdFormula::SaltPrefix.compute(&self.keys.keys[2], &[], plain);
            (id, encrypt_arqo(&lz4_frame(plain), &self.keys))
        }

        /// Append `plain` to pack `pack` after `gap` filler bytes.
        fn packed(&mut self, pack: &str, plain: &[u8], gap: usize) -> BlobLoc {
            let (identifier, raw) = self.stored(plain);
            let rel = format!("{PLAN}/{pack}");
            let buf = self.files.entry(rel.clone()).or_default();
            buf.extend(std::iter::repeat_n(0xEE, gap));
            let offset = buf.len() as u64;
            buf.extend_from_slice(&raw);
            BlobLoc {
                identifier,
                is_packed: true,
                is_large_pack: false,
                relative_path: Some(format!("/{rel}")),
                offset,
                length: raw.len() as u64,
                stretch_encryption_key: true,
                compression_type: 2,
                is_arq5_pack_entry: false,
            }
        }

        fn standalone(&mut self, plain: &[u8]) -> BlobLoc {
            let (identifier, raw) = self.stored(plain);
            let rel = format!("{PLAN}/standardobjects/{identifier}");
            self.files.insert(rel.clone(), raw.clone());
            BlobLoc {
                identifier,
                is_packed: false,
                is_large_pack: false,
                relative_path: Some(format!("/{rel}")),
                offset: 0,
                length: raw.len() as u64,
                stretch_encryption_key: true,
                compression_type: 2,
                is_arq5_pack_entry: false,
            }
        }

        fn record(&mut self, ts: u64, root: &BlobLoc) {
            let json = serde_json::json!({
                "creationDate": ts as f64,
                "localPath": "/src",
                "isComplete": true,
                "node": {"treeBlobLoc": {
                    "blobIdentifier": root.identifier,
                    "isPacked": root.is_packed,
                    "relativePath": root.relative_path,
                    "offset": root.offset,
                    "length": root.length,
                    "compressionType": root.compression_type,
                }},
            });
            let raw = encrypt_arqo(&lz4_frame(json.to_string().as_bytes()), &self.keys);
            self.files.insert(
                format!("{PLAN}/backupfolders/F/backuprecords/00001/{ts}.backuprecord"),
                raw,
            );
        }

        fn write(&self) {
            for (rel, data) in &self.files {
                let p = self.dir.path().join(rel);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(p, data).unwrap();
            }
            std::fs::write(
                self.dir.path().join(PLAN).join("backupconfig.json"),
                br#"{"blobIdentifierType":2}"#,
            )
            .unwrap();
        }

        fn run(&self) -> VerifyReport {
            run(&VerifyOptions {
                storage_root: self.dir.path().to_path_buf(),
                plan_dir: self.dir.path().join(PLAN),
                keys: test_keys(),
                check_identifier: true,
                json: false,
                report_csv: None,
                max_files_printed: 10,
                latest: None,
            })
            .unwrap()
        }
    }

    /// root/{dir/{file1, file2}, big} with file1 and file2 neighbours in one pack.
    fn sample_repo() -> (Repo, BlobLoc, BlobLoc) {
        let mut repo = Repo::new();
        let f1 = repo.packed("blobpacks/bb/B.pack", b"first file content", 0);
        let f2 = repo.packed("blobpacks/bb/B.pack", b"second file content", 100);
        let big = repo.standalone(&[42u8; 5000]);
        let dir = repo.packed(
            "treepacks/aa/T.pack",
            &tree_bytes(&[
                ("file1", None, std::slice::from_ref(&f1)),
                ("file2", None, std::slice::from_ref(&f2)),
            ]),
            0,
        );
        let root = repo.packed(
            "treepacks/aa/T.pack",
            &tree_bytes(&[("dir", Some(&dir), &[]), ("big", None, &[big])]),
            0,
        );
        repo.record(1000, &root);
        repo.record(2000, &root);
        (repo, f1, f2)
    }

    #[test]
    fn clean_repository_verifies_clean() {
        let (repo, _, _) = sample_repo();
        repo.write();
        let r = repo.run();
        assert!(r.is_clean(), "{:?}", r.failure_samples);
        assert_eq!(r.records_total, 2);
        assert_eq!(r.trees_checked, 2);
        assert_eq!(r.blobs_checked, 5);
        assert_eq!(
            r.identifier_formula.as_deref(),
            Some("sha256(salt||plaintext)")
        );
    }

    #[test]
    fn damaged_blob_is_reported_with_its_file() {
        let (mut repo, f1, _) = sample_repo();
        let pack = repo
            .files
            .get_mut(&format!("{PLAN}/blobpacks/bb/B.pack"))
            .unwrap();
        pack[(f1.offset + f1.length - 1) as usize] ^= 0xFF;
        repo.write();
        let r = repo.run();
        assert_eq!(r.blobs_bad, 1);
        assert_eq!(r.failures_by_kind.get("HmacMismatch"), Some(&1));
        let paths: Vec<&str> = r.affected_files.iter().map(|a| a.path.as_str()).collect();
        assert_eq!(paths, ["/src/dir/file1"]);
        assert_eq!(r.affected_files[0].records_affected, 2);
        assert_eq!(r.affected_files[0].newest_record, 2000);
    }

    #[test]
    fn damaged_blob_with_a_second_copy_is_reported_recoverable() {
        let mut repo = Repo::new();
        let a = repo.packed("blobpacks/bb/A.pack", b"same content", 0);
        let b = repo.packed("blobpacks/bb/B.pack", b"same content", 0);
        let other = repo.packed("blobpacks/bb/B.pack", b"only copy", 0);
        assert_eq!(a.identifier, b.identifier);
        let root = repo.packed(
            "treepacks/aa/T.pack",
            &tree_bytes(&[
                ("old", None, std::slice::from_ref(&a)),
                ("new", None, std::slice::from_ref(&b)),
                ("solo", None, std::slice::from_ref(&other)),
            ]),
            0,
        );
        repo.record(1000, &root);
        let pa = repo
            .files
            .get_mut(&format!("{PLAN}/blobpacks/bb/A.pack"))
            .unwrap();
        pa[(a.offset + a.length - 1) as usize] ^= 0xFF;
        let pb = repo
            .files
            .get_mut(&format!("{PLAN}/blobpacks/bb/B.pack"))
            .unwrap();
        pb[(other.offset + other.length - 1) as usize] ^= 0xFF;
        repo.write();
        let csv = repo.dir.path().join("report.csv");
        let r = run(&VerifyOptions {
            storage_root: repo.dir.path().to_path_buf(),
            plan_dir: repo.dir.path().join(PLAN),
            keys: test_keys(),
            check_identifier: true,
            json: false,
            report_csv: Some(csv.clone()),
            max_files_printed: 10,
            latest: None,
        })
        .unwrap();

        assert_eq!(r.blobs_bad, 2);
        assert_eq!(r.blobs_bad_with_intact_copy, 1);
        let rec: Vec<(&str, bool)> = r
            .affected_files
            .iter()
            .map(|a| (a.path.as_str(), a.recoverable_from_copies))
            .collect();
        assert_eq!(rec, [("/src/old", true), ("/src/solo", false)]);
        let text = std::fs::read_to_string(csv).unwrap();
        let old_row = text.lines().find(|l| l.contains("/src/old")).unwrap();
        assert!(old_row.ends_with(&format!("{PLAN}/blobpacks/bb/B.pack@{}", b.offset)));
        let solo_row = text.lines().find(|l| l.contains("/src/solo")).unwrap();
        assert!(solo_row.ends_with(','));
    }

    #[test]
    fn truncated_pack_reports_out_of_range() {
        let (mut repo, _, f2) = sample_repo();
        let pack = repo
            .files
            .get_mut(&format!("{PLAN}/blobpacks/bb/B.pack"))
            .unwrap();
        pack.truncate((f2.offset + 10) as usize);
        repo.write();
        let r = repo.run();
        assert_eq!(r.failures_by_kind.get("OutOfRange"), Some(&1));
        assert_eq!(r.blobs_bad, 1);
    }

    #[test]
    fn coalesced_reads_match_single_reads() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.path().join("p"), &data).unwrap();
        let loc = |offset: u64, length: u64| BlobLoc {
            identifier: "x".into(),
            is_packed: true,
            is_large_pack: false,
            relative_path: Some("p".into()),
            offset,
            length,
            stretch_encryption_key: true,
            compression_type: 0,
            is_arq5_pack_entry: false,
        };
        // Neighbours, an overlap, a duplicate, a gap wider than MAX_COALESCE_GAP,
        // and one past the end of the file.
        let locs = [
            loc(0, 10),
            loc(10, 20),
            loc(25, 10),
            loc(25, 10),
            loc(40, 1000),
            loc(200_000, 5),
            loc(299_990, 50),
        ];
        let refs: Vec<&BlobLoc> = locs.iter().collect();
        let file = File::open(dir.path().join("p")).unwrap();
        let mut got = Vec::new();
        for_each_stored(dir.path(), "p", &refs, |i, raw| {
            got.push((i, raw.map(<[u8]>::to_vec).map_err(|f| f.kind)));
        });
        assert_eq!(got.len(), locs.len());
        for (i, res) in got {
            let want = read_stored(&file, data.len() as u64, &locs[i], "p").map_err(|f| f.kind);
            assert_eq!(res, want, "blob {i}");
        }
    }

    #[test]
    fn missing_pack_fails_every_blob_in_it() {
        let dir = tempfile::tempdir().unwrap();
        let l = BlobLoc {
            identifier: "x".into(),
            is_packed: true,
            is_large_pack: false,
            relative_path: Some("nope".into()),
            offset: 0,
            length: 1,
            stretch_encryption_key: true,
            compression_type: 0,
            is_arq5_pack_entry: false,
        };
        let mut kinds = Vec::new();
        for_each_stored(dir.path(), "nope", &[&l, &l], |_, raw| {
            kinds.push(raw.err().map(|f| f.kind));
        });
        assert_eq!(
            kinds,
            [Some(FailKind::MissingFile), Some(FailKind::MissingFile)]
        );
    }
}
