// SPDX-License-Identifier: MIT
//! Resolves a [`BlobLoc`] to raw decrypted+decompressed bytes.
//!
//! A [`BlobLoc`] can point to either a standalone object file or a slice
//! within a pack file.  In both cases the raw bytes may be ARQO-encrypted
//! and/or compressed; this module handles all three steps in order:
//!
//! 1. **Read** — fetch the relevant bytes from storage (with pack file caching).
//! 2. **Decrypt** — if the bytes start with the `"ARQO"` magic and a decryption
//!    function is available, call it to obtain the plaintext.
//! 3. **Decompress** — pass through [`decompress_blob`] according to
//!    `blob_loc.compression_type`.
//!
//! ## Pack file cache
//!
//! Pack files are typically 30–40 MB and contain many blobs. Without caching,
//! the same pack file gets re-read from storage for every blob it contains —
//! extremely wasteful over network storage (SMB/S3). The cache keeps pack
//! file contents in memory so each file is read from storage exactly once.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Instant;

use anyhow::{Context, Result, bail};

use crate::format::arq7::{BlobLoc, decompress_blob};
use crate::identifier::IdFormula;
use crate::storage::Storage;

/// A pluggable decryption function.
///
/// Given raw ARQO-encrypted bytes, returns the decrypted plaintext.
/// Arq7 closures call `decrypt_arq7_object`; Arq5 closures strip the
/// `"encrypted"` prefix and call `decrypt_arq5_object`.
pub type DecryptFn = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync>;

/// Blob-identifier checks enabled for this process (`restore --verify`).
///
/// Each entry is a plan's `(salt, formula)`; the formula was calibrated against
/// that plan's root trees (see [`crate::identifier`]). When any entry is
/// registered, [`BlobReader::read_blob`] recomputes the identifier after
/// decompression and fails the read if no registered entry reproduces it.
/// HMAC verification of encrypted blobs is always on; this adds an end-to-end
/// content check. Process-wide because readers are created in several places,
/// and a list because one `restore-from-csv` run can span several plans, each
/// with its own salt: a blob passes when its plan's entry matches, and a wrong
/// blob cannot match under another plan's salt.
static VERIFY_ENTRIES: RwLock<Vec<(Vec<u8>, IdFormula)>> = RwLock::new(Vec::new());

/// Turn on blob-identifier verification for a plan, for all readers in this process.
pub fn enable_identifier_verification(salt: Vec<u8>, formula: IdFormula) {
    let mut entries = VERIFY_ENTRIES.write().unwrap_or_else(|e| e.into_inner());
    if !entries.iter().any(|(s, f)| *s == salt && *f == formula) {
        entries.push((salt, formula));
    }
}

fn check_blob_identifier(loc: &BlobLoc, comp: &[u8], plain: &[u8]) -> Result<()> {
    let entries = VERIFY_ENTRIES.read().unwrap_or_else(|e| e.into_inner());
    check_against(&entries, loc, comp, plain)
}

/// Pure core of [`check_blob_identifier`]: no entries means no check.
fn check_against(
    entries: &[(Vec<u8>, IdFormula)],
    loc: &BlobLoc,
    comp: &[u8],
    plain: &[u8],
) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    // Only Arq 7 (SHA-256, 64 hex chars); Arq 5 identifiers are SHA-1.
    if loc.identifier.len() != 64 || loc.is_arq5_pack_entry {
        return Ok(());
    }
    let mut first = None;
    for (salt, formula) in entries {
        let got = formula.compute(salt, comp, plain);
        if got.eq_ignore_ascii_case(&loc.identifier) {
            return Ok(());
        }
        first.get_or_insert(got);
    }
    bail!(
        "blob identifier mismatch: expected {}, content hashes to {}",
        loc.identifier,
        first.unwrap_or_default()
    )
}

/// Magic bytes that mark an ARQO-encrypted payload.
const ARQO_MAGIC: &[u8] = b"ARQO";

/// I/O and cache statistics for a [`BlobReader`].
///
/// All fields are atomics — safe to read from any thread at any time.
pub struct BlobReaderStats {
    /// Total `read_blob` calls.
    pub total_reads: AtomicUsize,
    /// Number of packed-blob reads served from the cache.
    pub cache_hits: AtomicUsize,
    /// Number of packed-blob reads that required a storage read.
    pub cache_misses: AtomicUsize,
    /// Total bytes read from storage (not from cache).
    pub bytes_from_storage: AtomicU64,
    /// Wall-clock time spent inside `storage.read()` calls (nanoseconds).
    pub storage_read_nanos: AtomicU64,
    /// Total `maybe_decrypt` calls that performed actual decryption.
    pub decryptions: AtomicUsize,
    /// Wall-clock time spent in decryption (nanoseconds).
    pub decrypt_nanos: AtomicU64,
    /// Total `decompress_blob` calls that performed decompression (type ≠ 0).
    pub decompressions: AtomicUsize,
    /// Wall-clock time spent in decompression (nanoseconds).
    pub decompress_nanos: AtomicU64,
    /// Per-pack storage read counter: how many times each pack file was read
    /// from storage (not from cache). Key = pack path, value = read count.
    pub pack_storage_reads: RwLock<HashMap<String, u64>>,
    /// Total logical (decompressed) bytes produced — the "useful" output.
    pub logical_bytes_out: AtomicU64,
}

impl BlobReaderStats {
    fn new() -> Self {
        Self {
            total_reads: AtomicUsize::new(0),
            cache_hits: AtomicUsize::new(0),
            cache_misses: AtomicUsize::new(0),
            bytes_from_storage: AtomicU64::new(0),
            storage_read_nanos: AtomicU64::new(0),
            decryptions: AtomicUsize::new(0),
            decrypt_nanos: AtomicU64::new(0),
            decompressions: AtomicUsize::new(0),
            decompress_nanos: AtomicU64::new(0),
            pack_storage_reads: RwLock::new(HashMap::new()),
            logical_bytes_out: AtomicU64::new(0),
        }
    }
}

/// Default byte budget for the in-memory pack file cache (512 MiB).
///
/// A small backup may have ~26 large packs (~40 MB each) = ~1 GB total but only 26 unique
/// ones, so 512 MB lets most of them stay hot.  A large backup may have 10K small packs
/// (~5 MB each) with near-zero reuse; 512 MB holds ~100 of them but they're
/// evicted quickly, keeping RSS bounded.
const PACK_CACHE_BUDGET_BYTES: u64 = 512 * 1024 * 1024;

/// A cache slot: the `OnceLock` is set exactly once by whichever thread
/// wins the race.  All other threads calling `get_or_init` will block until
/// the data is ready, then share the same `Arc<Vec<u8>>`.  This eliminates
/// the "thundering herd" where N rayon threads each read the same 40 MB
/// pack file independently.
type PackSlot = Arc<OnceLock<Vec<u8>>>;

/// A cache entry. `counted` is true once the slot's bytes have been added to
/// `pack_cache_bytes`; it is read and written only under the cache write lock,
/// so a slot evicted while it was still loading is never counted.
struct CacheEntry {
    slot: PackSlot,
    counted: bool,
}

/// Resolves [`BlobLoc`] references to their final, usable byte content.
///
/// Includes an in-memory cache for pack files to avoid redundant storage
/// reads when many blobs reside in the same pack.  Uses `OnceLock` per
/// slot to guarantee each pack file is read from storage at most once even
/// under heavy concurrent access from rayon workers.
pub struct BlobReader {
    storage: Arc<dyn Storage>,
    decrypt: Option<DecryptFn>,
    /// Cache: pack-file path → slot.
    pack_cache: RwLock<HashMap<String, CacheEntry>>,
    /// Current total bytes held in the cache (populated slots only).
    pack_cache_bytes: std::sync::atomic::AtomicU64,
    /// Maximum bytes to hold in the cache (0 = disabled).
    max_cache_bytes: u64,
    /// Accumulated I/O statistics.
    stats: BlobReaderStats,
}

impl BlobReader {
    /// Create a new `BlobReader` with the default pack cache byte budget.
    pub fn new(storage: Arc<dyn Storage>, decrypt: Option<DecryptFn>) -> Self {
        Self::with_cache_bytes(storage, decrypt, PACK_CACHE_BUDGET_BYTES)
    }

    /// Create a new `BlobReader` with a specific pack cache byte budget.
    ///
    /// Use `max_cache_bytes = 0` to disable caching entirely.
    pub fn with_cache_bytes(
        storage: Arc<dyn Storage>,
        decrypt: Option<DecryptFn>,
        max_cache_bytes: u64,
    ) -> Self {
        Self {
            storage,
            decrypt,
            pack_cache: RwLock::new(HashMap::new()),
            pack_cache_bytes: std::sync::atomic::AtomicU64::new(0),
            max_cache_bytes,
            stats: BlobReaderStats::new(),
        }
    }

    /// Resolve a `BlobLoc` to its raw, decrypted, decompressed bytes.
    ///
    /// Returns an error if:
    /// - The backing file cannot be read from storage.
    /// - The slice indices are out of range (packed case).
    /// - The payload is ARQO-encrypted but no decryption function was provided.
    /// - Decryption or decompression fails.
    pub fn read_blob(&self, loc: &BlobLoc) -> Result<Vec<u8>> {
        let (comp, plain) = self.read_blob_parts(loc)?;
        check_blob_identifier(loc, &comp, &plain)?;
        // Track logical bytes produced (the useful output).
        self.stats
            .logical_bytes_out
            .fetch_add(plain.len() as u64, Ordering::Relaxed);
        Ok(plain)
    }

    /// Like [`read_blob`] but returns `(compressed, plaintext)` and performs no
    /// identifier check. Used to calibrate the identifier formula.
    pub fn read_blob_parts(&self, loc: &BlobLoc) -> Result<(Vec<u8>, Vec<u8>)> {
        self.stats.total_reads.fetch_add(1, Ordering::Relaxed);

        let path = loc.relative_path.as_deref().unwrap_or(&loc.identifier);
        let raw = if loc.is_packed {
            self.read_packed_slice(loc)
                .with_context(|| format!("reading packed blob at {}", path))?
        } else {
            let t0 = Instant::now();
            let data = self
                .storage
                .read(path)
                .with_context(|| format!("reading standalone blob at {}", path))?;
            let elapsed = t0.elapsed().as_nanos() as u64;
            self.stats
                .storage_read_nanos
                .fetch_add(elapsed, Ordering::Relaxed);
            self.stats
                .bytes_from_storage
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            data
        };

        let decrypted = self.maybe_decrypt(raw, loc)?;

        let result = if loc.compression_type != 0 {
            self.stats.decompressions.fetch_add(1, Ordering::Relaxed);
            let t0 = Instant::now();
            let result = decompress_blob(&decrypted, loc.compression_type).with_context(|| {
                format!(
                    "decompressing blob {} (compression_type={})",
                    loc.identifier, loc.compression_type
                )
            });
            self.stats
                .decompress_nanos
                .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
            result
        } else {
            decompress_blob(&decrypted, loc.compression_type)
        };

        result.map(|plain| (decrypted, plain))
    }

    /// Same as [`read_blob`] but returns `None` if `loc` is `None` or if the
    /// `BlobLoc`'s identifier is empty (indicating a missing/null blob).
    #[allow(dead_code)]
    pub fn read_blob_opt(&self, loc: Option<&BlobLoc>) -> Result<Option<Vec<u8>>> {
        match loc {
            None => Ok(None),
            Some(l) if l.identifier.is_empty() => Ok(None),
            Some(l) => self.read_blob(l).map(Some),
        }
    }

    /// Print a summary of I/O statistics to stderr in `key=value` format.
    ///
    /// `label` is a short tag (e.g. `"walk"` or `"restore"`) prefixed to
    /// every key, making the output easy to grep and parse:
    ///
    /// ```text
    /// blob.walk.reads=22600 cache_hits=22540 cache_misses=60
    /// blob.walk.storage_mb=2.1 storage_s=32.500
    /// …
    /// ```
    pub fn print_stats(&self, label: &str) {
        let total = self.stats.total_reads.load(Ordering::Relaxed);
        let hits = self.stats.cache_hits.load(Ordering::Relaxed);
        let misses = self.stats.cache_misses.load(Ordering::Relaxed);
        let bytes = self.stats.bytes_from_storage.load(Ordering::Relaxed);
        let storage_secs = self.stats.storage_read_nanos.load(Ordering::Relaxed) as f64 / 1e9;
        let decryptions = self.stats.decryptions.load(Ordering::Relaxed);
        let decrypt_secs = self.stats.decrypt_nanos.load(Ordering::Relaxed) as f64 / 1e9;
        let decompressions = self.stats.decompressions.load(Ordering::Relaxed);
        let decompress_secs = self.stats.decompress_nanos.load(Ordering::Relaxed) as f64 / 1e9;
        let logical_out = self.stats.logical_bytes_out.load(Ordering::Relaxed);

        let cache = self.pack_cache.read().unwrap();
        let cached_packs = cache.len();
        drop(cache);
        let cached_bytes = self.pack_cache_bytes.load(Ordering::Relaxed);
        let mb_cached = cached_bytes as f64 / 1_048_576.0;
        let budget_mb = self.max_cache_bytes as f64 / 1_048_576.0;

        let mb_storage = bytes as f64 / 1_048_576.0;
        let mb_logical = logical_out as f64 / 1_048_576.0;
        let read_amp = if logical_out > 0 {
            bytes as f64 / logical_out as f64
        } else {
            0.0
        };

        eprintln!("blob.{label}.reads={total} cache_hits={hits} cache_misses={misses}");
        eprintln!("blob.{label}.storage_mb={mb_storage:.1} storage_s={storage_secs:.3}");
        eprintln!("blob.{label}.logical_mb={mb_logical:.1} read_amplification={read_amp:.2}x");
        eprintln!(
            "blob.{label}.pack_cache_packs={cached_packs} pack_cache_mb={mb_cached:.1}/{budget_mb:.0}"
        );
        eprintln!("blob.{label}.decryptions={decryptions} decrypt_s={decrypt_secs:.3}");
        eprintln!("blob.{label}.decompressions={decompressions} decompress_s={decompress_secs:.3}");

        // Per-pack storage read report: show packs that were read from
        // storage more than once (indicating cache eviction + re-read).
        if let Ok(map) = self.stats.pack_storage_reads.read() {
            let unique_packs = map.len();
            let multi_read: Vec<_> = map.iter().filter(|(_, count)| **count > 1).collect();
            let total_reread_count: u64 = multi_read.iter().map(|(_, c)| **c - 1).sum();
            eprintln!(
                "blob.{label}.unique_packs={unique_packs} packs_re_read={} total_extra_reads={total_reread_count}",
                multi_read.len()
            );

            // Show top-10 most re-read packs.
            if !multi_read.is_empty() {
                let mut sorted: Vec<_> = multi_read;
                sorted.sort_by(|a, b| b.1.cmp(a.1));
                eprintln!("blob.{label}.top_re_read_packs:");
                for (path, count) in sorted.iter().take(10) {
                    // Shorten path for display — show just the last 2 components.
                    let short = path
                        .rsplit('/')
                        .take(2)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect::<Vec<_>>()
                        .join("/");
                    eprintln!("  {count}x  {short}");
                }
                if sorted.len() > 10 {
                    eprintln!("  ... and {} more re-read packs", sorted.len() - 10);
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Read the `[offset .. offset+length]` slice from a pack file.
    ///
    /// Uses the in-memory pack cache to avoid re-reading the same pack file.
    /// Each cache slot is an `Arc<OnceLock<Vec<u8>>>`: the first thread to
    /// claim the slot does the storage read while all others wait on the same
    /// `OnceLock`.  This eliminates the thundering-herd where N rayon workers
    /// would each independently read the same 40 MB pack file.
    fn read_packed_slice(&self, loc: &BlobLoc) -> Result<Vec<u8>> {
        let path = loc.relative_path.as_deref().unwrap_or(&loc.identifier);

        // If caching is disabled, read directly from storage every time.
        if self.max_cache_bytes == 0 {
            self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
            let t0 = Instant::now();
            let pack = self
                .storage
                .read(path)
                .with_context(|| format!("reading pack file {}", path))?;
            self.stats
                .storage_read_nanos
                .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
            self.stats
                .bytes_from_storage
                .fetch_add(pack.len() as u64, Ordering::Relaxed);
            // Track per-pack storage read count (no-cache path).
            if let Ok(mut map) = self.stats.pack_storage_reads.write() {
                *map.entry(path.to_string()).or_insert(0) += 1;
            }
            return Self::extract_slice(&pack, loc);
        }

        let slot = self.claim_slot(path);
        match self.load_slot(path, &slot)? {
            Some(pack) => Self::extract_slice(pack, loc),
            None => {
                // Another thread's read of this pack failed and was not cached:
                // read it ourselves (a transient error must not fail every blob).
                let pack = self
                    .storage
                    .read(path)
                    .with_context(|| format!("reading pack file {}", path))?;
                Self::extract_slice(&pack, loc)
            }
        }
    }

    /// Return the cache slot for `path`, inserting an empty one (after evicting
    /// entries to stay within the byte budget) when there is none.
    fn claim_slot(&self, path: &str) -> PackSlot {
        {
            let cache = self.pack_cache.read().unwrap();
            if let Some(e) = cache.get(path)
                && e.slot.get().is_some()
            {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                return e.slot.clone();
            }
        }
        let mut cache = self.pack_cache.write().unwrap();
        if let Some(e) = cache.get(path) {
            if e.slot.get().is_some() {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            }
            return e.slot.clone();
        }
        // Evict entries until we're under the byte budget. The new entry's size
        // is unknown until it is loaded, so we evict conservatively.
        while self.pack_cache_bytes.load(Ordering::Relaxed) >= self.max_cache_bytes
            && !cache.is_empty()
        {
            if let Some(key) = cache.keys().next().cloned() {
                self.evict(&mut cache, &key);
            }
        }
        let new_slot: PackSlot = Arc::new(OnceLock::new());
        cache.insert(
            path.to_string(),
            CacheEntry {
                slot: new_slot.clone(),
                counted: false,
            },
        );
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        new_slot
    }

    /// Remove `key` from the cache, releasing its bytes if they were counted.
    fn evict(&self, cache: &mut HashMap<String, CacheEntry>, key: &str) {
        if let Some(e) = cache.remove(key)
            && e.counted
            && let Some(data) = e.slot.get()
        {
            self.pack_cache_bytes
                .fetch_sub(data.len() as u64, Ordering::Relaxed);
        }
    }

    /// Populate `slot` (exactly one thread does the I/O; others wait).
    ///
    /// Returns `Ok(None)` when another thread's read of this pack failed: failed
    /// reads are never cached, the caller reads the pack itself. When this
    /// thread's own read fails, the slot is dropped from the cache and the error
    /// is returned.
    fn load_slot<'s>(&self, path: &str, slot: &'s PackSlot) -> Result<Option<&'s Vec<u8>>> {
        let mut read_error: Option<anyhow::Error> = None;
        let mut loaded_here = false;
        let pack: &Vec<u8> = slot.get_or_init(|| {
            loaded_here = true;
            let t0 = Instant::now();
            let data = match self.storage.read(path) {
                Ok(d) => d,
                Err(e) => {
                    read_error = Some(e);
                    Vec::new()
                }
            };
            self.stats
                .storage_read_nanos
                .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
            self.stats
                .bytes_from_storage
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            if let Ok(mut map) = self.stats.pack_storage_reads.write() {
                *map.entry(path.to_string()).or_insert(0) += 1;
            }
            data
        });

        if loaded_here {
            // Count the bytes only while the slot is still in the cache; it may
            // have been evicted by another thread while it was loading.
            let mut cache = self.pack_cache.write().unwrap();
            let ours = cache.get(path).is_some_and(|e| Arc::ptr_eq(&e.slot, slot));
            if ours {
                if read_error.is_some() || pack.is_empty() {
                    cache.remove(path);
                } else if let Some(e) = cache.get_mut(path) {
                    e.counted = true;
                    self.pack_cache_bytes
                        .fetch_add(pack.len() as u64, Ordering::Relaxed);
                }
            }
        }
        if let Some(e) = read_error {
            return Err(e).with_context(|| format!("reading pack file {}", path));
        }
        Ok(if pack.is_empty() { None } else { Some(pack) })
    }

    /// Extract the raw object data from an Arq5 pack entry at the given offset.
    ///
    /// Arq5 pack entry format at offset:
    ///   - mimetype: Arq-encoded string (1 byte null flag, if not null: 8 bytes BE length + bytes)
    ///   - name: Arq-encoded string (same encoding)
    ///   - data_length: u64 BE
    ///   - data: [u8; data_length]
    fn extract_arq5_pack_entry(pack: &[u8], offset: usize) -> Result<Vec<u8>> {
        let mut pos = offset;

        // Skip mimetype (Arq-encoded optional string)
        if pos >= pack.len() {
            bail!("Arq5 pack entry: unexpected EOF at mimetype null flag");
        }
        let is_null = pack[pos] == 0;
        pos += 1;
        if !is_null {
            if pos + 8 > pack.len() {
                bail!("Arq5 pack entry: unexpected EOF at mimetype length");
            }
            let len = u64::from_be_bytes(pack[pos..pos + 8].try_into().unwrap()) as usize;
            pos += 8 + len;
        }

        // Skip name (same encoding)
        if pos >= pack.len() {
            bail!("Arq5 pack entry: unexpected EOF at name null flag");
        }
        let is_null = pack[pos] == 0;
        pos += 1;
        if !is_null {
            if pos + 8 > pack.len() {
                bail!("Arq5 pack entry: unexpected EOF at name length");
            }
            let len = u64::from_be_bytes(pack[pos..pos + 8].try_into().unwrap()) as usize;
            pos += 8 + len;
        }

        // Read data length
        if pos + 8 > pack.len() {
            bail!("Arq5 pack entry: unexpected EOF at data length");
        }
        let data_len = u64::from_be_bytes(pack[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;

        // Read data
        let end = pos + data_len;
        if end > pack.len() {
            bail!(
                "Arq5 pack entry: data [{pos}..{end}) out of bounds (pack size {})",
                pack.len()
            );
        }
        Ok(pack[pos..end].to_vec())
    }

    /// Extract object bytes from a pack buffer based on BlobLoc.
    fn extract_slice(pack: &[u8], loc: &BlobLoc) -> Result<Vec<u8>> {
        if loc.is_arq5_pack_entry {
            return Self::extract_arq5_pack_entry(pack, loc.offset as usize);
        }

        let start = loc.offset as usize;
        let end = start
            .checked_add(loc.length as usize)
            .context("blob slice end overflows usize")?;

        if end > pack.len() {
            bail!(
                "pack slice [{start}..{end}) is out of bounds (pack size {})",
                pack.len()
            );
        }

        Ok(pack[start..end].to_vec())
    }

    /// Decrypt `data` if it starts with the ARQO magic, otherwise pass through.
    fn maybe_decrypt(&self, data: Vec<u8>, loc: &BlobLoc) -> Result<Vec<u8>> {
        if !data.starts_with(ARQO_MAGIC) {
            return Ok(data);
        }

        self.stats.decryptions.fetch_add(1, Ordering::Relaxed);

        let decrypt = self.decrypt.as_ref().with_context(|| {
            format!(
                "blob {} is ARQO-encrypted but no decryption function was provided",
                loc.identifier
            )
        })?;

        let t0 = Instant::now();
        let result =
            (decrypt)(&data).with_context(|| format!("decrypting blob {}", loc.identifier));
        self.stats
            .decrypt_nanos
            .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        result
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    // -------------------------------------------------------------------------
    // MockStorage
    // -------------------------------------------------------------------------

    /// Simple in-memory storage backed by a `HashMap<String, Vec<u8>>`.
    struct MockStorage {
        files: HashMap<String, Vec<u8>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                files: HashMap::new(),
            }
        }

        fn insert(&mut self, path: impl Into<String>, data: Vec<u8>) {
            self.files.insert(path.into(), data);
        }
    }

    impl Storage for MockStorage {
        fn read(&self, path: &str) -> Result<Vec<u8>> {
            self.files
                .get(path)
                .cloned()
                .with_context(|| format!("MockStorage: path not found: {path}"))
        }

        fn list(&self, _path: &str) -> Result<Vec<String>> {
            Ok(Vec::new())
        }

        fn exists(&self, path: &str) -> Result<bool> {
            Ok(self.files.contains_key(path))
        }
    }

    // -------------------------------------------------------------------------
    // Helper: build a minimal BlobLoc
    // -------------------------------------------------------------------------

    fn make_loc(
        relative_path: &str,
        is_packed: bool,
        offset: u64,
        length: u64,
        compression_type: u32,
    ) -> BlobLoc {
        BlobLoc {
            identifier: "deadbeef".to_string(),
            is_packed,
            is_large_pack: false,
            relative_path: Some(relative_path.to_string()),
            offset,
            length,
            stretch_encryption_key: false,
            compression_type,
            is_arq5_pack_entry: false,
        }
    }

    // -------------------------------------------------------------------------
    // Test 1: standalone, unencrypted, no compression
    // -------------------------------------------------------------------------

    #[test]
    fn standalone_unencrypted_no_compression() {
        let content = b"hello arq world".to_vec();

        let mut storage = MockStorage::new();
        storage.insert("standardobjects/ab/deadbeef", content.clone());

        let reader = BlobReader::new(Arc::new(storage), None);
        let loc = make_loc(
            "standardobjects/ab/deadbeef",
            false,
            0,
            content.len() as u64,
            0,
        );

        let result = reader.read_blob(&loc).unwrap();
        assert_eq!(result, content);
    }

    // -------------------------------------------------------------------------
    // Test 2: packed, unencrypted, LZ4-compressed
    // -------------------------------------------------------------------------

    #[test]
    fn packed_unencrypted_lz4() {
        let original = b"the quick brown fox jumps over the lazy dog";

        // Build the LZ4 frame: 4-byte BE uncompressed length + raw LZ4 block.
        let be_len = (original.len() as u32).to_be_bytes();
        let compressed_block = lz4_flex::compress(original);
        let mut blob_bytes = be_len.to_vec();
        blob_bytes.extend_from_slice(&compressed_block);

        // Place the blob at an arbitrary offset within a larger "pack" file.
        let prefix = b"xxxx_padding_xxxx";
        let offset = prefix.len() as u64;
        let length = blob_bytes.len() as u64;

        let mut pack_data = prefix.to_vec();
        pack_data.extend_from_slice(&blob_bytes);
        // Append some trailing garbage to confirm we only read the slice.
        pack_data.extend_from_slice(b"trailing_garbage");

        let mut storage = MockStorage::new();
        storage.insert("blobpacks/ab/cdef1234.pack", pack_data);

        let reader = BlobReader::new(Arc::new(storage), None);
        let loc = make_loc(
            "blobpacks/ab/cdef1234.pack",
            true,
            offset,
            length,
            2, // LZ4
        );

        let result = reader.read_blob(&loc).unwrap();
        assert_eq!(result, original.as_ref());
    }

    // -------------------------------------------------------------------------
    // Test 3: read_blob_opt with None and empty identifier
    // -------------------------------------------------------------------------

    #[test]
    fn read_blob_opt_none_and_empty_identifier() {
        let storage = MockStorage::new();
        let reader = BlobReader::new(Arc::new(storage), None);

        // None input → None output, no error.
        assert!(reader.read_blob_opt(None).unwrap().is_none());

        // BlobLoc with empty identifier → None output, no error.
        let empty_loc = BlobLoc {
            identifier: String::new(),
            is_packed: false,
            is_large_pack: false,
            relative_path: Some("does/not/matter".to_string()),
            offset: 0,
            length: 0,
            stretch_encryption_key: false,
            compression_type: 0,
            is_arq5_pack_entry: false,
        };
        assert!(reader.read_blob_opt(Some(&empty_loc)).unwrap().is_none());
    }

    // -------------------------------------------------------------------------
    // Test 4: packed slice out of bounds → error
    // -------------------------------------------------------------------------

    #[test]
    fn packed_slice_out_of_bounds() {
        let mut storage = MockStorage::new();
        storage.insert("blobpacks/small.pack", vec![0u8; 10]);

        let reader = BlobReader::new(Arc::new(storage), None);
        let loc = make_loc("blobpacks/small.pack", true, 5, 20, 0); // 5+20 = 25 > 10

        assert!(reader.read_blob(&loc).is_err());
    }

    // -------------------------------------------------------------------------
    // Pack cache: failed reads and byte accounting
    // -------------------------------------------------------------------------

    /// Storage whose first `fail_first` reads fail, then serves `inner`.
    struct FlakyStorage {
        inner: MockStorage,
        fail_first: AtomicUsize,
        reads: AtomicUsize,
    }

    impl Storage for FlakyStorage {
        fn read(&self, path: &str) -> Result<Vec<u8>> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let left = self.fail_first.load(Ordering::Relaxed);
            if left > 0 {
                self.fail_first.store(left - 1, Ordering::Relaxed);
                bail!("transient I/O error");
            }
            self.inner.read(path)
        }

        fn list(&self, _path: &str) -> Result<Vec<String>> {
            Ok(Vec::new())
        }

        fn exists(&self, path: &str) -> Result<bool> {
            self.inner.exists(path)
        }
    }

    fn cached_bytes_in_map(reader: &BlobReader) -> u64 {
        reader
            .pack_cache
            .read()
            .unwrap()
            .values()
            .filter(|e| e.counted)
            .map(|e| e.slot.get().map_or(0, |d| d.len() as u64))
            .sum()
    }

    #[test]
    fn failed_pack_read_is_not_cached() {
        let mut inner = MockStorage::new();
        inner.insert("p.pack", b"0123456789".to_vec());
        let storage = Arc::new(FlakyStorage {
            inner,
            fail_first: AtomicUsize::new(1),
            reads: AtomicUsize::new(0),
        });
        let reader = BlobReader::new(storage.clone(), None);
        let loc = make_loc("p.pack", true, 2, 3, 0);

        let err = reader.read_blob(&loc).unwrap_err();
        assert!(format!("{err:#}").contains("transient"), "{err:#}");
        // The next blob from the same pack must succeed and then be cached.
        assert_eq!(reader.read_blob(&loc).unwrap(), b"234");
        assert_eq!(reader.read_blob(&loc).unwrap(), b"234");
        assert_eq!(storage.reads.load(Ordering::Relaxed), 2);
        assert_eq!(reader.pack_cache_bytes.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn slot_evicted_while_loading_is_not_counted() {
        let mut storage = MockStorage::new();
        storage.insert("a.pack", vec![7u8; 10]);
        let reader = BlobReader::new(Arc::new(storage), None);

        let slot = reader.claim_slot("a.pack");
        // Another thread evicts the entry before the load finishes.
        {
            let mut cache = reader.pack_cache.write().unwrap();
            reader.evict(&mut cache, "a.pack");
        }
        let pack = reader.load_slot("a.pack", &slot).unwrap().unwrap();
        assert_eq!(pack.len(), 10);
        assert_eq!(reader.pack_cache_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(cached_bytes_in_map(&reader), 0);
    }

    #[test]
    fn cache_bytes_match_cached_slots_under_eviction() {
        let mut storage = MockStorage::new();
        for name in ["a", "b", "c", "d", "e"] {
            storage.insert(format!("{name}.pack"), vec![1u8; 10]);
        }
        let reader = BlobReader::with_cache_bytes(Arc::new(storage), None, 25);
        for name in ["a", "b", "c", "d", "e", "a", "c"] {
            let loc = make_loc(&format!("{name}.pack"), true, 0, 4, 0);
            reader.read_blob(&loc).unwrap();
            assert_eq!(
                reader.pack_cache_bytes.load(Ordering::Relaxed),
                cached_bytes_in_map(&reader)
            );
        }
    }

    // -------------------------------------------------------------------------
    // Test 5: encrypted blob without decrypt fn → error
    // -------------------------------------------------------------------------

    #[test]
    fn encrypted_blob_without_keys_returns_error() {
        let mut data = b"ARQO".to_vec();
        data.extend_from_slice(b"some_ciphertext_payload");

        let mut storage = MockStorage::new();
        storage.insert("standardobjects/ab/encblob", data.clone());

        let reader = BlobReader::new(Arc::new(storage), None);
        let loc = make_loc("standardobjects/ab/encblob", false, 0, data.len() as u64, 0);

        let err = reader.read_blob(&loc).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no decryption function was provided"),
            "unexpected error: {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // Identifier check (pure core; the process-wide list is not touched)
    // -------------------------------------------------------------------------

    fn loc_with_id(id: &str) -> BlobLoc {
        let mut l = make_loc("p", false, 0, 0, 0);
        l.identifier = id.to_string();
        l
    }

    #[test]
    fn identifier_check_accepts_matching_and_rejects_changed_content() {
        let salt = b"salt".to_vec();
        let id = IdFormula::SaltPrefix.compute(&salt, b"comp", b"plain");
        let entries = vec![(salt, IdFormula::SaltPrefix)];
        assert!(check_against(&entries, &loc_with_id(&id), b"comp", b"plain").is_ok());
        let err = check_against(&entries, &loc_with_id(&id), b"comp", b"PLAIN")
            .unwrap_err()
            .to_string();
        assert!(err.contains("blob identifier mismatch"), "{err}");
    }

    #[test]
    fn identifier_check_uses_the_calibrated_formula() {
        let salt = b"salt".to_vec();
        // A repository whose identifiers are over the compressed payload.
        let id = IdFormula::CompSaltPrefix.compute(&salt, b"comp", b"plain");
        let wrong = vec![(salt.clone(), IdFormula::SaltPrefix)];
        let right = vec![(salt, IdFormula::CompSaltPrefix)];
        assert!(check_against(&wrong, &loc_with_id(&id), b"comp", b"plain").is_err());
        assert!(check_against(&right, &loc_with_id(&id), b"comp", b"plain").is_ok());
    }

    #[test]
    fn identifier_check_with_several_plans_matches_any_but_still_rejects_bad_content() {
        let a = b"salt-a".to_vec();
        let b = b"salt-b".to_vec();
        let id_b = IdFormula::SaltPrefix.compute(&b, b"c", b"p");
        let entries = vec![(a, IdFormula::SaltPrefix), (b, IdFormula::SaltPrefix)];
        assert!(check_against(&entries, &loc_with_id(&id_b), b"c", b"p").is_ok());
        assert!(check_against(&entries, &loc_with_id(&id_b), b"c", b"other").is_err());
    }

    #[test]
    fn identifier_check_is_off_without_entries_and_skips_non_sha256() {
        let id = "0".repeat(64);
        assert!(check_against(&[], &loc_with_id(&id), b"c", b"p").is_ok());
        let entries = vec![(b"s".to_vec(), IdFormula::SaltPrefix)];
        // 40-hex (Arq 5 / SHA-1) identifiers are not checked.
        assert!(check_against(&entries, &loc_with_id(&"0".repeat(40)), b"c", b"p").is_ok());
        let mut a5 = loc_with_id(&id);
        a5.is_arq5_pack_entry = true;
        assert!(check_against(&entries, &a5, b"c", b"p").is_ok());
    }

    #[test]
    fn read_blob_parts_returns_compressed_and_plain_bytes() {
        let mut storage = MockStorage::new();
        storage.insert("blob", b"hello".to_vec());
        let reader = BlobReader::new(Arc::new(storage), None);
        let loc = make_loc("blob", false, 0, 5, 0);
        let (comp, plain) = reader.read_blob_parts(&loc).unwrap();
        assert_eq!(comp, b"hello");
        assert_eq!(plain, b"hello");
    }
}
