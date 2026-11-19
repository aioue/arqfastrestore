// SPDX-License-Identifier: MIT
//! Blob identifier formulas and per-repository calibration.
//!
//! An Arq 7 blob identifier is a hex SHA-256, but the exact hash input is not
//! something this tool can assume for every repository. The candidates below
//! are tried against blobs whose identifier is known (the root trees named by
//! the backup records), and the first formula that reproduces every sample is
//! used. If none does, callers must not claim a blob is damaged on the strength
//! of an identifier mismatch. Shared by `verify` and `restore --verify`.

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdFormula {
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

pub const ID_FORMULAS: [IdFormula; 5] = [
    IdFormula::Plain,
    IdFormula::SaltPrefix,
    IdFormula::SaltSuffix,
    IdFormula::CompSaltPrefix,
    IdFormula::CompSaltSuffix,
];

impl IdFormula {
    pub fn name(self) -> &'static str {
        match self {
            IdFormula::Plain => "sha256(plaintext)",
            IdFormula::SaltPrefix => "sha256(salt||plaintext)",
            IdFormula::SaltSuffix => "sha256(plaintext||salt)",
            IdFormula::CompSaltPrefix => "sha256(salt||compressed plaintext)",
            IdFormula::CompSaltSuffix => "sha256(compressed plaintext||salt)",
        }
    }

    /// Hex identifier of a blob. `comp` is the decrypted, still-compressed
    /// payload and `plain` is the decompressed content.
    pub fn compute(self, salt: &[u8], comp: &[u8], plain: &[u8]) -> String {
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

/// One blob with a known identifier, used to calibrate the formula.
pub struct Sample<'a> {
    pub identifier: &'a str,
    pub comp: &'a [u8],
    pub plain: &'a [u8],
}

/// The first formula that reproduces the identifier of every sample, or `None`
/// when there are no samples or no formula fits them all.
pub fn pick_formula(salt: &[u8], samples: &[Sample<'_>]) -> Option<IdFormula> {
    if samples.is_empty() {
        return None;
    }
    ID_FORMULAS.into_iter().find(|f| {
        samples.iter().all(|s| {
            f.compute(salt, s.comp, s.plain)
                .eq_ignore_ascii_case(s.identifier)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"salty";

    fn sample<'a>(id: &'a str, comp: &'a [u8], plain: &'a [u8]) -> Sample<'a> {
        Sample {
            identifier: id,
            comp,
            plain,
        }
    }

    #[test]
    fn picks_the_formula_that_matches_every_sample() {
        for want in ID_FORMULAS {
            let a = want.compute(SALT, b"comp-a", b"plain-a");
            let b = want.compute(SALT, b"comp-b", b"plain-b");
            let got = pick_formula(
                SALT,
                &[
                    sample(&a, b"comp-a", b"plain-a"),
                    sample(&b, b"comp-b", b"plain-b"),
                ],
            );
            assert_eq!(got, Some(want), "{}", want.name());
        }
    }

    #[test]
    fn no_samples_or_no_match_gives_none() {
        assert_eq!(pick_formula(SALT, &[]), None);
        let id = IdFormula::SaltPrefix.compute(SALT, b"c", b"p");
        // Same identifier, different content: no formula fits.
        assert_eq!(pick_formula(SALT, &[sample(&id, b"c", b"other")]), None);
        // Wrong salt: no formula fits.
        assert_eq!(pick_formula(b"wrong", &[sample(&id, b"c", b"p")]), None);
    }

    #[test]
    fn one_mismatching_sample_rejects_the_formula() {
        let a = IdFormula::SaltPrefix.compute(SALT, b"c1", b"p1");
        let bad = "0".repeat(64);
        assert_eq!(
            pick_formula(
                SALT,
                &[sample(&a, b"c1", b"p1"), sample(&bad, b"c2", b"p2")]
            ),
            None
        );
    }

    #[test]
    fn identifier_comparison_ignores_case() {
        let id = IdFormula::Plain.compute(SALT, b"c", b"p").to_uppercase();
        assert_eq!(
            pick_formula(SALT, &[sample(&id, b"c", b"p")]),
            Some(IdFormula::Plain)
        );
    }
}
