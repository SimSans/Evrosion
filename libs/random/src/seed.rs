//! Bounded acquisition after an adapter independently qualifies its source.
//! A returned word, successful acquisition or nonzero bytes do not establish
//! source quality. The trusted adapter owns that separate decision.
use zeroize::Zeroize;

pub const ATTEMPTS_PER_WORD: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unavailable;

/// Collect four successful words with a finite retry bound for each. `None`
/// represents an actual source failure flag, including when a failed
/// instruction also wrote a numeric value. Zero is a valid successful word.
/// Every partial seed is erased on refusal; callers must erase successful input
/// after passing it to their reviewed generator. Never log these bytes.
pub fn acquire_after_qualification(
    mut word: impl FnMut() -> Option<u64>,
    output: &mut [u8; 32],
) -> Result<(), Unavailable> {
    output.zeroize();
    for chunk in output.as_chunks_mut::<8>().0 {
        let value = (0..ATTEMPTS_PER_WORD).find_map(|_| word());
        match value {
            Some(value) => chunk.copy_from_slice(&value.to_le_bytes()),
            None => {
                output.zeroize();
                return Err(Unavailable);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_zero_is_not_retried_or_misrepresented_as_failure() {
        let mut calls = 0;
        let mut bytes = [0xa5; 32];
        acquire_after_qualification(
            || {
                calls += 1;
                Some(0)
            },
            &mut bytes,
        )
        .unwrap();
        assert_eq!(calls, 4);
        assert_eq!(bytes, [0; 32]);
    }

    #[test]
    fn source_failure_is_finite_and_erases_every_partial_word() {
        for successful_words in 0..4 {
            let mut calls = 0;
            let mut bytes = [0xa5; 32];
            let result = acquire_after_qualification(
                || {
                    calls += 1;
                    (calls <= successful_words).then_some(u64::MAX)
                },
                &mut bytes,
            );
            assert_eq!(result, Err(Unavailable));
            assert_eq!(calls, successful_words + ATTEMPTS_PER_WORD);
            assert_eq!(bytes, [0; 32]);
        }
    }

    #[test]
    fn each_word_has_its_own_original_retry_bound() {
        let mut calls: usize = 0;
        let mut bytes = [0xa5; 32];
        acquire_after_qualification(
            || {
                calls += 1;
                calls
                    .is_multiple_of(ATTEMPTS_PER_WORD)
                    .then_some(calls as u64)
            },
            &mut bytes,
        )
        .unwrap();
        assert_eq!(calls, 4 * ATTEMPTS_PER_WORD);
        for (index, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
            assert_eq!(
                u64::from_le_bytes(*chunk),
                ((index + 1) * ATTEMPTS_PER_WORD) as u64
            );
        }
    }
}
