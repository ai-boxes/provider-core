use bytes::{Bytes, BytesMut};
use provider_core::{ProviderError, ProviderErrorKind};

/// Largest single un-delimited frame the decoder will hold.
///
/// The *stream* is legitimately unbounded — a long completion arrives as many
/// small frames — but one frame never is. Without this cap an upstream that never
/// sends a frame delimiter grows the buffer to the whole response, and because a
/// compatible account's `base_url` is operator-supplied, that upstream is not
/// necessarily trustworthy. One generous megabyte is far above any real SSE event.
pub(crate) const MAX_PENDING_FRAME: usize = 1024 * 1024;

/// The pending frame passed [`MAX_PENDING_FRAME`] with no delimiter in sight.
///
/// Callers decide what this means: a translator cannot translate what it cannot
/// parse and must surface an error, while a passive observer must stay silent and
/// let the bytes through untouched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SseFrameTooLarge;

/// The single error every translator reports for an oversized frame, so the
/// client-visible message does not depend on which conversion path was taken.
pub(crate) fn frame_too_large_error() -> ProviderError {
    ProviderError::new(
        ProviderErrorKind::Upstream,
        "upstream sent an oversized event without a frame delimiter",
    )
}

#[derive(Default)]
pub(crate) struct SseDecoder {
    buffer: BytesMut,
    overflowed: bool,
}

impl SseDecoder {
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<Vec<Bytes>, SseFrameTooLarge> {
        if self.overflowed {
            return Err(SseFrameTooLarge);
        }
        self.buffer.extend_from_slice(chunk);
        let mut output = Vec::new();
        while let Some(end) = find_frame_end(&self.buffer) {
            let frame = self.buffer.split_to(end);
            let delimiter_len = if self.buffer.starts_with(b"\r\n\r\n") {
                4
            } else {
                2
            };
            let _ = self.buffer.split_to(delimiter_len);
            if let Some(data) = frame_data(&frame) {
                output.push(data);
            }
        }
        // Whatever is left is one incomplete frame. If it alone is oversized, no
        // delimiter is coming that we are willing to wait for.
        if self.buffer.len() > MAX_PENDING_FRAME {
            self.overflowed = true;
            // Release the memory rather than holding it for a frame we rejected.
            self.buffer = BytesMut::new();
            return Err(SseFrameTooLarge);
        }
        Ok(output)
    }

    pub(crate) fn finish(&mut self) -> Option<Bytes> {
        if self.buffer.is_empty() {
            return None;
        }
        let frame = self.buffer.split().freeze();
        frame_data(&frame)
    }
}

fn find_frame_end(buffer: &[u8]) -> Option<usize> {
    let lf = buffer.windows(2).position(|window| window == b"\n\n");
    let crlf = buffer.windows(4).position(|window| window == b"\r\n\r\n");
    match (lf, crlf) {
        (Some(lf), Some(crlf)) => Some(lf.min(crlf)),
        (Some(end), None) | (None, Some(end)) => Some(end),
        (None, None) => None,
    }
}

fn frame_data(frame: &[u8]) -> Option<Bytes> {
    let mut data = Vec::new();
    for line in frame.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(value) = line.strip_prefix(b"data:") else {
            continue;
        };
        let value = value.strip_prefix(b" ").unwrap_or(value);
        if !data.is_empty() {
            data.push(b'\n');
        }
        data.extend_from_slice(value);
    }
    (!data.is_empty()).then(|| Bytes::from(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn many_small_frames_are_never_capped() {
        // The total stream may far exceed the per-frame cap; only one frame is bounded.
        let mut decoder = SseDecoder::default();
        let frame = format!("data: {}\n\n", "x".repeat(1024));
        let mut total = 0usize;
        for _ in 0..4096 {
            let frames = decoder
                .push(frame.as_bytes())
                .expect("small frames are fine");
            total += frames.len();
        }
        assert_eq!(total, 4096);
    }

    #[test]
    fn an_oversized_frame_is_rejected_and_memory_released() {
        let mut decoder = SseDecoder::default();
        // A stream that never sends a delimiter must not be buffered forever.
        let chunk = vec![b'x'; 256 * 1024];
        let mut result = Ok(Vec::new());
        for _ in 0..8 {
            result = decoder.push(&chunk);
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(SseFrameTooLarge));
        assert!(
            decoder.buffer.is_empty(),
            "the rejected frame's memory must be freed, not retained"
        );
    }

    #[test]
    fn overflow_is_sticky() {
        let mut decoder = SseDecoder::default();
        let _ = decoder.push(&vec![b'x'; MAX_PENDING_FRAME + 1]);
        assert_eq!(
            decoder.push(b"data: recovered\n\n"),
            Err(SseFrameTooLarge),
            "a poisoned decoder must not silently resume mid-stream"
        );
    }

    #[test]
    fn a_frame_at_the_limit_still_parses() {
        let mut decoder = SseDecoder::default();
        let payload = "y".repeat(MAX_PENDING_FRAME - "data: ".len());
        let frame = format!("data: {payload}\n\n");
        let frames = decoder
            .push(frame.as_bytes())
            .expect("exactly at the limit");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), payload.len());
    }
}
