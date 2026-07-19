use bytes::{Bytes, BytesMut};

#[derive(Default)]
pub(crate) struct SseDecoder {
    buffer: BytesMut,
}

impl SseDecoder {
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Vec<Bytes> {
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
        output
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
