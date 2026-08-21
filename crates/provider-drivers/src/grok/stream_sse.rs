use bytes::Bytes;
use serde_json::Value;

pub(super) fn find_sse_frame_end(buffer: &[u8]) -> Option<usize> {
    let mut line_start = 0;
    let mut index = 0;
    while index < buffer.len() {
        if !matches!(buffer[index], b'\r' | b'\n') {
            index += 1;
            continue;
        }
        let ending_len =
            usize::from(buffer[index] == b'\r' && buffer.get(index + 1) == Some(&b'\n')) + 1;
        let end = index + ending_len;
        if index == line_start {
            return Some(end);
        }
        line_start = end;
        index = end;
    }
    None
}

pub(super) fn sse_event_name(frame: &[u8]) -> Option<&str> {
    for (line, _) in sse_lines(frame) {
        if let Some(event) = line
            .strip_prefix(b"event: ")
            .or_else(|| line.strip_prefix(b"event:"))
            && let Ok(event) = std::str::from_utf8(event)
        {
            return Some(event.trim());
        }
    }
    None
}

pub(super) fn sse_data_payload(frame: &[u8]) -> Option<Vec<u8>> {
    let mut payload = Vec::new();
    for (line, _) in sse_lines(frame) {
        let Some(data) = line
            .strip_prefix(b"data: ")
            .or_else(|| line.strip_prefix(b"data:"))
        else {
            continue;
        };
        if !payload.is_empty() {
            payload.push(b'\n');
        }
        payload.extend_from_slice(data);
    }
    (!payload.is_empty()).then_some(payload)
}

pub(super) fn ping_comment(frame: &[u8]) -> Bytes {
    if frame.windows(2).any(|window| window == b"\r\n") {
        Bytes::from_static(b": ping\r\n\r\n")
    } else if frame.contains(&b'\r') {
        Bytes::from_static(b": ping\r\r")
    } else {
        Bytes::from_static(b": ping\n\n")
    }
}

pub(super) fn rewrite_sse_frame(frame: &[u8], payload: &Value) -> Bytes {
    let mut output = Vec::with_capacity(frame.len());
    let event_type = payload.get("type").and_then(Value::as_str);
    let mut wrote_data = false;
    for (content, ending) in sse_lines(frame) {
        if content.starts_with(b"data:") {
            if !wrote_data {
                output.extend_from_slice(b"data: ");
                if serde_json::to_writer(&mut output, payload).is_err() {
                    return Bytes::copy_from_slice(frame);
                }
                output.extend_from_slice(ending);
                wrote_data = true;
            }
        } else if content.starts_with(b"event:") {
            output.extend_from_slice(b"event: ");
            output.extend_from_slice(event_type.unwrap_or_default().as_bytes());
            output.extend_from_slice(ending);
        } else {
            output.extend_from_slice(content);
            output.extend_from_slice(ending);
        }
    }
    Bytes::from(output)
}

fn sse_lines(frame: &[u8]) -> Vec<(&[u8], &[u8])> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < frame.len() {
        if !matches!(frame[index], b'\r' | b'\n') {
            index += 1;
            continue;
        }
        let end = if frame[index] == b'\r' && frame.get(index + 1) == Some(&b'\n') {
            index + 2
        } else {
            index + 1
        };
        lines.push((&frame[start..index], &frame[index..end]));
        start = end;
        index = end;
    }
    if start < frame.len() {
        lines.push((&frame[start..], &[]));
    }
    lines
}
