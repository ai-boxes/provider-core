use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use serde_json::{Map, Value};

const MAX_ENCRYPTED_CONTENT_LEN: usize = 8 * 1024 * 1024;
const MIN_ENCRYPTED_CONTENT_DECODED_LEN: usize = 32;
const MIN_ENCRYPTED_CONTENT_ENTROPY_RATIO: f64 = 0.85;

pub(super) fn normalize_reasoning(body: &mut Map<String, Value>) {
    let Some(Value::Array(input)) = body.get_mut("input") else {
        return;
    };
    input.retain_mut(|item| {
        let Some(item) = item.as_object_mut() else {
            return true;
        };
        let is_reasoning = item.get("type").and_then(Value::as_str) == Some("reasoning");
        let is_compaction = matches!(
            item.get("type").and_then(Value::as_str),
            Some("compaction" | "compaction_summary")
        );
        if !is_reasoning && !is_compaction {
            return true;
        }
        if is_reasoning {
            item.remove("status");
            if item.get("content").is_some_and(Value::is_null) {
                item.remove("content");
            }
        }
        let encrypted_content_is_valid = match item.get("encrypted_content") {
            None => return true,
            Some(Value::String(value)) => is_grok_encrypted_content(value),
            Some(_) => false,
        };
        if encrypted_content_is_valid {
            return true;
        }
        if !is_reasoning {
            return false;
        }
        item.remove("encrypted_content");
        item.get("summary")
            .and_then(Value::as_array)
            .is_some_and(|summary| !summary.is_empty())
            || item
                .get("content")
                .and_then(Value::as_array)
                .is_some_and(|content| !content.is_empty())
    });
}

fn is_grok_encrypted_content(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed != value {
        return false;
    }
    let value = trimmed;
    if value.is_empty()
        || value.len() > MAX_ENCRYPTED_CONTENT_LEN
        || value.starts_with("gAAAA")
        || matches!(value.len(), 4_340 | 12_946)
        || value.contains('=')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
    {
        return false;
    }
    STANDARD_NO_PAD.decode(value).is_ok_and(|decoded| {
        decoded.len() >= MIN_ENCRYPTED_CONTENT_DECODED_LEN
            && !is_foreign_signature_envelope(value, &decoded)
            && byte_entropy_ratio(&decoded) >= MIN_ENCRYPTED_CONTENT_ENTROPY_RATIO
    })
}

fn byte_entropy_ratio(bytes: &[u8]) -> f64 {
    if bytes.len() <= 1 {
        return 0.0;
    }
    let mut counts = [0_usize; 256];
    for byte in bytes {
        counts[usize::from(*byte)] += 1;
    }
    let length = bytes.len() as f64;
    let entropy = counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum::<f64>();
    entropy / (bytes.len().min(256) as f64).log2()
}

fn is_foreign_signature_envelope(encoded: &str, decoded: &[u8]) -> bool {
    match encoded.as_bytes().first() {
        Some(b'C') => is_claude_cais_envelope(decoded),
        Some(b'E') => is_claude_classic_envelope(decoded) || is_gemini_envelope(decoded),
        Some(b'R') => std::str::from_utf8(decoded).is_ok_and(|inner| {
            inner.starts_with('E')
                && STANDARD_NO_PAD
                    .decode(inner)
                    .or_else(|_| STANDARD.decode(inner))
                    .is_ok_and(|inner| is_claude_classic_envelope(&inner))
        }),
        _ => false,
    }
}

fn is_claude_classic_envelope(decoded: &[u8]) -> bool {
    protobuf_fields(decoded)
        .and_then(|fields| protobuf_bytes_field(&fields, 2))
        .and_then(protobuf_fields)
        .and_then(|fields| protobuf_bytes_field(&fields, 1))
        .and_then(protobuf_fields)
        .is_some_and(|fields| protobuf_varint_field(&fields, 1).is_some())
}

fn is_claude_cais_envelope(decoded: &[u8]) -> bool {
    let Some(fields) = protobuf_fields(decoded) else {
        return false;
    };
    if protobuf_varint_field(&fields, 1).is_none() {
        return false;
    }
    let Some(channel) = protobuf_bytes_field(&fields, 2)
        .and_then(protobuf_fields)
        .and_then(|fields| protobuf_bytes_field(&fields, 1))
        .and_then(protobuf_fields)
    else {
        return false;
    };
    protobuf_varint_field(&channel, 1).is_some()
        && protobuf_bytes_field(&channel, 5).is_some_and(|value| !value.is_empty())
        && protobuf_bytes_field(&channel, 6).is_some_and(|value| value.starts_with(b"claude-"))
}

fn is_gemini_envelope(decoded: &[u8]) -> bool {
    let Some(fields) = protobuf_fields(decoded) else {
        return false;
    };
    if fields.len() != 1 || fields[0].0 != 2 || fields[0].1 != 2 {
        return false;
    }
    let Some(container) = protobuf_fields(fields[0].2) else {
        return false;
    };
    container.len() == 1
        && container[0].0 == 1
        && container[0].1 == 2
        && container[0].2.first() == Some(&0x01)
}

fn protobuf_fields(input: &[u8]) -> Option<Vec<(u64, u8, &[u8])>> {
    let mut fields = Vec::new();
    let mut offset = 0;
    while offset < input.len() {
        let (tag, tag_len) = protobuf_varint(&input[offset..])?;
        offset += tag_len;
        let field_number = tag >> 3;
        let wire_type = (tag & 0x07) as u8;
        if field_number == 0 {
            return None;
        }
        let start = offset;
        match wire_type {
            0 => {
                let (_, length) = protobuf_varint(&input[offset..])?;
                offset += length;
            }
            1 => offset = offset.checked_add(8)?,
            2 => {
                let (length, length_len) = protobuf_varint(&input[offset..])?;
                offset += length_len;
                let value_start = offset;
                offset = offset.checked_add(usize::try_from(length).ok()?)?;
                if offset > input.len() {
                    return None;
                }
                fields.push((field_number, wire_type, &input[value_start..offset]));
                continue;
            }
            5 => offset = offset.checked_add(4)?,
            _ => return None,
        }
        if offset > input.len() {
            return None;
        }
        fields.push((field_number, wire_type, &input[start..offset]));
    }
    Some(fields)
}

fn protobuf_varint(input: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0_u64;
    for (index, byte) in input.iter().copied().take(10).enumerate() {
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

fn protobuf_bytes_field<'a>(fields: &[(u64, u8, &'a [u8])], number: u64) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|(field, wire, _)| *field == number && *wire == 2)
        .map(|(_, _, value)| *value)
}

fn protobuf_varint_field(fields: &[(u64, u8, &[u8])], number: u64) -> Option<u64> {
    fields
        .iter()
        .find(|(field, wire, _)| *field == number && *wire == 0)
        .and_then(|(_, _, value)| protobuf_varint(value).map(|(value, _)| value))
}

pub(super) fn normalize_model_fields(body: &mut Map<String, Value>, model: &str) {
    let model = normalized_model_name(model).to_ascii_lowercase();
    if model == "grok-4.5" {
        for field in [
            "stop",
            "presence_penalty",
            "presencePenalty",
            "frequency_penalty",
            "frequencyPenalty",
        ] {
            body.remove(field);
        }
    }
    if model.starts_with("grok-4.20") {
        body.remove("logprobs");
        body.remove("top_logprobs");
    }
    normalize_reasoning_effort(body, &model);
}

fn normalized_model_name(model: &str) -> &str {
    model
        .trim()
        .rsplit_once('/')
        .map_or(model.trim(), |(_, model)| model.trim())
}

fn normalize_reasoning_effort(body: &mut Map<String, Value>, model: &str) {
    let supports_effort = matches!(
        model.to_ascii_lowercase().as_str(),
        "grok-4.5"
            | "grok-4.5-latest"
            | "grok-4.6"
            | "grok-4.6-latest"
            | "grok-4.3"
            | "grok-4.3-latest"
            | "grok-3-mini"
            | "grok-3-mini-fast"
            | "grok-4.20-0309-reasoning"
            | "grok-4.20-reasoning"
            | "grok-4.20-multi-agent-0309"
    );

    if let Some(Value::Object(reasoning)) = body.get_mut("reasoning")
        && let Some(effort) = reasoning.remove("effort")
        && supports_effort
        && let Some(effort) = normalized_reasoning_effort_value(&effort)
    {
        reasoning.insert("effort".to_owned(), Value::String(effort));
    }
    if body
        .get("reasoning")
        .is_some_and(|value| value.as_object().is_some_and(Map::is_empty))
    {
        body.remove("reasoning");
    }

    let snake = body.remove("reasoning_effort");
    let camel = body.remove("reasoningEffort");
    if supports_effort
        && let Some(effort) = snake
            .as_ref()
            .and_then(normalized_reasoning_effort_value)
            .or_else(|| camel.as_ref().and_then(normalized_reasoning_effort_value))
    {
        body.insert("reasoning_effort".to_owned(), Value::String(effort));
    }
}

fn normalized_reasoning_effort_value(value: &Value) -> Option<String> {
    let value = value.as_str()?.trim().to_ascii_lowercase();
    let compact = value
        .chars()
        .filter(|character| !matches!(character, '-' | '_' | ' '))
        .collect::<String>();
    match compact.as_str() {
        "none" | "low" | "medium" | "high" => Some(compact),
        "minimal" => Some("low".to_owned()),
        "xhigh" | "extrahigh" | "max" | "ultra" => Some("high".to_owned()),
        _ => None,
    }
}
