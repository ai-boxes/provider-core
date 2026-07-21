use bytes::Bytes;
use provider_core::{
    ProviderError, ProviderErrorKind, ProviderRequest, RequestMetadata, WireFormat,
};
use serde_json::Value;

const ENCRYPTED_REASONING_INCLUDE: &str = "reasoning.encrypted_content";

pub(crate) struct PreparedCodexRequest {
    pub(crate) payload: Bytes,
    pub(crate) metadata: RequestMetadata,
}

pub(crate) fn prepare_request(
    request: ProviderRequest,
) -> Result<PreparedCodexRequest, ProviderError> {
    if request.format != WireFormat::OpenAiResponses {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Codex driver requires the OpenAI Responses format",
        ));
    }

    let model = request.model.trim();
    if model.is_empty() {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "model must not be empty",
        ));
    }

    let mut payload: Value = serde_json::from_slice(&request.payload).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Codex Responses request body must be valid JSON",
        )
    })?;
    let body = payload.as_object_mut().ok_or_else(|| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Codex Responses request body must be a JSON object",
        )
    })?;

    body.insert("model".to_owned(), Value::String(model.to_owned()));
    body.insert("stream".to_owned(), Value::Bool(true));
    body.insert("store".to_owned(), Value::Bool(false));
    ensure_encrypted_reasoning(body)?;
    remove_server_item_ids(body);

    let payload = serde_json::to_vec(&payload).map(Bytes::from).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::Internal,
            "failed to serialize normalized Codex request",
        )
    })?;
    Ok(PreparedCodexRequest {
        payload,
        metadata: request.metadata,
    })
}

fn ensure_encrypted_reasoning(
    body: &mut serde_json::Map<String, Value>,
) -> Result<(), ProviderError> {
    match body.get_mut("include") {
        None => {
            body.insert(
                "include".to_owned(),
                Value::Array(vec![Value::String(ENCRYPTED_REASONING_INCLUDE.to_owned())]),
            );
        }
        Some(Value::Array(include)) => {
            if !include
                .iter()
                .any(|value| value.as_str() == Some(ENCRYPTED_REASONING_INCLUDE))
            {
                include.push(Value::String(ENCRYPTED_REASONING_INCLUDE.to_owned()));
            }
        }
        Some(_) => {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "Codex Responses include must be an array",
            ));
        }
    }
    Ok(())
}

fn remove_server_item_ids(body: &mut serde_json::Map<String, Value>) {
    let Some(Value::Array(input)) = body.get_mut("input") else {
        return;
    };
    for item in input {
        if let Some(object) = item.as_object_mut() {
            object.remove("id");
        }
    }
}

#[cfg(test)]
mod tests {
    use provider_core::RequestMetadata;

    use super::*;

    #[test]
    fn normalizes_required_fields_without_dropping_native_payload() {
        let mut metadata = RequestMetadata::default();
        metadata.thread_id = Some("thread-1".to_owned());
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "gpt-5.5".to_owned(),
            payload: bytes::Bytes::from_static(
                br#"{
                    "model":"caller-model",
                    "stream":false,
                    "store":true,
                    "include":["file_search_call.results"],
                    "input":[{
                        "id":"server-item-id",
                        "call_id":"call-1",
                        "type":"function_call_output",
                        "output":"ok"
                    }],
                    "client_metadata":{"caller":"kept"},
                    "stream_options":{"include_usage":true},
                    "previous_response_id":"response-1",
                    "unknown_field":{"kept":true}
                }"#,
            ),
            metadata: metadata.clone(),
        };

        let prepared = prepare_request(request).expect("prepared request");
        let body: Value = serde_json::from_slice(&prepared.payload).expect("request JSON");

        assert_eq!(body["model"], "gpt-5.5");
        assert_eq!(body["stream"], true);
        assert_eq!(body["store"], false);
        assert_eq!(body["include"][0], "file_search_call.results");
        assert_eq!(body["include"][1], ENCRYPTED_REASONING_INCLUDE);
        assert!(body["input"][0].get("id").is_none());
        assert_eq!(body["input"][0]["call_id"], "call-1");
        assert_eq!(body["client_metadata"]["caller"], "kept");
        assert_eq!(body["stream_options"]["include_usage"], true);
        assert_eq!(body["previous_response_id"], "response-1");
        assert_eq!(body["unknown_field"]["kept"], true);
        assert_eq!(prepared.metadata, metadata);
    }

    #[test]
    fn rejects_non_array_include() {
        let request = ProviderRequest {
            format: WireFormat::OpenAiResponses,
            model: "gpt-5.5".to_owned(),
            payload: bytes::Bytes::from_static(br#"{"include":"reasoning.encrypted_content"}"#),
            metadata: RequestMetadata::default(),
        };

        let error = match prepare_request(request) {
            Ok(_) => panic!("invalid include must fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
    }
}
