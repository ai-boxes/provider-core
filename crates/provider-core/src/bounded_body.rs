use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use futures_util::StreamExt;

#[derive(Debug)]
pub enum BoundedBodyError<E> {
    Read(E),
    TooLarge,
}

pub async fn collect_bounded_body<S, E>(
    stream: S,
    limit: usize,
) -> Result<Bytes, BoundedBodyError<E>>
where
    S: Stream<Item = Result<Bytes, E>>,
{
    let retained_limit = limit.saturating_add(1);
    let mut body = BytesMut::new();
    futures_util::pin_mut!(stream);

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(BoundedBodyError::Read)?;
        let remaining = retained_limit.saturating_sub(body.len());
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            return Err(BoundedBodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
        if body.len() > limit {
            return Err(BoundedBodyError::TooLarge);
        }
    }

    Ok(body.freeze())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures_util::stream;

    use super::{BoundedBodyError, collect_bounded_body};

    #[tokio::test]
    async fn exact_limit_succeeds() {
        let body =
            collect_bounded_body(stream::iter([Ok::<_, ()>(Bytes::from_static(b"1234"))]), 4)
                .await
                .expect("body at the limit");
        assert_eq!(body, "1234");
    }

    #[tokio::test]
    async fn limit_plus_one_is_explicit_overflow() {
        let error =
            collect_bounded_body(stream::iter([Ok::<_, ()>(Bytes::from_static(b"12345"))]), 4)
                .await
                .expect_err("body over the limit");
        assert!(matches!(error, BoundedBodyError::TooLarge));
    }

    #[tokio::test]
    async fn chunked_limit_plus_one_is_explicit_overflow() {
        let error = collect_bounded_body(
            stream::iter([
                Ok::<_, ()>(Bytes::from_static(b"12")),
                Ok(Bytes::from_static(b"345")),
            ]),
            4,
        )
        .await
        .expect_err("chunked body over the limit");
        assert!(matches!(error, BoundedBodyError::TooLarge));
    }

    #[tokio::test]
    async fn transport_failure_is_distinct_from_overflow() {
        let error = collect_bounded_body(
            stream::iter([
                Ok::<_, &'static str>(Bytes::from_static(b"12")),
                Err("read failed"),
            ]),
            4,
        )
        .await
        .expect_err("read failure");
        assert!(matches!(error, BoundedBodyError::Read("read failed")));
    }
}
