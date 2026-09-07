use std::convert::Infallible;
use std::path::{Path, PathBuf};

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use tower::{ServiceExt, service_fn, util::BoxCloneSyncService};
use tower_http::services::{ServeDir, ServeFile};

/// Serve compiled UI assets and fall back to `index.html` for browser routes.
pub(super) fn ui_service(
    public_dir: impl AsRef<Path>,
) -> BoxCloneSyncService<Request<Body>, Response, Infallible> {
    let public_dir = public_dir.as_ref();
    let files = ServeDir::new(public_dir);
    let index = public_dir.join("index.html");
    BoxCloneSyncService::new(service_fn(move |request| {
        serve_ui(request, files.clone(), index.clone())
    }))
}

async fn serve_ui(
    request: Request<Body>,
    files: ServeDir,
    index: PathBuf,
) -> Result<Response, Infallible> {
    if !matches!(*request.method(), Method::GET | Method::HEAD)
        || is_backend_path(request.uri().path())
    {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }

    let accepts_html = accepts_html(request.headers());
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let mut response = into_axum_response(files.oneshot(request).await);
    if response.status() != StatusCode::NOT_FOUND {
        apply_cache_policy(&mut response, &path, false);
        return Ok(response);
    }
    if !accepts_html {
        apply_cache_policy(&mut response, &path, false);
        return Ok(response);
    }

    let request = Request::builder()
        .method(method)
        .uri("/")
        .body(Body::empty())
        .expect("static fallback request is valid");
    let mut response = into_axum_response(ServeFile::new(index).oneshot(request).await);
    apply_cache_policy(&mut response, &path, true);
    Ok(response)
}

fn apply_cache_policy(response: &mut Response, path: &str, browser_fallback: bool) {
    let value = if response.status() == StatusCode::NOT_FOUND {
        "no-store"
    } else if browser_fallback || path == "/" || path.ends_with(".html") {
        "no-cache"
    } else if path.starts_with("/assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        value.parse().expect("valid cache policy"),
    );
}

fn into_axum_response<T>(response: Result<T, Infallible>) -> Response
where
    T: IntoResponse,
{
    response
        .map(IntoResponse::into_response)
        .unwrap_or_else(|never| match never {})
}

fn is_backend_path(path: &str) -> bool {
    ["/api", "/v1", "/healthz", "/livez", "/readyz"]
        .iter()
        .any(|prefix| {
            path == *prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
}

fn accepts_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .filter_map(|media_type| media_type.split(';').next())
                .any(|media_type| media_type.trim().eq_ignore_ascii_case("text/html"))
        })
}
