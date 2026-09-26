//! Body-surface probe for the interop extraction differential and body
//! detect vector runners (interop/extraction_differential.py and
//! interop/body_detect_vectors.py in the guard-core reference checkout).
//!
//! The runner materializes a throwaway cargo project whose dependencies
//! point at the audited checkouts by path, so the audited detection code is
//! exactly master and nothing is written to the repositories.
//!
//! Modes (env GUARDCORE_RS_PROBE_MODE, line protocol, no JSON dependency):
//!
//!   extraction: input lines `label\tcontent_type\tbody_b64`; output per
//!   vector a header `=label` then one line per extracted value
//!   `value_b64\tcontext\tforced`.
//!
//!   detect: input lines `label\tcontent_type\tbody_b64`; output per vector
//!   `label\tis_threat\tcategories_comma` (first hitting value wins, like
//!   the engine's per-value scan loop).
//!
//!   middleware: input lines `label\tpath_with_query\tcontent_type\tbody_b64`;
//!   the tower GuardLayer service runs the request end to end; output
//!   `label\tblocked\tstatus`.

use std::env;
use std::fs;

use bytes::Bytes;
use guard_core_engine::body_scan::extract_body_scan_values;
use guard_core_engine::detect::{detect, DetectConfig};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use std::convert::Infallible;
use tower::{Layer, Service, ServiceExt};
use tower_guard_rs::{default_config, GuardLayer};

fn b64_decode(input: &str) -> Vec<u8> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in input.bytes() {
        if byte == b'=' || byte == b'\n' || byte == b'\r' {
            continue;
        }
        let value = TABLE
            .iter()
            .position(|candidate| *candidate == byte)
            .expect("valid base64") as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

fn b64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let buffer = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | (*chunk.get(2).unwrap_or(&0) as u32);
        out.push(TABLE[(buffer >> 18) as usize & 63] as char);
        out.push(TABLE[(buffer >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(buffer >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[buffer as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn main() {
    let mode = env::var("GUARDCORE_RS_PROBE_MODE").expect("GUARDCORE_RS_PROBE_MODE");
    let input = env::var("GUARDCORE_RS_PROBE_INPUT").expect("GUARDCORE_RS_PROBE_INPUT");
    let output = env::var("GUARDCORE_RS_PROBE_OUTPUT").expect("GUARDCORE_RS_PROBE_OUTPUT");
    let input_text = fs::read_to_string(&input).expect("input readable");
    let mut out_lines: Vec<String> = Vec::new();

    match mode.as_str() {
        "extraction" => {
            let config: DetectConfig = default_config();
            for line in input_text.lines().filter(|line| !line.is_empty()) {
                let mut parts = line.split('\t');
                let label = parts.next().expect("label");
                let content_type = parts.next().expect("content_type");
                let body = b64_decode(parts.next().expect("body_b64"));
                let body_text = String::from_utf8_lossy(&body).into_owned();
                out_lines.push(format!("={label}"));
                for value in extract_body_scan_values(&body_text, content_type, &config) {
                    let forced = value.forced_category.unwrap_or("");
                    out_lines.push(format!(
                        "{}\t{}\t{}",
                        b64_encode(value.content.as_bytes()),
                        value.context,
                        forced
                    ));
                }
            }
        }
        "detect" => {
            let config: DetectConfig = default_config();
            for line in input_text.lines().filter(|line| !line.is_empty()) {
                let mut parts = line.split('\t');
                let label = parts.next().expect("label");
                let content_type = parts.next().expect("content_type");
                let body = b64_decode(parts.next().expect("body_b64"));
                let body_text = String::from_utf8_lossy(&body).into_owned();
                let mut is_threat = false;
                let mut categories: Vec<String> = Vec::new();
                for value in extract_body_scan_values(&body_text, content_type, &config) {
                    if let Some(category) = value.forced_category {
                        is_threat = true;
                        if !categories.iter().any(|seen| seen == category) {
                            categories.push(category.to_string());
                        }
                        break;
                    }
                    let verdict = detect(&value.content, &value.context, &config);
                    if !verdict.is_threat {
                        continue;
                    }
                    for threat in &verdict.threats {
                        let category = match threat {
                            guard_core_engine::detect::Threat::Regex(regex) => {
                                regex.category.clone()
                            }
                            guard_core_engine::detect::Threat::Semantic(semantic) => {
                                semantic.attack_type.clone()
                            }
                        };
                        if !categories.iter().any(|seen| seen == &category) {
                            categories.push(category);
                        }
                    }
                    if categories.is_empty() {
                        is_threat = false;
                        break;
                    }
                    is_threat = true;
                    break;
                }
                categories.sort();
                out_lines.push(format!(
                    "{label}\t{}\t{}",
                    if is_threat { "1" } else { "0" },
                    categories.join(",")
                ));
            }
        }
        "middleware" => {
            let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
            for line in input_text.lines().filter(|line| !line.is_empty()) {
                let mut parts = line.split('\t');
                let label = parts.next().expect("label");
                let uri = parts.next().expect("uri");
                let content_type = parts.next().expect("content_type");
                let body = b64_decode(parts.next().expect("body_b64"));
                let blocked_status = runtime.block_on(run_middleware(&uri, content_type, &body));
                out_lines.push(match blocked_status {
                    Some(status) => format!("{label}\t1\t{}", status.as_u16()),
                    None => format!("{label}\t0\t200"),
                });
            }
        }
        other => panic!("unknown GUARDCORE_RS_PROBE_MODE {other}"),
    }

    fs::write(&output, out_lines.join("\n") + "\n").expect("output writable");
}

async fn run_middleware(uri: &str, content_type: &str, body: &[u8]) -> Option<StatusCode> {
    fn echo() -> tower::util::BoxCloneService<Request<Full<Bytes>>, Response<Full<Bytes>>, Infallible>
    {
        tower::util::BoxCloneService::new(tower::service_fn(
            |request: Request<Full<Bytes>>| async move {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            },
        ))
    }
    let mut service = GuardLayer::new(default_config()).layer(echo());
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", content_type)
        .body(Full::new(Bytes::copy_from_slice(body)))
        .expect("request");
    let response = service
        .ready()
        .await
        .expect("ready")
        .call(request)
        .await
        .expect("response");
    let status = response.status();
    if status == StatusCode::OK {
        return None;
    }
    Some(status)
}
