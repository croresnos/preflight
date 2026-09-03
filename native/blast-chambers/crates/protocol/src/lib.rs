#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Strict, versioned wire contract shared by the Blast Chambers service/client.

use std::collections::BTreeSet;
use std::io::{Read, Write};

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("frame exceeds the 1 MiB protocol limit")]
    Oversized,
    #[error("truncated protocol frame")]
    Truncated,
    #[error("protocol frame is not valid UTF-8")]
    Utf8,
    #[error("invalid protocol JSON: {0}")]
    Json(String),
    #[error("duplicate JSON field: {0}")]
    DuplicateField(String),
    #[error("unsupported protocol version")]
    Version,
    #[error("invalid request: {0}")]
    Invalid(&'static str),
    #[error("protocol I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Envelope<T> {
    pub protocol_version: u16,
    pub request_id: Uuid,
    pub sequence: u64,
    pub nonce: String,
    pub body: T,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Doctor {},
    Run(RunRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunRequest {
    pub command: Vec<String>,
    pub cwd: String,
    pub limits: Limits,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub wall_time_ms: u64,
    pub cpu_time_ms: u64,
    pub cpu_rate_percent: u32,
    pub process_memory_bytes: u64,
    pub job_memory_bytes: u64,
    pub active_process_limit: u32,
    pub output_bytes: u64,
}

impl Limits {
    /// Validate resource bounds before they cross the trust boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when a bound is zero, inconsistent, or outside the
    /// protocol's deliberately finite range.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wall_time_ms == 0 || self.wall_time_ms > 24 * 60 * 60 * 1000 {
            return Err(ProtocolError::Invalid("wall_time_ms is outside 1ms..24h"));
        }
        if self.cpu_time_ms == 0 || self.cpu_time_ms > self.wall_time_ms * 256 {
            return Err(ProtocolError::Invalid(
                "cpu_time_ms is outside the allowed range",
            ));
        }
        if !(1..=100).contains(&self.cpu_rate_percent) {
            return Err(ProtocolError::Invalid("cpu_rate_percent must be 1..100"));
        }
        if self.process_memory_bytes < 16 * 1024 * 1024 {
            return Err(ProtocolError::Invalid("process memory limit is too small"));
        }
        if self.job_memory_bytes < self.process_memory_bytes {
            return Err(ProtocolError::Invalid(
                "job memory must cover process memory",
            ));
        }
        if !(1..=256).contains(&self.active_process_limit) {
            return Err(ProtocolError::Invalid(
                "active_process_limit must be 1..256",
            ));
        }
        if self.output_bytes == 0 || self.output_bytes > 1024 * 1024 * 1024 {
            return Err(ProtocolError::Invalid(
                "output limit is outside the allowed range",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Doctor(DoctorResponse),
    Run(RunResponse),
    Error(ErrorResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DoctorResponse {
    pub service_version: String,
    pub protocol_version: u16,
    pub service_pid: u32,
    pub identity_verified: bool,
    pub controls: ResourceControls,
    pub missing_protections: Vec<String>,
    pub reason_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ResourceControls {
    pub suspended_before_assignment: bool,
    pub kill_on_job_close: bool,
    pub active_process_limit: bool,
    pub process_memory_limit: bool,
    pub job_memory_limit: bool,
    pub cpu_hard_cap: bool,
    pub cpu_time_limit: bool,
    pub wall_clock_limit: bool,
    pub output_limit: bool,
    pub no_breakaway: bool,
    pub caller_token: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunResponse {
    pub returncode: i32,
    pub stdout: String,
    pub stderr: String,
    pub elapsed_ms: u64,
    pub timed_out: bool,
    pub evidence: EvidenceEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEnvelope {
    pub payload_sha256: String,
    pub previous_sha256: String,
    pub signature_algorithm: String,
    pub signature: String,
    pub sealed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    pub reason_code: String,
    pub message: String,
}

impl Envelope<Request> {
    /// Validate version, anti-replay fields, command, and resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported versions or invalid request fields.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::Version);
        }
        if self.request_id.is_nil() {
            return Err(ProtocolError::Invalid("request_id must not be nil"));
        }
        if self.sequence == 0 || self.nonce.len() < 32 || self.nonce.len() > 128 {
            return Err(ProtocolError::Invalid("invalid sequence or nonce"));
        }
        if let Request::Run(run) = &self.body {
            if run.command.is_empty() || run.command.len() > 256 {
                return Err(ProtocolError::Invalid(
                    "command must contain 1..256 arguments",
                ));
            }
            if run.command.iter().any(|value| value.contains('\0')) {
                return Err(ProtocolError::Invalid("command contains NUL"));
            }
            if run.cwd.is_empty() || run.cwd.as_bytes().contains(&0) {
                return Err(ProtocolError::Invalid("cwd is empty or contains NUL"));
            }
            run.limits.validate()?;
        }
        Ok(())
    }
}

/// Read one length-delimited, duplicate-free JSON value.
///
/// # Errors
///
/// Returns an error for I/O failure, truncation, oversize frames, invalid
/// UTF-8/JSON, duplicates, unknown fields, or a target schema mismatch.
pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
) -> Result<T, ProtocolError> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            ProtocolError::Truncated
        } else {
            ProtocolError::Io(error)
        }
    })?;
    let length = u32::from_le_bytes(header) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(ProtocolError::Oversized);
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            ProtocolError::Truncated
        } else {
            ProtocolError::Io(error)
        }
    })?;
    let text = std::str::from_utf8(&body).map_err(|_| ProtocolError::Utf8)?;
    let value = strict_json(text)?;
    serde_json::from_value(value).map_err(|error| ProtocolError::Json(error.to_string()))
}

/// Serialize one value into the length-delimited framing.
///
/// # Errors
///
/// Returns an error if serialization or I/O fails, or the payload is too large.
pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<(), ProtocolError> {
    let body = serde_json::to_vec(value).map_err(|error| ProtocolError::Json(error.to_string()))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::Oversized);
    }
    let length = u32::try_from(body.len()).map_err(|_| ProtocolError::Oversized)?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

/// Parse JSON while rejecting duplicate keys at every nesting depth.
///
/// # Errors
///
/// Returns an error for invalid JSON, duplicate fields, or trailing content.
pub fn strict_json(text: &str) -> Result<Value, ProtocolError> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = StrictValue
        .deserialize(&mut deserializer)
        .map_err(|error| ProtocolError::Json(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| ProtocolError::Json(error.to_string()))?;
    Ok(value)
}

struct StrictValue;

impl<'de> DeserializeSeed<'de> for StrictValue {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate fields")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Ok(Value::from(value))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        StrictValue.deserialize(d)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(StrictValue)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut keys = BTreeSet::new();
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON field: {key}")));
            }
            values.insert(key, map.next_value_seed(StrictValue)?);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            wall_time_ms: 30_000,
            cpu_time_ms: 30_000,
            cpu_rate_percent: 50,
            process_memory_bytes: 64 * 1024 * 1024,
            job_memory_bytes: 128 * 1024 * 1024,
            active_process_limit: 4,
            output_bytes: 1024 * 1024,
        }
    }

    fn request() -> Envelope<Request> {
        Envelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::from_u128(1),
            sequence: 1,
            nonce: "0123456789abcdef0123456789abcdef".into(),
            body: Request::Run(RunRequest {
                command: vec!["fixture.exe".into()],
                cwd: r"C:\staged".into(),
                limits: limits(),
            }),
        }
    }

    #[test]
    fn frame_round_trip_is_exact() {
        let expected = request();
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &expected).unwrap();
        let actual: Envelope<Request> = read_frame(&mut bytes.as_slice()).unwrap();
        assert_eq!(actual, expected);
        actual.validate().unwrap();
    }

    #[test]
    fn duplicate_and_unknown_fields_are_rejected() {
        let duplicate = r#"{"protocol_version":1,"protocol_version":1}"#;
        assert!(strict_json(duplicate).is_err());

        let mut value = serde_json::to_value(request()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("surprise".into(), Value::Bool(true));
        let bytes = serde_json::to_vec(&value).unwrap();
        let mut frame = u32::try_from(bytes.len()).unwrap().to_le_bytes().to_vec();
        frame.extend(bytes);
        assert!(read_frame::<_, Envelope<Request>>(&mut frame.as_slice()).is_err());

        let doctor_with_extra = br#"{"kind":"doctor","surprise":true}"#;
        let mut frame = u32::try_from(doctor_with_extra.len())
            .unwrap()
            .to_le_bytes()
            .to_vec();
        frame.extend(doctor_with_extra);
        assert!(read_frame::<_, Request>(&mut frame.as_slice()).is_err());
    }

    #[test]
    fn oversized_and_truncated_frames_are_rejected() {
        let oversized = u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_le_bytes();
        assert!(matches!(
            read_frame::<_, Value>(&mut oversized.as_slice()),
            Err(ProtocolError::Oversized)
        ));
        let truncated = [4_u8, 0, 0, 0, b'{'];
        assert!(matches!(
            read_frame::<_, Value>(&mut truncated.as_slice()),
            Err(ProtocolError::Truncated)
        ));
    }

    #[test]
    fn version_nonce_and_limits_fail_closed() {
        let mut value = request();
        value.protocol_version = 0;
        assert!(matches!(value.validate(), Err(ProtocolError::Version)));
        value.protocol_version = PROTOCOL_VERSION;
        value.request_id = Uuid::nil();
        assert!(value.validate().is_err());
        value.request_id = Uuid::from_u128(1);
        value.nonce.clear();
        assert!(value.validate().is_err());
        value.nonce = "0".repeat(32);
        if let Request::Run(run) = &mut value.body {
            run.limits.active_process_limit = 0;
        }
        assert!(value.validate().is_err());
    }
}
