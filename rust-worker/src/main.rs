use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Number, Value};
use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::process::ExitCode;

mod matrix;
mod tor;

const PROTOCOL_VERSION: i32 = 2;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const READ_BUFFER_BYTES: usize = 4096;

#[derive(Debug)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<JsonValue>),
    Object {
        fields: Vec<(String, JsonValue)>,
        has_duplicate_keys: bool,
    },
}

impl JsonValue {
    fn object_field(&self, name: &str) -> Option<&JsonValue> {
        match self {
            Self::Object { fields, .. } => fields
                .iter()
                .find_map(|(key, value)| (key == name).then_some(value)),
            _ => None,
        }
    }

    fn max_container_depth(&self) -> usize {
        match self {
            Self::Object { fields, .. } => {
                1 + fields
                    .iter()
                    .map(|(_, value)| value.max_container_depth())
                    .max()
                    .unwrap_or(0)
            }
            Self::Array(values) => {
                1 + values
                    .iter()
                    .map(JsonValue::max_container_depth)
                    .max()
                    .unwrap_or(0)
            }
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) => 0,
        }
    }

    fn contains_duplicates(&self) -> bool {
        match self {
            Self::Object {
                fields,
                has_duplicate_keys,
            } => *has_duplicate_keys || fields.iter().any(|(_, value)| value.contains_duplicates()),
            Self::Array(values) => values.iter().any(JsonValue::contains_duplicates),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) => false,
        }
    }

    fn to_serde_value(&self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Bool(value) => Value::Bool(*value),
            Self::Number(value) => Value::Number(value.clone()),
            Self::String(value) => Value::String(value.clone()),
            Self::Array(values) => {
                Value::Array(values.iter().map(JsonValue::to_serde_value).collect())
            }
            Self::Object { fields, .. } => Value::Object(
                fields
                    .iter()
                    .map(|(name, value)| (name.clone(), value.to_serde_value()))
                    .collect(),
            ),
        }
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = JsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(JsonValue::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(JsonValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(JsonValue::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(JsonValue::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(JsonValue::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(JsonValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(JsonValue::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(JsonValue::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = Vec::new();
        let mut names = HashSet::new();
        let mut has_duplicate_keys = false;

        while let Some(name) = object.next_key::<String>()? {
            let value = object.next_value()?;
            if !names.insert(name.clone()) {
                has_duplicate_keys = true;
            } else {
                fields.push((name, value));
            }
        }

        Ok(JsonValue::Object {
            fields,
            has_duplicate_keys,
        })
    }
}

impl<'de> Deserialize<'de> for JsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorCode {
    InvalidRequest,
    MalformedRequest,
    FrameTooLarge,
    TruncatedFrame,
    UnsupportedVersion,
    UnknownMethod,
    TorNotConfigured,
    TorNotReady,
    AuthenticationFailed,
    DirectMessageRequired,
    EncryptionRequired,
    VerificationUnavailable,
    NotLoggedIn,
    OperationFailed,
    InvalidPayload,
    OutputTooLarge,
    InternalError,
}

impl ErrorCode {
    fn wire_name(self) -> &'static str {
        match self {
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::MalformedRequest => "MALFORMED_REQUEST",
            Self::FrameTooLarge => "FRAME_TOO_LARGE",
            Self::TruncatedFrame => "TRUNCATED_FRAME",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::UnknownMethod => "UNKNOWN_METHOD",
            Self::TorNotConfigured => "TOR_NOT_CONFIGURED",
            Self::TorNotReady => "TOR_NOT_READY",
            Self::AuthenticationFailed => "AUTHENTICATION_FAILED",
            Self::DirectMessageRequired => "DIRECT_MESSAGE_REQUIRED",
            Self::EncryptionRequired => "ENCRYPTION_REQUIRED",
            Self::VerificationUnavailable => "VERIFICATION_UNAVAILABLE",
            Self::NotLoggedIn => "NOT_LOGGED_IN",
            Self::OperationFailed => "OPERATION_FAILED",
            Self::InvalidPayload => "INVALID_PAYLOAD",
            Self::OutputTooLarge => "OUTPUT_TOO_LARGE",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Method {
    Hello,
    PrivacyStatus,
    TorStatus,
    MatrixLogin,
    MatrixRestore,
    MatrixLogout,
    RoomsList,
    InvitesList,
    RoomCreateDm,
    RoomAcceptInvite,
    RoomMessages,
    RoomSendText,
    PeerVerificationStart,
    PeerVerificationStatus,
    PeerVerificationConfirm,
    PeerVerificationCancel,
}

#[derive(Debug)]
struct ParsedRequest {
    id: Option<String>,
    method: Option<Method>,
    payload: Option<Value>,
    error: Option<ErrorCode>,
}

impl ParsedRequest {
    fn failure(error: ErrorCode, id: Option<String>) -> Self {
        Self {
            id,
            method: None,
            payload: None,
            error: Some(error),
        }
    }
}

fn parse_request(frame: &[u8]) -> ParsedRequest {
    if frame.len() > MAX_FRAME_BYTES {
        return ParsedRequest::failure(ErrorCode::FrameTooLarge, None);
    }

    let mut deserializer = serde_json::Deserializer::from_slice(frame);
    let value = match JsonValue::deserialize(&mut deserializer) {
        Ok(value) if deserializer.end().is_ok() => value,
        _ => return ParsedRequest::failure(ErrorCode::MalformedRequest, None),
    };

    if value.max_container_depth() > 8 {
        return ParsedRequest::failure(ErrorCode::MalformedRequest, None);
    }

    let JsonValue::Object {
        fields,
        has_duplicate_keys,
    } = &value
    else {
        return ParsedRequest::failure(ErrorCode::InvalidRequest, None);
    };

    const ALLOWED_PROPERTIES: [&str; 5] = ["v", "kind", "id", "method", "payload"];
    if *has_duplicate_keys
        || fields.len() != ALLOWED_PROPERTIES.len()
        || fields
            .iter()
            .any(|(name, _)| !ALLOWED_PROPERTIES.contains(&name.as_str()))
    {
        return ParsedRequest::failure(ErrorCode::InvalidRequest, None);
    }

    let Some(JsonValue::String(raw_id)) = value.object_field("id") else {
        return ParsedRequest::failure(ErrorCode::InvalidRequest, None);
    };
    let Some(id) = canonical_uuid(raw_id) else {
        return ParsedRequest::failure(ErrorCode::InvalidRequest, None);
    };

    let Some(JsonValue::Number(version_number)) = value.object_field("v") else {
        return ParsedRequest::failure(ErrorCode::InvalidRequest, Some(id));
    };
    let version = version_number
        .as_i64()
        .and_then(|number| i32::try_from(number).ok())
        .or_else(|| {
            version_number
                .as_u64()
                .and_then(|number| i32::try_from(number).ok())
        });
    let Some(version) = version else {
        return ParsedRequest::failure(ErrorCode::InvalidRequest, Some(id));
    };
    if version != PROTOCOL_VERSION {
        return ParsedRequest::failure(ErrorCode::UnsupportedVersion, Some(id));
    }

    if !matches!(value.object_field("kind"), Some(JsonValue::String(kind)) if kind == "request") {
        return ParsedRequest::failure(ErrorCode::InvalidRequest, Some(id));
    }

    let Some(JsonValue::String(method_name)) = value.object_field("method") else {
        return ParsedRequest::failure(ErrorCode::InvalidRequest, Some(id));
    };
    if method_name.encode_utf16().count() > 64 || method_name.chars().all(char::is_whitespace) {
        return ParsedRequest::failure(ErrorCode::InvalidRequest, Some(id));
    }

    let Some(payload) = value.object_field("payload") else {
        return ParsedRequest::failure(ErrorCode::InvalidRequest, Some(id));
    };
    if !matches!(payload, JsonValue::Object { .. }) || payload.contains_duplicates() {
        return ParsedRequest::failure(ErrorCode::InvalidRequest, Some(id));
    }

    let method = match method_name.as_str() {
        "worker.hello" => Method::Hello,
        "privacy.status" => Method::PrivacyStatus,
        "tor.status" => Method::TorStatus,
        "matrix.login" => Method::MatrixLogin,
        "matrix.restore" => Method::MatrixRestore,
        "matrix.logout" => Method::MatrixLogout,
        "rooms.list" => Method::RoomsList,
        "invites.list" => Method::InvitesList,
        "room.create_dm" => Method::RoomCreateDm,
        "room.accept_invite" => Method::RoomAcceptInvite,
        "room.messages" => Method::RoomMessages,
        "room.send_text" => Method::RoomSendText,
        "peer_verification.start" => Method::PeerVerificationStart,
        "peer_verification.status" => Method::PeerVerificationStatus,
        "peer_verification.confirm" => Method::PeerVerificationConfirm,
        "peer_verification.cancel" => Method::PeerVerificationCancel,
        _ => return ParsedRequest::failure(ErrorCode::UnknownMethod, Some(id)),
    };

    let payload = payload.to_serde_value();
    if !valid_payload(method, &payload) {
        return ParsedRequest::failure(ErrorCode::InvalidPayload, Some(id));
    }

    ParsedRequest {
        id: Some(id),
        method: Some(method),
        payload: Some(payload),
        error: None,
    }
}

fn valid_payload(method: Method, payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    let string = |name: &str| object.get(name).is_some_and(Value::is_string);
    match method {
        Method::Hello
        | Method::PrivacyStatus
        | Method::TorStatus
        | Method::MatrixLogout
        | Method::RoomsList
        | Method::InvitesList => object.is_empty(),
        Method::MatrixLogin => {
            object.len() == 5
                && string("homeserver")
                && string("username")
                && string("password")
                && string("storePassphrase")
                && string("storeId")
        }
        Method::MatrixRestore => {
            object.len() == 4
                && string("homeserver")
                && object.get("session").is_some_and(Value::is_object)
                && string("storePassphrase")
                && string("storeId")
        }
        Method::RoomCreateDm => object.len() == 1 && string("userId"),
        Method::RoomAcceptInvite => object.len() == 1 && string("roomId"),
        Method::RoomMessages => object.len() == 1 && string("roomId"),
        Method::RoomSendText => object.len() == 2 && string("roomId") && string("body"),
        Method::PeerVerificationStart => {
            object.len() == 1 && bounded_string(object, "peerUserId", 255)
        }
        Method::PeerVerificationStatus
        | Method::PeerVerificationConfirm
        | Method::PeerVerificationCancel => {
            object.len() == 2
                && bounded_string(object, "peerUserId", 255)
                && bounded_string(object, "flowId", 255)
        }
    }
}

fn canonical_uuid(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if bytes.len() != 36 || [8, 13, 18, 23].iter().any(|index| bytes[*index] != b'-') {
        return None;
    }

    let mut has_non_zero_hex = false;
    for (index, byte) in bytes.iter().enumerate() {
        if [8, 13, 18, 23].contains(&index) {
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return None;
        }
        has_non_zero_hex |= *byte != b'0';
    }

    has_non_zero_hex.then(|| value.to_ascii_lowercase())
}

fn response_frame(id: Option<&str>, result: Option<Value>, error: Option<ErrorCode>) -> Vec<u8> {
    let (ok, result, error) = match (result, error) {
        (Some(result), None) => (true, Some(result), None),
        (None, Some(error)) => (false, None, Some(error)),
        _ => (false, None, Some(ErrorCode::InternalError)),
    };

    let envelope = serde_json::json!({
        "v": PROTOCOL_VERSION,
        "kind": "response",
        "id": id,
        "ok": ok,
        "result": result,
        "error": error.map(|code| serde_json::json!({ "code": code.wire_name() })),
    });

    let mut body = serde_json::to_vec(&envelope).unwrap_or_default();
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        body = serde_json::to_vec(&serde_json::json!({
            "v": PROTOCOL_VERSION,
            "kind": "response",
            "id": id,
            "ok": false,
            "result": null,
            "error": { "code": ErrorCode::OutputTooLarge.wire_name() }
        }))
        .unwrap_or_else(|_| {
            b"{\"v\":2,\"kind\":\"response\",\"id\":null,\"ok\":false,\"result\":null,\"error\":{\"code\":\"INTERNAL_ERROR\"}}".to_vec()
        });
    }
    body.push(b'\n');
    body
}

struct WorkerState {
    tor: Option<tor::TorSupervisor>,
    matrix: matrix::MatrixService,
}

impl WorkerState {
    fn new() -> Self {
        Self {
            tor: None,
            matrix: matrix::MatrixService::new(),
        }
    }

    async fn ready_tor_route(&mut self) -> Result<tor::VerifiedTorRoute, ErrorCode> {
        if self.tor.is_none() {
            self.tor = Some(
                tor::TorSupervisor::start_from_environment()
                    .await
                    .map_err(map_tor_failure)?,
            );
        }
        let ready = match self.tor.as_mut() {
            Some(tor) => tor.ensure_ready().await.is_ok(),
            None => false,
        };
        if !ready {
            self.matrix = matrix::MatrixService::new();
            if let Some(mut tor) = self.tor.take() {
                tor.stop().await;
            }
            return Err(ErrorCode::TorNotReady);
        }
        let tor = self.tor.as_ref().ok_or(ErrorCode::TorNotReady)?;
        Ok(tor.verified_route())
    }

    async fn dispatch(&mut self, request: &ParsedRequest) -> (Option<Value>, Option<ErrorCode>) {
        let (Some(method), Some(payload)) = (request.method, request.payload.as_ref()) else {
            return (
                None,
                Some(request.error.unwrap_or(ErrorCode::InternalError)),
            );
        };

        let result = match method {
            Method::Hello => Ok(serde_json::json!({ "protocolVersion": PROTOCOL_VERSION })),
            Method::PrivacyStatus => Ok(serde_json::json!({
                "state": "matrix_sdk_available",
                "networkAccess": "tor_required",
                "e2ee": "sdk_feature_available",
                "tor": "not_checked"
            })),
            Method::TorStatus => self.tor_status().await,
            Method::MatrixLogin => {
                let route = match self.ready_tor_route().await {
                    Ok(route) => route,
                    Err(error) => return (None, Some(error)),
                };
                let Some(homeserver) = string_field(payload, "homeserver") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                let Some(username) = string_field(payload, "username") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                let Some(password) = string_field(payload, "password") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                let Some(passphrase) = string_field(payload, "storePassphrase") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                let Some(store_id) = string_field(payload, "storeId").and_then(canonical_uuid)
                else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                let Some(data_dir) = configured_data_directory() else {
                    return (None, Some(ErrorCode::OperationFailed));
                };
                if std::fs::create_dir_all(&data_dir).is_err() {
                    return (None, Some(ErrorCode::OperationFailed));
                }
                let database_path = data_dir.join(format!("matrix-store-{store_id}.sqlite3"));
                let result = self
                    .matrix
                    .login(
                        homeserver,
                        username,
                        password,
                        &database_path,
                        passphrase,
                        &route,
                    )
                    .await;
                if result.is_err() {
                    remove_store_files(&database_path);
                }
                result.map_err(map_matrix_failure)
            }
            Method::MatrixRestore => {
                let route = match self.ready_tor_route().await {
                    Ok(route) => route,
                    Err(error) => return (None, Some(error)),
                };
                let Some(homeserver) = string_field(payload, "homeserver") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                let Some(passphrase) = string_field(payload, "storePassphrase") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                let Some(store_id) = string_field(payload, "storeId").and_then(canonical_uuid)
                else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                let Some(session) = payload
                    .get("session")
                    .cloned()
                    .and_then(|value| serde_json::from_value(value).ok())
                else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                let Some(data_dir) = configured_data_directory() else {
                    return (None, Some(ErrorCode::OperationFailed));
                };
                if std::fs::create_dir_all(&data_dir).is_err() {
                    return (None, Some(ErrorCode::OperationFailed));
                }
                let database_path = data_dir.join(format!("matrix-store-{store_id}.sqlite3"));
                self.matrix
                    .restore(homeserver, session, &database_path, passphrase, &route)
                    .await
                    .map_err(map_matrix_failure)
            }
            Method::MatrixLogout => {
                let route = match self.ready_tor_route().await {
                    Ok(route) => route,
                    Err(error) => return (None, Some(error)),
                };
                drop(route);
                self.matrix.logout().await.map_err(map_matrix_failure)
            }
            Method::RoomsList => {
                let route = match self.ready_tor_route().await {
                    Ok(route) => route,
                    Err(error) => return (None, Some(error)),
                };
                drop(route);
                if let Err(error) = self.matrix.sync_once().await {
                    return (None, Some(map_matrix_failure(error)));
                }
                self.matrix
                    .list_direct_rooms()
                    .await
                    .map_err(map_matrix_failure)
            }
            Method::InvitesList => {
                let route = match self.ready_tor_route().await {
                    Ok(route) => route,
                    Err(error) => return (None, Some(error)),
                };
                drop(route);
                if let Err(error) = self.matrix.sync_once().await {
                    return (None, Some(map_matrix_failure(error)));
                }
                self.matrix.list_invites().await.map_err(map_matrix_failure)
            }
            Method::RoomCreateDm => {
                let route = match self.ready_tor_route().await {
                    Ok(route) => route,
                    Err(error) => return (None, Some(error)),
                };
                drop(route);
                let Some(user_id) = string_field(payload, "userId") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                self.matrix
                    .create_direct_room(user_id)
                    .await
                    .map_err(map_matrix_failure)
            }
            Method::RoomAcceptInvite => {
                let route = match self.ready_tor_route().await {
                    Ok(route) => route,
                    Err(error) => return (None, Some(error)),
                };
                drop(route);
                let Some(room_id) = string_field(payload, "roomId") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                self.matrix
                    .accept_encrypted_direct_invite(room_id)
                    .await
                    .map_err(map_matrix_failure)
            }
            Method::RoomMessages => {
                let route = match self.ready_tor_route().await {
                    Ok(route) => route,
                    Err(error) => return (None, Some(error)),
                };
                drop(route);
                let Some(room_id) = string_field(payload, "roomId") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                self.matrix
                    .messages(room_id)
                    .await
                    .map_err(map_matrix_failure)
            }
            Method::RoomSendText => {
                let route = match self.ready_tor_route().await {
                    Ok(route) => route,
                    Err(error) => return (None, Some(error)),
                };
                drop(route);
                let Some(room_id) = string_field(payload, "roomId") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                let Some(body) = string_field(payload, "body") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                self.matrix
                    .send_text(room_id, body)
                    .await
                    .map_err(map_matrix_failure)
            }
            Method::PeerVerificationStart => {
                let route = match self.ready_tor_route().await {
                    Ok(route) => route,
                    Err(error) => return (None, Some(error)),
                };
                drop(route);
                let Some(peer_user_id) = string_field(payload, "peerUserId") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                self.matrix
                    .start_peer_verification(peer_user_id)
                    .await
                    .map_err(map_matrix_failure)
            }
            Method::PeerVerificationStatus => {
                let route = match self.ready_tor_route().await {
                    Ok(route) => route,
                    Err(error) => return (None, Some(error)),
                };
                drop(route);
                if let Err(error) = self.matrix.sync_once().await {
                    return (None, Some(map_matrix_failure(error)));
                }
                let Some(peer_user_id) = string_field(payload, "peerUserId") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                let Some(flow_id) = string_field(payload, "flowId") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                self.matrix
                    .peer_verification_status(peer_user_id, flow_id)
                    .await
                    .map_err(map_matrix_failure)
            }
            Method::PeerVerificationConfirm => {
                let route = match self.ready_tor_route().await {
                    Ok(route) => route,
                    Err(error) => return (None, Some(error)),
                };
                drop(route);
                let Some(peer_user_id) = string_field(payload, "peerUserId") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                let Some(flow_id) = string_field(payload, "flowId") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                self.matrix
                    .confirm_peer_verification(peer_user_id, flow_id)
                    .await
                    .map_err(map_matrix_failure)
            }
            Method::PeerVerificationCancel => {
                let route = match self.ready_tor_route().await {
                    Ok(route) => route,
                    Err(error) => return (None, Some(error)),
                };
                drop(route);
                let Some(peer_user_id) = string_field(payload, "peerUserId") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                let Some(flow_id) = string_field(payload, "flowId") else {
                    return (None, Some(ErrorCode::InvalidPayload));
                };
                self.matrix
                    .cancel_peer_verification(peer_user_id, flow_id)
                    .await
                    .map_err(map_matrix_failure)
            }
        };

        match result {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error)),
        }
    }

    async fn stop(&mut self) {
        if let Some(tor) = &mut self.tor {
            tor.stop().await;
        }
        self.tor = None;
        self.matrix = matrix::MatrixService::new();
    }

    async fn tor_status(&mut self) -> Result<Value, ErrorCode> {
        let state = if let Some(tor) = &mut self.tor {
            if tor.ensure_ready().await.is_ok() {
                "bootstrap_verified"
            } else {
                "not_ready"
            }
        } else if std::env::var_os("VEIL_CHAT_TOR_EXECUTABLE").is_some()
            && configured_data_directory().is_some()
        {
            "configured_not_started"
        } else {
            "not_configured"
        };
        let ready = state == "bootstrap_verified";
        if state == "not_ready" {
            self.matrix = matrix::MatrixService::new();
            if let Some(tor) = &mut self.tor {
                tor.stop().await;
            }
            self.tor = None;
        }
        Ok(serde_json::json!({ "state": state, "networkOperationsAllowed": ready }))
    }
}

fn configured_data_directory() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("VEIL_CHAT_DATA_DIRECTORY").map(std::path::PathBuf::from)?;
    path.is_absolute().then_some(path)
}

fn remove_store_files(database_path: &std::path::Path) {
    for suffix in ["", "-wal", "-shm"] {
        let path = if suffix.is_empty() {
            database_path.to_owned()
        } else {
            let mut path = database_path.as_os_str().to_os_string();
            path.push(suffix);
            std::path::PathBuf::from(path)
        };
        let _ = std::fs::remove_file(path);
    }
}

fn string_field<'a>(payload: &'a Value, name: &str) -> Option<&'a str> {
    payload.as_object()?.get(name)?.as_str()
}

fn bounded_string(object: &serde_json::Map<String, Value>, name: &str, max_bytes: usize) -> bool {
    object
        .get(name)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty() && value.len() <= max_bytes)
}

fn map_tor_failure(failure: tor::TorFailure) -> ErrorCode {
    match failure {
        tor::TorFailure::NotConfigured => ErrorCode::TorNotConfigured,
        tor::TorFailure::StartupFailed | tor::TorFailure::NotReady => ErrorCode::TorNotReady,
    }
}

fn map_matrix_failure(failure: matrix::MatrixFailure) -> ErrorCode {
    match failure {
        matrix::MatrixFailure::InvalidInput => ErrorCode::InvalidPayload,
        matrix::MatrixFailure::AuthenticationFailed => ErrorCode::AuthenticationFailed,
        matrix::MatrixFailure::TorNotReady => ErrorCode::TorNotReady,
        matrix::MatrixFailure::DirectMessageRequired => ErrorCode::DirectMessageRequired,
        matrix::MatrixFailure::EncryptionRequired => ErrorCode::EncryptionRequired,
        matrix::MatrixFailure::VerificationUnavailable => ErrorCode::VerificationUnavailable,
        matrix::MatrixFailure::NotLoggedIn => ErrorCode::NotLoggedIn,
        matrix::MatrixFailure::OperationFailed => ErrorCode::OperationFailed,
    }
}

#[derive(Debug, Eq, PartialEq)]
enum FrameReadError {
    TooLarge,
    Truncated,
    Io,
}

fn read_frame<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, FrameReadError> {
    let mut frame = Vec::with_capacity(1024);

    loop {
        let available = reader.fill_buf().map_err(|_| FrameReadError::Io)?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(FrameReadError::Truncated)
            };
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let bytes_before_newline = newline.unwrap_or(available.len());
        if frame.len().saturating_add(bytes_before_newline) > MAX_FRAME_BYTES {
            return Err(FrameReadError::TooLarge);
        }

        frame.extend_from_slice(&available[..bytes_before_newline]);
        let consumed = bytes_before_newline + usize::from(newline.is_some());
        reader.consume(consumed);

        if newline.is_some() {
            if frame.last() == Some(&b'\r') {
                frame.pop();
            }
            return Ok(Some(frame));
        }
    }
}

fn write_frame<W: Write>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
    writer.write_all(frame)?;
    writer.flush()
}

fn report_static_diagnostic(code: &str) {
    let _ = writeln!(io::stderr().lock(), "veil-worker: {code}");
}

async fn run() -> ExitCode {
    if std::env::args_os().len() != 1 {
        report_static_diagnostic("INVALID_ARGUMENTS");
        return ExitCode::from(64);
    }

    let stdin = io::stdin();
    let mut reader = BufReader::with_capacity(READ_BUFFER_BYTES, stdin.lock());
    let stdout = io::stdout();
    let mut writer = BufWriter::with_capacity(READ_BUFFER_BYTES, stdout.lock());
    let mut state = WorkerState::new();

    loop {
        match read_frame(&mut reader) {
            Ok(Some(frame)) => {
                let parsed = parse_request(&frame);
                let request_id = parsed.id.as_deref();
                let (result, error) = state.dispatch(&parsed).await;
                let response = response_frame(request_id, result, error);
                if write_frame(&mut writer, &response).is_err() {
                    report_static_diagnostic("OUTPUT_FAILURE");
                    state.stop().await;
                    return ExitCode::from(74);
                }
            }
            Ok(None) => {
                state.stop().await;
                return ExitCode::SUCCESS;
            }
            Err(FrameReadError::TooLarge) => {
                let response = response_frame(None, None, Some(ErrorCode::FrameTooLarge));
                let _ = write_frame(&mut writer, &response);
                report_static_diagnostic(ErrorCode::FrameTooLarge.wire_name());
                state.stop().await;
                return ExitCode::from(65);
            }
            Err(FrameReadError::Truncated) => {
                let response = response_frame(None, None, Some(ErrorCode::TruncatedFrame));
                let _ = write_frame(&mut writer, &response);
                report_static_diagnostic(ErrorCode::TruncatedFrame.wire_name());
                state.stop().await;
                return ExitCode::from(65);
            }
            Err(FrameReadError::Io) => {
                report_static_diagnostic("INPUT_FAILURE");
                state.stop().await;
                return ExitCode::from(74);
            }
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const ID: &str = "d41c435b-24c8-458a-b873-3ca1d77c2c34";

    fn request(version: i32, method: &str) -> Vec<u8> {
        format!(
            "{{\"v\":{version},\"kind\":\"request\",\"id\":\"{ID}\",\"method\":\"{method}\",\"payload\":{{}}}}"
        )
        .into_bytes()
    }

    #[test]
    fn parses_v2_status_methods_and_rejects_unknown_methods() {
        assert_eq!(
            parse_request(&request(PROTOCOL_VERSION, "worker.hello")).method,
            Some(Method::Hello)
        );
        assert_eq!(
            parse_request(&request(PROTOCOL_VERSION, "privacy.status")).method,
            Some(Method::PrivacyStatus)
        );
        assert_eq!(
            parse_request(&request(PROTOCOL_VERSION, "invites.list")).method,
            Some(Method::InvitesList)
        );
        assert_eq!(
            parse_request(&request(PROTOCOL_VERSION, "not.a.method")).error,
            Some(ErrorCode::UnknownMethod)
        );
    }

    #[test]
    fn peer_verification_methods_require_bounded_typed_identifiers() {
        let valid = format!(
            "{{\"v\":2,\"kind\":\"request\",\"id\":\"{ID}\",\"method\":\"peer_verification.status\",\"payload\":{{\"peerUserId\":\"@peer:example.org\",\"flowId\":\"flow-123\"}}}}"
        );
        assert_eq!(
            parse_request(valid.as_bytes()).method,
            Some(Method::PeerVerificationStatus)
        );

        let invalid = format!(
            "{{\"v\":2,\"kind\":\"request\",\"id\":\"{ID}\",\"method\":\"peer_verification.status\",\"payload\":{{\"peerUserId\":\"@peer:example.org\",\"flowId\":\"\"}}}}"
        );
        assert_eq!(
            parse_request(invalid.as_bytes()).error,
            Some(ErrorCode::InvalidPayload)
        );
    }

    #[test]
    fn extra_active_member_failure_has_a_stable_protocol_error() {
        assert_eq!(
            map_matrix_failure(matrix::MatrixFailure::DirectMessageRequired),
            ErrorCode::DirectMessageRequired
        );
        assert_eq!(
            ErrorCode::DirectMessageRequired.wire_name(),
            "DIRECT_MESSAGE_REQUIRED"
        );
    }

    #[test]
    fn invite_acceptance_requires_a_room_id_payload() {
        let valid = format!(
            "{{\"v\":2,\"kind\":\"request\",\"id\":\"{ID}\",\"method\":\"room.accept_invite\",\"payload\":{{\"roomId\":\"!room:example.org\"}}}}"
        );
        assert_eq!(
            parse_request(valid.as_bytes()).method,
            Some(Method::RoomAcceptInvite)
        );

        let invalid = format!(
            "{{\"v\":2,\"kind\":\"request\",\"id\":\"{ID}\",\"method\":\"room.accept_invite\",\"payload\":{{\"roomId\":\"!room:example.org\",\"force\":true}}}}"
        );
        assert_eq!(
            parse_request(invalid.as_bytes()).error,
            Some(ErrorCode::InvalidPayload)
        );
    }

    #[test]
    fn accepts_typed_login_payload_and_rejects_missing_or_duplicate_fields() {
        let valid = format!(
            "{{\"v\":2,\"kind\":\"request\",\"id\":\"{ID}\",\"method\":\"matrix.login\",\"payload\":{{\"homeserver\":\"https://example.org\",\"username\":\"alice\",\"password\":\"secret\",\"storePassphrase\":\"passphrase\",\"storeId\":\"a34585cf-3381-4fdd-a122-945360e3878c\"}}}}"
        );
        assert_eq!(
            parse_request(valid.as_bytes()).method,
            Some(Method::MatrixLogin)
        );

        let incomplete = format!(
            "{{\"v\":2,\"kind\":\"request\",\"id\":\"{ID}\",\"method\":\"matrix.login\",\"payload\":{{\"homeserver\":\"https://example.org\",\"username\":\"alice\",\"password\":\"secret\",\"storePassphrase\":\"passphrase\"}}}}"
        );
        assert_eq!(
            parse_request(incomplete.as_bytes()).error,
            Some(ErrorCode::InvalidPayload)
        );

        let duplicate = format!(
            "{{\"v\":2,\"kind\":\"request\",\"id\":\"{ID}\",\"method\":\"matrix.login\",\"payload\":{{\"homeserver\":\"https://example.org\",\"username\":\"alice\",\"username\":\"mallory\",\"password\":\"secret\",\"storePassphrase\":\"passphrase\",\"storeId\":\"a34585cf-3381-4fdd-a122-945360e3878c\"}}}}"
        );
        assert_eq!(
            parse_request(duplicate.as_bytes()).error,
            Some(ErrorCode::InvalidRequest)
        );
    }

    #[test]
    fn unsupported_version_keeps_a_valid_request_id() {
        let parsed = parse_request(&request(3, "worker.hello"));
        assert_eq!(parsed.error, Some(ErrorCode::UnsupportedVersion));
        assert_eq!(parsed.id.as_deref(), Some(ID));
    }

    #[test]
    fn malformed_json_and_duplicate_properties_are_rejected() {
        assert_eq!(
            parse_request(b"{\"v\":").error,
            Some(ErrorCode::MalformedRequest)
        );
        assert_eq!(
            parse_request(format!(
                "{{\"v\":1,\"v\":1,\"kind\":\"request\",\"id\":\"{ID}\",\"method\":\"worker.hello\",\"payload\":{{}}}}"
            ).as_bytes()).error,
            Some(ErrorCode::InvalidRequest)
        );
    }

    #[test]
    fn request_depth_is_limited_to_eight_containers() {
        let too_deep = format!(
            "{{\"v\":1,\"kind\":\"request\",\"id\":\"{ID}\",\"method\":\"worker.hello\",\"payload\":{{\"a\":{{\"b\":{{\"c\":{{\"d\":{{\"e\":{{\"f\":{{\"g\":{{}}}}}}}}}}}}}}}}}}"
        );
        assert_eq!(
            parse_request(too_deep.as_bytes()).error,
            Some(ErrorCode::MalformedRequest)
        );
    }

    #[test]
    fn response_frames_match_the_fixed_v2_envelopes() {
        let hello = response_frame(
            Some(ID),
            Some(serde_json::json!({ "protocolVersion": PROTOCOL_VERSION })),
            None,
        );
        let hello_value: serde_json::Value = serde_json::from_slice(&hello).unwrap();
        assert_eq!(hello_value["v"], PROTOCOL_VERSION);
        assert_eq!(hello_value["id"], ID);
        assert_eq!(hello_value["result"]["protocolVersion"], PROTOCOL_VERSION);

        let privacy = response_frame(
            Some(ID),
            Some(serde_json::json!({
                "state": "matrix_sdk_available", "networkAccess": "tor_required", "e2ee": "sdk_enabled", "tor": "not_started"
            })),
            None,
        );
        let privacy_value: serde_json::Value = serde_json::from_slice(&privacy).unwrap();
        assert_eq!(privacy_value["result"]["state"], "matrix_sdk_available");
        assert_eq!(privacy_value["result"]["networkAccess"], "tor_required");
    }

    #[test]
    fn frame_reader_accepts_crlf_and_detects_eof_states() {
        let mut reader = Cursor::new(b"one\r\ntwo\n".to_vec());
        assert_eq!(read_frame(&mut reader).unwrap(), Some(b"one".to_vec()));
        assert_eq!(read_frame(&mut reader).unwrap(), Some(b"two".to_vec()));
        assert_eq!(read_frame(&mut reader).unwrap(), None);

        let mut truncated = Cursor::new(b"partial".to_vec());
        assert_eq!(read_frame(&mut truncated), Err(FrameReadError::Truncated));
    }

    #[test]
    fn frame_reader_rejects_more_than_the_byte_limit() {
        let mut input = vec![b'x'; MAX_FRAME_BYTES + 1];
        input.push(b'\n');
        let mut reader = Cursor::new(input);
        assert_eq!(read_frame(&mut reader), Err(FrameReadError::TooLarge));
    }
}
