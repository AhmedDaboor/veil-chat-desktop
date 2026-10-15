use matrix_sdk::{
    Client, RoomMemberships,
    authentication::matrix::MatrixSession,
    encryption::verification::{
        SasState, SasVerification, VerificationRequest, VerificationRequestState,
    },
    room::{MessagesOptions, Room},
    ruma::{
        RoomId, UserId,
        events::{key::verification::VerificationMethod, room::message::RoomMessageEventContent},
    },
};
use reqwest::{Proxy, Url};
use serde_json::{Value, json};
use std::path::Path;

use crate::tor::VerifiedTorRoute;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatrixFailure {
    InvalidInput,
    AuthenticationFailed,
    TorNotReady,
    DirectMessageRequired,
    EncryptionRequired,
    NotLoggedIn,
    VerificationUnavailable,
    OperationFailed,
}

pub struct MatrixService {
    client: Option<Client>,
    peer_verification: Option<PeerVerification>,
}

struct PeerVerification {
    peer_user_id: String,
    request: VerificationRequest,
    sas: Option<SasVerification>,
}

impl MatrixService {
    pub fn new() -> Self {
        Self {
            client: None,
            peer_verification: None,
        }
    }

    pub async fn login(
        &mut self,
        homeserver: &str,
        username: &str,
        password: &str,
        database_path: &Path,
        store_passphrase: &str,
        tor: &VerifiedTorRoute,
    ) -> Result<Value, MatrixFailure> {
        validate_homeserver(homeserver)?;
        if username.trim().is_empty()
            || username.len() > 255
            || password.is_empty()
            || password.len() > 4096
            || store_passphrase.len() < 32
            || !database_path.is_absolute()
        {
            return Err(MatrixFailure::InvalidInput);
        }

        let client = build_client(homeserver, database_path, store_passphrase, tor).await?;
        client
            .matrix_auth()
            .login_username(username, password)
            .initial_device_display_name("Veil Chat")
            .await
            .map_err(|_| MatrixFailure::AuthenticationFailed)?;

        let session = client
            .matrix_auth()
            .session()
            .ok_or(MatrixFailure::OperationFailed)?;
        let encoded = serde_json::to_value(session).map_err(|_| MatrixFailure::OperationFailed)?;
        self.client = Some(client);
        Ok(json!({
            "userId": self.client.as_ref().and_then(Client::user_id).map(ToString::to_string),
            "session": encoded,
            "e2eeAvailable": true,
        }))
    }

    pub async fn restore(
        &mut self,
        homeserver: &str,
        session: MatrixSession,
        database_path: &Path,
        store_passphrase: &str,
        tor: &VerifiedTorRoute,
    ) -> Result<Value, MatrixFailure> {
        validate_homeserver(homeserver)?;
        if store_passphrase.len() < 32 || !database_path.is_absolute() {
            return Err(MatrixFailure::InvalidInput);
        }
        let client = build_client(homeserver, database_path, store_passphrase, tor).await?;
        client
            .restore_session(session)
            .await
            .map_err(|_| MatrixFailure::AuthenticationFailed)?;
        let user_id = client.user_id().map(ToString::to_string);
        self.client = Some(client);
        Ok(json!({ "userId": user_id, "e2eeAvailable": true }))
    }

    pub async fn logout(&mut self) -> Result<Value, MatrixFailure> {
        let client = self.client.take().ok_or(MatrixFailure::NotLoggedIn)?;
        self.peer_verification = None;
        client
            .matrix_auth()
            .logout()
            .await
            .map_err(|_| MatrixFailure::OperationFailed)?;
        Ok(json!({ "loggedOut": true }))
    }

    pub async fn sync_once(&self) -> Result<Value, MatrixFailure> {
        let client = self.client.as_ref().ok_or(MatrixFailure::NotLoggedIn)?;
        client
            .sync_once(Default::default())
            .await
            .map_err(|_| MatrixFailure::OperationFailed)?;
        Ok(json!({ "synced": true }))
    }

    pub async fn list_direct_rooms(&self) -> Result<Value, MatrixFailure> {
        let client = self.client.as_ref().ok_or(MatrixFailure::NotLoggedIn)?;
        let mut rooms = Vec::new();
        for room in client.joined_rooms() {
            if room.direct_targets().len() != 1 || !room.encryption_state().is_encrypted() {
                continue;
            }
            let Some(peer_user_id) = one_to_one_peer(client, &room).await? else {
                continue;
            };
            let peer_user_id =
                UserId::parse(peer_user_id).map_err(|_| MatrixFailure::OperationFailed)?;
            let peer_identity = client
                .encryption()
                .get_user_identity(&peer_user_id)
                .await
                .map_err(|_| MatrixFailure::OperationFailed)?;
            let peer_identity_status = peer_identity.as_ref().map_or("unknown", |identity| {
                identity_trust_status(
                    true,
                    identity.is_verified(),
                    identity.was_previously_verified(),
                    identity.has_verification_violation(),
                )
            });
            let encryption = room.encryption_state();
            rooms.push(json!({
                "roomId": room.room_id().to_string(),
                "encrypted": encryption.is_encrypted(),
                "encryptionKnown": !encryption.is_unknown(),
                "peerUserId": peer_user_id.to_string(),
                "peerIdentityStatus": peer_identity_status,
            }));
            if rooms.len() == 100 {
                break;
            }
        }
        Ok(json!({ "rooms": rooms }))
    }

    pub async fn list_invites(&self) -> Result<Value, MatrixFailure> {
        let client = self.client.as_ref().ok_or(MatrixFailure::NotLoggedIn)?;
        let mut invites = Vec::new();
        for room in client.invited_rooms().into_iter().take(100) {
            let is_direct = room
                .is_direct()
                .await
                .map_err(|_| MatrixFailure::OperationFailed)?;
            let encryption = room.encryption_state();
            invites.push(json!({
                "roomId": room.room_id().to_string(),
                "isDirect": is_direct,
                "encrypted": encryption.is_encrypted(),
                "encryptionKnown": !encryption.is_unknown(),
            }));
        }
        Ok(json!({ "invites": invites }))
    }

    pub async fn accept_encrypted_direct_invite(
        &self,
        room_id: &str,
    ) -> Result<Value, MatrixFailure> {
        let client = self.client.as_ref().ok_or(MatrixFailure::NotLoggedIn)?;
        let room_id = RoomId::parse(room_id).map_err(|_| MatrixFailure::InvalidInput)?;
        let room = client
            .invited_rooms()
            .into_iter()
            .find(|room| room.room_id() == room_id)
            .ok_or(MatrixFailure::InvalidInput)?;
        let is_direct = room
            .is_direct()
            .await
            .map_err(|_| MatrixFailure::OperationFailed)?;
        let encryption = room.encryption_state();
        require_encrypted_direct_invite(
            is_direct,
            !encryption.is_unknown(),
            encryption.is_encrypted(),
        )?;

        room.join()
            .await
            .map_err(|_| MatrixFailure::OperationFailed)?;
        if client.sync_once(Default::default()).await.is_err() {
            let _ = room.leave().await;
            return Err(MatrixFailure::OperationFailed);
        }
        let Some(joined_room) = client.get_room(&room_id) else {
            let _ = room.leave().await;
            return Err(MatrixFailure::OperationFailed);
        };
        let encryption = match joined_room.latest_encryption_state().await {
            Ok(encryption) => encryption,
            Err(_) => {
                let _ = joined_room.leave().await;
                return Err(MatrixFailure::OperationFailed);
            }
        };
        if !encryption.is_encrypted() {
            let _ = joined_room.leave().await;
            return Err(MatrixFailure::EncryptionRequired);
        }
        match one_to_one_peer(client, &joined_room).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                let _ = joined_room.leave().await;
                return Err(MatrixFailure::DirectMessageRequired);
            }
            Err(failure) => {
                let _ = joined_room.leave().await;
                return Err(failure);
            }
        }
        if joined_room.set_is_direct(true).await.is_err() {
            let _ = joined_room.leave().await;
            return Err(MatrixFailure::OperationFailed);
        }

        Ok(json!({
            "roomId": room_id.to_string(),
            "encrypted": true,
            "encryptionKnown": true,
        }))
    }

    pub async fn create_direct_room(&self, user_id: &str) -> Result<Value, MatrixFailure> {
        let client = self.client.as_ref().ok_or(MatrixFailure::NotLoggedIn)?;
        let user_id = UserId::parse(user_id).map_err(|_| MatrixFailure::InvalidInput)?;
        let room = client
            .create_dm(&user_id)
            .await
            .map_err(|_| MatrixFailure::OperationFailed)?;
        let encryption = room
            .latest_encryption_state()
            .await
            .map_err(|_| MatrixFailure::OperationFailed)?;
        require_encrypted_room(encryption.is_encrypted())?;
        Ok(json!({
            "roomId": room.room_id().to_string(),
            "encrypted": true,
        }))
    }

    pub async fn messages(&self, room_id: &str) -> Result<Value, MatrixFailure> {
        let client = self.client.as_ref().ok_or(MatrixFailure::NotLoggedIn)?;
        let room = get_room(client, room_id)?;
        let state = room
            .latest_encryption_state()
            .await
            .map_err(|_| MatrixFailure::OperationFailed)?;
        if !state.is_encrypted() {
            return Err(MatrixFailure::EncryptionRequired);
        }
        let response = room
            .messages(MessagesOptions::backward())
            .await
            .map_err(|_| MatrixFailure::OperationFailed)?;
        let events = response
            .chunk
            .into_iter()
            .rev()
            .filter_map(|event| {
                let raw = serde_json::to_value(event.kind.raw()).ok()?;
                if raw.get("type")?.as_str()? != "m.room.message"
                    || raw.get("content")?.get("msgtype")?.as_str()? != "m.text"
                {
                    return None;
                }
                let body = raw.get("content")?.get("body")?.as_str()?;
                let sender = event.kind.parse_sender()?.to_string();
                Some(json!({
                    "eventId": event.kind.parse_event_id().map(|id| id.to_string()),
                    "sender": sender,
                    "body": truncate_utf8(body, 1536),
                }))
            })
            .take(4)
            .collect::<Vec<_>>();
        Ok(json!({
            "roomId": room.room_id().to_string(),
            "encrypted": state.is_encrypted(),
            "events": events,
        }))
    }

    pub async fn send_text(&self, room_id: &str, body: &str) -> Result<Value, MatrixFailure> {
        let client = self.client.as_ref().ok_or(MatrixFailure::NotLoggedIn)?;
        if body.trim().is_empty() || body.len() > 8 * 1024 {
            return Err(MatrixFailure::InvalidInput);
        }
        let room = get_room(client, room_id)?;
        let encryption = room
            .latest_encryption_state()
            .await
            .map_err(|_| MatrixFailure::OperationFailed)?;
        if !encryption.is_encrypted() {
            return Err(MatrixFailure::EncryptionRequired);
        }
        room.send(RoomMessageEventContent::text_plain(body))
            .await
            .map_err(|_| MatrixFailure::OperationFailed)?;
        Ok(json!({ "sent": true, "encrypted": true }))
    }

    pub async fn start_peer_verification(
        &mut self,
        peer_user_id: &str,
    ) -> Result<Value, MatrixFailure> {
        let client = self.client.as_ref().ok_or(MatrixFailure::NotLoggedIn)?;
        if self.peer_verification.is_some() {
            return Err(MatrixFailure::VerificationUnavailable);
        }
        let peer_user_id = UserId::parse(peer_user_id).map_err(|_| MatrixFailure::InvalidInput)?;
        if client.user_id() == Some(&peer_user_id)
            || !has_encrypted_direct_room(client, &peer_user_id).await?
        {
            return Err(MatrixFailure::VerificationUnavailable);
        }
        let identity = client
            .encryption()
            .request_user_identity(&peer_user_id)
            .await
            .map_err(|_| MatrixFailure::OperationFailed)?
            .ok_or(MatrixFailure::VerificationUnavailable)?;
        let request = identity
            .request_verification_with_methods(vec![VerificationMethod::SasV1])
            .await
            .map_err(|_| MatrixFailure::OperationFailed)?;
        let flow_id = request.flow_id().to_owned();
        let peer_user_id = peer_user_id.to_string();
        self.peer_verification = Some(PeerVerification {
            peer_user_id: peer_user_id.clone(),
            request,
            sas: None,
        });
        Ok(peer_verification_result(
            &peer_user_id,
            &flow_id,
            "waiting",
            None,
            "unverified",
        ))
    }

    pub async fn peer_verification_status(
        &mut self,
        peer_user_id: &str,
        flow_id: &str,
    ) -> Result<Value, MatrixFailure> {
        let client = self.client.as_ref().ok_or(MatrixFailure::NotLoggedIn)?;
        let active = self
            .peer_verification
            .as_ref()
            .filter(|active| {
                active.peer_user_id == peer_user_id && active.request.flow_id() == flow_id
            })
            .ok_or(MatrixFailure::VerificationUnavailable)?;
        let request = active.request.clone();
        let mut sas = active.sas.clone();
        let request_state = request.state();
        let state = match request_state {
            VerificationRequestState::Ready { .. } => {
                sas = request
                    .start_sas()
                    .await
                    .map_err(|_| MatrixFailure::OperationFailed)?;
                "waiting"
            }
            VerificationRequestState::Transitioned { verification, .. } => {
                if sas.is_none() {
                    sas = verification.sas();
                }
                "waiting"
            }
            VerificationRequestState::Done => "completed",
            VerificationRequestState::Cancelled(_) => "cancelled",
            VerificationRequestState::Created { .. }
            | VerificationRequestState::Requested { .. } => "waiting",
        };

        let flow_state = sas.as_ref().map(SasVerification::state);
        let state = match flow_state {
            Some(SasState::KeysExchanged { .. }) => "sas_ready",
            Some(SasState::Confirmed) => "confirming",
            Some(SasState::Done { .. }) => "completed",
            Some(SasState::Cancelled(_)) => "cancelled",
            _ => state,
        };
        if let Some(active) = self.peer_verification.as_mut() {
            active.sas = sas.clone();
        }
        let identity_status = client
            .encryption()
            .get_user_identity(
                &UserId::parse(peer_user_id).map_err(|_| MatrixFailure::InvalidInput)?,
            )
            .await
            .map_err(|_| MatrixFailure::OperationFailed)?
            .map_or("unknown", |identity| {
                identity_trust_status(
                    true,
                    identity.is_verified(),
                    identity.was_previously_verified(),
                    identity.has_verification_violation(),
                )
            });
        let result =
            peer_verification_result(peer_user_id, flow_id, state, sas.as_ref(), identity_status);
        if matches!(state, "completed" | "cancelled") {
            self.peer_verification = None;
        }
        Ok(result)
    }

    pub async fn confirm_peer_verification(
        &mut self,
        peer_user_id: &str,
        flow_id: &str,
    ) -> Result<Value, MatrixFailure> {
        let active = self
            .peer_verification
            .as_ref()
            .filter(|active| {
                active.peer_user_id == peer_user_id && active.request.flow_id() == flow_id
            })
            .ok_or(MatrixFailure::VerificationUnavailable)?;
        let sas = active
            .sas
            .as_ref()
            .ok_or(MatrixFailure::VerificationUnavailable)?;
        if !matches!(sas.state(), SasState::KeysExchanged { .. }) || !sas.can_be_presented() {
            return Err(MatrixFailure::VerificationUnavailable);
        }
        sas.confirm()
            .await
            .map_err(|_| MatrixFailure::OperationFailed)?;
        Ok(json!({ "confirmed": true }))
    }

    pub async fn cancel_peer_verification(
        &mut self,
        peer_user_id: &str,
        flow_id: &str,
    ) -> Result<Value, MatrixFailure> {
        let active = self
            .peer_verification
            .as_ref()
            .filter(|active| {
                active.peer_user_id == peer_user_id && active.request.flow_id() == flow_id
            })
            .ok_or(MatrixFailure::VerificationUnavailable)?;
        if let Some(sas) = &active.sas {
            sas.cancel()
                .await
                .map_err(|_| MatrixFailure::OperationFailed)?;
        } else {
            active
                .request
                .cancel()
                .await
                .map_err(|_| MatrixFailure::OperationFailed)?;
        }
        self.peer_verification = None;
        Ok(json!({ "cancelled": true }))
    }
}

fn get_room(client: &Client, room_id: &str) -> Result<Room, MatrixFailure> {
    let room_id = RoomId::parse(room_id).map_err(|_| MatrixFailure::InvalidInput)?;
    client.get_room(&room_id).ok_or(MatrixFailure::InvalidInput)
}

async fn one_to_one_peer(client: &Client, room: &Room) -> Result<Option<String>, MatrixFailure> {
    let own_user_id = client
        .user_id()
        .ok_or(MatrixFailure::NotLoggedIn)?
        .to_string();
    let members = room
        .members(RoomMemberships::ACTIVE)
        .await
        .map_err(|_| MatrixFailure::OperationFailed)?;
    let member_ids = members
        .iter()
        .map(|member| member.user_id().to_string())
        .collect::<Vec<_>>();
    if !has_exactly_two_active_members(&member_ids, &own_user_id) {
        return Ok(None);
    }
    Ok(member_ids
        .into_iter()
        .find(|user_id| user_id != &own_user_id))
}

async fn has_encrypted_direct_room(
    client: &Client,
    peer_user_id: &UserId,
) -> Result<bool, MatrixFailure> {
    for room in client.joined_rooms() {
        if room.direct_targets().len() != 1
            || room
                .direct_targets()
                .iter()
                .next()
                .and_then(|target| target.as_user_id())
                != Some(peer_user_id)
            || !room.encryption_state().is_encrypted()
        {
            continue;
        }
        if one_to_one_peer(client, &room).await?.as_deref() == Some(peer_user_id.as_str()) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn peer_verification_result(
    peer_user_id: &str,
    flow_id: &str,
    state: &str,
    sas: Option<&SasVerification>,
    identity_status: &str,
) -> Value {
    let emojis = sas
        .and_then(SasVerification::emoji)
        .map(|emojis| {
            emojis
                .into_iter()
                .map(|emoji| json!({ "symbol": emoji.symbol, "description": emoji.description }))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let decimals = sas
        .and_then(SasVerification::decimals)
        .map(|(first, second, third)| vec![first, second, third])
        .unwrap_or_default();
    json!({
        "peerUserId": peer_user_id,
        "flowId": flow_id,
        "state": state,
        "emojis": emojis,
        "decimals": decimals,
        "identityStatus": identity_status,
    })
}

async fn build_client(
    homeserver: &str,
    database_path: &Path,
    store_passphrase: &str,
    tor: &VerifiedTorRoute,
) -> Result<Client, MatrixFailure> {
    let http_client = build_http_client(tor)?;

    Client::builder()
        .homeserver_url(homeserver)
        .http_client(http_client)
        .sqlite_store(database_path, Some(store_passphrase))
        .build()
        .await
        .map_err(|_| MatrixFailure::OperationFailed)
}

fn build_http_client(tor: &VerifiedTorRoute) -> Result<reqwest::Client, MatrixFailure> {
    let proxy = Url::parse(tor.socks_url()).map_err(|_| MatrixFailure::TorNotReady)?;
    if proxy.scheme() != "socks5h"
        || proxy.host_str() != Some("127.0.0.1")
        || proxy.port().is_none()
        || !proxy.username().is_empty()
        || proxy.password().is_some()
        || !(proxy.path().is_empty() || proxy.path() == "/")
    {
        return Err(MatrixFailure::TorNotReady);
    }
    let http_client = reqwest::Client::builder()
        .no_proxy()
        .proxy(Proxy::all(proxy.as_str()).map_err(|_| MatrixFailure::TorNotReady)?)
        .build()
        .map_err(|_| MatrixFailure::TorNotReady)?;
    Ok(http_client)
}

fn validate_homeserver(homeserver: &str) -> Result<(), MatrixFailure> {
    let url = Url::parse(homeserver).map_err(|_| MatrixFailure::InvalidInput)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(MatrixFailure::InvalidInput);
    }
    Ok(())
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    let mut end = value.len().min(max_bytes);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn require_encrypted_room(encrypted: bool) -> Result<(), MatrixFailure> {
    if encrypted {
        Ok(())
    } else {
        Err(MatrixFailure::EncryptionRequired)
    }
}

fn require_encrypted_direct_invite(
    is_direct: bool,
    encryption_known: bool,
    encrypted: bool,
) -> Result<(), MatrixFailure> {
    if is_direct && encryption_known && encrypted {
        Ok(())
    } else {
        Err(MatrixFailure::EncryptionRequired)
    }
}

fn has_exactly_two_active_members(member_ids: &[String], own_user_id: &str) -> bool {
    member_ids.len() == 2
        && member_ids[0] != member_ids[1]
        && member_ids.iter().any(|user_id| user_id == own_user_id)
}

fn identity_trust_status(
    identity_available: bool,
    verified: bool,
    previously_verified: bool,
    verification_violation: bool,
) -> &'static str {
    if !identity_available {
        "unknown"
    } else if verification_violation {
        "verification_violation"
    } else if verified {
        "verified"
    } else if previously_verified {
        "previously_verified"
    } else {
        "unverified"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, timeout};

    struct ProxyEnvironmentRestore(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl ProxyEnvironmentRestore {
        fn set(values: &[(&'static str, &'static str)]) -> Self {
            let previous = values
                .iter()
                .map(|(name, _)| (*name, std::env::var_os(name)))
                .collect();
            for (name, value) in values {
                // SAFETY: This test is the only network-client test in the worker
                // binary; the guard restores each variable when the test ends.
                unsafe { std::env::set_var(name, value) };
            }
            Self(previous)
        }
    }

    impl Drop for ProxyEnvironmentRestore {
        fn drop(&mut self) {
            for (name, value) in self.0.drain(..) {
                if let Some(value) = value {
                    // SAFETY: This test is the only network-client test and
                    // restores the environment values it changed.
                    unsafe { std::env::set_var(name, value) };
                } else {
                    // SAFETY: This test is the only network-client test and
                    // removes only values it inserted.
                    unsafe { std::env::remove_var(name) };
                }
            }
        }
    }

    #[tokio::test]
    async fn matrix_http_sends_remote_dns_through_socks_and_fails_closed() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();

            let mut request_header = [0; 4];
            stream.read_exact(&mut request_header).await.unwrap();
            assert_eq!(request_header, [5, 1, 0, 3]);
            let mut domain_length = [0];
            stream.read_exact(&mut domain_length).await.unwrap();
            let mut domain = vec![0; domain_length[0] as usize];
            stream.read_exact(&mut domain).await.unwrap();
            let mut port = [0; 2];
            stream.read_exact(&mut port).await.unwrap();
            assert_eq!(u16::from_be_bytes(port), 443);

            // Reject the connection. The configured client must return this
            // failure rather than attempting a direct connection.
            stream
                .write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            String::from_utf8(domain).unwrap()
        });

        let _proxy_environment = ProxyEnvironmentRestore::set(&[
            ("HTTP_PROXY", "http://192.0.2.1:9"),
            ("HTTPS_PROXY", "http://192.0.2.1:9"),
            ("ALL_PROXY", "http://192.0.2.1:9"),
            ("http_proxy", "http://192.0.2.1:9"),
            ("https_proxy", "http://192.0.2.1:9"),
            ("all_proxy", "http://192.0.2.1:9"),
            ("NO_PROXY", "*"),
            ("no_proxy", "*"),
        ]);
        let route = VerifiedTorRoute::for_test(format!("socks5h://127.0.0.1:{}", address.port()));
        let client = build_http_client(&route).unwrap();
        let request = timeout(
            Duration::from_secs(5),
            client.get("https://veil-chat-egress-check.invalid/").send(),
        )
        .await
        .expect("the proxy request should complete promptly");
        assert!(request.is_err());
        let domain = timeout(Duration::from_secs(5), proxy)
            .await
            .expect("the configured SOCKS proxy should receive the request")
            .unwrap();
        assert_eq!(domain, "veil-chat-egress-check.invalid");
    }

    #[test]
    fn direct_room_creation_requires_verified_encryption() {
        assert_eq!(require_encrypted_room(true), Ok(()));
        assert_eq!(
            require_encrypted_room(false),
            Err(MatrixFailure::EncryptionRequired)
        );
    }

    #[test]
    fn invite_acceptance_requires_direct_and_known_encryption() {
        assert_eq!(require_encrypted_direct_invite(true, true, true), Ok(()));
        assert_eq!(
            require_encrypted_direct_invite(false, true, true),
            Err(MatrixFailure::EncryptionRequired)
        );
        assert_eq!(
            require_encrypted_direct_invite(true, false, true),
            Err(MatrixFailure::EncryptionRequired)
        );
        assert_eq!(
            require_encrypted_direct_invite(true, true, false),
            Err(MatrixFailure::EncryptionRequired)
        );
    }

    #[test]
    fn direct_room_must_have_exactly_two_active_members_including_self() {
        assert!(has_exactly_two_active_members(
            &["@alice:example.org".into(), "@bob:example.org".into()],
            "@alice:example.org"
        ));
        assert!(!has_exactly_two_active_members(
            &["@alice:example.org".into()],
            "@alice:example.org"
        ));
        assert!(!has_exactly_two_active_members(
            &[
                "@alice:example.org".into(),
                "@bob:example.org".into(),
                "@mallory:example.org".into()
            ],
            "@alice:example.org"
        ));
        assert!(!has_exactly_two_active_members(
            &["@bob:example.org".into(), "@mallory:example.org".into()],
            "@alice:example.org"
        ));
        assert!(!has_exactly_two_active_members(
            &["@alice:example.org".into(), "@alice:example.org".into()],
            "@alice:example.org"
        ));
    }

    #[test]
    fn peer_identity_status_never_treats_missing_or_changed_identity_as_verified() {
        assert_eq!(identity_trust_status(false, false, false, false), "unknown");
        assert_eq!(
            identity_trust_status(true, false, false, false),
            "unverified"
        );
        assert_eq!(identity_trust_status(true, true, true, false), "verified");
        assert_eq!(
            identity_trust_status(true, false, true, false),
            "previously_verified"
        );
        assert_eq!(
            identity_trust_status(true, true, true, true),
            "verification_violation"
        );
    }
}
