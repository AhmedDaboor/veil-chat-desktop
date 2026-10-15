use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep, timeout};

const MAX_CONTROL_LINE: usize = 8192;
const CONTROL_REPLY_TIMEOUT: Duration = Duration::from_secs(3);
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TorFailure {
    NotConfigured,
    StartupFailed,
    NotReady,
}

/// Owns an explicitly configured Tor process and exposes its verified loopback
/// SOCKS endpoint only after SAFECOOKIE control authentication and bootstrap.
pub struct TorSupervisor {
    child: Child,
    control_port: u16,
    socks_port: u16,
    socks_url: String,
    control_stream: Option<TcpStream>,
}

/// Capability token that can only be created from a bootstrapped Tor process.
/// Matrix SDK clients accept this type rather than arbitrary proxy strings.
pub struct VerifiedTorRoute {
    socks_url: String,
}

impl VerifiedTorRoute {
    pub(crate) fn socks_url(&self) -> &str {
        &self.socks_url
    }

    #[cfg(test)]
    pub(crate) fn for_test(socks_url: String) -> Self {
        Self { socks_url }
    }
}

impl TorSupervisor {
    pub async fn start_from_environment() -> Result<Self, TorFailure> {
        let executable = std::env::var_os("VEIL_CHAT_TOR_EXECUTABLE")
            .map(PathBuf::from)
            .ok_or(TorFailure::NotConfigured)?;
        let data_directory = std::env::var_os("VEIL_CHAT_DATA_DIRECTORY")
            .map(PathBuf::from)
            .ok_or(TorFailure::NotConfigured)?;
        Self::start(executable, data_directory).await
    }

    async fn start(executable: PathBuf, data_directory: PathBuf) -> Result<Self, TorFailure> {
        if !executable.is_absolute() || !executable.is_file() || !data_directory.is_absolute() {
            return Err(TorFailure::NotConfigured);
        }

        std::fs::create_dir_all(&data_directory).map_err(|_| TorFailure::StartupFailed)?;
        set_private_directory_permissions(&data_directory)?;

        // A port collision makes startup fail closed; Tor is never pointed at
        // an arbitrary listener as a SOCKS proxy.
        let socks_port = reserve_loopback_port().await?;
        let control_port = reserve_loopback_port().await?;
        let cookie_path = data_directory.join("control_auth_cookie");
        let torrc_path = data_directory.join("veil-chat-empty-torrc");
        tokio::fs::write(&torrc_path, b"")
            .await
            .map_err(|_| TorFailure::StartupFailed)?;
        let mut command = build_tor_command(
            &executable,
            &data_directory,
            &cookie_path,
            &torrc_path,
            control_port,
            socks_port,
        );

        let mut child = command.spawn().map_err(|_| TorFailure::StartupFailed)?;
        if let Some(mut stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut discard = tokio::io::sink();
                let _ = tokio::io::copy(&mut stderr, &mut discard).await;
            });
        }

        let mut supervisor = Self {
            child,
            control_port,
            socks_port,
            socks_url: format!("socks5h://127.0.0.1:{socks_port}"),
            control_stream: None,
        };
        if let Err(error) = supervisor
            .connect_control_and_take_ownership(&cookie_path)
            .await
        {
            supervisor.stop().await;
            return Err(error);
        }
        if let Err(error) = supervisor.wait_until_bootstrapped().await {
            supervisor.stop().await;
            return Err(error);
        }
        Ok(supervisor)
    }

    pub(crate) fn verified_route(&self) -> VerifiedTorRoute {
        VerifiedTorRoute {
            socks_url: self.socks_url.clone(),
        }
    }

    /// Recheck both the owned process and Tor's current control-port bootstrap
    /// state before each Matrix operation. A failed check prevents the request.
    pub async fn ensure_ready(&mut self) -> Result<(), TorFailure> {
        if self
            .child
            .try_wait()
            .map_err(|_| TorFailure::NotReady)?
            .is_some()
        {
            return Err(TorFailure::NotReady);
        }
        let progress = self.bootstrap_progress().await?;
        if progress == 100 {
            Ok(())
        } else {
            Err(TorFailure::NotReady)
        }
    }

    async fn connect_control_and_take_ownership(
        &mut self,
        cookie_path: &Path,
    ) -> Result<(), TorFailure> {
        let deadline = Instant::now() + BOOTSTRAP_TIMEOUT;
        loop {
            if self
                .child
                .try_wait()
                .map_err(|_| TorFailure::StartupFailed)?
                .is_some()
            {
                return Err(TorFailure::StartupFailed);
            }
            if let Ok(Ok(mut stream)) = timeout(
                CONTROL_REPLY_TIMEOUT,
                TcpStream::connect(("127.0.0.1", self.control_port)),
            )
            .await
            {
                let handshake = timeout(CONTROL_REPLY_TIMEOUT, async {
                    authenticate_safecookie(&mut stream, cookie_path).await?;
                    command(&mut stream, "TAKEOWNERSHIP\r\n").await?;
                    Ok::<(), TorFailure>(())
                })
                .await;
                if matches!(handshake, Ok(Ok(()))) {
                    self.control_stream = Some(stream);
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(TorFailure::StartupFailed);
            }
            sleep(Duration::from_millis(250)).await;
        }
    }

    async fn wait_until_bootstrapped(&mut self) -> Result<(), TorFailure> {
        let deadline = Instant::now() + BOOTSTRAP_TIMEOUT;
        loop {
            if self
                .child
                .try_wait()
                .map_err(|_| TorFailure::StartupFailed)?
                .is_some()
            {
                return Err(TorFailure::StartupFailed);
            }
            if let Ok(100) = self.bootstrap_progress().await {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(TorFailure::StartupFailed);
            }
            sleep(Duration::from_millis(500)).await;
        }
    }

    async fn bootstrap_progress(&mut self) -> Result<u8, TorFailure> {
        timeout(CONTROL_REPLY_TIMEOUT, async {
            let stream = self.control_stream.as_mut().ok_or(TorFailure::NotReady)?;
            let response = command(stream, "GETINFO status/bootstrap-phase\r\n").await?;
            let value = response
                .iter()
                .find_map(|line| line.strip_prefix("250-status/bootstrap-phase="))
                .ok_or(TorFailure::NotReady)?;
            let progress = parse_bootstrap_progress(value).ok_or(TorFailure::NotReady)?;
            let listeners = command(stream, "GETINFO net/listeners/socks\r\n").await?;
            let listener_value = listeners
                .iter()
                .find_map(|line| line.strip_prefix("250-net/listeners/socks="))
                .ok_or(TorFailure::NotReady)?;
            if !contains_listener(listener_value, &format!("127.0.0.1:{}", self.socks_port)) {
                return Err(TorFailure::NotReady);
            }
            Ok(progress)
        })
        .await
        .map_err(|_| TorFailure::NotReady)?
    }

    pub async fn stop(&mut self) {
        // Tor's TAKEOWNERSHIP contract shuts it down when this authenticated
        // control connection closes, including when the worker exits normally.
        self.control_stream.take();
        let _ = timeout(Duration::from_secs(2), self.child.wait()).await;
        let _ = self.child.start_kill();
        let _ = timeout(Duration::from_secs(2), self.child.wait()).await;
    }
}

impl Drop for TorSupervisor {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

fn build_tor_command(
    executable: &Path,
    data_directory: &Path,
    cookie_path: &Path,
    torrc_path: &Path,
    control_port: u16,
    socks_port: u16,
) -> Command {
    let mut command = Command::new(executable);
    command
        .arg("--defaults-torrc")
        .arg(torrc_path)
        .arg("--torrc-file")
        .arg(torrc_path)
        .arg("--RunAsDaemon")
        .arg("0")
        .arg("--DataDirectory")
        .arg(data_directory)
        .arg("--SocksPort")
        .arg(format!("127.0.0.1:{socks_port}"))
        .arg("--ControlPort")
        .arg(format!("127.0.0.1:{control_port}"))
        .arg("--CookieAuthentication")
        .arg("1")
        .arg("--CookieAuthFile")
        .arg(cookie_path)
        .arg("--CookieAuthFileGroupReadable")
        .arg("0")
        .arg("--Log")
        .arg("notice stderr")
        .env_clear()
        .env("HOME", data_directory)
        .env("APPDATA", data_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    if cfg!(windows) {
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
    }
    command
}

async fn reserve_loopback_port() -> Result<u16, TorFailure> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|_| TorFailure::StartupFailed)?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|_| TorFailure::StartupFailed)
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), TorFailure> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| TorFailure::StartupFailed)
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), TorFailure> {
    Ok(())
}

async fn authenticate_safecookie(
    stream: &mut TcpStream,
    cookie_path: &Path,
) -> Result<(), TorFailure> {
    let info = command(stream, "PROTOCOLINFO 1\r\n").await?;
    let methods = info
        .iter()
        .find_map(|line| line.strip_prefix("250-AUTH METHODS="))
        .ok_or(TorFailure::NotReady)?;
    if !methods
        .split([',', ' '])
        .any(|method| method == "SAFECOOKIE")
    {
        return Err(TorFailure::NotReady);
    }

    let cookie = tokio::fs::read(cookie_path)
        .await
        .map_err(|_| TorFailure::NotReady)?;
    if cookie.len() != 32 {
        return Err(TorFailure::NotReady);
    }

    let mut client_nonce = [0_u8; 32];
    getrandom::fill(&mut client_nonce).map_err(|_| TorFailure::NotReady)?;
    let challenge = format!("AUTHCHALLENGE SAFECOOKIE {}\r\n", hex(&client_nonce));
    let challenge_reply = command(stream, &challenge).await?;
    let challenge_line = challenge_reply
        .iter()
        .find(|line| line.starts_with("250 AUTHCHALLENGE "))
        .ok_or(TorFailure::NotReady)?;
    let server_hash = response_hex(challenge_line, "SERVERHASH=").ok_or(TorFailure::NotReady)?;
    let server_nonce = response_hex(challenge_line, "SERVERNONCE=").ok_or(TorFailure::NotReady)?;
    if server_hash.len() != 32 || server_nonce.len() != 32 {
        return Err(TorFailure::NotReady);
    }

    let mut server_mac =
        HmacSha256::new_from_slice(b"Tor safe cookie authentication server-to-controller hash")
            .map_err(|_| TorFailure::NotReady)?;
    server_mac.update(&cookie);
    server_mac.update(&client_nonce);
    server_mac.update(&server_nonce);
    server_mac
        .verify_slice(&server_hash)
        .map_err(|_| TorFailure::NotReady)?;

    let mut client_mac =
        HmacSha256::new_from_slice(b"Tor safe cookie authentication controller-to-server hash")
            .map_err(|_| TorFailure::NotReady)?;
    client_mac.update(&cookie);
    client_mac.update(&client_nonce);
    client_mac.update(&server_nonce);
    let authenticate = format!(
        "AUTHENTICATE {}\r\n",
        hex(&client_mac.finalize().into_bytes())
    );
    command(stream, &authenticate).await?;
    Ok(())
}

async fn command(stream: &mut TcpStream, request: &str) -> Result<Vec<String>, TorFailure> {
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| TorFailure::NotReady)?;
    stream.flush().await.map_err(|_| TorFailure::NotReady)?;

    let mut lines = Vec::new();
    let mut total = 0;
    loop {
        let mut bytes = Vec::with_capacity(128);
        read_bounded_line(stream, &mut bytes).await?;
        total += bytes.len();
        if total > 32 * 1024 {
            return Err(TorFailure::NotReady);
        }
        let line = std::str::from_utf8(&bytes).map_err(|_| TorFailure::NotReady)?;
        let line = line.trim_end_matches(['\r', '\n']);
        if !line.starts_with("250") {
            return Err(TorFailure::NotReady);
        }
        let done = line.starts_with("250 ");
        lines.push(line.to_owned());
        if done {
            return Ok(lines);
        }
    }
}

async fn read_bounded_line<R: AsyncRead + Unpin>(
    reader: &mut R,
    bytes: &mut Vec<u8>,
) -> Result<(), TorFailure> {
    loop {
        let mut byte = [0_u8; 1];
        let read = reader
            .read(&mut byte)
            .await
            .map_err(|_| TorFailure::NotReady)?;
        if read == 0 || bytes.len() >= MAX_CONTROL_LINE {
            return Err(TorFailure::NotReady);
        }
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(());
        }
    }
}

fn response_hex(line: &str, key: &str) -> Option<Vec<u8>> {
    let value = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix(key))?;
    decode_hex(value)
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Some((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn parse_bootstrap_progress(value: &str) -> Option<u8> {
    let progress = value
        .split_whitespace()
        .find_map(|part| part.strip_prefix("PROGRESS="))?;
    let progress = progress.parse::<u8>().ok()?;
    (progress <= 100).then_some(progress)
}

fn contains_listener(listeners: &str, expected: &str) -> bool {
    listeners
        .split_ascii_whitespace()
        .map(|listener| listener.trim_matches('"'))
        .any(|listener| listener == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_valid_bootstrap_percentages() {
        assert_eq!(
            parse_bootstrap_progress("NOTICE BOOTSTRAP PROGRESS=100 TAG=done"),
            Some(100)
        );
        assert_eq!(
            parse_bootstrap_progress("NOTICE BOOTSTRAP PROGRESS=54 TAG=conn"),
            Some(54)
        );
        assert_eq!(
            parse_bootstrap_progress("WARN BOOTSTRAP PROGRESS=110"),
            None
        );
        assert_eq!(parse_bootstrap_progress("NOTICE BOOTSTRAP TAG=done"), None);
    }

    #[test]
    fn decodes_control_hex_without_accepting_invalid_input() {
        assert_eq!(decode_hex("0aFF"), Some(vec![10, 255]));
        assert_eq!(decode_hex("0"), None);
        assert_eq!(decode_hex("gg"), None);
    }

    #[test]
    fn formats_hex_as_lowercase() {
        assert_eq!(hex(&[0x00, 0x7f, 0xff]), "007fff");
    }

    #[test]
    fn safe_cookie_hmac_uses_the_specified_label_as_the_key() {
        let cookie = (0_u8..32).collect::<Vec<_>>();
        let client_nonce = (32_u8..64).collect::<Vec<_>>();
        let server_nonce = (64_u8..96).collect::<Vec<_>>();
        let mut mac =
            HmacSha256::new_from_slice(b"Tor safe cookie authentication server-to-controller hash")
                .unwrap();
        mac.update(&cookie);
        mac.update(&client_nonce);
        mac.update(&server_nonce);
        assert_eq!(
            hex(&mac.finalize().into_bytes()),
            "3c8780ab52365c0d080750447e5f64dabc00428c6c434579c2043e18c1f85389"
        );
    }

    #[test]
    fn accepts_only_the_supervised_loopback_socks_listener() {
        assert!(contains_listener("\"127.0.0.1:9150\"", "127.0.0.1:9150"));
        assert!(!contains_listener("\"127.0.0.1:9151\"", "127.0.0.1:9150"));
        assert!(!contains_listener("\"0.0.0.0:9150\"", "127.0.0.1:9150"));
        assert!(!contains_listener("", "127.0.0.1:9150"));
    }

    #[tokio::test]
    async fn safe_cookie_authentication_completes_against_a_control_protocol_peer() {
        let cookie = (0_u8..32).collect::<Vec<_>>();
        let cookie_path =
            std::env::temp_dir().join(format!("veil-chat-safe-cookie-{}.bin", std::process::id()));
        tokio::fs::write(&cookie_path, &cookie).await.unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(read_test_line(&mut stream).await, "PROTOCOLINFO 1\r\n");
            stream
                .write_all(b"250-PROTOCOLINFO 1\r\n250-AUTH METHODS=SAFECOOKIE\r\n250 OK\r\n")
                .await
                .unwrap();

            let challenge = read_test_line(&mut stream).await;
            let parts = challenge.split_whitespace().collect::<Vec<_>>();
            assert_eq!(&parts[..2], &["AUTHCHALLENGE", "SAFECOOKIE"]);
            let client_nonce = decode_hex(parts[2]).unwrap();
            assert_eq!(client_nonce.len(), 32);
            let server_nonce = [0x5a; 32];

            let mut server_mac = HmacSha256::new_from_slice(
                b"Tor safe cookie authentication server-to-controller hash",
            )
            .unwrap();
            server_mac.update(&cookie);
            server_mac.update(&client_nonce);
            server_mac.update(&server_nonce);
            let reply = format!(
                "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                hex(&server_mac.finalize().into_bytes()),
                hex(&server_nonce)
            );
            stream.write_all(reply.as_bytes()).await.unwrap();

            let authenticate = read_test_line(&mut stream).await;
            let mut client_mac = HmacSha256::new_from_slice(
                b"Tor safe cookie authentication controller-to-server hash",
            )
            .unwrap();
            client_mac.update(&cookie);
            client_mac.update(&client_nonce);
            client_mac.update(&server_nonce);
            let expected = format!(
                "AUTHENTICATE {}\r\n",
                hex(&client_mac.finalize().into_bytes())
            );
            assert_eq!(authenticate, expected);
            stream.write_all(b"250 OK\r\n").await.unwrap();
        });

        let mut control = TcpStream::connect(address).await.unwrap();
        authenticate_safecookie(&mut control, &cookie_path)
            .await
            .unwrap();
        server.await.unwrap();
        tokio::fs::remove_file(cookie_path).await.unwrap();
    }

    #[tokio::test]
    async fn relative_tor_executable_is_rejected_without_spawning_a_process() {
        let result = TorSupervisor::start(PathBuf::from("tor"), std::env::temp_dir()).await;
        assert!(matches!(result, Err(TorFailure::NotConfigured)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn supervisor_starts_verifies_and_stops_an_owned_control_peer() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let executable = directory.0.join("fake-tor");
        let test_executable = std::env::current_exe().unwrap();
        let script = format!(
            "#!/bin/sh\n\
            control=\n\
            socks=\n\
            cookie=\n\
            while [ \"$#\" -gt 0 ]; do\n\
              case \"$1\" in\n\
                --ControlPort) control=\"${{2##*:}}\"; shift 2 ;;\n\
                --SocksPort) socks=\"${{2##*:}}\"; shift 2 ;;\n\
                --CookieAuthFile) cookie=\"$2\"; shift 2 ;;\n\
                *) shift ;;\n\
              esac\n\
            done\n\
            VEIL_CHAT_FAKE_CONTROL_PORT=\"$control\" \\\n\
            VEIL_CHAT_FAKE_SOCKS_PORT=\"$socks\" \\\n\
            VEIL_CHAT_FAKE_COOKIE_PATH=\"$cookie\" \\\n\
            exec {} --exact tor::tests::fake_tor_child --nocapture\n",
            shell_quote(&test_executable.to_string_lossy())
        );
        std::fs::write(&executable, script).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();

        let mut supervisor = timeout(
            Duration::from_secs(15),
            TorSupervisor::start(executable, directory.0.clone()),
        )
        .await
        .expect("fake Tor should start within the test deadline")
        .expect("supervisor should authenticate and bootstrap the fake Tor process");

        timeout(Duration::from_secs(5), supervisor.ensure_ready())
            .await
            .expect("readiness should be bounded")
            .expect("supervised Tor should report bootstrap and its SOCKS listener");
        supervisor.stop().await;
        assert!(supervisor.child.try_wait().unwrap().is_some());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fake_tor_child() {
        let (Some(control_port), Some(socks_port), Some(cookie_path)) = (
            std::env::var("VEIL_CHAT_FAKE_CONTROL_PORT").ok(),
            std::env::var("VEIL_CHAT_FAKE_SOCKS_PORT").ok(),
            std::env::var("VEIL_CHAT_FAKE_COOKIE_PATH").ok(),
        ) else {
            return;
        };
        let control_port = control_port.parse::<u16>().unwrap();
        let socks_port = socks_port.parse::<u16>().unwrap();
        let cookie_path = PathBuf::from(cookie_path);
        let cookie = (0_u8..32).collect::<Vec<_>>();
        tokio::fs::write(&cookie_path, &cookie).await.unwrap();

        let listener = TcpListener::bind(("127.0.0.1", control_port))
            .await
            .unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut client_nonce = None;
        loop {
            let mut bytes = Vec::new();
            if read_bounded_line(&mut stream, &mut bytes).await.is_err() {
                break;
            }
            let request = String::from_utf8(bytes).unwrap();
            let parts = request.split_whitespace().collect::<Vec<_>>();
            let response = match parts.first().copied() {
                Some("PROTOCOLINFO") => {
                    b"250-PROTOCOLINFO 1\r\n250-AUTH METHODS=SAFECOOKIE\r\n250 OK\r\n".to_vec()
                }
                Some("AUTHCHALLENGE") => {
                    let nonce = decode_hex(parts[2]).unwrap();
                    client_nonce = Some(nonce.clone());
                    let server_nonce = [0xa5; 32];
                    let mut server_mac = HmacSha256::new_from_slice(
                        b"Tor safe cookie authentication server-to-controller hash",
                    )
                    .unwrap();
                    server_mac.update(&cookie);
                    server_mac.update(&nonce);
                    server_mac.update(&server_nonce);
                    format!(
                        "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                        hex(&server_mac.finalize().into_bytes()),
                        hex(&server_nonce)
                    )
                    .into_bytes()
                }
                Some("AUTHENTICATE") => {
                    let provided_mac = decode_hex(parts[1]).unwrap();
                    let Some(client_nonce) = client_nonce.as_deref() else {
                        stream.write_all(b"515 Authentication failed\r\n").await.unwrap();
                        continue;
                    };
                    let mut client_mac = HmacSha256::new_from_slice(
                        b"Tor safe cookie authentication controller-to-server hash",
                    )
                    .unwrap();
                    client_mac.update(&cookie);
                    client_mac.update(client_nonce);
                    client_mac.update(&[0xa5; 32]);
                    if client_mac.verify_slice(&provided_mac).is_ok() {
                        b"250 OK\r\n".to_vec()
                    } else {
                        b"515 Authentication failed\r\n".to_vec()
                    }
                }
                Some("TAKEOWNERSHIP") => b"250 OK\r\n".to_vec(),
                Some("GETINFO") if request.contains("status/bootstrap-phase") => {
                    b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250 OK\r\n"
                        .to_vec()
                }
                Some("GETINFO") if request.contains("net/listeners/socks") => format!(
                    "250-net/listeners/socks=\"127.0.0.1:{socks_port}\"\r\n250 OK\r\n"
                )
                .into_bytes(),
                _ => b"510 Unrecognized command\r\n".to_vec(),
            };
            stream.write_all(&response).await.unwrap();
        }
    }

    #[cfg(unix)]
    struct TestDirectory(PathBuf);

    #[cfg(unix)]
    impl TestDirectory {
        fn new() -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "veil-chat-tor-supervisor-{}-{suffix}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    #[cfg(unix)]
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    #[test]
    fn tor_command_uses_isolated_config_and_loopback_ports() {
        let torrc = Path::new("/private/veil-chat-empty-torrc");
        let command = build_tor_command(
            Path::new("/trusted/tor"),
            Path::new("/private/data"),
            Path::new("/private/data/control_auth_cookie"),
            torrc,
            9051,
            9050,
        );
        let arguments = command
            .as_std()
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(arguments[0], "--defaults-torrc");
        assert_eq!(arguments[1], torrc.to_string_lossy());
        assert_eq!(arguments[2], "--torrc-file");
        assert_eq!(arguments[3], torrc.to_string_lossy());
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--SocksPort", "127.0.0.1:9050"])
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--ControlPort", "127.0.0.1:9051"])
        );
    }

    async fn read_test_line(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        read_bounded_line(stream, &mut bytes).await.unwrap();
        String::from_utf8(bytes).unwrap()
    }
}
