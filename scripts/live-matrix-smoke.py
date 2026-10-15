#!/usr/bin/env python3
"""Opt-in live smoke test for the configured Rust worker, Tor, and Matrix SDK.

This script intentionally uses only the Python standard library. It never takes
credentials on the command line, never prints protocol payloads, and leaves the
encrypted SDK data directory in place for inspection/explicit user cleanup.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import re
import select
import secrets
import subprocess
import sys
import time
import uuid
from urllib.parse import urlsplit


PROTOCOL_VERSION = 2
MAX_FRAME_BYTES = 65_536
REQUEST_TIMEOUT_SECONDS = 240
MESSAGE_HISTORY_ATTEMPTS = 6


class SmokeFailure(Exception):
    """Failure with a safe message that contains no request or response body."""


def parse_response_frame(frame: bytes, expected_id: str, method: str) -> dict:
    if len(frame) > MAX_FRAME_BYTES:
        raise SmokeFailure(f"{method}: worker response exceeded the frame limit")
    try:
        response = json.loads(frame.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SmokeFailure(f"{method}: worker returned malformed protocol data") from None

    if not isinstance(response, dict):
        raise SmokeFailure(f"{method}: worker returned an invalid response envelope")
    if (set(response) != {"v", "kind", "id", "ok", "result", "error"} or
            response.get("v") != PROTOCOL_VERSION or response.get("kind") != "response" or
            response.get("id") != expected_id or type(response.get("ok")) is not bool):
        raise SmokeFailure(f"{method}: worker response did not match the request")
    if response["ok"] is not True:
        error = response.get("error")
        code = error.get("code") if isinstance(error, dict) else None
        if not isinstance(code, str) or re.fullmatch(r"[A-Z0-9_]{1,64}", code) is None:
            code = "UNKNOWN_WORKER_ERROR"
        raise SmokeFailure(f"{method}: worker returned {code}")
    result = response.get("result")
    if not isinstance(result, dict) or response.get("error") is not None:
        raise SmokeFailure(f"{method}: worker returned an invalid success response")

    # Login returns a session token as part of its protocol result. The smoke
    # test does not persist or use it; discard it as soon as the result is read.
    result.pop("session", None)
    return result


def is_encrypted_direct_invite(invite: object) -> bool:
    return (
        isinstance(invite, dict)
        and set(invite) == {"roomId", "isDirect", "encrypted", "encryptionKnown"}
        and isinstance(invite.get("roomId"), str)
        and invite.get("isDirect") is True
        and invite.get("encrypted") is True
        and invite.get("encryptionKnown") is True
    )


class Worker:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process
        self.output = bytearray()

    def request(self, method: str, payload: dict) -> dict:
        if self.process.poll() is not None:
            raise SmokeFailure(f"{method}: worker exited before the request")

        request_id = str(uuid.uuid4())
        request = {
            "v": PROTOCOL_VERSION,
            "kind": "request",
            "id": request_id,
            "method": method,
            "payload": payload,
        }
        encoded = (json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) - 1 > MAX_FRAME_BYTES:
            raise SmokeFailure(f"{method}: request exceeded the frame limit")

        try:
            assert self.process.stdin is not None
            self.process.stdin.write(encoded)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError):
            raise SmokeFailure(f"{method}: worker input pipe closed") from None

        deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
        while True:
            newline = self.output.find(b"\n")
            if newline >= 0:
                frame = bytes(self.output[:newline])
                del self.output[:newline + 1]
                if frame.endswith(b"\r"):
                    frame = frame[:-1]
                return parse_response_frame(frame, request_id, method)

            if len(self.output) > MAX_FRAME_BYTES:
                raise SmokeFailure(f"{method}: worker response exceeded the frame limit")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SmokeFailure(f"{method}: worker response timed out")
            assert self.process.stdout is not None
            ready, _, _ = select.select([self.process.stdout], [], [], remaining)
            if not ready:
                raise SmokeFailure(f"{method}: worker response timed out")
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                raise SmokeFailure(f"{method}: worker closed its output pipe")
            self.output.extend(chunk)

    def close(self) -> None:
        if self.process.poll() is None:
            if self.process.stdin is not None:
                try:
                    self.process.stdin.close()
                except OSError:
                    pass
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                # Closing worker stdin normally shuts down its owned Tor process.
                # Force-killing the worker closes the SAFECOOKIE control socket too.
                self.process.kill()
                self.process.wait(timeout=5)
        for stream in (self.process.stdin, self.process.stdout):
            if stream is not None:
                stream.close()


def validate_args(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    worker = Path(args.worker)
    tor = Path(args.tor)
    data_directory = Path(args.data_dir)
    for label, path in (("worker", worker), ("Tor", tor)):
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise SmokeFailure(f"{label} path must be an absolute executable file")
    if not data_directory.is_absolute():
        raise SmokeFailure("data directory must be an absolute path")
    if data_directory.exists():
        raise SmokeFailure("data directory must not already exist; choose a fresh dedicated path")
    if not data_directory.parent.is_dir():
        raise SmokeFailure("data directory parent must already exist")

    parsed = urlsplit(args.homeserver)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or
            parsed.password is not None or parsed.fragment):
        raise SmokeFailure("homeserver must be an HTTPS URL without embedded credentials or a fragment")
    if not args.recipient.startswith("@") or ":" not in args.recipient:
        raise SmokeFailure("recipient must be a full Matrix user ID such as @user:example.org")
    return worker, tor, data_directory


def start_worker(worker_path: Path, tor_path: Path, data_directory: Path) -> Worker:
    try:
        data_directory.mkdir(mode=0o700)
        os.chmod(data_directory, 0o700)
    except OSError:
        raise SmokeFailure("fresh private data directory could not be created") from None

    child_environment = {}
    for name in ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"):
        value = os.environ.get(name)
        if value:
            child_environment[name] = value
    child_environment["VEIL_CHAT_TOR_EXECUTABLE"] = str(tor_path)
    child_environment["VEIL_CHAT_DATA_DIRECTORY"] = str(data_directory)
    try:
        process = subprocess.Popen(
            [str(worker_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=child_environment,
            close_fds=True,
        )
    except OSError:
        raise SmokeFailure("configured Rust worker could not be started") from None
    return Worker(process)


def run(args: argparse.Namespace) -> None:
    worker_path, tor_path, data_root = validate_args(args)
    sender_username = args.sender_username or input("Sender Matrix username or localpart: ").strip()
    recipient_username = args.recipient_username or input("Recipient Matrix username or localpart: ").strip()
    sender_password = getpass.getpass("Sender Matrix password (not saved or displayed): ")
    recipient_password = getpass.getpass("Recipient Matrix password (not saved or displayed): ")
    if not sender_username or not recipient_username or not sender_password or not recipient_password:
        raise SmokeFailure("both account usernames and passwords are required")

    sender = None
    recipient = None
    try:
        data_root.mkdir(mode=0o700)
        os.chmod(data_root, 0o700)
        sender = start_worker(worker_path, tor_path, data_root / "sender")
        recipient = start_worker(worker_path, tor_path, data_root / "recipient")

        for label, worker in (("sender", sender), ("recipient", recipient)):
            hello = worker.request("worker.hello", {})
            if hello.get("protocolVersion") != PROTOCOL_VERSION:
                raise SmokeFailure(f"{label}: worker hello returned an unexpected protocol version")

        sender_login = sender.request("matrix.login", {
            "homeserver": args.homeserver,
            "username": sender_username,
            "password": sender_password,
            "storePassphrase": secrets.token_hex(32),
            "storeId": str(uuid.uuid4()),
        })
        sender_password = ""
        recipient_login = recipient.request("matrix.login", {
            "homeserver": args.homeserver,
            "username": recipient_username,
            "password": recipient_password,
            "storePassphrase": secrets.token_hex(32),
            "storeId": str(uuid.uuid4()),
        })
        recipient_password = ""
        for label, login in (("sender", sender_login), ("recipient", recipient_login)):
            if not isinstance(login.get("userId"), str) or login.get("e2eeAvailable") is not True:
                raise SmokeFailure(f"{label}: SDK did not confirm an authenticated E2EE-capable session")
        if recipient_login["userId"] != args.recipient:
            raise SmokeFailure("recipient login did not match the Matrix user ID supplied for the invite")
        if sender_login["userId"] == recipient_login["userId"]:
            raise SmokeFailure("sender and recipient must be separate Matrix accounts")

        for label, worker in (("sender", sender), ("recipient", recipient)):
            tor_status = worker.request("tor.status", {})
            if tor_status.get("state") != "bootstrap_verified" or tor_status.get("networkOperationsAllowed") is not True:
                raise SmokeFailure(f"{label}: Tor did not report verified bootstrap and an allowed network route")

        created = sender.request("room.create_dm", {"userId": args.recipient})
        room_id = created.get("roomId")
        if not isinstance(room_id, str) or created.get("encrypted") is not True:
            raise SmokeFailure("SDK did not confirm an encrypted direct room")

        recipient.request("rooms.list", {})
        invitations = recipient.request("invites.list", {}).get("invites")
        if not isinstance(invitations, list):
            raise SmokeFailure("recipient SDK did not return an invitation list")
        invite = next((item for item in invitations if isinstance(item, dict) and item.get("roomId") == room_id), None)
        if not is_encrypted_direct_invite(invite):
            raise SmokeFailure("recipient SDK did not report the invite as a known encrypted direct room")
        accepted = recipient.request("room.accept_invite", {"roomId": room_id})
        if accepted.get("encrypted") is not True or accepted.get("encryptionKnown") is not True:
            raise SmokeFailure("recipient SDK did not confirm encryption after joining the direct room")

        marker = f"VeilChat live smoke {uuid.uuid4()}"
        sent = sender.request("room.send_text", {"roomId": room_id, "body": marker})
        if sent.get("sent") is not True or sent.get("encrypted") is not True:
            raise SmokeFailure("sender SDK did not confirm encrypted text send")

        received_by_sender = False
        received_by_recipient = False
        for attempt in range(MESSAGE_HISTORY_ATTEMPTS):
            for label, worker in (("sender", sender), ("recipient", recipient)):
                rooms = worker.request("rooms.list", {})
                if not isinstance(rooms.get("rooms"), list):
                    raise SmokeFailure(f"{label}: SDK room synchronization returned an invalid room list")
            for label, worker in (("sender", sender), ("recipient", recipient)):
                history = worker.request("room.messages", {"roomId": room_id})
                if history.get("encrypted") is not True or not isinstance(history.get("events"), list):
                    raise SmokeFailure(f"{label}: SDK did not confirm encrypted room history")
                found = any(
                    isinstance(event, dict) and event.get("body") == marker
                    for event in history["events"]
                )
                if label == "sender":
                    received_by_sender = found
                else:
                    received_by_recipient = found
            if received_by_sender and received_by_recipient:
                break
            if attempt + 1 < MESSAGE_HISTORY_ATTEMPTS:
                time.sleep(2)

        if not received_by_sender:
            raise SmokeFailure("sent message was not visible in sender encrypted SDK history before the deadline")
        if not received_by_recipient:
            raise SmokeFailure("recipient did not decrypt the sent marker in encrypted SDK history before the deadline")

        print("PASS: two-account login, supervised Tor bootstrap, encrypted direct invite and acceptance, encrypted send, and recipient SDK decryption.")
        print(f"Sender: {sender_login['userId']}; recipient: {recipient_login['userId']}")
        print(f"Room: {room_id}")
        print(f"Recipient-decrypted message marker: {marker}")
        print(f"Encrypted SDK data remains in: {data_root}")
        print("A successful run does not independently prove Tor egress or peer identity verification.")
    finally:
        sender_password = ""
        recipient_password = ""
        if recipient is not None:
            recipient.close()
        if sender is not None:
            sender.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", required=True, help="absolute path to the trusted Rust worker executable")
    parser.add_argument("--tor", required=True, help="absolute path to the trusted Tor executable")
    parser.add_argument("--data-dir", required=True, help="fresh absolute parent directory for both accounts' private smoke-test data")
    parser.add_argument("--homeserver", required=True, help="HTTPS Matrix homeserver URL")
    parser.add_argument("--recipient", required=True, help="full Matrix user ID of a second controlled account")
    parser.add_argument("--sender-username", help="sender username/localpart; password is always prompted interactively")
    parser.add_argument("--recipient-username", help="recipient username/localpart; password is always prompted interactively")
    args = parser.parse_args()
    try:
        run(args)
    except (SmokeFailure, KeyboardInterrupt) as error:
        if isinstance(error, KeyboardInterrupt):
            print("STOPPED: interrupted; worker cleanup was requested.", file=sys.stderr)
        else:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
