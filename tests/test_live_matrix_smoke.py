import importlib.util
import json
from pathlib import Path
import unittest
import uuid


SCRIPT = Path(__file__).parents[1] / "scripts" / "live-matrix-smoke.py"
SPEC = importlib.util.spec_from_file_location("live_matrix_smoke", SCRIPT)
smoke = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(smoke)


class ResponseFrameTests(unittest.TestCase):
    def setUp(self):
        self.request_id = str(uuid.uuid4())

    def frame(self, **overrides):
        response = {
            "v": 2,
            "kind": "response",
            "id": self.request_id,
            "ok": True,
            "result": {"protocolVersion": 2},
            "error": None,
        }
        response.update(overrides)
        return json.dumps(response).encode("utf-8")

    def test_accepts_correlated_success_envelope(self):
        result = smoke.parse_response_frame(self.frame(), self.request_id, "worker.hello")
        self.assertEqual({"protocolVersion": 2}, result)

    def test_rejects_wrong_request_id(self):
        with self.assertRaisesRegex(smoke.SmokeFailure, "did not match"):
            smoke.parse_response_frame(self.frame(id=str(uuid.uuid4())), self.request_id, "worker.hello")

    def test_rejects_invalid_utf8_and_oversized_response(self):
        with self.assertRaisesRegex(smoke.SmokeFailure, "malformed"):
            smoke.parse_response_frame(b"\xff", self.request_id, "worker.hello")
        with self.assertRaisesRegex(smoke.SmokeFailure, "frame limit"):
            smoke.parse_response_frame(b" " * (smoke.MAX_FRAME_BYTES + 1), self.request_id, "worker.hello")

    def test_remote_error_displays_only_a_safe_code(self):
        response = {
            "v": 2,
            "kind": "response",
            "id": self.request_id,
            "ok": False,
            "result": None,
            "error": {"code": "TOR_NOT_CONFIGURED", "message": "password must never appear"},
        }
        with self.assertRaises(smoke.SmokeFailure) as raised:
            smoke.parse_response_frame(
                json.dumps(response).encode(), self.request_id, "matrix.login"
            )
        self.assertEqual("matrix.login: worker returned TOR_NOT_CONFIGURED", str(raised.exception))
        self.assertNotIn("password", str(raised.exception))

    def test_login_session_is_discarded_from_result(self):
        result = {"userId": "@alice:example.org", "session": {"access_token": "secret"}}
        frame = self.frame(result=result)
        parsed = smoke.parse_response_frame(frame, self.request_id, "matrix.login")
        self.assertEqual({"userId": "@alice:example.org"}, parsed)


class EncryptedInviteTests(unittest.TestCase):
    def test_requires_exact_known_encrypted_direct_invite(self):
        invite = {
            "roomId": "!room:example.org",
            "isDirect": True,
            "encrypted": True,
            "encryptionKnown": True,
        }
        self.assertTrue(smoke.is_encrypted_direct_invite(invite))
        for key, value in (("isDirect", False), ("encrypted", False), ("encryptionKnown", False)):
            rejected = dict(invite, **{key: value})
            self.assertFalse(smoke.is_encrypted_direct_invite(rejected))
        self.assertFalse(smoke.is_encrypted_direct_invite(dict(invite, extra="ignored")))
        self.assertFalse(smoke.is_encrypted_direct_invite(None))


if __name__ == "__main__":
    unittest.main()
