import json
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from keyloom_errors import KeyloomError
from keyloom_ipc import IPCBroker, IPCClient, _seal
from vault_device_keys import MemorySecretKeyStore


class IPCBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        self.store = MemorySecretKeyStore()
        self.requests = []
        def receive(request):
            self.requests.append(request)
            return {"ok": True, "data": {"accepted": True}}
        self.broker = IPCBroker(self.state, receive, key_store=self.store)
        self.broker.start()
        self.addCleanup(self.broker.close)
        self.metadata = json.loads(self.broker.metadata_path.read_text(encoding="ascii"))
        self.url = f"http://127.0.0.1:{self.metadata['port']}/v1"
        self.http = build_opener(ProxyHandler({}))

    def test_binds_only_loopback_and_metadata_contains_no_key(self):
        self.assertEqual("127.0.0.1", self.broker._server.server_address[0])
        self.assertEqual({"port", "pid", "session"}, set(self.metadata))
        client = IPCClient(self.state, key_store=self.store)
        self.assertEqual({"accepted": True}, client.request({"method": "cli.status"}))

    def test_origin_and_host_are_rejected_before_decryption(self):
        packet = _seal(self.broker.key, self.broker.session, "request", {"method": "cli.status"})
        for headers in ({"Origin": "https://example.invalid"}, {"Host": "attacker.invalid"}):
            with self.subTest(headers=headers), self.assertRaises(HTTPError) as error:
                self.http.open(Request(self.url, data=packet, headers=headers), timeout=5)
            self.assertEqual(403, error.exception.code)
            error.exception.close()
        self.assertEqual([], self.requests)

    def test_replay_and_wrong_cipher_are_rejected(self):
        packet = _seal(self.broker.key, self.broker.session, "request", {"method": "cli.status"})
        with self.http.open(Request(self.url, data=packet), timeout=5) as response:
            self.assertEqual(200, response.status)
        with self.assertRaises(HTTPError) as replay:
            self.http.open(Request(self.url, data=packet), timeout=5)
        self.assertEqual(401, replay.exception.code)
        replay.exception.close()
        with self.assertRaises(HTTPError) as invalid:
            self.http.open(Request(self.url, data=b'{"nonce":"bad","ciphertext":"bad"}'), timeout=5)
        self.assertEqual(401, invalid.exception.code)
        invalid.exception.close()

    def test_only_one_broker_can_own_a_profile(self):
        second = IPCBroker(self.state, lambda request: request, key_store=self.store)
        self.addCleanup(second.close)
        with self.assertRaises(KeyloomError) as error:
            second.start()
        self.assertEqual("busy", error.exception.code)


if __name__ == "__main__":
    unittest.main()
