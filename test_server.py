"""
VoiceBridge server.py テストスイート
テスト対象: GET /, POST /input, GET /ping のHTTPハンドラ
Windows SendInput/Clipboard API は mock化して実行
"""

import importlib.util
import json
import re
import sys
import threading
import time
import unittest
from http.client import HTTPConnection
from http.server import HTTPServer
from unittest.mock import MagicMock, patch

# --------------------------------------------------------------------------
# server.py をモジュールとしてロード（SendInput/Clipboard は後でモック化）
# --------------------------------------------------------------------------
spec = importlib.util.spec_from_file_location("server", "server.py")
server_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server_mod)

SESSION_TOKEN = server_mod._SESSION_TOKEN
PORT = server_mod.PORT
MAX_TEXT_LENGTH = server_mod.MAX_TEXT_LENGTH
RATE_LIMIT_SEC = server_mod.RATE_LIMIT_SEC


# --------------------------------------------------------------------------
# テスト用HTTPサーバーをランダムポートで起動するヘルパー
# --------------------------------------------------------------------------
def start_test_server():
    """空きポートでサーバーを起動し (httpd, port) を返す。"""
    httpd = HTTPServer(("127.0.0.1", 0), server_mod.VoiceBridgeHandler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, port


def make_conn(port):
    return HTTPConnection("127.0.0.1", port, timeout=5)


def post_input(port, body: dict, token: str = SESSION_TOKEN,
               extra_headers: dict | None = None) -> tuple[int, dict]:
    payload = json.dumps(body).encode("utf-8")
    conn = make_conn(port)
    headers = {
        "Content-Type": "application/json",
        "X-VoiceBridge-Token": token,
        "Content-Length": str(len(payload)),
    }
    if extra_headers:
        headers.update(extra_headers)
    conn.request("POST", "/input", body=payload, headers=headers)
    resp = conn.getresponse()
    return resp.status, json.loads(resp.read())


# --------------------------------------------------------------------------
# テストクラス
# --------------------------------------------------------------------------

class TestGETRoot(unittest.TestCase):
    """GET / エンドポイント"""

    def setUp(self):
        # 各テストでグローバル状態をリセット
        with server_mod._allowed_ip_lock:
            server_mod._allowed_ip = None
            server_mod._ip_locked = False
        self.httpd, self.port = start_test_server()

    def tearDown(self):
        self.httpd.shutdown()

    # --- 正常系 ---
    def test_valid_token_returns_200_and_html(self):
        """正しいトークンでアクセスすると200とHTMLが返る"""
        conn = make_conn(self.port)
        conn.request("GET", f"/?t={SESSION_TOKEN}")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        ct = resp.getheader("Content-Type", "")
        self.assertIn("text/html", ct)
        html = resp.read().decode("utf-8")
        self.assertIn("VoiceBridge", html)

    def test_valid_token_registers_ip(self):
        """正しいトークンでアクセスすると送信元IPが登録される"""
        conn = make_conn(self.port)
        conn.request("GET", f"/?t={SESSION_TOKEN}")
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 200)
        with server_mod._allowed_ip_lock:
            self.assertEqual(server_mod._allowed_ip, "127.0.0.1")

    def test_html_contains_session_token(self):
        """返却HTMLにセッショントークンが埋め込まれている（__SESSION_TOKEN__プレースホルダーが置換済み）"""
        conn = make_conn(self.port)
        conn.request("GET", f"/?t={SESSION_TOKEN}")
        resp = conn.getresponse()
        html = resp.read().decode("utf-8")
        self.assertIn(SESSION_TOKEN, html)
        self.assertNotIn("__SESSION_TOKEN__", html)

    def test_index_html_path_also_works(self):
        """/index.html パスでも同じくHTML返却"""
        conn = make_conn(self.port)
        conn.request("GET", f"/index.html?t={SESSION_TOKEN}")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)

    # --- 異常系 ---
    def test_invalid_token_returns_403(self):
        """誤ったトークンでは403"""
        conn = make_conn(self.port)
        conn.request("GET", "/?t=wrongtoken")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 403)
        body = json.loads(resp.read())
        self.assertIn("error", body)

    def test_empty_token_returns_403(self):
        """トークンなしでは403"""
        conn = make_conn(self.port)
        conn.request("GET", "/")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 403)

    def test_partial_token_returns_403(self):
        """トークンの一部だけでは403（タイミング攻撃対策のcompare_digestも正しく機能）"""
        conn = make_conn(self.port)
        conn.request("GET", f"/?t={SESSION_TOKEN[:8]}")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 403)

    def test_second_registration_returns_403(self):
        """正しいトークンで1回目は200、2回目は403 already registered"""
        # 1回目: 正常登録
        conn1 = make_conn(self.port)
        conn1.request("GET", f"/?t={SESSION_TOKEN}")
        resp1 = conn1.getresponse()
        resp1.read()
        self.assertEqual(resp1.status, 200)
        # _ip_locked が True になっていることを確認
        with server_mod._allowed_ip_lock:
            self.assertTrue(server_mod._ip_locked)
        # 2回目: 同じトークンでアクセスしても403
        conn2 = make_conn(self.port)
        conn2.request("GET", f"/?t={SESSION_TOKEN}")
        resp2 = conn2.getresponse()
        body2 = json.loads(resp2.read())
        self.assertEqual(resp2.status, 403)
        self.assertIn("already registered", body2.get("error", ""))

    def test_ip_locked_set_after_first_registration(self):
        """1回目の登録後に _ip_locked が True になる"""
        with server_mod._allowed_ip_lock:
            self.assertFalse(server_mod._ip_locked)
        conn = make_conn(self.port)
        conn.request("GET", f"/?t={SESSION_TOKEN}")
        resp = conn.getresponse()
        resp.read()
        with server_mod._allowed_ip_lock:
            self.assertTrue(server_mod._ip_locked)

    def test_html_contains_history_replace_state(self):
        """HTMLにhistory.replaceState(null, '', '/')が含まれている"""
        conn = make_conn(self.port)
        conn.request("GET", f"/?t={SESSION_TOKEN}")
        resp = conn.getresponse()
        html = resp.read().decode("utf-8")
        self.assertIn("history.replaceState(null, '', '/')", html)


class TestGETPing(unittest.TestCase):
    """GET /ping エンドポイント"""

    def setUp(self):
        self.httpd, self.port = start_test_server()

    def tearDown(self):
        self.httpd.shutdown()

    def test_ping_returns_200_alive(self):
        """登録済みIPからは200 + alive"""
        with server_mod._allowed_ip_lock:
            server_mod._allowed_ip = "127.0.0.1"
        conn = make_conn(self.port)
        conn.request("GET", "/ping")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        body = json.loads(resp.read())
        self.assertEqual(body.get("status"), "alive")

    def test_ping_unregistered_ip_returns_403(self):
        """/ping はIP未登録の場合403"""
        with server_mod._allowed_ip_lock:
            server_mod._allowed_ip = None
        conn = make_conn(self.port)
        conn.request("GET", "/ping")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 403)


class TestGETNotFound(unittest.TestCase):
    """GET 未定義パス"""

    def setUp(self):
        self.httpd, self.port = start_test_server()

    def tearDown(self):
        self.httpd.shutdown()

    def test_unknown_path_returns_404(self):
        conn = make_conn(self.port)
        conn.request("GET", "/unknown")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 404)


class TestPOSTInput(unittest.TestCase):
    """POST /input エンドポイント（SendInputをモック化）"""

    def setUp(self):
        # IP登録済み状態にする
        with server_mod._allowed_ip_lock:
            server_mod._allowed_ip = "127.0.0.1"
        # レート制限タイマーをリセット
        server_mod._last_inject_time = 0.0
        self.httpd, self.port = start_test_server()
        # send_unicode_text をモック化（実際のキー入力をしない）
        self.patcher = patch.object(server_mod, "send_unicode_text", return_value=None)
        self.mock_send = self.patcher.start()
        # INJECT_DELAY_SEC を 0 に短縮してテスト高速化
        self._orig_delay = server_mod.INJECT_DELAY_SEC
        server_mod.INJECT_DELAY_SEC = 0.0

    def tearDown(self):
        self.patcher.stop()
        server_mod.INJECT_DELAY_SEC = self._orig_delay
        self.httpd.shutdown()

    # --- 正常系 ---
    def test_normal_text_returns_200(self):
        """通常テキストで200 + status:ok"""
        status, body = post_input(self.port, {"text": "hello"})
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ok")
        self.assertEqual(body.get("length"), 5)

    def test_returns_correct_length(self):
        """length フィールドが文字数と一致"""
        text = "テストテキスト"
        status, body = post_input(self.port, {"text": text})
        self.assertEqual(body.get("length"), len(text))

    def test_enter_true_passed_to_send(self):
        """enter=True が send_unicode_text に渡される"""
        post_input(self.port, {"text": "hi", "enter": True})
        self.mock_send.assert_called_once_with("hi", enter=True)

    def test_enter_false_default(self):
        """enter フィールドなし → enter=False"""
        post_input(self.port, {"text": "hi"})
        self.mock_send.assert_called_once_with("hi", enter=False)

    def test_max_length_text_ok(self):
        """MAX_TEXT_LENGTH ちょうどは受理される"""
        text = "a" * MAX_TEXT_LENGTH
        status, body = post_input(self.port, {"text": text})
        self.assertEqual(status, 200)

    def test_japanese_text_ok(self):
        """日本語テキストも正常処理"""
        status, body = post_input(self.port, {"text": "音声テスト"})
        self.assertEqual(status, 200)

    # --- 異常系 ---
    def test_wrong_token_returns_403(self):
        """誤トークンで403"""
        status, body = post_input(self.port, {"text": "hi"}, token="badtoken")
        self.assertEqual(status, 403)

    def test_no_token_returns_403(self):
        """トークンなしで403"""
        status, body = post_input(self.port, {"text": "hi"}, token="")
        self.assertEqual(status, 403)

    def test_unregistered_ip_returns_403(self):
        """IP未登録（None）で403"""
        with server_mod._allowed_ip_lock:
            server_mod._allowed_ip = None
        status, body = post_input(self.port, {"text": "hi"})
        self.assertEqual(status, 403)

    def test_text_too_long_returns_400(self):
        """MAX_TEXT_LENGTH+1文字で400"""
        text = "a" * (MAX_TEXT_LENGTH + 1)
        status, body = post_input(self.port, {"text": text})
        self.assertEqual(status, 400)
        self.assertIn("too long", body.get("error", ""))

    def test_empty_text_returns_400(self):
        """text が空文字列で400"""
        status, body = post_input(self.port, {"text": ""})
        self.assertEqual(status, 400)

    def test_missing_text_field_returns_400(self):
        """text フィールドなしで400"""
        status, body = post_input(self.port, {"other": "value"})
        self.assertEqual(status, 400)

    def test_text_not_string_returns_400(self):
        """text が文字列以外（数値）で400"""
        status, body = post_input(self.port, {"text": 12345})
        self.assertEqual(status, 400)

    def test_invalid_json_returns_400(self):
        """不正JSONで400"""
        conn = make_conn(self.port)
        payload = b"not json"
        conn.request("POST", "/input", body=payload, headers={
            "Content-Type": "application/json",
            "X-VoiceBridge-Token": SESSION_TOKEN,
            "Content-Length": str(len(payload)),
        })
        resp = conn.getresponse()
        self.assertEqual(resp.status, 400)

    def test_empty_body_returns_400(self):
        """Content-Length: 0 で400"""
        conn = make_conn(self.port)
        conn.request("POST", "/input", body=b"", headers={
            "Content-Type": "application/json",
            "X-VoiceBridge-Token": SESSION_TOKEN,
            "Content-Length": "0",
        })
        resp = conn.getresponse()
        self.assertEqual(resp.status, 400)
        body = json.loads(resp.read())
        self.assertIn("empty body", body.get("error", ""))

    def test_rate_limit_second_request_returns_429(self):
        """1秒以内に2回目のリクエストで429"""
        server_mod._last_inject_time = time.time()  # 直前に注入済みに設定
        status, body = post_input(self.port, {"text": "hi"})
        self.assertEqual(status, 429)
        self.assertIn("rate limit", body.get("error", ""))

    def test_rate_limit_after_cooldown_ok(self):
        """RATE_LIMIT_SEC 以上経過後は再度200"""
        server_mod._last_inject_time = time.time() - (RATE_LIMIT_SEC + 0.1)
        status, body = post_input(self.port, {"text": "hi"})
        self.assertEqual(status, 200)

    def test_wrong_path_returns_404(self):
        """POST /other は404"""
        conn = make_conn(self.port)
        payload = json.dumps({"text": "hi"}).encode()
        conn.request("POST", "/other", body=payload, headers={
            "Content-Type": "application/json",
            "X-VoiceBridge-Token": SESSION_TOKEN,
            "Content-Length": str(len(payload)),
        })
        resp = conn.getresponse()
        self.assertEqual(resp.status, 404)

    # --- 境界値 ---
    def test_boundary_exactly_max_length(self):
        """MAX_TEXT_LENGTH 境界: ちょうどMAXは200"""
        text = "x" * MAX_TEXT_LENGTH
        status, _ = post_input(self.port, {"text": text})
        self.assertEqual(status, 200)

    def test_boundary_over_max_length_by_one(self):
        """MAX_TEXT_LENGTH 境界: MAX+1は400"""
        text = "x" * (MAX_TEXT_LENGTH + 1)
        status, _ = post_input(self.port, {"text": text})
        self.assertEqual(status, 400)

    def test_single_char_text(self):
        """1文字は受理される"""
        status, body = post_input(self.port, {"text": "a"})
        self.assertEqual(status, 200)
        self.assertEqual(body.get("length"), 1)


class TestUtilityFunctions(unittest.TestCase):
    """ユーティリティ関数のユニットテスト"""

    def test_get_local_ip_returns_string(self):
        """get_local_ip() が文字列を返す"""
        ip = server_mod.get_local_ip()
        self.assertIsInstance(ip, str)
        self.assertRegex(ip, r"^\d+\.\d+\.\d+\.\d+$")

    def test_find_port_listeners_returns_list(self):
        """_find_port_listeners() がリストを返す（Windows環境）"""
        result = server_mod._find_port_listeners(9999)
        self.assertIsInstance(result, list)

    def test_find_port_listeners_no_crash_on_unused_port(self):
        """使っていないポートを渡してもクラッシュしない"""
        result = server_mod._find_port_listeners(19999)
        self.assertIsInstance(result, list)

    def test_session_token_is_hex_16chars(self):
        """セッショントークンは16文字の16進文字列"""
        self.assertEqual(len(SESSION_TOKEN), 16)
        self.assertRegex(SESSION_TOKEN, r"^[0-9a-f]+$")

    def test_constants_are_positive(self):
        """定数が正の値"""
        self.assertGreater(server_mod.PORT, 0)
        self.assertGreater(server_mod.MAX_TEXT_LENGTH, 0)
        self.assertGreater(server_mod.RATE_LIMIT_SEC, 0)
        self.assertGreater(server_mod.INJECT_DELAY_SEC, 0)


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestGETRoot))
    suite.addTests(loader.loadTestsFromTestCase(TestGETPing))
    suite.addTests(loader.loadTestsFromTestCase(TestGETNotFound))
    suite.addTests(loader.loadTestsFromTestCase(TestPOSTInput))
    suite.addTests(loader.loadTestsFromTestCase(TestUtilityFunctions))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
