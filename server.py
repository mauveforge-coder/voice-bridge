"""
VoiceBridge Server
------------------
iOSショートカットから受け取った音声認識テキストを
Windows のフォーカス中ウィンドウに SendInput API で注入する。

使用ライブラリ: Python 標準ライブラリのみ
対応文字: Unicode BMP 範囲（U+0000〜U+FFFF）
ポート: 9876
"""

import ctypes
import ctypes.wintypes
import io
import json
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import qrcode
    _HAS_QRCODE = True
except ImportError:
    _HAS_QRCODE = False


PORT = 9876
INJECT_DELAY_SEC = 0.3
MAX_TEXT_LENGTH = 10_000
RATE_LIMIT_SEC = 1.0

_SESSION_TOKEN: str = secrets.token_hex(8)
_allowed_ip: str | None = None
_ip_locked: bool = False
_allowed_ip_lock = threading.Lock()
_last_inject_time: float = 0.0
_rate_lock = threading.Lock()


# ------------------------------------------------------------------
# Windows SendInput 関連の構造体定義
# ------------------------------------------------------------------

INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
VK_CONTROL = 0x11
VK_V = 0x56
VK_RETURN = 0x0D
CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002

class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk",         ctypes.wintypes.WORD),
        ("wScan",       ctypes.wintypes.WORD),
        ("dwFlags",     ctypes.wintypes.DWORD),
        ("time",        ctypes.wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    ]

class _INPUT_UNION(ctypes.Union):
    _fields_ = [
        ("ki", KEYBDINPUT),
        ("padding", ctypes.c_byte * 28),
    ]

class INPUT(ctypes.Structure):
    _fields_ = [
        ("type",   ctypes.wintypes.DWORD),
        ("_input", _INPUT_UNION),
    ]

_inject_lock = threading.Lock()

_u32 = ctypes.windll.user32
_k32 = ctypes.windll.kernel32
_u32.GetClipboardData.restype   = ctypes.c_void_p
_u32.GetClipboardData.argtypes  = [ctypes.c_uint]
_u32.SetClipboardData.argtypes  = [ctypes.c_uint, ctypes.c_void_p]
_k32.GlobalAlloc.restype        = ctypes.c_void_p
_k32.GlobalAlloc.argtypes       = [ctypes.c_uint, ctypes.c_size_t]
_k32.GlobalLock.restype         = ctypes.c_void_p
_k32.GlobalLock.argtypes        = [ctypes.c_void_p]
_k32.GlobalUnlock.argtypes      = [ctypes.c_void_p]

def _clipboard_get() -> str:
    if not _u32.OpenClipboard(0):
        return ""
    try:
        handle = _u32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return ""
        ptr = _k32.GlobalLock(handle)
        if not ptr:
            return ""
        try:
            return ctypes.wstring_at(ptr)
        finally:
            _k32.GlobalUnlock(handle)
    finally:
        _u32.CloseClipboard()

def _clipboard_set(text: str) -> None:
    if not _u32.OpenClipboard(0):
        return
    try:
        _u32.EmptyClipboard()
        encoded = (text + "\0").encode("utf-16-le")
        handle = _k32.GlobalAlloc(GMEM_MOVEABLE, len(encoded))
        if not handle:
            return
        ptr = _k32.GlobalLock(handle)
        if not ptr:
            _k32.GlobalFree(handle)
            print("[ERROR] GlobalLock failed")
            return
        ctypes.memmove(ptr, encoded, len(encoded))
        _k32.GlobalUnlock(handle)
        _u32.SetClipboardData(CF_UNICODETEXT, handle)
    finally:
        _u32.CloseClipboard()

def _send_ctrl_v() -> None:
    events = []
    for vk, flags in [(VK_CONTROL, 0), (VK_V, 0), (VK_V, KEYEVENTF_KEYUP), (VK_CONTROL, KEYEVENTF_KEYUP)]:
        ki = KEYBDINPUT(wVk=vk, wScan=0, dwFlags=flags, time=0, dwExtraInfo=None)
        inp = INPUT(type=INPUT_KEYBOARD)
        inp._input.ki = ki
        events.append(inp)
    arr = (INPUT * 4)(*events)
    ctypes.windll.user32.SendInput(4, arr, ctypes.sizeof(INPUT))

def _send_enter() -> None:
    events = []
    for vk, flags in [(VK_RETURN, 0), (VK_RETURN, KEYEVENTF_KEYUP)]:
        ki = KEYBDINPUT(wVk=vk, wScan=0, dwFlags=flags, time=0, dwExtraInfo=None)
        inp = INPUT(type=INPUT_KEYBOARD)
        inp._input.ki = ki
        events.append(inp)
    arr = (INPUT * 2)(*events)
    ctypes.windll.user32.SendInput(2, arr, ctypes.sizeof(INPUT))

def send_unicode_text(text: str, enter: bool = False) -> None:
    with _inject_lock:
        old = _clipboard_get()
        try:
            _clipboard_set(text)
            time.sleep(0.05)
            _send_ctrl_v()
            time.sleep(0.1)
            if enter:
                _send_enter()
        finally:
            _clipboard_set(old)


# ------------------------------------------------------------------
# HTTP リクエストハンドラ
# ------------------------------------------------------------------

class VoiceBridgeHandler(BaseHTTPRequestHandler):

    def _check_auth(self) -> bool:
        """登録済みIPアドレスとセッショントークンの両方を検証する。"""
        with _allowed_ip_lock:
            if _allowed_ip is None or self.client_address[0] != _allowed_ip:
                return False
        token = self.headers.get("X-VoiceBridge-Token", "")
        return secrets.compare_digest(token, _SESSION_TOKEN)

    def do_POST(self):
        global _last_inject_time

        if self.path != "/input":
            self._send(404, {"error": "not found"})
            return

        if not self._check_auth():
            self._send(403, {"error": "forbidden"})
            return

        with _rate_lock:
            now = time.time()
            if now - _last_inject_time < RATE_LIMIT_SEC:
                self._send(429, {"error": "rate limit exceeded"})
                return
            _last_inject_time = now

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._send(400, {"error": "invalid Content-Length"})
            return
        if length == 0:
            self._send(400, {"error": "empty body"})
            return
        if length > MAX_TEXT_LENGTH * 4:
            self._send(413, {"error": "request too large"})
            return

        try:
            body = self.rfile.read(length)
            data = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self._send(400, {"error": f"invalid JSON: {e}"})
            return

        text = data.get("text", "")
        if not isinstance(text, str) or not text:
            self._send(400, {"error": "text field is required"})
            return
        if len(text) > MAX_TEXT_LENGTH:
            self._send(400, {"error": f"text too long (max {MAX_TEXT_LENGTH})"})
            return
        enter = bool(data.get("enter", False))

        time.sleep(INJECT_DELAY_SEC)
        send_unicode_text(text, enter=enter)

        self._send(200, {"status": "ok", "length": len(text)})

    def do_GET(self):
        global _allowed_ip, _ip_locked

        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path in ("/", "/index.html"):
            token = params.get("t", [""])[0]
            if not secrets.compare_digest(token, _SESSION_TOKEN):
                self._send(403, {"error": "invalid token"})
                return
            with _allowed_ip_lock:
                if _ip_locked:
                    self._send(403, {"error": "already registered"})
                    return
                _allowed_ip = self.client_address[0]
                _ip_locked = True
            print(f"[AUTH] 端末を登録しました: {_allowed_ip}")
            self._send_html()
        elif parsed.path == "/ping":
            with _allowed_ip_lock:
                if _allowed_ip is None or self.client_address[0] != _allowed_ip:
                    self._send(403, {"error": "forbidden"})
                    return
            self._send(200, {"status": "alive"})
        else:
            self._send(404, {"error": "not found"})

    def _send_html(self):
        html = """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VoiceBridge</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🎙</text></svg>">
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, sans-serif; background: #f5f5f7;
         display: flex; flex-direction: column; align-items: center;
         min-height: 100vh; margin: 0; padding: 16px; }
  h1 { font-size: 1.4rem; color: #1d1d1f; margin: 16px 0; }
  textarea { width: 100%; max-width: 480px; height: 140px; font-size: 1.1rem;
             padding: 12px; border: 1px solid #d2d2d7; border-radius: 12px; resize: none; }
  #sendBtn { margin-top: 10px; width: 100%; max-width: 480px; padding: 16px;
             font-size: 1.1rem; font-weight: 600; color: #fff; background: #007aff;
             border: none; border-radius: 12px; cursor: pointer; }
  #sendBtn:active { background: #0051a8; }
  #status { margin-top: 10px; font-size: 0.9rem; color: #6e6e73; min-height: 1.2em; width: 100%; max-width: 480px; }
  .toggle-row { display: flex; align-items: center; gap: 10px; margin-top: 10px; width: 100%; max-width: 480px; }
  .toggle-row label { font-size: 0.95rem; color: #3a3a3c; }
  input[type=checkbox] { width: 20px; height: 20px; cursor: pointer; }
  #history { margin-top: 16px; width: 100%; max-width: 480px; }
  #history h2 { font-size: 0.85rem; color: #8e8e93; margin: 0 0 8px 4px; font-weight: 500; }
  .hist-item { background: #fff; border: 1px solid #e5e5ea; border-radius: 10px;
               padding: 10px 12px; margin-bottom: 8px; font-size: 1rem;
               color: #1d1d1f; cursor: pointer; }
  .hist-item:active { background: #f0f0f5; }
  .hist-meta { font-size: 0.75rem; color: #8e8e93; margin-bottom: 4px; }
</style>
</head>
<body>
<h1>🎙 VoiceBridge</h1>
<textarea id="txt" placeholder="ここをタップ → キーボードのマイクボタンで話す"></textarea>
<button id="sendBtn" onclick="send()">PCに送信</button>
<div class="toggle-row">
  <input type="checkbox" id="enterChk">
  <label for="enterChk">送信後にEnterを押す</label>
</div>
<div id="status"></div>
<div id="history"></div>
<script>
const TOKEN = '__SESSION_TOKEN__';
history.replaceState(null, '', '/');
const HISTORY_MAX = 3;
let historyList = [];

async function send() {
  const txt = document.getElementById('txt');
  const text = txt.value.trim();
  if (!text) { setStatus('テキストを入力してください'); return; }
  const enter = document.getElementById('enterChk').checked;
  setStatus('送信中...');
  try {
    const res = await fetch('/input', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-VoiceBridge-Token': TOKEN},
      body: JSON.stringify({text, enter})
    });
    const data = await res.json();
    if (data.status === 'ok') {
      setStatus('✓ 送信しました（' + data.length + '文字）');
      addHistory(text);
      txt.value = '';
    } else {
      setStatus('エラー: ' + JSON.stringify(data));
    }
  } catch(e) {
    setStatus('接続エラー: ' + e.message);
  }
}

function addHistory(text) {
  const now = new Date();
  const time = now.getHours() + ':' + String(now.getMinutes()).padStart(2,'0');
  historyList.unshift({text, time});
  if (historyList.length > HISTORY_MAX) historyList.pop();
  renderHistory();
}

function renderHistory() {
  const el = document.getElementById('history');
  if (historyList.length === 0) { el.innerHTML = ''; return; }
  el.innerHTML = '<h2>履歴</h2>' + historyList.map((h, i) =>
    '<div class="hist-item" onclick="reuse(' + i + ')">' +
    '<div class="hist-meta">' + h.time + '</div>' +
    '<div>' + escHtml(h.text) + '</div></div>'
  ).join('');
}

function reuse(i) {
  document.getElementById('txt').value = historyList[i].text;
  setStatus('履歴から読み込みました');
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function setStatus(msg) { document.getElementById('status').textContent = msg; }
</script>
</body>
</html>""".replace("__SESSION_TOKEN__", _SESSION_TOKEN)
        payload = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send(self, status: int, body: dict) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        pass


# ------------------------------------------------------------------
# エントリーポイント
# ------------------------------------------------------------------

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def _find_port_listeners(port: int) -> list[int]:
    """指定ポートをLISTENしているPIDの一覧を返す（PID表示用）。"""
    pids: list[int] = []
    try:
        netstat = r"C:\Windows\System32\netstat.exe"
        out = subprocess.check_output(
            [netstat, "-ano"],
            text=True,
            encoding="utf-8",
            errors="ignore",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        for line in out.splitlines():
            if f":{port}" in line and "LISTENING" in line:
                m = re.search(r"\s(\d+)\s*$", line.strip())
                if m and int(m.group(1)) != 0:
                    pids.append(int(m.group(1)))
    except Exception:
        pass
    return list(set(pids))


class _ExclusiveHTTPServer(HTTPServer):
    """SO_REUSEADDR を無効にし、ポート二重起動を OS レベルで防ぐ。"""
    allow_reuse_address = False


def main():
    local_ip = get_local_ip()

    # ポートへの bind を試みる。既に使用中なら OS がエラーを返す。
    try:
        server = _ExclusiveHTTPServer(("0.0.0.0", PORT), VoiceBridgeHandler)
    except OSError:
        conflicting = _find_port_listeners(PORT)
        pid_str = f" (PID: {', '.join(map(str, conflicting))})" if conflicting else ""
        print(f"\n[ERROR] ポート {PORT} は既に使用中です{pid_str}")
        print("  古いVoiceBridgeが残っている可能性があります。")
        ans = input("  自動的に停止してから起動しますか？ [y/N]: ").strip().lower()
        if ans != "y":
            print("  手動で停止してから再起動してください。終了します。")
            sys.exit(1)
        for pid in conflicting:
            try:
                subprocess.run(
                    [r"C:\Windows\System32\taskkill.exe", "/PID", str(pid), "/F"],
                    capture_output=True, check=True,
                )
                print(f"  → PID {pid} を停止しました")
            except Exception as e:
                print(f"  → PID {pid} の停止に失敗しました: {e}")
                sys.exit(1)
        try:
            server = _ExclusiveHTTPServer(("0.0.0.0", PORT), VoiceBridgeHandler)
        except OSError:
            print(f"[ERROR] ポート {PORT} の解放に失敗しました。手動で停止してください。")
            sys.exit(1)

    ui_url = f"http://{local_ip}:{PORT}/?t={_SESSION_TOKEN}"

    print("=" * 50)
    print("  VoiceBridge サーバー起動")
    print("=" * 50)
    print(f"  ローカルIP : {local_ip}")
    print(f"  ポート     : {PORT}")
    print(f"  トークン   : {_SESSION_TOKEN}")
    print()
    print("  QRをスキャンしてiPhoneで開く:")
    print(f"    {ui_url}")
    print()
    if _HAS_QRCODE:
        qr = qrcode.QRCode(border=1)
        qr.add_data(ui_url)
        qr.make(fit=True)
        utf8_out = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
        try:
            qr.print_ascii(out=utf8_out, invert=True)
        finally:
            utf8_out.detach()
    print()
    print("  停止: Ctrl+C")
    print("=" * 50)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nサーバーを停止しました。")
        server.server_close()


if __name__ == "__main__":
    main()
