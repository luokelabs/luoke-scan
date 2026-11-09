"""假的主控（luoke-core 的任务层）：Unix socket 上的 HTTP，只答扫描用到的两样。

    GET  /tasks                                   哪些任务开着（status: available）
    POST /tasks/<任务>/v1/chat/completions         生成：流式答复（data: {...}，最后 data: [DONE]）

每个请求原样记下（路径、X-Luoke-Accessory、X-Luoke-Priority、请求体解成 JSON），每一步新来的放进 golden 的 "hub"。
答复按任务配：一段文字、拒绝（HTTP 状态码加 code、retry_after_ms）、流里的 luoke.error、不是 JSON 的块、断掉的流。
socket 放在 /tmp 下一个新建的短目录里（sockaddr_un 只放得下 104 字节左右），只在本机，不开网络端口。
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import tempfile
import threading
from typing import Any, Callable, Dict, List, Optional, Union

Answer = Union[str, Dict[str, Any]]


class Hub:
    def __init__(self, tasks: Dict[str, str], answers: Optional[Dict[str, Union[Answer, Callable[[dict], Answer]]]] = None):
        """tasks：任务名 → 状态（"available"、"unavailable"…）。answers：任务名 → 答复，或由请求体算出答复的函数。
        答复是文字，或 {"refuse": code, "status": 503, "retry_after_ms": …}、{"error_event": code}、{"garbage": True}、
        {"cut": "半句"}（发一半就断）。"""
        self.tasks, self.answers = tasks, answers or {}
        self.dir = tempfile.mkdtemp(prefix="lsb-", dir="/tmp")
        self.path = os.path.join(self.dir, "hub.sock")
        self.log: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        self.sock.listen(16)
        self.running = True
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(30)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            lines = head.decode("utf-8", "replace").split("\r\n")
            method, path = lines[0].split(" ")[:2]
            headers = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:])}
            n = int(headers.get("content-length", "0"))
            while len(rest) < n:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                rest += chunk
            entry: Dict[str, Any] = {"method": method, "path": path, "accessory": headers.get("x-luoke-accessory")}
            if "x-luoke-priority" in headers:
                entry["priority"] = headers["x-luoke-priority"]
            if n:
                try:
                    entry["body"] = json.loads(rest[:n])
                except ValueError:
                    entry["body"] = rest[:n].decode("utf-8", "replace")
            with self.lock:
                self.log.append(entry)
            conn.sendall(self.reply(method, path, entry.get("body")))
        except OSError:
            pass
        finally:
            conn.close()

    @staticmethod
    def http(status: int, body: bytes, kind: str = "application/json") -> bytes:
        reason = {200: "OK", 404: "Not Found", 429: "Too Many Requests", 503: "Service Unavailable"}.get(status, "Error")
        return (f"HTTP/1.1 {status} {reason}\r\nContent-Type: {kind}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                .encode() + body)

    def reply(self, method: str, path: str, body: Any) -> bytes:
        if method == "GET" and path == "/tasks":
            tasks = {t: {"status": s, "accessory": t.split(".")[0]} for t, s in self.tasks.items()}
            return self.http(200, json.dumps({"tasks": tasks}).encode())
        parts = path.strip("/").split("/")
        if method != "POST" or len(parts) != 5 or parts[0] != "tasks" or parts[2:] != ["v1", "chat", "completions"]:
            return self.http(404, b'{"code": "not_found"}')
        a = self.answers.get(parts[1], "（没配答复）")
        if callable(a):
            a = a(body if isinstance(body, dict) else {})
        if isinstance(a, dict) and "refuse" in a:
            o = {"code": a["refuse"]}
            for k in ("retry_after_ms", "retry_after"):
                if k in a:
                    o[k] = a[k]
            return self.http(a.get("status", 503), json.dumps(o).encode())
        head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n"
        if isinstance(a, dict) and "error_event" in a:
            return head + b"event: luoke.error\ndata: " + json.dumps({"code": a["error_event"]}).encode() + b"\n\n"
        if isinstance(a, dict) and "garbage" in a:
            return head + b"data: {not json\n\ndata: [DONE]\n\n"
        if isinstance(a, dict) and "cut" in a:
            return head + self.chunk(a["cut"])
        text = a if isinstance(a, str) else json.dumps(a, ensure_ascii=False)
        # 分两块发，照真的流：拼起来才是整段答复
        mid = len(text) // 2
        return head + self.chunk(text[:mid]) + self.chunk(text[mid:]) + b"data: [DONE]\n\n"

    @staticmethod
    def chunk(text: str) -> bytes:
        return b"data: " + json.dumps({"choices": [{"delta": {"content": text}}]}, ensure_ascii=False).encode() + b"\n\n"

    def take(self) -> List[Dict[str, Any]]:
        """这一步新来的请求。"""
        with self.lock:
            out, self.log = self.log, []
        return out

    def close(self) -> None:
        self.running = False
        try:
            self.sock.close()
        finally:
            shutil.rmtree(self.dir, ignore_errors=True)
