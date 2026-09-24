"""Local, synthetic pyspnego server for the persistent NTLM Go test."""

import base64
import json
import os
import re
import struct
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import spnego


temporary = tempfile.TemporaryDirectory(prefix="winsh-ntlm-persistent-")
credential_file = Path(temporary.name) / "credentials"
credential_file.write_text("EXAMPLE:alice:test-secret\n")
credential_file.chmod(0o600)
os.environ["NTLM_USER_FILE"] = str(credential_file)
counts = {}
lock = threading.Lock()
envelope = b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>'
marker = b"--Encrypted Boundary\r\n"
shell_uri = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/"
transfer_uri = "http://schemas.xmlsoap.org/ws/2004/09/transfer/"
addressing_uri = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
soap_uri = "http://www.w3.org/2003/05/soap-envelope"
wsman_fault_uri = "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"
next_shell = 0
# Shells are global: data lanes send and receive on connections other than
# the one that created the shell. Each entry holds the command ID, whether
# stdin reached EOF and the stdin bytes echoed back on completion.
shells = {}


def soap_response(action, body):
    return (f'<s:Envelope xmlns:s="{soap_uri}" xmlns:a="{addressing_uri}" '
            f'xmlns:rsp="{shell_uri[:-1]}"><s:Header><a:Action>{action}</a:Action>'
            f'</s:Header><s:Body>{body}</s:Body></s:Envelope>').encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def setup(self):
        super().setup()
        self.ntlm = spnego.server(protocol="ntlm")

    def reply(self, code, data=b"", content_type="application/soap+xml", auth=None, close=False):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if auth:
            self.send_header("WWW-Authenticate", auth)
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != "/stats":
            self.reply(404)
            return
        with lock:
            data = json.dumps(sorted(counts.values())).encode()
        self.reply(200, data, "application/json")

    def do_POST(self):
        payload = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if not self.ntlm.complete:
            auth = self.headers.get("Authorization")
            if not auth:
                assert not payload
                self.reply(401, auth="Negotiate", close=True)
                return
            token = self.ntlm.step(base64.b64decode(auth.split(" ", 1)[1]))
            if not self.ntlm.complete:
                self.reply(401, auth="Negotiate " + base64.b64encode(token).decode())
                return
            with lock:
                counts[self.client_address] = 0
            self.reply(200)
            return

        assert "multipart/encrypted" in self.headers["Content-Type"]
        header, binary = payload[len(marker) :].split(marker, 1)
        binary = binary.split(b"\r\n", 1)[1][: -len(b"--Encrypted Boundary--\r\n")]
        siglen = struct.unpack("<I", binary[:4])[0]
        plain = self.ntlm.unwrap_winrm(binary[4 : 4 + siglen], binary[4 + siglen :])
        assert len(plain) == int(re.search(rb"Length=(\d+)", header)[1])
        with lock:
            counts[self.client_address] += 1
        root = ET.fromstring(plain)
        action_node = root.find(f"./{{{soap_uri}}}Header/{{{addressing_uri}}}Action")
        action = action_node.text if action_node is not None else None
        if action is None:
            response = envelope
        elif action == transfer_uri + "Create":
            global next_shell
            with lock:
                next_shell += 1
                shell_id = f"shell-{next_shell}"
                shells[shell_id] = {"command": None, "eof": False, "stdin": bytearray()}
            response = soap_response(transfer_uri + "CreateResponse", f'<rsp:Shell><rsp:ShellId>{shell_id}</rsp:ShellId></rsp:Shell>')
        elif action == shell_uri + "Command":
            shell_id = self.shell(plain)
            with lock:
                shells[shell_id]["command"] = f"command-{shell_id[6:]}"
            response = soap_response(shell_uri + "CommandResponse", f'<rsp:CommandResponse><rsp:CommandId>command-{shell_id[6:]}</rsp:CommandId></rsp:CommandResponse>')
        elif action in (shell_uri + "Send", shell_uri + "Receive", shell_uri + "Signal"):
            shell_id = self.shell(plain)
            with lock:
                shell = shells[shell_id]
            assert shell["command"] and shell["command"].encode() in plain
            if action == shell_uri + "Send":
                stream = root.find(f".//{{{shell_uri[:-1]}}}Stream")
                with lock:
                    assert not shell["eof"], "Send after EOF"
                    shell["stdin"] += base64.b64decode(stream.text or "")
                    shell["eof"] = stream.get("End") == "true"
                response = soap_response(action + "Response", "")
            elif action == shell_uri + "Receive":
                with lock:
                    eof, stdin = shell["eof"], bytes(shell["stdin"])
                if not eof:
                    # Like WinRM, a Receive without output ends in an
                    # OperationTimeout fault sealed inside HTTP 500.
                    time.sleep(0.02)
                    self.sealed_reply(500, (f'<s:Envelope xmlns:s="{soap_uri}" xmlns:a="{addressing_uri}"><s:Header><a:Action>fault</a:Action></s:Header>'
                                            f'<s:Body><s:Fault><s:Detail><f:WSManFault xmlns:f="{wsman_fault_uri}" Code="2150858793"/></s:Detail></s:Fault></s:Body></s:Envelope>').encode())
                    return
                stdout = base64.b64encode(stdin or b"ok\n").decode()
                response = soap_response(shell_uri + "ReceiveResponse", f'<rsp:ReceiveResponse><rsp:Stream Name="stdout">{stdout}</rsp:Stream><rsp:Stream Name="stderr">ZXJyCg==</rsp:Stream><rsp:CommandState State="{shell_uri}CommandState/Done"><rsp:ExitCode>7</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>')
            else:
                response = soap_response(action + "Response", "")
        elif action == transfer_uri + "Delete":
            shell_id = self.shell(plain)
            with lock:
                del shells[shell_id]
            response = soap_response(transfer_uri + "DeleteResponse", "")
        else:
            raise AssertionError(f"unexpected SOAP action: {action}")
        self.sealed_reply(200, response)

    def shell(self, plain):
        match = re.search(rb"shell-\d+", plain)
        assert match, "request names no shell"
        shell_id = match[0].decode()
        with lock:
            assert shell_id in shells, f"unknown {shell_id}"
        return shell_id

    def sealed_reply(self, code, response):
        sealed = self.ntlm.wrap_winrm(response)
        frame = (
            marker
            + b"\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n"
            + f"\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length={len(response)}\r\n".encode()
            + marker
            + b"\tContent-Type: application/octet-stream\r\n"
            + struct.pack("<I", len(sealed.header))
            + sealed.header
            + sealed.data
            + b"--Encrypted Boundary--\r\n"
        )
        self.reply(code, frame, 'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"')


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    print(f"http://127.0.0.1:{server.server_port}/wsman", flush=True)
    sys.stdin.readline()
finally:
    server.shutdown()
    server.server_close()
    temporary.cleanup()
