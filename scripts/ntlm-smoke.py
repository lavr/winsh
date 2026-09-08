import argparse, base64, os, struct, subprocess, tempfile, threading, re
import xml.etree.ElementTree as ET
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import spnego

# Synthetic fixture credentials only; never reads workstation credentials.
temporary = tempfile.TemporaryDirectory(prefix='winsh-ntlm-test-')
credential_file = Path(temporary.name) / 'credentials'
parser = argparse.ArgumentParser(description='Verify winsh against an independent NTLM server (synthetic credentials only).')
parser.add_argument('--binary', default='dist/winsh')
args = parser.parse_args()
credential_file.write_text('EXAMPLE:alice:test-secret\n')
credential_file.chmod(0o600)
os.environ['NTLM_USER_FILE'] = str(credential_file)
S = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/'
T = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/'
seen = []

def envelope(action, body):
    return (f'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:rsp="{S[:-1]}"><s:Header><a:Action>{action}</a:Action></s:Header><s:Body>{body}</s:Body></s:Envelope>').encode()

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_): pass
    def setup(self):
        super().setup()
        self.ntlm = spnego.server(protocol='ntlm')
    def reply(self, code, data=b'', ct='application/soap+xml', auth=None):
        self.send_response(code)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', str(len(data)))
        if auth: self.send_header('WWW-Authenticate', auth)
        if code == 401 and auth == 'Negotiate':
            self.send_header('Connection', 'close')
            self.close_connection = True
        self.end_headers()
        self.wfile.write(data)
    def do_POST(self):
        payload = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if not self.ntlm.complete:
            auth = self.headers.get('Authorization')
            if not auth:
                assert not payload
                self.reply(401, auth='Negotiate'); return
            try:
                token = self.ntlm.step(base64.b64decode(auth.split(' ', 1)[1]))
            except spnego.exceptions.SpnegoError:
                self.reply(401, auth='Negotiate'); return
            if not self.ntlm.complete:
                self.reply(401, auth='Negotiate ' + base64.b64encode(token).decode()); return
            self.reply(200); return
        assert 'multipart/encrypted' in self.headers['Content-Type']
        marker = b'--Encrypted Boundary\r\n'
        head, binary = payload[len(marker):].split(marker, 1)
        binary = binary.split(b'\r\n', 1)[1][:-len(b'--Encrypted Boundary--\r\n')]
        siglen = struct.unpack('<I', binary[:4])[0]
        plain = self.ntlm.unwrap_winrm(binary[4:4+siglen], binary[4+siglen:])
        assert len(plain) == int(re.search(rb'Length=(\d+)', head)[1])
        if (T + 'Create').encode() in plain:
            seen.append('create'); response = envelope(T+'CreateResponse', '<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>')
        elif (S+'Command').encode() in plain:
            command = ET.fromstring(plain).find('.//{' + S[:-1] + '}Command').text
            encoded = command.split('-EncodedCommand ', 1)[1]
            assert "Write-Output 'Привет 😀'; exit 37" in base64.b64decode(encoded).decode('utf-16-le')
            seen.append('command'); response = envelope(S+'CommandResponse', '<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>')
        elif (S+'Send').encode() in plain:
            seen.append('stdin'); response = envelope(S+'SendResponse', '')
        elif (S+'Receive').encode() in plain:
            seen.append('receive'); out=base64.b64encode('Привет 😀\n'.encode()).decode()
            response = envelope(S+'ReceiveResponse', f'<rsp:ReceiveResponse><rsp:Stream Name="stdout">{out}</rsp:Stream><rsp:Stream Name="stderr">c3RkZXJyCg==</rsp:Stream><rsp:CommandState State="{S}CommandState/Done"><rsp:ExitCode>37</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>')
        elif (T+'Delete').encode() in plain:
            seen.append('delete'); response = envelope(T+'DeleteResponse', '')
        else: raise AssertionError('unexpected SOAP action')
        sealed = self.ntlm.wrap_winrm(response)
        frame = (marker + b'\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n' + f'\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length={len(response)}\r\n'.encode() + marker + b'\tContent-Type: application/octet-stream\r\n' + struct.pack('<I',len(sealed.header)) + sealed.header + sealed.data + b'--Encrypted Boundary--\r\n')
        self.reply(200, frame, 'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"')

server=ThreadingHTTPServer(('127.0.0.1',0), Handler)
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
try:
    result=subprocess.run([args.binary,'ps','--endpoint',f'http://127.0.0.1:{server.server_port}/wsman','--user','EXAMPLE\\alice','--password-stdin','--',"Write-Output 'Привет 😀'; exit 37"], input='test-secret\n',text=True,capture_output=True,timeout=20)
    assert result.returncode==37, (result.returncode,result.stderr)
    assert result.stdout=='Привет 😀\n', repr(result.stdout)
    assert result.stderr=='stderr\n',repr(result.stderr)
    assert seen==['create','command','stdin','receive','delete'],seen
    print('PASS: independent pyspnego server verified NTLM authentication, sealed SOAP both directions, UTF-8 streams, rc=37, shell cleanup')
finally:
    server.shutdown();server.server_close();temporary.cleanup()
