#!/usr/bin/env python3
import argparse
import base64
import binascii
import logging
import re
import socket
import socketserver
import ssl
import struct


MAX_LINE = 65536
MAX_TOKEN = 32767
TAG = re.compile(rb"[A-Za-z0-9._-]{1,64}\Z")
NTLM_SIGNATURE = b"NTLMSSP\x00"


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data.extend(chunk)
    return bytes(data)


def read_line(sock):
    data = bytearray()
    while len(data) < MAX_LINE:
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError("connection closed")
        data.extend(chunk)
        if chunk == b"\n":
            if len(data) < 2 or data[-2] != 13:
                raise ValueError("expected CRLF")
            return bytes(data[:-2])
    raise ValueError("line too long")


def ntlm_token(encoded, message_type):
    if len(encoded) > 4 * ((MAX_TOKEN + 2) // 3):
        raise ValueError("NTLM token too large")
    try:
        token = base64.b64decode(encoded, validate=True)
    except binascii.Error as exc:
        raise ValueError("invalid base64") from exc
    if len(token) < 12 or len(token) > MAX_TOKEN:
        raise ValueError("invalid NTLM token length")
    if token[:8] != NTLM_SIGNATURE or struct.unpack_from("<I", token, 8)[0] != message_type:
        raise ValueError("unexpected NTLM message")
    return token


def raw_exchange(host, port, negotiate, authenticate, timeout):
    with socket.create_connection((host, port), timeout=timeout) as relay:
        relay.settimeout(timeout)
        relay.sendall(struct.pack("=h", len(negotiate)) + negotiate)
        length = struct.unpack("=h", read_exact(relay, 2))[0]
        if length < 12 or length > MAX_TOKEN:
            raise ValueError("invalid RAW challenge length")
        challenge = read_exact(relay, length)
        if challenge[:8] != NTLM_SIGNATURE or struct.unpack_from("<I", challenge, 8)[0] != 2:
            raise ValueError("invalid RAW challenge")
        authenticate(challenge, relay)
        length = struct.unpack("=h", read_exact(relay, 2))[0]
        if length != 1:
            raise ValueError("invalid RAW result length")
        result = read_exact(relay, 1)
        if result not in (b"\x00", b"\x01"):
            raise ValueError("invalid RAW result")
        return result == b"\x01"


class ImapServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, context, relay, timeout, implicit_tls):
        self.context = context
        self.relay = relay
        self.timeout = timeout
        self.implicit_tls = implicit_tls
        super().__init__(address, ImapHandler)

class ImapHandler(socketserver.BaseRequestHandler):
    def send(self, data):
        self.request.sendall(data + b"\r\n")

    def token_line(self):
        line = read_line(self.request)
        if line == b"*":
            raise InterruptedError("authentication cancelled")
        return line

    def authenticate(self, tag, initial):
        if not self.tls_active:
            self.send(tag + b" NO TLS required")
            return
        try:
            if initial is None:
                self.send(b"+")
                initial = self.token_line()
            negotiate = ntlm_token(initial, 1)

            def finish(challenge, relay):
                self.send(b"+ " + base64.b64encode(challenge))
                response = ntlm_token(self.token_line(), 3)
                relay.sendall(struct.pack("=h", len(response)) + response)

            accepted = raw_exchange(*self.server.relay, negotiate, finish, self.server.timeout)
        except InterruptedError:
            self.send(tag + b" BAD Authentication cancelled")
            return
        except (EOFError, OSError, ValueError) as exc:
            logging.info("%s relay failed: %s", self.client_address[0], exc)
            self.send(tag + b" NO AUTHENTICATE failed")
            return
        self.send(tag + (b" OK AUTHENTICATE completed" if accepted else b" NO AUTHENTICATE failed"))
        self.authenticated = accepted
        logging.info("%s relay %s", self.client_address[0], "accepted" if accepted else "rejected")

    def handle(self):
        original = self.request
        self.request.settimeout(self.server.timeout)
        self.tls_active = False
        self.authenticated = False
        try:
            if self.server.implicit_tls:
                self.request = self.server.context.wrap_socket(self.request, server_side=True)
                self.request.settimeout(self.server.timeout)
                self.tls_active = True
            self.send(b"* OK IMAP4rev1 ready")
            while True:
                line = read_line(self.request)
                parts = line.split(b" ", 3)
                if len(parts) < 2 or not TAG.fullmatch(parts[0]):
                    self.send(b"* BAD Invalid command")
                    continue
                tag, command = parts[0], parts[1].upper()
                if command == b"CAPABILITY":
                    capabilities = b"IMAP4rev1 AUTH=NTLM SASL-IR" if self.tls_active else b"IMAP4rev1 STARTTLS LOGINDISABLED"
                    self.send(b"* CAPABILITY " + capabilities)
                    self.send(tag + b" OK CAPABILITY completed")
                elif command == b"STARTTLS" and not self.tls_active and len(parts) == 2:
                    self.send(tag + b" OK Begin TLS negotiation")
                    self.request = self.server.context.wrap_socket(self.request, server_side=True)
                    self.request.settimeout(self.server.timeout)
                    self.tls_active = True
                elif command == b"AUTHENTICATE" and len(parts) in (3, 4) and parts[2].upper() == b"NTLM" and not self.authenticated:
                    self.authenticate(tag, parts[3] if len(parts) == 4 else None)
                elif command == b"NOOP" and len(parts) == 2:
                    self.send(tag + b" OK NOOP completed")
                elif command == b"ID":
                    self.send(b"* ID NIL")
                    self.send(tag + b" OK ID completed")
                elif command == b"LOGOUT" and len(parts) == 2:
                    self.send(b"* BYE Logging out")
                    self.send(tag + b" OK LOGOUT completed")
                    break
                else:
                    self.send(tag + b" BAD Unsupported command")
        except (EOFError, OSError) as exc:
            logging.info("%s closed: %s", self.client_address[0], exc)
        except ValueError as exc:
            logging.info("%s rejected: %s", self.client_address[0], exc)
            self.send(b"* BAD Invalid command")
        finally:
            if self.request is not original:
                self.request.close()


def main():
    parser = argparse.ArgumentParser(description="IMAP NTLM frontend for Impacket's RAW relay listener")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=1143)
    parser.add_argument("--relay-host", default="127.0.0.1")
    parser.add_argument("--relay-port", type=int, default=6666)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--implicit-tls", action="store_true")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    if not 0 < args.timeout <= 300:
        parser.error("--timeout must be between 0 and 300 seconds")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    with ImapServer((args.listen_host, args.listen_port), context,
                    (args.relay_host, args.relay_port), args.timeout, args.implicit_tls) as server:
        logging.info("listening on %s:%s", *server.server_address)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
