import socket
import ssl
import time
from typing import Dict, Any, Optional, Tuple

DEFAULT_TIMEOUT = 10.0

IMMEDIATE_TLS_PORTS = {443, 465, 636, 993, 995, 994, 8443}
STARTTLS_PORTS = {25: "smtp", 587: "smtp", 110: "pop3", 143: "imap", 21: "ftp"}

def _recv_all(sock: socket.socket, timeout: float, end_marker: Optional[bytes] = None, max_bytes: int = 65536) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    start = time.time()
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
            if end_marker and end_marker in buf:
                break
            if len(buf) >= max_bytes:
                break
        except socket.timeout:
            break
        except Exception:
            break
        if time.time() - start > timeout:
            break
    return bytes(buf)


def _recv_until_code(sock: socket.socket, timeout: float, codes: Tuple[int, ...]) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    start = time.time()
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            buf.extend(data)
            try:
                txt = buf.decode("utf-8", errors="replace")
                lines = txt.split("\r\n")
            except Exception:
                lines = []
            # find last non-empty line
            for line in reversed(lines):
                if not line:
                    continue
                parts = line.split()
                if parts:
                    code_str = parts[0]
                    if len(code_str) >= 3 and code_str[:3].isdigit():
                        try:
                            code = int(code_str[:3])
                            if len(line) >= 4 and line[3] == " " or (len(line) == 3):
                                if code in codes:
                                    return bytes(buf)
                        except Exception:
                            pass
        except socket.timeout:
            break
        except Exception:
            break
        if time.time() - start > timeout:
            break
    return bytes(buf)


def _wrap_socket_and_collect(sock: socket.socket, server_hostname: str, timeout: float) -> Dict[str, Any]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # dont enable insecure legacy ciphers
    try:
        ssock = context.wrap_socket(sock, server_hostname=server_hostname, do_handshake_on_connect=True)
    except Exception:
        raise
    try:
        proto = ssock.version() or "UNKNOWN"
        cipher = ssock.cipher() or ("UNKNOWN", 0, "")
        try:
            der = ssock.getpeercert(binary_form=True)
        except Exception:
            der = None
        try:
            ssock.close()
        except Exception:
            pass
        return {"protocol": proto, "cipher": cipher, "der_cert": der}
    finally:
        pass


def _do_starttls_smtp(sock: socket.socket, server_hostname: str, timeout: float) -> Tuple[bool, bytes]:
    raw = bytearray()
    banner = _recv_until_code(sock, timeout, (220,))
    raw.extend(banner)
    try:
        ehlo_cmd = f"EHLO {server_hostname}\r\n".encode("utf-8")
        sock.sendall(ehlo_cmd)
    except Exception:
        return False, bytes(raw)
    resp = _recv_until_code(sock, timeout, (250,))
    raw.extend(resp)
    try:
        sock.sendall(b"STARTTLS\r\n")
    except Exception:
        return False, bytes(raw)
    resp2 = _recv_until_code(sock, timeout, (220,))
    raw.extend(resp2)
    ok = False
    try:
        txt = resp2.decode("utf-8", errors="replace")
        if txt.startswith("220") or "220" in txt.splitlines()[-1]:
            ok = True
    except Exception:
        ok = False
    return ok, bytes(raw)


def _do_starttls_imap(sock: socket.socket, server_hostname: str, timeout: float) -> Tuple[bool, bytes]:
    raw = bytearray()
    banner = _recv_all(sock, timeout)
    raw.extend(banner)
    try:
        sock.sendall(b"a001 CAPABILITY\r\n")
    except Exception:
        return False, bytes(raw)
    resp = _recv_all(sock, timeout)
    raw.extend(resp)
    try:
        sock.sendall(b"a002 STARTTLS\r\n")
    except Exception:
        return False, bytes(raw)
    resp2 = _recv_all(sock, timeout)
    raw.extend(resp2)
    ok = b"OK" in resp2.upper()
    return ok, bytes(raw)


def _do_starttls_pop3(sock: socket.socket, server_hostname: str, timeout: float) -> Tuple[bool, bytes]:
    raw = bytearray()
    banner = _recv_all(sock, timeout)
    raw.extend(banner)
    try:
        sock.sendall(b"STLS\r\n")
    except Exception:
        return False, bytes(raw)
    resp = _recv_all(sock, timeout)
    raw.extend(resp)
    ok = resp.startswith(b"+OK")
    return ok, bytes(raw)


def _do_starttls_ftp(sock: socket.socket, server_hostname: str, timeout: float) -> Tuple[bool, bytes]:
    raw = bytearray()
    banner = _recv_all(sock, timeout)
    raw.extend(banner)
    try:
        sock.sendall(b"AUTH TLS\r\n")
    except Exception:
        return False, bytes(raw)
    resp = _recv_all(sock, timeout)
    raw.extend(resp)
    ok = resp.startswith(b"234") or resp.startswith(b"2")
    return ok, bytes(raw)


def probe(host: str, port: Optional[int] = None, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    server = host
    server_port = port or 443
    if ":" in host and host.count(":") == 1 and not host.startswith("["):
        try:
            h, p = host.split(":")
            server = h
            server_port = int(p)
        except Exception:
            server = host

    server_hostname = server
    out: Dict[str, Any] = {
        "host": host,
        "port": server_port,
        "server_hostname": server_hostname,
        "service_attempted": None,
        "pre_tls_banner": None,
        "protocol": None,
        "cipher": None,
        "der_cert": None,
        "error": None,
    }

    sock = None
    try:
        sock = socket.create_connection((server, server_port), timeout=timeout)
    except Exception as e:
        out["error"] = f"tcp_error: {e}"
        return out

    if server_port in IMMEDIATE_TLS_PORTS:
        out["service_attempted"] = "direct-tls"
        try:
            res = _wrap_socket_and_collect(sock, server_hostname, timeout)
            out.update(res)
            return out
        except ssl.SSLError as se:
            out["error"] = f"ssl_error: {se}"
            try:
                sock.close()
            except Exception:
                pass
            return out
        except Exception as e:
            out["error"] = f"tls_wrap_failed: {e}"
            try:
                sock.close()
            except Exception:
                pass
            return out

    if server_port in STARTTLS_PORTS:
        svc = STARTTLS_PORTS[server_port]
        out["service_attempted"] = f"starttls-{svc}"
        try:
            if svc == "smtp":
                ok, pre = _do_starttls_smtp(sock, server_hostname, timeout)
            elif svc == "imap":
                ok, pre = _do_starttls_imap(sock, server_hostname, timeout)
            elif svc == "pop3":
                ok, pre = _do_starttls_pop3(sock, server_hostname, timeout)
            elif svc == "ftp":
                ok, pre = _do_starttls_ftp(sock, server_hostname, timeout)
            else:
                ok, pre = False, b""
            out["pre_tls_banner"] = pre.decode("utf-8", errors="replace")
            if not ok:
                out["error"] = "starttls_not_offered_or_failed"
                try:
                    sock.close()
                except Exception:
                    pass
                return out
            try:
                res = _wrap_socket_and_collect(sock, server_hostname, timeout)
                out.update(res)
                return out
            except ssl.SSLError as se:
                out["error"] = f"ssl_error_after_starttls: {se}"
                try:
                    sock.close()
                except Exception:
                    pass
                return out
            except Exception as e:
                out["error"] = f"tls_after_starttls_failed: {e}"
                try:
                    sock.close()
                except Exception:
                    pass
                return out
        except Exception as e:
            out["pre_tls_banner"] = out.get("pre_tls_banner") or ""
            out["error"] = f"starttls_exchange_error: {e}"
            try:
                sock.close()
            except Exception:
                pass
            return out

    out["service_attempted"] = "direct-tls-or-plaintext"
    try:
        res = _wrap_socket_and_collect(sock, server_hostname, timeout)
        out.update(res)
        return out
    except ssl.SSLError as se:
        try:
            pre = _recv_all(sock, 1.0)
            out["pre_tls_banner"] = pre.decode("utf-8", errors="replace")
        except Exception:
            out["pre_tls_banner"] = None
        out["error"] = f"ssl_error: {se}"
        try:
            sock.close()
        except Exception:
            pass
        return out
    except Exception as e:
        try:
            pre = _recv_all(sock, 1.0)
            out["pre_tls_banner"] = pre.decode("utf-8", errors="replace")
        except Exception:
            out["pre_tls_banner"] = None
        out["error"] = f"unknown_error: {e}"
        try:
            sock.close()
        except Exception:
            pass
        return out
