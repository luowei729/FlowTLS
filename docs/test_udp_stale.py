#!/usr/bin/env python3
"""验证「UDP 会话失效后能否自愈」。

场景：向一个不可达的 UDP 端口发包 → 服务端收到 ICMP port unreachable
→ `sock.recv` 返回错误 → 出站任务退出。

期望：会话被删除，后续包能重新建会话（表现为服务端 udp_sessions 回落）。
"""
import socket
import struct
import sys
import time

SOCKS = ("127.0.0.1", 1080)
USER, PASS = b"admin", b"abcd1234"


def associate():
    t = socket.create_connection(SOCKS, timeout=10)
    t.sendall(b"\x05\x01\x02")
    assert t.recv(2) == b"\x05\x02"
    t.sendall(b"\x01" + bytes([len(USER)]) + USER + bytes([len(PASS)]) + PASS)
    assert t.recv(2) == b"\x01\x00"
    t.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
    r = t.recv(10)
    ip = socket.inet_ntoa(r[4:8])
    port = struct.unpack(">H", r[8:10])[0]
    return t, ("127.0.0.1" if ip == "0.0.0.0" else ip, port)


def frame(ip, port, payload):
    return b"\x00\x00\x00\x01" + socket.inet_aton(ip) + struct.pack(">H", port) + payload


def main():
    tcp, relay = associate()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(1)
    print(f"relay = {relay}")

    # 持续向不可达端口发包，每 2 秒 1 个，共 20 秒
    for i in range(10):
        udp.sendto(frame("127.0.0.1", 9999, b"ping-%02d" % i), relay)
        try:
            udp.recvfrom(4096)
            print("  ? 意外收到回程")
        except socket.timeout:
            pass
        time.sleep(2)
        print(f"  第 {i+1} 轮已发送")
    tcp.close()
    print("完成：请在服务端观察 udp_sessions 是否回落")


if __name__ == "__main__":
    sys.exit(main())
