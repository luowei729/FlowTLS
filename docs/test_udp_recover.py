#!/usr/bin/env python3
"""验证「UDP 会话失效后被回收」的修复。

向 127.0.0.1:1（服务端本机的关闭端口）发若干包：
- 第 1 个包建会话 → 目标回 ICMP port unreachable → `sock.recv` 返回错误 → 出站任务退出；
- 修复前：会话条目永远留在表里（每来一个包就刷新 last_active），
  后续到同一目标的包全部黑洞，只能等 120 秒空闲超时；
- 修复后：条目立刻删掉，下一个包重新建会话（建-死-建-死循环），
  `udp_sessions` 不会增长。

观察方式：运行本脚本，对比服务端日志里 udp_sessions 的变化。
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
    assert r[1] == 0, f"UDP ASSOCIATE 失败 REP={r[1]}"
    ip = socket.inet_ntoa(r[4:8])
    port = struct.unpack(">H", r[8:10])[0]
    return t, ("127.0.0.1" if ip == "0.0.0.0" else ip, port)


def main():
    tcp, relay = associate()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(1)
    print(f"relay = {relay}")
    # 每 1 秒一个，共 8 个，全部指向服务端的关闭端口
    for i in range(8):
        pkt = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", 1) + b"x%02d" % i
        udp.sendto(pkt, relay)
        print(f"  发送 x{i:02d}")
        time.sleep(1)
    tcp.close()
    print("完成：服务端 udp_sessions 应回到基线（不累积、不残留）")


if __name__ == "__main__":
    sys.exit(main())
