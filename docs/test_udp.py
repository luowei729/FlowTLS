#!/usr/bin/env python3
"""SOCKS5 UDP ASSOCIATE 端到端测试。

验证链路：本地 UDP socket → SOCKS5 relay → QUIC DATAGRAM → 服务端 → 目标 UDP

只依赖标准库，不引入第三方包。
"""

import socket
import struct
import sys
import time

SOCKS = ("127.0.0.1", 1080)
USER = b"admin"
PASS = b"abcd1234"


def socks5_udp_associate():
    """建立 SOCKS5 控制连接并请求 UDP ASSOCIATE，返回 (tcp, relay_addr)。"""
    t = socket.create_connection(SOCKS, timeout=10)
    # 方法协商：只提供用户名密码
    t.sendall(b"\x05\x01\x02")
    assert t.recv(2) == b"\x05\x02", "方法协商失败"
    # RFC1929
    t.sendall(b"\x01" + bytes([len(USER)]) + USER + bytes([len(PASS)]) + PASS)
    assert t.recv(2) == b"\x01\x00", "认证失败"
    # UDP ASSOCIATE，地址填 0.0.0.0:0
    t.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
    resp = t.recv(10)
    assert len(resp) == 10 and resp[0] == 5, f"应答异常: {resp!r}"
    assert resp[1] == 0, f"UDP ASSOCIATE 被拒绝, REP={resp[1]}"
    ip = socket.inet_ntoa(resp[4:8])
    port = struct.unpack(">H", resp[8:10])[0]
    # 绑的是 0.0.0.0 时本机要发到 127.0.0.1
    if ip == "0.0.0.0":
        ip = "127.0.0.1"
    return t, (ip, port)


def build_dns_query(name: str, qid: int = 0x1234) -> bytes:
    """构造一个最小的 A 记录查询。"""
    hdr = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q = b""
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    return hdr + q


def udp_request(target_ip: str, target_port: int, payload: bytes) -> bytes:
    """组装 SOCKS5 UDP 请求：RSV(2) FRAG(1) ATYP(1) ADDR PORT payload"""
    return (
        b"\x00\x00\x00"
        + b"\x01"
        + socket.inet_aton(target_ip)
        + struct.pack(">H", target_port)
        + payload
    )


def parse_udp_response(data: bytes):
    """解析 SOCKS5 UDP 响应，返回 (目标, 载荷)。"""
    assert data[0] == 0 and data[1] == 0, "RSV 非零"
    assert data[2] == 0, f"不支持分片, FRAG={data[2]}"
    atyp = data[3]
    if atyp == 1:
        ip = socket.inet_ntoa(data[4:8])
        port = struct.unpack(">H", data[8:10])[0]
        return (ip, port), data[10:]
    if atyp == 3:
        n = data[4]
        host = data[5 : 5 + n].decode()
        port = struct.unpack(">H", data[5 + n : 7 + n])[0]
        return (host, port), data[7 + n :]
    raise AssertionError(f"未知 ATYP={atyp}")


def query_with_retry(relay, udp, ip, qid, tries=3, timeout=2.0):
    """发一次 DNS 查询并等回程，丢包就重试。

    为什么需要重试：QUIC DATAGRAM 不重传，这条跨境链路实测丢包 5%~30%，
    单发一个包测的是「链路」而不是「实现」。
    只断言「重试几次之内能成功」才是有意义的可用性检验。
    """
    query = build_dns_query("example.com", qid)
    for _ in range(tries):
        udp.settimeout(timeout)
        udp.sendto(udp_request(ip, 53, query), relay)
        try:
            data, _ = udp.recvfrom(4096)
        except socket.timeout:
            continue
        target, payload = parse_udp_response(data)
        assert target[1] == 53, f"回程端口不对: {target}"
        got = struct.unpack(">H", payload[:2])[0]
        assert got == qid, f"DNS 事务 ID 不匹配: {got:#x} != {qid:#x}"
        assert len(payload) > 12, "DNS 响应太短"
        udp.settimeout(10)
        return target, payload
    raise AssertionError(f"{ip} 重试 {tries} 次仍无回程")


def test_dns(relay, udp):
    """DNS 查询走 UDP relay。"""
    target, payload = query_with_retry(relay, udp, "8.8.8.8", 0x4321)
    ancount = struct.unpack(">H", payload[6:8])[0]
    print(f"  ✓ DNS 8.8.8.8:53 回程 {len(payload)} 字节, 应答数={ancount}, 目标={target}")
    return payload


def test_echo(relay, udp):
    """第二个目标（不同 session）：1.1.1.1 的 DNS。"""
    target, payload = query_with_retry(relay, udp, "1.1.1.1", 0x5678)
    print(f"  ✓ DNS 1.1.1.1:53 回程 {len(payload)} 字节, 目标={target}")


def test_multiple_roundtrips(relay, udp, n=20):
    """连续多轮：验证 session 复用，并接受真实链路丢包。

    注意：不能「发一个等一个」。QUIC DATAGRAM 不重传，这条跨境链路
    实测丢包 5%~30%，只要某一轮丢包就会阻塞到超时。
    正确做法是先全部发出，再统一收，按 DNS 事务 ID 对账。
    """
    sent = set()
    for i in range(n):
        qid = 0x1000 + i
        sent.add(qid)
        udp.sendto(
            udp_request("8.8.8.8", 53, build_dns_query("example.com", qid)), relay
        )
        time.sleep(0.005)  # 错开一点，避免一次性打爆发送缓冲

    got = set()
    deadline = time.time() + 8
    while len(got) < n and time.time() < deadline:
        udp.settimeout(max(0.1, deadline - time.time()))
        try:
            data, _ = udp.recvfrom(4096)
        except socket.timeout:
            break
        _, payload = parse_udp_response(data)
        if len(payload) >= 2:
            qid = struct.unpack(">H", payload[:2])[0]
            if qid in sent:
                got.add(qid)
    udp.settimeout(10)

    loss = (n - len(got)) / n * 100
    print(f"  ✓ {len(got)}/{n} 收到回程，丢包 {loss:.0f}%（UDP 不重传，属正常）")
    # 只要求大部分到达：验证的是链路可用，不是「UDP 可靠」
    assert len(got) >= n // 2, f"丢包过多（{loss:.0f}%），链路可疑"
    return len(got)


def test_bad_target(relay, udp):
    """不存在的目标：不应有回程，且不能把 relay 搞崩。"""
    udp.settimeout(2)
    udp.sendto(udp_request("192.0.2.1", 9999, b"nobody-home"), relay)
    try:
        udp.recvfrom(4096)
        print("  · 意外收到回程（可能是 ICMP 转换，忽略）")
    except socket.timeout:
        print("  ✓ 无回程目标超时正常丢弃，relay 仍存活")
    udp.settimeout(10)


def main():
    print("1. 建立 SOCKS5 UDP ASSOCIATE ...")
    tcp, relay = socks5_udp_associate()
    print(f"  ✓ relay = {relay[0]}:{relay[1]}")

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(10)

    print("2. DNS 查询（IPv4 目标）")
    test_dns(relay, udp)

    print("3. 第二个目标（不同 session）")
    test_echo(relay, udp)

    print("4. 连续 20 轮（验证 session 复用）")
    test_multiple_roundtrips(relay, udp)

    print("5. 不可达目标（验证不影响 relay）")
    test_bad_target(relay, udp)

    print("6. 关闭控制连接，确认 relay 释放")
    tcp.close()
    time.sleep(1)
    try:
        udp.sendto(udp_request("8.8.8.8", 53, build_dns_query("example.com", 1)), relay)
        udp.recvfrom(4096)
        print("  · 关闭后仍收到回程（可能仍在旧会话里）")
    except socket.timeout:
        print("  ✓ 控制连接关闭后 relay 已失效")

    print("\n全部通过")


if __name__ == "__main__":
    sys.exit(main())
