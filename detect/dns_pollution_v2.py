# -*- coding: utf-8 -*-
import argparse
import socket
import random
import struct
import string
def hexdump(src: bytes, width: int = 16) -> None:
    """按行打印十六进制和 ASCII（不可打印字符用 . 表示）"""
    for i in range(0, len(src), width):
        chunk = src[i : i + width]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        ascii_bytes = "".join(chr(b) if chr(b) in string.printable and b >= 0x20 else "." for b in chunk)
        print(f"{i:04x}  {hex_bytes:<{width*3}}  {ascii_bytes}")

def build_malformed_dns_query(domain_name):
    """
    构造一个简单的 DNS 查询报文：
      - txid: 事务 ID（16 位）
      - flags: 标准查询，递归查询 (0x0100)
      - qdcount=1, ancount=0, nscount=0, arcount=0
      - question: 域名 + QTYPE=A(1) + QCLASS=CS(2)
    返回字节串。
    """
    # 1. DNS Header （12 字节）
    # >H = 16-bit unsigned，>BB = 8-bit unsigned
    txid = random.randint(0,0xFFFF)
    flags = 0x0100  # 标准查询 + 递归
    qdcount = 1
    ancount = 1
    nscount = arcount = 0
    header = struct.pack(">HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)

    # 2. Question 部分：QNAME
    # DNS 域名以标签（label）形式存储，每段前置一个长度字节，末尾以 0x00 结束
    qname = b""
    for label in domain_name.split("."):
        qname += struct.pack("B", len(label)) + label.encode()
    qname += b"\x00"  # 结束

    # QTYPE = 1(A 记录), QCLASS = 5(Invaild)
    qtype = 1
    qclass = 5
    question = qname + struct.pack(">HH", qtype, qclass)
    payload = header + question
    hexdump(payload)
    return payload


def is_dns_cache_pollution_response(domain, server="8.8.8.8", port=53, timeout=2):
    """
    发起 DNS 查询
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    query = build_malformed_dns_query(domain)
    flags = 1
    try:
        sock.sendto(query, (server, port))
        data, _ = sock.recvfrom(512)  # DNS UDP 最多 512 字节
        print("Recived data ...")
        hexdump(data)
        _, flags = struct.unpack(">HH", data[:4])
    finally:
        sock.close()
    return (flags & 0x0F) != 2

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="查询当前域名是否被 DNS 缓存投毒"
    )
    parser.add_argument(
        "domain",
        help="要查询的域名，例如 example.com"
    )
    args = parser.parse_args()
    domain = args.domain
    print(f"send A records payload for {domain} ...")
    is_pollution = is_dns_cache_pollution_response(domain)
    if is_pollution:
        print("[+]Detected DNS cache pollution")
    else:
        print("[+]No DNS cache pollution detected.")
