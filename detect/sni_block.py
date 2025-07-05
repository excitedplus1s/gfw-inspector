# -*- coding: utf-8 -*-
import argparse
import os
import random
import socket
import string
import struct
import time

def hexdump(src: bytes, width: int = 16) -> None:
    """按行打印十六进制和 ASCII（不可打印字符用 . 表示）"""
    for i in range(0, len(src), width):
        chunk = src[i : i + width]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        ascii_bytes = "".join(chr(b) if chr(b) in string.printable and b >= 0x20 else "." for b in chunk)
        print(f"{i:04x}  {hex_bytes:<{width*3}}  {ascii_bytes}")

def build_client_hello(hostname: str) -> bytes:
    # 1. TLS Record Layer header (5 bytes)
    #    ContentType = 0x16(handshake), Version = 0x0303(TLS1.2), Length = total_handshake_bytes
    # 2. Handshake Layer header (4 bytes)
    #    HandshakeType = 0x01(ClientHello), length = len(body) (3 bytes)
    #
    # 3. ClientHello body:
    #    - legacy_version (2 bytes): 0x0303
    #    - random (32 bytes): 4 bytes gmt_unix + 28 bytes random
    #    - session_id: length(1 byte)=0
    #    - cipher_suites: length(2 bytes) + suites (2 bytes each)
    #    - compression_methods: length(1 byte)=1 + method 0x00
    #    - extensions: length(2 bytes) + [each extension]
    
    # -- ClientHello body --
    body = b""
    # legacy_version
    body += b"\x03\x03"
    # random: 4-byte timestamp + 28-byte random
    gmt_unix = struct.pack("!I", int(time.time()))
    rand_bytes = os.urandom(28)
    body += gmt_unix + rand_bytes
    # session_id (32-bytes)
    body += b"\x20"
    body += os.urandom(32)
    # cipher_suites 
    cipher_suites = [
        0x1301, # TLS_AES_128_GCM_SHA256 (TLS1.3，兼容性向下)
        0x1302, # TLS_AES_256_GCM_SHA384
        0x1303, # TLS_CHACHA20_POLY1305_SHA256
        0xC02F, # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC02B, # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0x009E, # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        0x009C, # TLS_RSA_WITH_AES_128_GCM_SHA256
        0xC030, # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xC02C, # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0x009F, # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        0x006B, # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        0x003C, # TLS_RSA_WITH_AES_128_CBC_SHA256
        0x002F, # TLS_RSA_WITH_AES_128_CBC_SHA
        0x000A, # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    ]
    cs_bytes = b"".join(struct.pack("!H", cs) for cs in cipher_suites)
    body += struct.pack("!H", len(cs_bytes)) + cs_bytes
    # compression_methods (只支持 null)
    body += b"\x01\x00"
    # ---- extensions ----
    ext_data = b""
    # 1) SNI 扩展 (0x0000)
    server_name = hostname.encode()
    # extension header: type(2) + length(2)
    # SNI inner: list_length(2) + name_type(1) + name_length(2) + name
    sni_inner = (
        struct.pack("!H", len(server_name) + 3)  # list_length = name_type(1) + name_length(2) + host
        + b"\x00"                                 # name_type = host_name(0)
        + struct.pack("!H", len(server_name))    # name_length
        + server_name
    )
    ext_data += (
        struct.pack("!H", 0x0000)             # extension type = SNI
        + struct.pack("!H", len(sni_inner))   # extension length
        + sni_inner
    )
    body += struct.pack("!H", len(ext_data)) + ext_data

    # ---- wrap with handshake header ----
    handshake = b"\x01"  # HandshakeType = ClientHello
    handshake += struct.pack("!I", len(body))[1:]  # 3-byte length
    handshake += body

    # ---- wrap with TLS record header ----
    record = b"\x16"      # ContentType = Handshake
    record += b"\x03\x03" # Version = TLS1.2
    record += struct.pack("!H", len(handshake))
    record += handshake

    return record

def get_fake_dst_domain():
    not_block_domains = [
                            'example.com',
                            'example.net',
                            'example.org',
                            'example.edu',
                            'www.un.org', # 联合国
                            'www.wto.org', # 世界贸易组织
                            'www.adb.org', # 亚洲开发银行
                            'www.olympics.com', #国际奥林匹克委员会
                            'www.icrc.org' # 国际红十字组织
                         ]
    idx = random.randrange(len(not_block_domains))
    return not_block_domains[idx]

def send_client_hello(host: str, port: int = 443):
    data = build_client_hello(host)
    # 建立 TCP 连接
    fake_domain = get_fake_dst_domain()
    print("使用%s作为目的IP" % fake_domain)
    with socket.create_connection((fake_domain, port)) as sock:
        # 发送 ClientHello
        sock.sendall(data)
        print("send payload...")
        hexdump(data)
        try:
            print("Detect block status...")
            resp = sock.recv(4096)
            hexdump(resp)
        except ConnectionResetError:
            print("[+]Detect SNI block")
            return
    print("[+]No SNI block detected")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="查询当前域名是否被 SNI 阻断"
    )
    parser.add_argument(
        "domain",
        help="要查询的域名，例如 google.com"
    )
    args = parser.parse_args()
    domain = args.domain
    send_client_hello(domain, 443)
