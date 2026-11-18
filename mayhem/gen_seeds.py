#!/usr/bin/env python3
"""Regenerates the starter seeds under mayhem/<target>/testsuite/ (run from the repo root)."""
import os
import struct

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)))


def put(target, name, data):
    d = os.path.join(ROOT, target, "testsuite")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())


# --- fuzz_seasmart ---------------------------------------------------------------------------
for i, s in enumerate([
    "$PCDIN,01F119,00000000,0F,2AAF00D1067414FF*59",
    "$PCDIN,01f119,00000000,0f,2aaf00d1067414ff*59\n",
    "$PCDIN,01F112,0000AC05,23,0110277FFF7FFFFD*24",
    "$PCDIN,01F010,0000AC05,23,0110277FFF7FFFFD*",
    "$PCDIN,01F010,0000AC05,",
    "$PCDIN,01F119,00000000,0F,2AAF00D1067414FF*99",
]):
    put("fuzz_seasmart", "seed%d" % i, s)


# --- fuzz_actisense --------------------------------------------------------------------------
def actisense(msgtype, body):
    payload = bytes([msgtype, len(body)]) + body
    crc = (256 - (sum(payload) % 256)) % 256
    out = bytearray([0x10, 0x02])
    for b in payload + bytes([crc]):
        out.append(b)
        if b == 0x10:
            out.append(0x10)
    out += bytes([0x10, 0x03])
    return bytes(out)


def n2k_data(pgn, data, src=65, dst=255, prio=6, ts=1234):
    body = bytes([prio, pgn & 255, (pgn >> 8) & 255, pgn >> 16, dst, src]) + struct.pack("<I", ts) + bytes([len(data)]) + data
    return actisense(0x93, body)


def n2k_request(pgn, data, dst=255, prio=6):
    body = bytes([prio, pgn & 255, (pgn >> 8) & 255, pgn >> 16, dst, len(data)]) + data
    return actisense(0x94, body)


attitude = bytes([42, 0xAF, 0x00, 0xD1, 0x06, 0x74, 0x14, 0xFF])
put("fuzz_actisense", "attitude", bytes([65]) + n2k_data(127257, attitude))
put("fuzz_actisense", "escaped_dle", bytes([65]) + n2k_data(127250, bytes([1, 0x10, 0x10, 0x10, 0x10, 0xFF, 0x7F, 0xFF])))
put("fuzz_actisense", "request", bytes([65]) + n2k_request(59904, bytes([0x14, 0xF0, 0x01])))
put("fuzz_actisense", "two_messages", bytes([3]) + n2k_data(127257, attitude) + n2k_data(129026, bytes([1, 0, 0, 0, 0, 0, 0, 0xFF])))
put("fuzz_actisense", "garbage_then_frame", bytes([65]) + b"\x00\x10\x05hello" + n2k_data(127257, attitude))
put("fuzz_actisense", "truncated", bytes([65]) + n2k_data(127257, attitude)[:-5])


# --- fuzz_canbus -----------------------------------------------------------------------------
def can_id(pgn, src, dst=255, prio=6):
    pf = (pgn >> 8) & 255
    if pf < 240:
        pgn = (pgn & 0x3FF00) | dst
    return (prio << 26) | (pgn << 8) | src


def frame(pgn, src, data, dst=255, prio=6):
    assert len(data) <= 8
    return struct.pack("<IB", can_id(pgn, src, dst, prio), len(data)) + data


def fast_packet(pgn, src, data, seq=1, dst=255):
    out = b""
    first = bytes([seq << 5, len(data)]) + data[:6]
    out += frame(pgn, src, first.ljust(8, b"\xff"), dst)
    rest, n = data[6:], 1
    while rest:
        out += frame(pgn, src, (bytes([(seq << 5) | n]) + rest[:7]).ljust(8, b"\xff"), dst)
        rest, n = rest[7:], n + 1
    return out


def header(mode, config, step):
    return bytes([mode, config, step])


name = bytes([0x01, 0x23, 0x45, 0x00, 0x20, 0x8C, 0x82, 0xC0])
prod_info = struct.pack("<HHH", 2100, 1234, 0) + b"Model ID".ljust(32, b"\xff") + b"1.0.0".ljust(32, b"\xff") + b"1.0".ljust(32, b"\xff") + b"000001".ljust(32, b"\xff") + bytes([1, 1])
heartbeat = struct.pack("<HBBBBH", 60000, 0, 0, 0xFF, 0xFF, 0xFF)[:8]
req_name = bytes([0x00, 0xEE, 0x00])
req_prod = bytes([0x14, 0xF0, 0x01])
gf_request = bytes([0x00, 0x14, 0xF0, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00])  # PGN 126208 payload

claim = frame(60928, 40, name)
common = (
    claim
    + fast_packet(126996, 40, prod_info)
    + frame(126993, 40, heartbeat)
    + frame(59904, 50, req_name, dst=20)
    + frame(59904, 50, req_prod, dst=255)
    + fast_packet(126208, 50, gf_request, dst=20)
    + frame(127257 & 0x3FFFF, 40, bytes([42, 0xAF, 0x00, 0xD1, 0x06, 0x74, 0x14, 0xFF]))
)
put("fuzz_canbus", "node_and_listen", header(2, 0x10, 5) + common)
put("fuzz_canbus", "listen_only_text", header(0, 0x06, 1) + common)
put("fuzz_canbus", "two_devices", header(1, 0x09, 20) + common + claim)
put("fuzz_canbus", "claim_conflict", header(2, 0x00, 3) + frame(60928, 20, name) + frame(60928, 20, bytes([0x00] * 8)) + frame(60928, 21, name))
put("fuzz_canbus", "fast_packet_stream", header(4, 0x08, 2) + fast_packet(129029, 41, bytes(range(43))) + fast_packet(129029, 41, bytes(range(43)), seq=2))
put("fuzz_canbus", "tp_rts", header(2, 0x00, 4) + frame(60416, 40, bytes([16, 20, 0, 3, 3, 0x14, 0xF0, 0x01]), dst=20))


# --- fuzz_n2kmessages: selector byte + data field ------------------------------------------------
put("fuzz_n2kmessages", "sel0_attitude", bytes([0]) + attitude)
put("fuzz_n2kmessages", "sel5_zeros", bytes([5]) + bytes(8))
put("fuzz_n2kmessages", "sel9_ff", bytes([9]) + b"\xff" * 16)
put("fuzz_n2kmessages", "sel20_text", bytes([20]) + bytes([1, 0, 0, 20, 33]) + b"Hello NMEA2000 world")
put("fuzz_n2kmessages", "sel40_long", bytes([40]) + bytes(range(1, 90)))
# CZone (selectors 54, 55) and Maretron (56, 57, 58) decoders: proprietary-id header, then the fields.
put("fuzz_n2kmessages", "sel54_czone_single", bytes([54, 0x27, 0x99, 1, 0x1E, 0x2A, 0, 0, 0]))
put("fuzz_n2kmessages", "sel55_czone_fastpacket", bytes([55, 0x27, 0x99, 2, 0x1E, 0x15, 0xAA, 0xBB, 0xCC]))
put("fuzz_n2kmessages", "sel56_maretron_temp", bytes([56, 0x89, 0x98, 1, 0, 2, 0x9C, 0x0B, 0x9C, 0x0B]))
put("fuzz_n2kmessages", "sel57_maretron_flow", bytes([57, 0x89, 0x98, 1, 0, 3, 0xE8, 0x03, 0x00]))
put("fuzz_n2kmessages", "sel58_maretron_trip", bytes([58, 0x89, 0x98, 1, 0, 3, 0x64, 0x00, 0x00]))
