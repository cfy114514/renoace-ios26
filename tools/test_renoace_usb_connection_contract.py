#!/usr/bin/env python3
"""Synthetic P12 EP0 challenge and DMA-stop contract model.

The model defines the evidence required for a future XNU USB computer
connection. It does not access a phone, USB controller, DMA engine, or host.
"""
import hashlib
import json
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out/analysis/p12-usb-connection-contract.json"
BUILD_ID = "a9b58102cfe98e75"
PAGE = 0x1000


@dataclass(frozen=True)
class Buffer:
    name: str
    address: int
    bytes: int

    def valid(self):
        return self.address % PAGE == 0 and self.bytes > 0 and self.bytes % PAGE == 0

    def end(self):
        return self.address + self.bytes


def overlap(a, b):
    return max(a.address, b.address) < min(a.end(), b.end())


def response(build_id, nonce):
    payload = b"RENOACE-P12\0" + build_id.encode("ascii") + b"\0" + nonce
    return payload + struct.pack("<I", zlib.crc32(payload) & 0xFFFFFFFF)


def verify_response(data, build_id, nonce):
    if len(data) < 4 or not data.startswith(b"RENOACE-P12\0") or not data.endswith(struct.pack("<I", zlib.crc32(data[:-4]) & 0xFFFFFFFF)):
        return False
    return build_id.encode("ascii") + b"\0" + nonce in data


def run():
    nonce = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    buffers = [Buffer("setup", 0x82000000, PAGE), Buffer("event", 0x82001000, PAGE), Buffer("trb", 0x82002000, PAGE), Buffer("response", 0x82003000, PAGE)]
    valid_layout = all(item.valid() for item in buffers) and not any(overlap(a, b) for i, a in enumerate(buffers) for b in buffers[i + 1:])
    descriptor = bytes((0x12, 0x01, 0x00, 0x02, 0, 0, 0, 64, 0x10, 0x27, 0x01, 0x00, 0, 0, 1, 2, 3, 1))
    setup = struct.pack("<BBHHH", 0x80, 6, 0x0100, 0, len(descriptor))
    challenge = struct.pack("<BBHHH", 0xC0, 0x52, 1, 0, len(nonce))
    reply = response(BUILD_ID, nonce)
    bad_nonce = bytes(reversed(nonce))
    stopped = ["disable_run_stop", "wait_event_quiet", "stop_trb_fetch", "confirm_no_dma", "unmap_iova", "restore_saved_state"]
    cases = {
        "device_descriptor_request": setup == bytes.fromhex("8006000100001200"),
        "vendor_challenge_request": challenge == bytes.fromhex("c052010000002000"),
        "fresh_nonce_response": verify_response(reply, BUILD_ID, nonce) and not verify_response(reply, BUILD_ID, bad_nonce),
        "page_aligned_nonoverlap_buffers": valid_layout,
        "stop_sequence_has_dma_quiet_before_unmap": stopped.index("confirm_no_dma") < stopped.index("unmap_iova"),
        "overlap_rejected": overlap(buffers[0], Buffer("bad", buffers[0].address, PAGE)),
        "unaligned_rejected": not Buffer("bad", 0x82000001, PAGE).valid(),
    }
    return {
        "passed": all(cases.values()),
        "hardware_tested": False,
        "device_access": False,
        "usb_started": False,
        "dma_access_verified": False,
        "build_id": BUILD_ID,
        "protocol": {"ep0_descriptor": "GET_DESCRIPTOR(DEVICE)", "challenge": "vendor IN bRequest=0x52", "nonce_bytes": len(nonce), "response_sha256": hashlib.sha256(reply).hexdigest()},
        "buffers": [item.__dict__ | {"end": item.end()} for item in buffers],
        "stop_sequence": stopped,
        "cases": cases,
        "scope": "synthetic P12 EP0 challenge/response and DMA-stop contract; no phone, USB, DMA, IOVA, or computer handshake",
        "remaining": ["host must observe the response while XNU is running", "real controller/PHY/SMMU ownership and endpoint timing remain unverified"],
    }


def main():
    result = run()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
