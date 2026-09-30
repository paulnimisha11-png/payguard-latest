"""Minimal, fast DEX reader.

We only need three tables from each classes*.dex file:
  * string_ids  -> every string constant in the code (URLs, bot tokens, USSD codes...)
  * type_ids    -> class names
  * method_ids  -> every method the code *references* (e.g. SmsManager.sendTextMessage)

Parsing just these tables is O(size of tables) and takes milliseconds even on
large apps, unlike full bytecode disassembly. Malformed input never raises;
it just yields fewer results.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

MAX_STRINGS = 400_000  # safety cap per dex


@dataclass
class DexScan:
    strings: list[str] = field(default_factory=list)
    method_refs: set[str] = field(default_factory=set)   # "Landroid/telephony/SmsManager;->sendTextMessage"
    classes: set[str] = field(default_factory=set)
    dex_count: int = 0
    errors: list[str] = field(default_factory=list)


def _uleb128(buf: bytes, off: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if b < 0x80 or shift > 28:
            return result, off
        shift += 7


def _read_string(buf: bytes, off: int) -> str:
    _, off = _uleb128(buf, off)
    end = buf.find(b"\x00", off)
    if end == -1:
        end = len(buf)
    # MUTF-8 is close enough to UTF-8 for our purposes
    return buf[off:end].decode("utf-8", errors="replace")


def scan_dex(buf: bytes, out: DexScan) -> None:
    if len(buf) < 0x70 or not buf.startswith(b"dex\n"):
        out.errors.append("not a dex file")
        return
    try:
        (str_size, str_off, type_size, type_off) = struct.unpack_from("<4I", buf, 0x38)
        (meth_size, meth_off) = struct.unpack_from("<2I", buf, 0x58)
        str_size = min(str_size, MAX_STRINGS)

        strings: list[str] = []
        for i in range(str_size):
            (data_off,) = struct.unpack_from("<I", buf, str_off + 4 * i)
            try:
                strings.append(_read_string(buf, data_off))
            except Exception:
                strings.append("")

        types: list[str] = []
        for i in range(type_size):
            (idx,) = struct.unpack_from("<I", buf, type_off + 4 * i)
            types.append(strings[idx] if idx < len(strings) else "")

        for i in range(meth_size):
            cls_idx, _proto, name_idx = struct.unpack_from("<HHI", buf, meth_off + 8 * i)
            if cls_idx < len(types) and name_idx < len(strings):
                out.method_refs.add(f"{types[cls_idx]}->{strings[name_idx]}")

        out.strings.extend(strings)
        out.classes.update(types)
        out.dex_count += 1
    except Exception as e:  # truncated / corrupted dex
        out.errors.append(f"dex parse error: {e}")
