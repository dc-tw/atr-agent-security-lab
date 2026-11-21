from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from urllib.parse import unquote

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "і": "i",
        "ј": "j",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Χ": "X",
        "α": "a",
        "ο": "o",
    }
)
_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
_SPACED_WORD = re.compile(r"(?<!\w)(?:[A-Za-z][\s._-]+){3,}[A-Za-z](?!\w)")
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/])")


def _decode_escape(match: re.Match[str]) -> str:
    return chr(int(match.group(1) or match.group(2), 16))


def _join_spaced_word(match: re.Match[str]) -> str:
    return re.sub(r"[^A-Za-z]", "", match.group(0))


def _decoded_base64(value: str, *, max_decoded_bytes: int) -> list[str]:
    decoded: list[str] = []
    for token in _BASE64.findall(value)[:8]:
        try:
            raw = base64.b64decode(token, validate=True)
            if not raw or len(raw) > max_decoded_bytes:
                continue
            text = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(character.isprintable() or character.isspace() for character in text)
        if printable / len(text) >= 0.9:
            decoded.append(text)
    return decoded


def normalize_for_atr(value: str, *, max_decoded_bytes: int = 8_192) -> str:
    """Return a bounded deobfuscated view without replacing the original evidence value."""

    original = str(value)
    normalized = html.unescape(original)
    for _ in range(2):
        decoded = unquote(normalized)
        if decoded == normalized:
            break
        normalized = decoded
    normalized = _ESCAPE.sub(_decode_escape, normalized)
    normalized = unicodedata.normalize("NFKC", normalized).translate(_ZERO_WIDTH)
    normalized = normalized.translate(_HOMOGLYPHS)
    normalized = _SPACED_WORD.sub(_join_spaced_word, normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    views = [normalized, *_decoded_base64(normalized, max_decoded_bytes=max_decoded_bytes)]
    unique = [view for index, view in enumerate(views) if view and view not in views[:index]]
    if unique == [original]:
        return original
    return original + "\n[ATR normalized view]\n" + "\n".join(unique)
