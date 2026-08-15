"""
RED phase: tests for AppendInfo crypto — write before implementation.

AppendInfo = base64(AES-CBC-PKCS7("<n>:<ne(n)>", key, IV=0001..0f))
key = MD5^Iterations(password + challenge)  (hex chain)
ne(n): t=|n·sin n|, m=|n·cos n|; swap if t<m; m=m||t; int(6.28·m + 4·(t-m))
tokenKeyNum starts at 11 and increments.
"""

import base64
import hashlib
import math
from unittest.mock import patch


def _ne(n: float) -> int:
    """Reference implementation of ne(n) from PROTOCOL.md."""
    t = abs(n * math.sin(n))
    m = abs(n * math.cos(n))
    if t < m:
        t, m = m, t
    if m == 0:
        m = t
    return int(6.28 * m + 4 * (t - m))


def _aes_cbc_pkcs7(
    plaintext: bytes, key_hex: str, iv_hex: str = "000102030405060708090a0b0c0d0e0f"
) -> bytes:
    """AES-CBC PKCS7 padding, using pycryptodome."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, 16))


def _derive_key(password: str, challenge: str, iterations: int) -> str:
    """MD5^Iterations(password + challenge) hex chain."""
    result = hashlib.md5((password + challenge).encode()).hexdigest()
    for _ in range(1, iterations):
        result = hashlib.md5(result.encode()).hexdigest()
    return result


def _build_append_info(key_num: int, password: str, challenge: str, iterations: int) -> str:
    """Reference AppendInfo builder."""
    key = _derive_key(password, challenge, iterations)
    plaintext = f"{key_num}:{_ne(key_num)}".encode()
    encrypted = _aes_cbc_pkcs7(plaintext, key)
    return base64.b64encode(encrypted).decode()


class TestNeFunction:
    """ne(n) formula tests — verify the math."""

    def test_ne_values_deterministic(self):
        """ne(n) is deterministic and produces positive integers."""
        for n in [11, 12, 13, 14, 15]:
            result = _ne(n)
            assert isinstance(result, int), f"ne({n}) must return int"
            assert result >= 0, f"ne({n}) must be non-negative, got {result}"


class TestKeyDerivation:
    """MD5^Iterations key chain."""

    def test_md5_chain_single_iteration(self):
        """One iteration = one MD5 of password+challenge."""
        result = hashlib.md5(("pass" + "chal").encode()).hexdigest()
        assert len(result) == 32

    def test_md5_chain_100_iterations(self):
        """100 iterations produces a 32-hex string."""
        result = _derive_key("pass", "chal", 100)
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)


class TestAppendInfo:
    """AppendInfo generation — must match reference implementation exactly."""

    def test_append_info_base64_encoded(self):
        """AppendInfo is a base64 string."""
        from hikcentral_bumblebee import BumblebeeClient

        with patch("hikcentral_bumblebee.client.httpx.Client"):
            cli = BumblebeeClient("https://fake", "user", "pass")
            cli._aes_key = _derive_key("pass", "deadbeef", 100)
            cli._token_key_num = 11

            info = cli._build_append_info()
            # Must decode without error
            decoded = base64.b64decode(info)
            assert len(decoded) == 16  # one AES block

    def test_append_info_token_num_increments(self):
        """Token key number increments starting from 11."""
        from hikcentral_bumblebee import BumblebeeClient

        with patch("hikcentral_bumblebee.client.httpx.Client"):
            cli = BumblebeeClient("https://fake", "user", "pass")
            cli._aes_key = _derive_key("pass", "deadbeef", 100)
            cli._token_key_num = 11

            info_11 = cli._build_append_info()
            cli._token_key_num = 12
            info_12 = cli._build_append_info()

            assert info_11 != info_12

    def test_append_info_matches_reference(self):
        """AppendInfo produced by client matches hand-rolled reference."""
        from hikcentral_bumblebee import BumblebeeClient

        password = "myPassword"
        challenge = "cafebabe1234"
        iterations = 100

        with patch("hikcentral_bumblebee.client.httpx.Client"):
            cli = BumblebeeClient("https://fake", "user", password)
            cli._aes_key = _derive_key(password, challenge, iterations)
            cli._token_key_num = 11

            actual = cli._build_append_info()
            expected = _build_append_info(11, password, challenge, iterations)

            assert actual == expected, (
                f"AppendInfo mismatch:\n  actual:   {actual}\n  expected: {expected}"
            )

    def test_append_info_decrypts_correctly(self):
        """The AppendInfo can be decrypted with the derived key."""
        from hikcentral_bumblebee import BumblebeeClient
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad

        password = "secret"
        challenge = "challenge48"
        iterations = 100
        key = _derive_key(password, challenge, iterations)

        with patch("hikcentral_bumblebee.client.httpx.Client"):
            cli = BumblebeeClient("https://fake", "user", password)
            cli._aes_key = key
            cli._token_key_num = 11

            info = cli._build_append_info()
            encrypted_bytes = base64.b64decode(info)

            iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
            cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted_bytes), 16)
            decrypted_str = decrypted.decode()

            n_str, ne_str = decrypted_str.split(":")
            assert int(n_str) == 11
            assert int(ne_str) == _ne(11)
