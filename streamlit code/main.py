"""
Classical Cryptography Toolkit - Web App (Streamlit)
--------------------------------------------------------
Run locally with:   streamlit run streamlit_app.py
Deploy free at:      https://share.streamlit.io
"""

import math
import random
import string
import time

import numpy as np
import streamlit as st

ALPHABET = string.ascii_uppercase


# =========================================================
# CIPHER LOGIC
# =========================================================

# ---- Caesar ----
def caesar_encrypt(text, key):
    key = int(key) % 26
    result = []
    for ch in text:
        if ch.isupper():
            result.append(chr((ord(ch) - 65 + key) % 26 + 65))
        elif ch.islower():
            result.append(chr((ord(ch) - 97 + key) % 26 + 97))
        else:
            result.append(ch)
    return "".join(result)


def caesar_decrypt(text, key):
    return caesar_encrypt(text, -int(key))


# ---- Monoalphabetic ----
def mono_generate_key():
    letters = list(ALPHABET)
    random.shuffle(letters)
    return "".join(letters)


def _mono_validate_key(key):
    key = key.upper()
    if len(key) != 26 or set(key) != set(ALPHABET):
        raise ValueError("Key must be a 26-letter permutation of A-Z")
    return key


def mono_encrypt(text, key):
    key = _mono_validate_key(key)
    mapping = str.maketrans(ALPHABET, key)
    mapping_lower = str.maketrans(ALPHABET.lower(), key.lower())
    return text.translate(mapping).translate(mapping_lower)


def mono_decrypt(text, key):
    key = _mono_validate_key(key)
    mapping = str.maketrans(key, ALPHABET)
    mapping_lower = str.maketrans(key.lower(), ALPHABET.lower())
    return text.translate(mapping).translate(mapping_lower)


# ---- Playfair ----
def _playfair_build_square(key):
    key = "".join(ch.upper() for ch in key if ch.isalpha()).replace("J", "I")
    seen = []
    for ch in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            seen.append(ch)
    return [seen[i * 5:(i + 1) * 5] for i in range(5)]


def _playfair_locate(square, ch):
    for r, row in enumerate(square):
        if ch in row:
            return r, row.index(ch)
    raise ValueError(f"Character {ch} not in square")


def _playfair_prepare(text):
    text = "".join(ch.upper() for ch in text if ch.isalpha()).replace("J", "I")
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else "X"
        if a == b:
            pairs.append((a, "X"))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    return pairs


def playfair_encrypt(text, key):
    square = _playfair_build_square(key)
    pairs = _playfair_prepare(text)
    result = []
    for a, b in pairs:
        ra, ca = _playfair_locate(square, a)
        rb, cb = _playfair_locate(square, b)
        if ra == rb:
            result.append(square[ra][(ca + 1) % 5])
            result.append(square[rb][(cb + 1) % 5])
        elif ca == cb:
            result.append(square[(ra + 1) % 5][ca])
            result.append(square[(rb + 1) % 5][cb])
        else:
            result.append(square[ra][cb])
            result.append(square[rb][ca])
    return "".join(result)


def playfair_decrypt(text, key):
    square = _playfair_build_square(key)
    text = "".join(ch.upper() for ch in text if ch.isalpha())
    pairs = [(text[i], text[i + 1]) for i in range(0, len(text) - 1, 2)]
    result = []
    for a, b in pairs:
        ra, ca = _playfair_locate(square, a)
        rb, cb = _playfair_locate(square, b)
        if ra == rb:
            result.append(square[ra][(ca - 1) % 5])
            result.append(square[rb][(cb - 1) % 5])
        elif ca == cb:
            result.append(square[(ra - 1) % 5][ca])
            result.append(square[(rb - 1) % 5][cb])
        else:
            result.append(square[ra][cb])
            result.append(square[rb][ca])
    return "".join(result)


# ---- Hill ----
def _hill_parse_key(key):
    nums = [int(x) for x in key.replace(",", " ").split()]
    n = int(len(nums) ** 0.5)
    if n * n != len(nums):
        raise ValueError("Key must form a square matrix (e.g. 4 numbers for 2x2)")
    return np.array(nums).reshape(n, n)


def _hill_mod_inverse_matrix(matrix, modulus=26):
    det = int(round(np.linalg.det(matrix)))
    det_mod = det % modulus
    det_inv = None
    for i in range(1, modulus):
        if (det_mod * i) % modulus == 1:
            det_inv = i
            break
    if det_inv is None:
        raise ValueError("Key matrix is not invertible mod 26. Choose another key.")
    n = matrix.shape[0]
    cofactors = np.zeros((n, n), dtype=int)
    for r in range(n):
        for c in range(n):
            minor = np.delete(np.delete(matrix, r, axis=0), c, axis=1)
            cofactors[r][c] = ((-1) ** (r + c)) * int(round(np.linalg.det(minor)))
    adjugate = cofactors.T
    return (det_inv * adjugate) % modulus


def _hill_text_to_nums(text):
    return [ord(ch.upper()) - 65 for ch in text if ch.isalpha()]


def _hill_nums_to_text(nums):
    return "".join(chr(int(n) % 26 + 65) for n in nums)


def hill_encrypt(text, key):
    matrix = _hill_parse_key(key)
    n = matrix.shape[0]
    nums = _hill_text_to_nums(text)
    while len(nums) % n != 0:
        nums.append(ord("X") - 65)
    result = []
    for i in range(0, len(nums), n):
        block = np.array(nums[i:i + n])
        result.extend(matrix.dot(block) % 26)
    return _hill_nums_to_text(result)


def hill_decrypt(text, key):
    matrix = _hill_parse_key(key)
    inverse = _hill_mod_inverse_matrix(matrix)
    n = matrix.shape[0]
    nums = _hill_text_to_nums(text)
    result = []
    for i in range(0, len(nums), n):
        block = np.array(nums[i:i + n])
        result.extend(inverse.dot(block) % 26)
    return _hill_nums_to_text(result)


# ---- Vigenere ----
def _vigenere_key_stream(text, key):
    key = "".join(ch for ch in key if ch.isalpha())
    if not key:
        raise ValueError("Key must contain at least one letter")
    key = key.upper()
    stream = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            stream.append(key[ki % len(key)])
            ki += 1
        else:
            stream.append(None)
    return stream


def vigenere_encrypt(text, key):
    stream = _vigenere_key_stream(text, key)
    result = []
    for ch, k in zip(text, stream):
        if k is None:
            result.append(ch)
        else:
            shift = ord(k) - 65
            base = 65 if ch.isupper() else 97
            result.append(chr((ord(ch) - base + shift) % 26 + base))
    return "".join(result)


def vigenere_decrypt(text, key):
    stream = _vigenere_key_stream(text, key)
    result = []
    for ch, k in zip(text, stream):
        if k is None:
            result.append(ch)
        else:
            shift = ord(k) - 65
            base = 65 if ch.isupper() else 97
            result.append(chr((ord(ch) - base - shift) % 26 + base))
    return "".join(result)


# ---- One-Time Pad ----
def otp_generate_key(length):
    return "".join(random.choice(ALPHABET) for _ in range(length))


def otp_encrypt(text, key=None):
    letters_count = sum(1 for ch in text if ch.isalpha())
    if not key:
        key = otp_generate_key(letters_count)
    key = "".join(ch for ch in key if ch.isalpha()).upper()
    if len(key) < letters_count:
        raise ValueError("Key must be at least as long as the plaintext letters")
    result = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[ki]) - 65
            ki += 1
            base = 65 if ch.isupper() else 97
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result), key[:letters_count]


def otp_decrypt(text, key):
    key = "".join(ch for ch in key if ch.isalpha()).upper()
    result = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[ki]) - 65
            ki += 1
            base = 65 if ch.isupper() else 97
            result.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


# ---- Rail Fence ----
def railfence_encrypt(text, key):
    rails_count = int(key)
    if rails_count < 2:
        raise ValueError("Number of rails must be at least 2")
    rails = [[] for _ in range(rails_count)]
    rail, direction = 0, 1
    for ch in text:
        rails[rail].append(ch)
        if rail == 0:
            direction = 1
        elif rail == rails_count - 1:
            direction = -1
        rail += direction
    return "".join("".join(r) for r in rails)


def railfence_decrypt(text, key):
    rails_count = int(key)
    if rails_count < 2:
        raise ValueError("Number of rails must be at least 2")
    pattern = []
    rail, direction = 0, 1
    for _ in text:
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails_count - 1:
            direction = -1
        rail += direction

    counts = [pattern.count(r) for r in range(rails_count)]
    idx = 0
    rails_content = []
    for c in counts:
        rails_content.append(list(text[idx:idx + c]))
        idx += c

    pointers = [0] * rails_count
    result = []
    for r in pattern:
        result.append(rails_content[r][pointers[r]])
        pointers[r] += 1
    return "".join(result)


# ---- Columnar Transposition ----
def _columnar_key_order(key):
    return sorted(range(len(key)), key=lambda i: (key[i], i))


def columnar_encrypt(text, key):
    key = key.upper()
    ncols = len(key)
    nrows = math.ceil(len(text) / ncols)
    padded = text + "X" * (nrows * ncols - len(text))
    grid = [padded[r * ncols:(r + 1) * ncols] for r in range(nrows)]
    order = _columnar_key_order(key)
    result = []
    for col in order:
        for row in grid:
            result.append(row[col])
    return "".join(result)


def columnar_decrypt(text, key):
    key = key.upper()
    ncols = len(key)
    nrows = math.ceil(len(text) / ncols)
    order = _columnar_key_order(key)

    cols_data = {}
    idx = 0
    for col in order:
        cols_data[col] = text[idx:idx + nrows]
        idx += nrows

    result = []
    for r in range(nrows):
        for c in range(ncols):
            result.append(cols_data[c][r])
    return "".join(result).rstrip("X")


# =========================================================
# CIPHER REGISTRY
# =========================================================
CIPHERS = {
    "Caesar Cipher": (caesar_encrypt, caesar_decrypt, "Integer shift, e.g. 5"),
    "Monoalphabetic Cipher": (mono_encrypt, mono_decrypt,
                                "26-letter key (leave blank to auto-generate)"),
    "Playfair Cipher": (playfair_encrypt, playfair_decrypt, "Keyword, e.g. MONARCHY"),
    "Hill Cipher": (hill_encrypt, hill_decrypt,
                     "Square matrix numbers, e.g. 3 3 2 5"),
    "Vigenere Cipher": (vigenere_encrypt, vigenere_decrypt, "Keyword, e.g. LEMON"),
    "One-Time Pad": (None, None, "Leave blank to auto-generate a random key"),
    "Rail Fence Cipher": (railfence_encrypt, railfence_decrypt,
                            "Number of rails, e.g. 3"),
    "Columnar Transposition": (columnar_encrypt, columnar_decrypt,
                                 "Keyword, e.g. ZEBRA"),
}

DEMO_KEYS = {
    "Caesar Cipher": "3",
    "Monoalphabetic Cipher": None,  # generated fresh on each comparison run
    "Playfair Cipher": "KEYWORD",
    "Hill Cipher": "3 3 2 5",
    "Vigenere Cipher": "LEMON",
    "Rail Fence Cipher": "3",
    "Columnar Transposition": "ZEBRA",
}


# =========================================================
# STREAMLIT UI
# =========================================================
st.set_page_config(page_title="Classical Cryptography Toolkit", page_icon="🔐",
                    layout="centered")

st.title("🔐 Classical Cryptography Toolkit")
st.caption("Substitution & Transposition Ciphers - Network Security Mini Project")

tab1, tab2, tab3 = st.tabs(["Encrypt / Decrypt", "Compare Algorithms", "Help"])

# ---------- Tab 1: Encrypt / Decrypt ----------
with tab1:
    cipher_name = st.selectbox("Select Cipher", list(CIPHERS.keys()))
    st.caption(f"Key format: {CIPHERS[cipher_name][2]}")

    plaintext = st.text_area("Enter Plaintext", value="NETWORK SECURITY", height=100)
    key_input = st.text_input("Enter Key", value="5" if cipher_name == "Caesar Cipher" else "")

    if st.button("Encrypt && Decrypt", type="primary"):
        if not plaintext.strip():
            st.warning("Please enter plaintext.")
        else:
            try:
                if cipher_name == "One-Time Pad":
                    encrypted, used_key = otp_encrypt(plaintext, key_input or None)
                    decrypted = otp_decrypt(encrypted, used_key)
                    st.success("Done")
                    st.text_input("Key Used", value=used_key, disabled=True)
                    st.text_area("Encrypted Text", value=encrypted, height=80)
                    st.text_area("Decrypted Text", value=decrypted, height=80)
                else:
                    encrypt_fn, decrypt_fn, _ = CIPHERS[cipher_name]
                    key = key_input
                    if cipher_name == "Monoalphabetic Cipher" and not key:
                        key = mono_generate_key()
                        st.info(f"Auto-generated key: {key}")
                    encrypted = encrypt_fn(plaintext, key)
                    decrypted = decrypt_fn(encrypted, key)
                    st.success("Done")
                    st.text_area("Encrypted Text", value=encrypted, height=80)
                    st.text_area("Decrypted Text", value=decrypted, height=80)
            except Exception as e:
                st.error(f"Error: {e}")

# ---------- Tab 2: Compare Algorithms ----------
with tab2:
    sample_text = st.text_input("Enter sample plaintext to compare",
                                 value="NETWORK SECURITY")
    if st.button("Compare All Ciphers"):
        rows = []
        for name, (encrypt_fn, _, _) in CIPHERS.items():
            if name == "One-Time Pad":
                continue
            key = DEMO_KEYS[name] or mono_generate_key()
            try:
                start = time.perf_counter()
                result = encrypt_fn(sample_text, key)
                elapsed = (time.perf_counter() - start) * 1000
                rows.append({"Cipher": name, "Key Used": key,
                             "Ciphertext": result, "Time (ms)": f"{elapsed:.3f}"})
            except Exception as e:
                rows.append({"Cipher": name, "Key Used": key,
                             "Ciphertext": f"Error: {e}", "Time (ms)": "-"})
        otp_result, otp_key = otp_encrypt(sample_text, None)
        rows.append({"Cipher": "One-Time Pad", "Key Used": otp_key,
                     "Ciphertext": otp_result, "Time (ms)": "-"})
        st.table(rows)

# ---------- Tab 3: Help ----------
with tab3:
    st.markdown("""
**How to use:**
1. Pick a cipher from the dropdown.
2. Enter plaintext and a key.
3. Click **Encrypt && Decrypt** to see both results at once.

**Key formats**

| Cipher | Key format |
|---|---|
| Caesar | integer, e.g. `5` |
| Monoalphabetic | 26-letter permutation of A-Z, or blank to auto-generate |
| Playfair / Vigenere | a keyword, e.g. `MONARCHY` |
| Hill | space-separated numbers forming a square matrix, e.g. `3 3 2 5` (2x2) |
| One-Time Pad | blank to auto-generate, or a key at least as long as the plaintext letters |
| Rail Fence | integer number of rails, e.g. `3` |
| Columnar Transposition | a keyword, e.g. `ZEBRA` |
""")
