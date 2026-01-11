import streamlit as st
import hashlib
import random
import base64

from ecdsa import SigningKey, VerifyingKey, SECP256k1, NIST256p

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(page_title="Crypto Suite", page_icon="🔐", layout="wide")

# ==========================================
# RSA MATH (NO external crypto libs)
# ==========================================
class RSAMath:
    @staticmethod
    def is_prime(n, k=40):
        if n in (2, 3):
            return True
        if n % 2 == 0 or n < 2:
            return False

        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k):
            a = random.randrange(2, n - 2)
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def generate_prime_candidate(length):
        p = random.getrandbits(length)
        p |= (1 << length - 1) | 1
        return p

    @staticmethod
    def generate_prime_number(length=256):
        p = 4
        while not RSAMath.is_prime(p):
            p = RSAMath.generate_prime_candidate(length)
        return p

    @staticmethod
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, y, x = RSAMath.extended_gcd(b % a, a)
        return g, x - (b // a) * y, y

    @staticmethod
    def mod_inverse(a, m):
        g, x, _ = RSAMath.extended_gcd(a, m)
        if g != 1:
            raise Exception("Mod inverse does not exist")
        return x % m

    @staticmethod
    def text_to_int(text):
        return int.from_bytes(text.encode("utf-8"), "big")

    @staticmethod
    def int_to_text(number):
        try:
            return number.to_bytes((number.bit_length() + 7) // 8, "big").decode("utf-8")
        except:
            return "[Error: invalid UTF-8 output]"


# ==========================================
# ECC (Manual) for ECDH demo
# ==========================================
class ECC:
    def __init__(self, a, b, p, G):
        self.a = a
        self.b = b
        self.p = p
        self.G = G

    def inv_mod(self, x):
        return pow(x, self.p - 2, self.p)

    def point_add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        # P + (-P) = O
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None

        # doubling
        if P == Q:
            m = ((3 * x1 * x1 + self.a) * self.inv_mod(2 * y1)) % self.p
        else:
            m = ((y2 - y1) * self.inv_mod(x2 - x1)) % self.p

        x3 = (m * m - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def scalar_mult(self, k, P):
        R = None
        Q = P
        while k > 0:
            if k & 1:
                R = self.point_add(R, Q)
            Q = self.point_add(Q, Q)
            k >>= 1
        return R


# Demo ECC curve (fast)
ECC_CURVE = ECC(a=2, b=3, p=97, G=(3, 6))


# ==========================================
# APP UI
# ==========================================
st.title("🔐 Crypto Suite (Streamlit)")
st.caption("Hashing • Avalanche • Compare • RSA (manual) • ECC (manual ECDH) • ECDSA (library)")

algos = [
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
    "blake2b", "blake2s"
]
algos = [a for a in algos if a in hashlib.algorithms_available]

tabs = st.tabs(["1) Hashing", "2) Avalanche", "3) Compare", "4) RSA", "5) ECC (ECDH)", "6) ECDSA Signature"])

# ==========================================
# TAB 1: HASHING
# ==========================================
with tabs[0]:
    st.subheader("✅ Hashing:  f(x) = hash(x)")
    x = st.text_area("Enter input text (x):", height=120)

    st.write("### Select Hash Algorithms:")
    cols = st.columns(4)

    selected_algos = []
    for i, algo in enumerate(algos):
        with cols[i % 4]:
            if st.checkbox(algo.upper(), value=(algo in ["md5", "sha1", "sha256"]), key=f"h_{algo}"):
                selected_algos.append(algo)

    if st.button("Calculate Hash"):
        if not x.strip():
            st.error("Please enter text.")
        elif not selected_algos:
            st.warning("Select at least one algorithm.")
        else:
            rows = []
            data = x.encode("utf-8")

            for algo in selected_algos:
                h = hashlib.new(algo)
                h.update(data)
                rows.append({
                    "Algorithm": algo.upper(),
                    "Bits": h.digest_size * 8,
                    "Hash (Hex)": h.hexdigest()
                })

            st.success("Hash calculated ✅")
            st.dataframe(rows, use_container_width=True)

# ==========================================
# TAB 2: AVALANCHE
# ==========================================
with tabs[1]:
    st.subheader("✅ Avalanche Effect Study")

    if "av1" not in st.session_state:
        st.session_state["av1"] = ""
    if "av2" not in st.session_state:
        st.session_state["av2"] = ""

    col1, col2 = st.columns(2)
    with col1:
        st.text_area("Text 1 (Original x):", key="av1", height=120)
    with col2:
        st.text_area("Text 2 (Modified x'):", key="av2", height=120)

    def auto_modify():
        base = st.session_state["av1"].strip() or "a"
        st.session_state["av2"] = base[:-1] + chr((ord(base[-1]) + 1) % 127)

    st.button("Auto Modify Text 2", on_click=auto_modify)

    algo_choice = st.multiselect("Select algorithms:", algos, default=["sha256", "sha512", "md5"])

    if st.button("Compare Avalanche"):
        t1 = st.session_state["av1"]
        t2 = st.session_state["av2"]

        if not t1.strip() or not t2.strip():
            st.error("Enter both texts.")
        else:
            results = []
            for algo in algo_choice:
                h1 = hashlib.new(algo, t1.encode()).hexdigest()
                h2 = hashlib.new(algo, t2.encode()).hexdigest()
                diff = int(h1, 16) ^ int(h2, 16)
                flipped = bin(diff).count("1")
                total_bits = len(h1) * 4
                pct = (flipped / total_bits) * 100

                results.append({
                    "Algorithm": algo.upper(),
                    "Bits Flipped": flipped,
                    "Total Bits": total_bits,
                    "Avalanche %": round(pct, 2)
                })

            st.success("Avalanche effect computed ✅")
            st.dataframe(results, use_container_width=True)

# ==========================================
# TAB 3: COMPARE
# ==========================================
with tabs[2]:
    st.subheader("✅ Hash Compare: ht1(x1) = ht2(x2)")

    x1 = st.text_input("Input x1:", key="cmp1")
    x2 = st.text_input("Input x2:", key="cmp2")
    algo = st.selectbox("Algorithm:", [a.upper() for a in algos], index=algos.index("sha256"))

    if st.button("Check Equality"):
        if not x1 or not x2:
            st.error("Enter both inputs.")
        else:
            h1 = hashlib.new(algo.lower(), x1.encode()).hexdigest()
            h2 = hashlib.new(algo.lower(), x2.encode()).hexdigest()
            st.write("### Hash Output")
            st.code(h1)
            st.code(h2)

            if h1 == h2:
                st.success("MATCH ✅")
            else:
                st.error("NOT MATCH ❌")

# ==========================================
# TAB 4: RSA
# ==========================================
with tabs[3]:
    st.subheader("✅ RSA (Manual Implementation)")

    if "pub" not in st.session_state:
        st.session_state["pub"] = None
        st.session_state["priv"] = None
        st.session_state["cipher"] = ""

    key_size = st.selectbox("RSA key size:", [512, 1024], index=0)

    if st.button("Generate RSA Keys"):
        with st.spinner("Generating keys..."):
            p = RSAMath.generate_prime_number(key_size // 2)
            q = RSAMath.generate_prime_number(key_size // 2)
            n = p * q
            phi = (p - 1) * (q - 1)
            e = 65537
            d = RSAMath.mod_inverse(e, phi)
            st.session_state["pub"] = (e, n)
            st.session_state["priv"] = (d, n)
        st.success("RSA keys generated ✅")

    if st.session_state["pub"]:
        e, n = st.session_state["pub"]
        d, _ = st.session_state["priv"]

        st.code(f"Public Key:\n e={e}\n n={n}\n\nPrivate Key:\n d={d}\n n={n}")

        msg = st.text_input("Message:", key="rsa_msg")

        if st.button("Encrypt RSA"):
            if not msg.strip():
                st.warning("Enter message")
            else:
                m = RSAMath.text_to_int(msg)
                if m >= n:
                    st.error("Message too long for key.")
                else:
                    st.session_state["cipher"] = str(pow(m, e, n))
                    st.success("Encrypted ✅")

        cipher = st.text_input("Ciphertext int:", value=st.session_state.get("cipher", ""), key="rsa_cipher")

        if st.button("Decrypt RSA"):
            try:
                c = int(cipher)
                m = pow(c, d, n)
                st.success("Decrypted ✅")
                st.code(RSAMath.int_to_text(m))
            except:
                st.error("Invalid ciphertext.")
    else:
        st.info("Generate keys first.")

# ==========================================
# TAB 5: ECC (ECDH + XOR)
# ==========================================
with tabs[4]:
    st.subheader("✅ ECC using ECDH + XOR Encryption")
    st.caption("ECC generates shared secret, message encrypted using symmetric XOR (demo).")

    st.code(f"Curve: y² = x³ + {ECC_CURVE.a}x + {ECC_CURVE.b} (mod {ECC_CURVE.p})\nBase Point G = {ECC_CURVE.G}")

    def xor_encrypt(data_bytes, key_int):
        key_bytes = str(key_int).encode()
        out = bytearray()
        for i, b in enumerate(data_bytes):
            out.append(b ^ key_bytes[i % len(key_bytes)])
        return bytes(out)

    if "ecc_priv" not in st.session_state:
        st.session_state["ecc_priv"] = None
        st.session_state["ecc_pub"] = None
        st.session_state["ecc_peer_priv"] = None
        st.session_state["ecc_peer_pub"] = None
        st.session_state["ecc_cipher_hex"] = ""

    colA, colB = st.columns(2)

    with colA:
        if st.button("Generate My ECC Keys"):
            d = random.randint(2, ECC_CURVE.p - 2)
            Q = ECC_CURVE.scalar_mult(d, ECC_CURVE.G)
            while Q is None:
                d = random.randint(2, ECC_CURVE.p - 2)
                Q = ECC_CURVE.scalar_mult(d, ECC_CURVE.G)
            st.session_state["ecc_priv"] = d
            st.session_state["ecc_pub"] = Q
            st.success("My keys generated ✅")

        if st.session_state["ecc_priv"]:
            st.code(f"My Private d = {st.session_state['ecc_priv']}\nMy Public Q = {st.session_state['ecc_pub']}")

    with colB:
        if st.button("Generate Peer ECC Keys"):
            d2 = random.randint(2, ECC_CURVE.p - 2)
            Q2 = ECC_CURVE.scalar_mult(d2, ECC_CURVE.G)
            while Q2 is None:
                d2 = random.randint(2, ECC_CURVE.p - 2)
                Q2 = ECC_CURVE.scalar_mult(d2, ECC_CURVE.G)
            st.session_state["ecc_peer_priv"] = d2
            st.session_state["ecc_peer_pub"] = Q2
            st.success("Peer keys generated ✅")

        if st.session_state["ecc_peer_priv"]:
            st.code(f"Peer Private d2 = {st.session_state['ecc_peer_priv']}\nPeer Public Q2 = {st.session_state['ecc_peer_pub']}")

    msg = st.text_input("Message to encrypt (any text):", key="ecc_full_msg")

    if st.button("Encrypt using ECC Shared Secret"):
        if not (st.session_state["ecc_priv"] and st.session_state["ecc_peer_pub"]):
            st.error("Generate both My keys and Peer keys first.")
        elif not msg.strip():
            st.error("Enter a message.")
        else:
            S = ECC_CURVE.scalar_mult(st.session_state["ecc_priv"], st.session_state["ecc_peer_pub"])
            if S is None:
                st.error("Shared secret infinity. Regenerate keys.")
            else:
                key = S[0]
                cipher_bytes = xor_encrypt(msg.encode(), key)
                st.session_state["ecc_cipher_hex"] = cipher_bytes.hex()
                st.success("Encrypted ✅")
                st.code(st.session_state["ecc_cipher_hex"])

    cipher_hex = st.text_input("Ciphertext HEX:", value=st.session_state.get("ecc_cipher_hex", ""), key="ecc_cipher_hex_in")

    if st.button("Decrypt using ECC Shared Secret"):
        if not (st.session_state["ecc_peer_priv"] and st.session_state["ecc_pub"]):
            st.error("Generate both Peer keys and My keys first.")
        else:
            S2 = ECC_CURVE.scalar_mult(st.session_state["ecc_peer_priv"], st.session_state["ecc_pub"])
            if S2 is None:
                st.error("Shared secret infinity. Regenerate keys.")
            else:
                key2 = S2[0]
                try:
                    cipher_bytes = bytes.fromhex(cipher_hex.strip())
                    plain_bytes = xor_encrypt(cipher_bytes, key2)
                    st.success("Decrypted ✅")
                    st.code(plain_bytes.decode())
                except:
                    st.error("Invalid ciphertext.")

# ==========================================
# TAB 6: ECDSA DIGITAL SIGNATURE (Library)
# ==========================================
with tabs[5]:
    st.subheader("✅ ECDSA Digital Signature (ECC using Library)")
    st.caption("Provides Authenticity + Integrity + Non-repudiation")

    curve_name = st.selectbox("Select ECC Curve:", ["SECP256k1 (Bitcoin)", "NIST256p (P-256)"])
    curve = SECP256k1 if "SECP256k1" in curve_name else NIST256p

    if "ecdsa_private" not in st.session_state:
        st.session_state["ecdsa_private"] = None
        st.session_state["ecdsa_public"] = None
        st.session_state["ecdsa_signature"] = ""

    if st.button("Generate ECDSA Key Pair"):
        sk = SigningKey.generate(curve=curve)
        vk = sk.verifying_key
        st.session_state["ecdsa_private"] = sk.to_pem().decode()
        st.session_state["ecdsa_public"] = vk.to_pem().decode()
        st.success("ECDSA keys generated ✅")

    if st.session_state["ecdsa_private"] and st.session_state["ecdsa_public"]:
        st.write("### Private Key (PEM)")
        st.code(st.session_state["ecdsa_private"])

        st.write("### Public Key (PEM)")
        st.code(st.session_state["ecdsa_public"])

        st.write("---")
        st.write("## ✍️ Sign Message")
        sign_msg = st.text_area("Message to sign:", height=120)

        if st.button("Sign Message"):
            if not sign_msg.strip():
                st.error("Enter message to sign.")
            else:
                sk = SigningKey.from_pem(st.session_state["ecdsa_private"].encode())
                signature = sk.sign(sign_msg.encode("utf-8"))
                sig_b64 = base64.b64encode(signature).decode()
                st.session_state["ecdsa_signature"] = sig_b64
                st.success("Signed ✅")
                st.code(sig_b64)

        st.write("---")
        st.write("## ✅ Verify Signature")
        verify_msg = st.text_area("Message for verification:", value=sign_msg, height=120)
        sig_input = st.text_area("Signature Base64:", value=st.session_state.get("ecdsa_signature", ""), height=90)

        if st.button("Verify Signature"):
            try:
                vk = VerifyingKey.from_pem(st.session_state["ecdsa_public"].encode())
                signature_bytes = base64.b64decode(sig_input.strip())
                ok = vk.verify(signature_bytes, verify_msg.encode("utf-8"))

                if ok:
                    st.success("✅ VALID Signature (Authentic + Integrity OK)")
                else:
                    st.error("❌ INVALID Signature")
            except Exception as e:
                st.error(f"Verification failed: {e}")

    else:
        st.info("Generate ECDSA keys to start.")
