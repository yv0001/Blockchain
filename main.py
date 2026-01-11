import streamlit as st
import hashlib
import random

# -----------------------------
# RSA MATH (NO external crypto libs)
# -----------------------------
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


# -----------------------------
# APP SETTINGS
# -----------------------------
st.set_page_config(page_title="BLOCKCHAIN", page_icon="🔐", layout="wide")

st.title(" Practical 1 ")
st.caption("Hashing • Avalanche Effect • Hash Compare • RSA without crypto library")

algos = [
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
    "blake2b", "blake2s"
]
algos = [a for a in algos if a in hashlib.algorithms_available]

tabs = st.tabs(["1) Hashing", "2) Avalanche", "3) Compare", "4) RSA"])

# -----------------------------
# TAB 1: HASHING
# -----------------------------
with tabs[0]:
    st.subheader("✅ Hashing: f(x) = hash(x)")
    x = st.text_area("Enter input text (x):", height=100)

    st.write("### Select hashing algorithms:")
    cols = st.columns(4)

    selected_algos = []
    for i, algo in enumerate(algos):
        with cols[i % 4]:
            if st.checkbox(algo.upper(), value=(algo in ["md5", "sha1", "sha256"]), key=f"h_{algo}"):
                selected_algos.append(algo)

    if st.button("Calculate Hash"):
        if not x.strip():
            st.error("Please enter text first.")
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
                    "Hash": h.hexdigest()
                })
            st.dataframe(rows, use_container_width=True)

# -----------------------------
# TAB 2: AVALANCHE EFFECT
# -----------------------------
with tabs[1]:
    st.subheader("✅ Avalanche Effect Study")

    # --- Initialize state BEFORE widgets ---
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
        # safe change in last char
        new_text = base[:-1] + chr((ord(base[-1]) + 1) % 127)
        st.session_state["av2"] = new_text

    c1, c2 = st.columns([1, 2])
    with c1:
        st.button("Auto Modify Text 2", on_click=auto_modify)

    algo_choice = st.multiselect(
        "Select algorithms for avalanche:",
        algos,
        default=["sha256", "sha512", "md5"]
    )

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

            st.dataframe(results, use_container_width=True)

# -----------------------------
# TAB 3: HASH COMPARE
# -----------------------------
with tabs[2]:
    st.subheader("✅ Hash Compare: ht1(x1) = ht2(x2)")

    x1 = st.text_input("Input x1:", key="cmp1")
    x2 = st.text_input("Input x2:", key="cmp2")
    algo = st.selectbox("Algorithm:", [a.upper() for a in algos], index=algos.index("sha256"))

    if st.button("Check Equality"):
        if not x1 or not x2:
            st.error("Enter both inputs.")
        else:
            algo_lower = algo.lower()
            h1 = hashlib.new(algo_lower, x1.encode()).hexdigest()
            h2 = hashlib.new(algo_lower, x2.encode()).hexdigest()

            st.write("### Hash Output")
            st.code(h1)
            st.code(h2)

            if h1 == h2:
                st.success("MATCH ✅")
            else:
                st.error("NOT MATCH ❌")

# -----------------------------
# TAB 4: RSA
# -----------------------------
with tabs[3]:
    st.subheader("✅ RSA (Manual Implementation)")

    if "pub" not in st.session_state:
        st.session_state["pub"] = None
        st.session_state["priv"] = None

    key_size = st.selectbox("Select RSA key size:", [512, 1024], index=0)

    if st.button("Generate RSA Keys"):
        st.info("Generating keys... please wait")
        p = RSAMath.generate_prime_number(key_size // 2)
        q = RSAMath.generate_prime_number(key_size // 2)

        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = RSAMath.mod_inverse(e, phi)

        st.session_state["pub"] = (e, n)
        st.session_state["priv"] = (d, n)

        st.success("Keys generated ✅")

    if st.session_state["pub"]:
        e, n = st.session_state["pub"]
        d, _ = st.session_state["priv"]

        st.write("### Public Key")
        st.code(f"e = {e}\nn = {n}")

        st.write("### Private Key")
        st.code(f"d = {d}\nn = {n}")

        msg = st.text_input("Enter message:")
        if st.button("Encrypt"):
            if not msg:
                st.warning("Enter a message.")
            else:
                m = RSAMath.text_to_int(msg)
                if m >= n:
                    st.error("Message too long for this key. Use shorter message or bigger key size.")
                else:
                    c = pow(m, e, n)
                    st.session_state["cipher"] = str(c)
                    st.success("Encrypted ✅")

        cipher = st.text_input("Ciphertext (integer):", value=st.session_state.get("cipher", ""))

        if st.button("Decrypt"):
            try:
                c = int(cipher)
                m = pow(c, d, n)
                text = RSAMath.int_to_text(m)
                st.success("Decrypted ✅")
                st.write("### Output")
                st.code(text)
            except:
                st.error("Invalid ciphertext.")
    else:
        st.warning("Generate keys first.")
