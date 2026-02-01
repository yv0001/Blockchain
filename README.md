# 🔐 Python Crypto Suite (Jupyter Edition)

A complete, interactive Python cybersecurity toolkit designed to run directly in Jupyter Notebooks. This project demonstrates core cryptographic concepts including Hashing, the Avalanche Effect, Hash Comparison, and a manual implementation of RSA Encryption without using external cryptographic libraries.

## 🚀 Features

### 1. Multi-Algorithm Hashing

* **Input:** Text string.
* **Algorithms:** Supports MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3-256, BLAKE2b.
* **Output:** Generates a clean HTML table showing the algorithm name, bit length, and hexadecimal hash digest.
* **Controls:** "Select All", "Clear All", and "Calculate" buttons.

### 2. Avalanche Effect Visualizer

* **Concept:** Demonstrates how changing a single character in the input results in a drastically different hash (ideally ~50% bit difference).
* **Features:**
* Compare two text inputs.
* **Auto Modify:** Button to automatically change one character of the original text.
* **Metrics:** Calculates Hamming Distance (bits flipped) and percentage difference.
* **Visuals:** Color-coded results (Green > 40% change, Orange otherwise).



### 3. Hash Equality Checker

* **Concept:** Verifies data integrity by comparing the hashes of two inputs.
* **Output:** Instant "MATCH ✅" or "NO MATCH ❌" visual feedback.

### 4. RSA Encryption (Manual Implementation)

* **Educational Focus:** Implements RSA from scratch using standard Python math (no `cryptography` or `PyCryptodome` libraries).
* **Key Generation:**
* Uses **Miller-Rabin** primality test to find large primes ().
* Calculates  and Euler's Totient .
* Computes private key exponent  using the **Extended Euclidean Algorithm**.


* **Operations:**
* **Encrypt:**  (converts text to integer first).
* **Decrypt:**  (recovers original text).



---

## 🛠️ Prerequisites

* **Python 3.x**
* **Jupyter Notebook** (or JupyterLab / VS Code Notebooks)
* **ipywidgets:** Required for the interactive GUI.

### Installation

Run the following commands in a code cell or terminal to ensure dependencies are ready:

```bash
pip install ipywidgets
jupyter nbextension enable --py widgetsnbextension

```

*(Note: In modern Jupyter Lab or VS Code, the extension enable step is often automatic.)*

---

## 🏃‍♂️ How to Run

1. **Open Jupyter Notebook.**
2. **Copy the Source Code:** Paste the complete Python code block into a single cell.
3. **Run the Cell:** Press `Shift + Enter`.
4. **Interact:** The GUI will appear directly in the output area below the cell.

---

## 📂 Project Structure

* **`RSAMath` Class:** Contains all static methods for pure mathematics (`mod_inverse`, `is_prime`, `extended_gcd`).
* **`CryptoApp` Class:** Manages the UI layout, widget events, and business logic.
* **Tabs:**
* `Hashing`: Generate hashes.
* `Avalanche`: Visualize bit changes.
* `Compare`: Check equality.
* `RSA`: Generate keys and encrypt/decrypt messages.



---

## ⚠️ Educational Use Warning

This project uses a manual, "textbook" implementation of RSA. It uses standard `random` (which is not cryptographically secure) and smaller key sizes for performance in the browser/notebook environment. 
**Do not use this code for securing real-world sensitive data.** It is intended for educational demonstrations only.
