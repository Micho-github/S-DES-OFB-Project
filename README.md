# S-DES OFB – Encryption CLI Tool

A simple command-line tool to demonstrate Simplified DES (S-DES) encryption using Output Feedback (OFB) mode. Great for learning how encryption, brute force, and cryptanalysis work.

---

## What Is This?

- S-DES: A simplified version of the DES algorithm using 10-bit keys and 8-bit blocks.
- OFB Mode: Turns block ciphers into stream ciphers using an Initialization Vector (IV) and keystream.

---

## Requirements

- Python 3.6 or higher  
- Install the only required package:
```bash
pip install colorama
```

---

## Getting Started

1. Download the project:
```bash
git clone <repository-url>
cd S-DES-OFB-Project
```

2. Run the program:
```bash
python main.py
```

---

## Operations

### 1. Generate Key
- Creates a random 10-bit key and shows how it's used.

### 2. Encrypt (Text or File)
- Input key and IV to encrypt a message or file.

### 3. Decrypt (Text or File)
- Input key, IV, and ciphertext to decrypt back to the original.

### 4. Brute Force
- Try all 1024 possible keys to find the correct one.

### 5. Cryptanalysis
- Use multiple known plaintext-ciphertext pairs to discover the key.

### 6. Exit
- Quit the application.
