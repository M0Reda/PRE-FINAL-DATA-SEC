# Secure Bank Transaction System

A complete **RSA-256 + AES-128 CBC Hybrid Cryptosystem** for secure bank transactions, built entirely from scratch in Python. This educational project implements advanced cryptographic algorithms with a fully functional bank simulation.

## Overview

This project demonstrates a production-like secure transaction infrastructure combining:
- **AES-128 in CBC mode** — Symmetric encryption for efficient bulk data encryption
- **RSA-256** — Asymmetric encryption for secure key exchange
- **Hybrid Cryptography** — Best of both worlds: RSA's security + AES's performance

The system includes a complete bank simulation with account management, transaction processing, and encrypted transaction logging.

## Team Members

- Mohamad Reda (212001281)
- El_Hassan Tarek (211014198)
- Ali Ayman (212004018)

## Key Features

### AES-128 CBC Encryption
- **S-Box substitution** using standard AES lookup tables
- **ShiftRows** — cyclic left-shift of state rows
- **MixColumns** — Galois Field GF(2⁸) matrix multiplication
- **Key Expansion** — 16-byte key expanded into 11 round keys (10 rounds + initial)
- **CBC Mode** — Each block chained with previous ciphertext for randomness
- **PKCS#7 Padding** — Proper block alignment
- Full 10-round encryption/decryption pipeline

### RSA-256 Encryption
- **Miller-Rabin Primality Test** — Probabilistic prime generation with 10 witnesses
- **Public/Private Key Generation** — Secure key pair creation
- **Modular Exponentiation** — Fast computation using repeated squaring
- **Extended Euclidean Algorithm** — Modular inverse computation
- **256-bit Security** — Two 128-bit prime factors (configurable)

### Hybrid Cryptosystem
- **Secure Key Exchange** — AES session key encrypted with RSA public key
- **Efficient Bulk Encryption** — Large transactions encrypted with AES
- **Per-Transaction Randomness** — New AES key and IV for each transaction
- **Base64 Encoding** — Safe transmission of binary data

### Bank System Features
- **Account Management** — Create and manage multiple bank accounts
- **Encrypted Transactions** — Transfer funds with cryptographic verification
- **Transaction Logging** — Immutable encrypted record of all transactions
- **Live Decryption** — Recover and verify transaction details using private key
- **Visual Architecture** — Step-by-step encryption/decryption flow display

## Demo Modes

The application offers multiple demonstration modes:

1. **Bank Transaction Simulation** (Full Hybrid Flow)
   - Send and receive encrypted transactions
   - View account balances with visual bars
   - Inspect encrypted transaction logs
   - Decrypt specific transactions to verify integrity

2. **AES-128 CBC Standalone Demo**
   - Encrypt/decrypt custom messages
   - View intermediate values (key, IV, ciphertext)
   - Test with your own transaction strings

3. **RSA-256 Standalone Demo**
   - Generate 256-bit key pairs
   - Encrypt/decrypt test integers
   - Observe modular exponentiation in action

4. **System Architecture Visualization**
   - Detailed flow diagrams for both encryption and decryption
   - Step-by-step encryption pipeline (client side)
   - Step-by-step decryption pipeline (bank side)

## Requirements

- **Python 3.6+**
- Standard library only: `os`, `random`, `time`, `base64`

## Installation & Running

```bash
# Navigate to project directory
cd "PRE-FINAL DATA SEC"

# Run the interactive system
python bank_transaction_sim.py
```

Once running, select from the main menu:
- Option 1: Full bank transaction simulation
- Option 2: AES-128 standalone encryption demo
- Option 3: RSA standalone encryption demo
- Option 4: View system architecture diagrams
- Option 5: Exit

## Usage Examples

### Basic Encryption Flow
```python
from bank_transaction_sim import hybrid_encrypt, generate_rsa_keys

# Generate RSA keys
public_key, private_key = generate_rsa_keys(256)

# Encrypt transaction
transaction = "FROM:ALICE | TO:BOB | AMOUNT:$500"
package = hybrid_encrypt(transaction, public_key)
# Returns: {encrypted_aes_key_b64, iv_b64, aes_ciphertext_b64}
```

### Decryption Flow
```python
from bank_transaction_sim import hybrid_decrypt

# Decrypt using private key
plaintext = hybrid_decrypt(package, private_key)
print(plaintext)  # "FROM:ALICE | TO:BOB | AMOUNT:$500"
```

### Bank Transaction
```
1. Client generates random AES key (128-bit)
2. Client generates random IV (128-bit)
3. Client encrypts transaction with AES-128 CBC
4. Client encrypts AES key with bank's RSA public key
5. Client sends: {encrypted_key, IV, ciphertext}
   
6. Bank decrypts AES key using RSA private key
7. Bank decrypts ciphertext using recovered AES key
8. Bank verifies transaction and updates ledger
```

## Project Structure

```
PRE-FINAL DATA SEC/
├── README.md                      # This file
└── bank_transaction_sim.py        # Complete implementation (800+ lines)
    ├── AES-128 Functions
    │   ├── gmul()                  # Galois Field multiplication
    │   ├── sub_bytes()             # S-Box substitution
    │   ├── shift_rows()            # Row permutation
    │   ├── mix_columns()           # Matrix multiplication
    │   ├── key_expansion()         # Key schedule generation
    │   ├── aes_encrypt_block()     # Single block encryption (10 rounds)
    │   └── aes_cbc_*()            # CBC mode operations
    │
    ├── RSA Functions
    │   ├── mod_exp()               # Fast modular exponentiation
    │   ├── is_prime_miller_rabin() # Primality testing
    │   ├── generate_prime()        # Secure prime generation
    │   ├── generate_rsa_keys()     # Key pair generation
    │   ├── rsa_encrypt()           # RSA encryption (c = m^e mod n)
    │   └── rsa_decrypt()           # RSA decryption (m = c^d mod n)
    │
    ├── Hybrid Cryptography
    │   ├── hybrid_encrypt()        # Full hybrid encryption pipeline
    │   └── hybrid_decrypt()        # Full hybrid decryption pipeline
    │
    ├── Bank System
    │   └── Bank class              # Account management and logging
    │
    └── Demo Functions
        ├── show_architecture()     # Display system diagrams
        ├── aes_only()             # Standalone AES demo
        ├── rsa_only()             # Standalone RSA demo
        └── run_bank_simulation()   # Interactive bank terminal
```

## Algorithm Deep Dive

### AES-128 in CBC Mode
```
Key Generation:
  input_key (16 bytes) → key_expansion() → 11 round_keys (44 words)

Encryption (10 rounds per block):
  plaintext + padding
  ↓
  AddRoundKey(state, round_key[0])
  ↓
  for round 1-9:
    SubBytes() → ShiftRows() → MixColumns() → AddRoundKey()
  ↓
  Round 10: SubBytes() → ShiftRows() → AddRoundKey() [no MixColumns]
  ↓
  ciphertext

CBC Mode: Each plaintext block XORed with previous ciphertext block before encryption
```

### RSA-256 Key Generation
```
1. Generate random 128-bit probable prime p using Miller-Rabin test
2. Generate random 128-bit probable prime q (≠ p)
3. Compute n = p × q (256-bit modulus)
4. Compute φ(n) = (p-1)(q-1) (Euler's totient)
5. Select public exponent e = 65537 (or 3 if needed)
6. Compute d = e⁻¹ mod φ(n) using Extended Euclidean Algorithm
7. Public key = (e, n); Private key = (d, n)

Encryption: c ≡ m^e (mod n)
Decryption: m ≡ c^d (mod n)
```

### Hybrid Key Exchange
```
Sender (Client):
  1. Generate random 16-byte AES key (K)
  2. Generate random 16-byte IV
  3. Encrypt message with AES-CBC using K and IV
  4. Encrypt K with bank's RSA public key
  5. Send: {RSA_encrypt(K), IV, AES_CBC_encrypt(message)}

Receiver (Bank):
  1. Decrypt K using bank's RSA private key
  2. Use recovered K and IV to AES-CBC decrypt the message
  3. Transaction verified and applied to ledger
```

## Security Considerations

### ✅ Educational Security
This implementation demonstrates cryptographic algorithms correctly for learning purposes.



## Testing & Validation

Run the program and explore each demo mode:

```bash
python bank_transaction_sim.py

# Try these flows:
# 1. Create transactions between ALICE, BOB, CHARLIE
# 2. Decrypt a transaction to see the plaintext
# 3. Verify account balances update correctly
# 4. Test AES standalone with custom messages
# 5. Observe RSA key generation and encryption
```

### Verification Checklist
- ✅ AES encryption produces different ciphertext with different IV (CBC property)
- ✅ Decrypting produces original plaintext (round-trip test)
- ✅ RSA encrypt/decrypt round-trip works (m = decrypt(encrypt(m)))
- ✅ Bank balances update correctly after transactions
- ✅ Encrypted transaction logs can be decrypted with private key

## Learning Objectives

This project covers:
- **Symmetric Cryptography** — How block ciphers work (AES)
- **Asymmetric Cryptography** — Public-key cryptography (RSA)
- **Hybrid Cryptosystems** — Combining both for efficiency and security
- **Number Theory** — Primes, modular arithmetic, Euler's totient
- **Algorithm Implementation** — From mathematical foundations to code
- **Cryptographic Modes** — CBC chaining and proper randomization
- **Key Management** — Generation, storage, exchange patterns
- **Real-World Patterns** — Transaction systems, encrypted logging

This project demonstrates:
- Cryptographic algorithm implementation
- Symmetric vs. asymmetric encryption
- Hybrid cryptosystem design
- Mathematical foundations of modern cryptography
- Secure communication protocols

## References

- AES Standard (FIPS 197)
- RSA Cryptography Specifications (PKCS #7)
- Galois Field arithmetic for cryptography

## License

Educational purposes only.
