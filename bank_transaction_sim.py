"""
--------------------------------------------------------------
  SECURE BANK TRANSACTION SYSTEM
  RSA + AES Hybrid Cryptosystem
--------------------------------------------------------------
"""

"""
Mohamad Reda 212001281
El_Hassan Tarek 211014198
Ali Ayman 212004018
"""
import os
import random
import time
import base64

#AES-128 IMPLEMENTATION
SBOX = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
]

INV_SBOX = [0] * 256
for sbox_index, sbox_value in enumerate(SBOX):
    INV_SBOX[sbox_value] = sbox_index

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def gmul(byte_a, byte_b):
    """Galois Field (GF 2^8) multiplication used in AES MixColumns."""
    result = 0
    for _ in range(8):
        if byte_b & 1:
            result ^= byte_a
        has_high_bit = byte_a & 0x80
        byte_a = (byte_a << 1) & 0xFF
        if has_high_bit:
            byte_a ^= 0x1B           # XOR with the AES irreducible polynomial
        byte_b >>= 1
    return result


def sub_bytes(state):
    """Apply the AES S-Box substitution to every byte in the state matrix."""
    return [[SBOX[byte] for byte in row] for row in state]


def inv_sub_bytes(state):
    """Apply the inverse S-Box substitution (used during decryption)."""
    return [[INV_SBOX[byte] for byte in row] for row in state]


def shift_rows(state):
    """Cyclically left-shift each row of the state by its row index."""
    return [
        state[0],
        state[1][1:] + state[1][:1],
        state[2][2:] + state[2][:2],
        state[3][3:] + state[3][:3],
    ]


def inv_shift_rows(state):
    """Reverse the row shifts (right-shift each row by its row index)."""
    return [
        state[0],
        state[1][-1:] + state[1][:-1],
        state[2][-2:] + state[2][:-2],
        state[3][-3:] + state[3][:-3],
    ]


def mix_columns(state):
    """Mix each column of the state using matrix multiplication."""
    mixed_columns = []
    for col_index in range(4):
        column = [state[row_index][col_index] for row_index in range(4)]
        mixed_columns.append([
            gmul(column[0], 2) ^ gmul(column[1], 3) ^ column[2]          ^ column[3],
            column[0]          ^ gmul(column[1], 2) ^ gmul(column[2], 3) ^ column[3],
            column[0]          ^ column[1]          ^ gmul(column[2], 2) ^ gmul(column[3], 3),
            gmul(column[0], 3) ^ column[1]          ^ column[2]          ^ gmul(column[3], 2),
        ])
    return [[mixed_columns[col_index][row_index] for col_index in range(4)] for row_index in range(4)]


def inv_mix_columns(state):
    """Inverse MixColumns transformation."""
    mixed_columns = []
    for col_index in range(4):
        column = [state[row_index][col_index] for row_index in range(4)]
        mixed_columns.append([
            gmul(column[0], 14) ^ gmul(column[1], 11) ^ gmul(column[2], 13) ^ gmul(column[3],  9),
            gmul(column[0],  9) ^ gmul(column[1], 14) ^ gmul(column[2], 11) ^ gmul(column[3], 13),
            gmul(column[0], 13) ^ gmul(column[1],  9) ^ gmul(column[2], 14) ^ gmul(column[3], 11),
            gmul(column[0], 11) ^ gmul(column[1], 13) ^ gmul(column[2],  9) ^ gmul(column[3], 14),
        ])
    return [[mixed_columns[col_index][row_index] for col_index in range(4)] for row_index in range(4)]


def add_round_key(state, round_key):
    """XOR the state with the current round key."""
    return [
        [state[row][col] ^ round_key[row][col] for col in range(4)]
        for row in range(4)
    ]


def key_expansion(key_bytes):
    """
    Expand a 16-byte AES key into 11 round keys (one per round + initial).
    Returns a list of 11 round keys, each a 4x4 matrix.
    """
    assert len(key_bytes) == 16
    key_words = [list(key_bytes[4 * word_index : 4 * word_index + 4]) for word_index in range(4)]

    for word_index in range(4, 44):
        previous_word = key_words[word_index - 1][:]
        if word_index % 4 == 0:
            # RotWord: rotate left by 1 byte
            previous_word = previous_word[1:] + previous_word[:1]
            # SubWord: apply S-Box to each byte
            previous_word = [SBOX[byte] for byte in previous_word]
            # XOR with round constant
            previous_word[0] ^= RCON[(word_index // 4) - 1]
        new_word = [key_words[word_index - 4][byte_pos] ^ previous_word[byte_pos] for byte_pos in range(4)]
        key_words.append(new_word)

    # Group the 44 words into 11 round keys, each as a 4x4 state matrix
    return [
        [[key_words[round_num * 4 + col][row] for col in range(4)] for row in range(4)]
        for round_num in range(11)
    ]


def bytes_to_state(block):
    """Convert a 16-byte block into the AES 4x4 state matrix (column-major)."""
    return [[block[row + 4 * col] for col in range(4)] for row in range(4)]


def state_to_bytes(state):
    """Convert an AES 4x4 state matrix back to a 16-byte block (column-major)."""
    return bytes([state[row][col] for col in range(4) for row in range(4)])


def aes_encrypt_block(block, round_keys):
    """Encrypt a single 16-byte block using AES-128 (10 rounds)."""
    state = bytes_to_state(block)
    state = add_round_key(state, round_keys[0])
    for round_num in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])
    #Round10: no MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return state_to_bytes(state)


def aes_decrypt_block(block, round_keys):
    """Decrypt a single 16-byte block using AES-128 (10 rounds, reversed)."""
    state = bytes_to_state(block)
    state = add_round_key(state, round_keys[10])
    for round_num in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_num])
        state = inv_mix_columns(state)
    # Final round: no InvMixColumns
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return state_to_bytes(state)


def pkcs7_padding(data, block_size=16):
    """Pad data to a multiple of block_size using PKCS#7 padding."""
    pad_length = block_size - (len(data) % block_size)
    return data + bytes([pad_length] * pad_length)


def pkcs7_unpadding(data):
    """Remove PKCS#7 padding from decrypted data."""
    return data[: -data[-1]]


def aes_cbc_encrypt(plaintext, key, iv):
    """
    Encrypt plaintext using AES-128 in CBC mode.
    Each block is XORed with the previous ciphertext block before encryption.
    """
    round_keys = key_expansion(key)
    padded_plaintext = pkcs7_padding(plaintext)
    ciphertext = b""
    previous_block = iv
    for block_start in range(0, len(padded_plaintext), 16):
        plaintext_block = padded_plaintext[block_start : block_start + 16]
        xored_block = bytes([plaintext_block[byte_pos] ^ previous_block[byte_pos] for byte_pos in range(16)])
        encrypted_block = aes_encrypt_block(xored_block, round_keys)
        ciphertext += encrypted_block
        previous_block = encrypted_block
    return ciphertext


def aes_cbc_decrypt(ciphertext, key, iv):
    """
    Decrypt ciphertext using AES-128 in CBC mode.
    Each decrypted block is XORed with the previous ciphertext block.
    """
    round_keys = key_expansion(key)
    plaintext = b""
    previous_block = iv
    for block_start in range(0, len(ciphertext), 16):
        ciphertext_block = ciphertext[block_start : block_start + 16]
        decrypted_block = aes_decrypt_block(ciphertext_block, round_keys)
        plaintext += bytes([decrypted_block[byte_pos] ^ previous_block[byte_pos] for byte_pos in range(16)])
        previous_block = ciphertext_block
    return pkcs7_unpadding(plaintext)


#RSA IMPLEMENTATION


def mod_exp(base, exponent, modulus):
    """Fast modular exponentiation using repeated squaring."""
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent //= 2
    return result


def gcd(first, second):
    """Compute the Greatest Common Divisor of two integers."""
    while second:
        first, second = second, first % second
    return first


def extended_gcd(first, second):
    """
    Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that: first*x + second*y = gcd
    """
    if second == 0:
        return first, 1, 0
    divisor, coeff_x, coeff_y = extended_gcd(second, first % second)
    return divisor, coeff_y, coeff_x - (first // second) * coeff_y


def mod_inverse(value, modulus):
    """
    Compute the modular multiplicative inverse of value mod modulus.
    Raises ValueError if the inverse does not exist.
    """
    divisor, inverse, _ = extended_gcd(value % modulus, modulus)
    if divisor != 1:
        raise ValueError("No modular inverse exists")
    return inverse % modulus


def miller_rabin(candidate, num_witnesses=10):
    """
    Probabilistic primality test using the Miller-Rabin algorithm.
    num_witnesses controls accuracy — higher means fewer false positives.
    """
    if candidate < 2:
        return False
    if candidate in (2, 3):
        return True
    if candidate % 2 == 0:
        return False

    # Write candidate-1 as 2^exponent_of_two * odd_part
    exponent_of_two = 0
    odd_part = candidate - 1
    while odd_part % 2 == 0:
        exponent_of_two += 1
        odd_part //= 2

    for _ in range(num_witnesses):
        witness = random.randrange(2, candidate - 1)
        test_value = mod_exp(witness, odd_part, candidate)
        if test_value in (1, candidate - 1):
            continue
        for _ in range(exponent_of_two - 1):
            test_value = mod_exp(test_value, 2, candidate)
            if test_value == candidate - 1:
                break
        else:
            return False    # Composite
    return True             # Probably prime


def generate_prime(num_bits):
    """Generate a random probable prime with the given number of bits."""
    while True:
        candidate = random.getrandbits(num_bits)
        candidate |= (1 << (num_bits - 1))   # Ensure the top bit is set (correct bit length)
        candidate |= 1                         # Ensure the number is odd
        if miller_rabin(candidate):
            return candidate


def generate_rsa_keys(num_bits=256):
    """
    Generate an RSA key pair.
    Returns (public_key, private_key) where each is a tuple (exponent, modulus).
    """
    print("  [RSA] Generating prime p ...", flush=True)
    prime_p = generate_prime(num_bits // 2)
    print(f"p bit-length: {prime_p.bit_length()}")
    print("  [RSA] Generating prime q ...", flush=True)
    prime_q = generate_prime(num_bits // 2)
    while prime_q == prime_p:
        prime_q = generate_prime(num_bits // 2)
    print(f"q bit-length: {prime_q.bit_length()}") 

    modulus = prime_p * prime_q        #n = p * q
    totient = (prime_p - 1) * (prime_q - 1)   #φ(n)= (p-1)(q-1)

    public_exponent = 65537                    #e
    if gcd(public_exponent, totient) != 1:
        public_exponent = 3
        while gcd(public_exponent, totient) != 1:
            public_exponent += 2

    private_exponent = mod_inverse(public_exponent, totient)    #d
    public_key  = (public_exponent, modulus)  #e,n
    private_key = (private_exponent, modulus) #d,n
    return public_key, private_key


def rsa_encrypt(message_int, public_key):
    """RSA encryption: ciphertext = message^e mod n"""
    public_exponent, modulus = public_key
    return mod_exp(message_int, public_exponent, modulus)


def rsa_decrypt(ciphertext_int, private_key):
    """RSA decryption: message = ciphertext^d mod n"""
    private_exponent, modulus = private_key
    return mod_exp(ciphertext_int, private_exponent, modulus)


def int_to_bytes(integer, byte_length):
    """Convert an integer to a fixed-length big-endian byte string."""
    return integer.to_bytes(byte_length, 'big')


def bytes_to_int(byte_string):
    """Convert a big-endian byte string to an integer."""
    return int.from_bytes(byte_string, 'big')


#HYBRID CRYPTOSYSTEM


def hybrid_encrypt(plaintext_str, rsa_public_key, running=False):
    """Encrypt a transaction string. If running=True, prints every step."""
    _, modulus = rsa_public_key
    rk_byte_length = (modulus.bit_length() + 7) // 8

    aes_session_key = os.urandom(16)
    iv              = os.urandom(16)

    aes_ciphertext       = aes_cbc_encrypt(plaintext_str.encode('utf-8'), aes_session_key, iv)
    ciphertext_base64    = base64.b64encode(aes_ciphertext).decode()
    encrypted_key_bytes  = int_to_bytes(rsa_encrypt(bytes_to_int(aes_session_key), rsa_public_key), rk_byte_length)
    encrypted_key_base64 = base64.b64encode(encrypted_key_bytes).decode()
    iv_base64            = base64.b64encode(iv).decode()

    if running:
        print("          ENCRYPTION FLOW  (CLIENT / SENDER)           ")
        print(f"\n  STEP 1 >> Plaintext transaction")
        print(f"            \"{plaintext_str}\"")
        print(f"\n  STEP 2 >> Generate random 128-bit AES session key")
        print(f"            AES Key  :\n            {aes_session_key.hex()}")
        print(f"\n  STEP 3 >> Generate random 128-bit IV for CBC mode")
        print(f"            IV  : \n            {iv.hex()}")
        print(f"\n  STEP 4 >> AES-128 CBC encrypt( transaction , AES_key , IV )")
        print(f"            Ciphertext  :")
        print(f"            {ciphertext_base64[:56]}...")
        print(f"\n  STEP 5 >> RSA-256 encrypt( AES_key , bank_PUBLIC_key )")
        print(f"            Encrypted AES Key  :")
        print(f"            {encrypted_key_base64[:56]}...")
        print(f"\n  STEP 6 >> Build encrypted package for transmission")
        print(f"            {{ encrypted_AES_key , IV , ciphertext }}")

    return {
        "encrypted_aes_key_b64": encrypted_key_base64,
        "iv_b64":                iv_base64,
        "aes_ciphertext_b64":    ciphertext_base64,
    }


def hybrid_decrypt(package, rsa_private_key, running=False):
    """Decrypt a transaction package. If running=True, prints every step."""
    encrypted_key_bytes = base64.b64decode(package["encrypted_aes_key_b64"])
    iv                  = base64.b64decode(package["iv_b64"])
    aes_ciphertext      = base64.b64decode(package["aes_ciphertext_b64"])
    aes_session_key     = int_to_bytes(rsa_decrypt(bytes_to_int(encrypted_key_bytes), rsa_private_key), 16)
    plaintext           = aes_cbc_decrypt(aes_ciphertext, aes_session_key, iv).decode('utf-8')

    if running:

        print("           DECRYPTION FLOW  (BANK / RECEIVER)          ")
        print(f"\n  STEP 1 >> Base64-decode all package components")
        print(f"            Encrypted key : {len(encrypted_key_bytes)} bytes")
        print(f"            IV            : {len(iv)} bytes")
        print(f"            Ciphertext    : {len(aes_ciphertext)} bytes")
        print(f"\n  STEP 2 >> RSA-256 decrypt( encrypted_key , bank_PRIVATE_key )")
        print(f"            Recovered AES Key  :\n            {aes_session_key.hex()}")
        print(f"\n  STEP 3 >> AES-128 CBC decrypt( ciphertext , AES_key , IV )")
        print(f"            Recovered plaintext :")
        print(f"            \"{plaintext}\"")
        print(f"\n  [OK] Decryption complete — transaction verified.")

    return plaintext


#BANK CLASS

class Bank:
    def __init__(self, name):
        self.name            = name
        self.accounts        = {}
        self.transaction_log = []
        self.public_key      = None

    def register_public_key(self, public_key):
        self.public_key = public_key

    def register_account(self, account_id, initial_balance):
        self.accounts[account_id] = initial_balance

    def receive_transaction(self, encrypted_package, from_account, to_account, amount):
        self.transaction_log.append({
            "from":    from_account,
            "to":      to_account,
            "amount":  amount,
            "package": encrypted_package,
        })
        if from_account in self.accounts and to_account in self.accounts:
            if self.accounts[from_account] >= amount:
                self.accounts[from_account] -= amount
                self.accounts[to_account]   += amount
                return True
        return False


#DEMO FLOWS

def show_architecture():
    print(f"\n{'-'*62}")
    print(f"  SYSTEM ARCHITECTURE")
    print('-'*62)
    print("""
  CLIENT (Sender Side)
  ─────────────────────────────────────────────────────────
  [1] Build plaintext transaction string  (UTF-8 text)
  [2] Generate random 128-bit AES session key  (new each TX)
  [3] Generate random 128-bit IV               (CBC randomness)
  [4] AES-128 CBC encrypt( transaction , AES_key , IV )
          └─► produces CIPHERTEXT  (bulk of the data)
  [5] RSA-256 encrypt( AES_key , bank_PUBLIC_key )
          └─► produces ENCRYPTED_AES_KEY  (16 bytes, locked)
  [6] Transmit package:
          { ENCRYPTED_AES_KEY , IV , CIPHERTEXT }

  ·  ·  ·  NETWORK  (only encrypted bytes travel)  ·  ·  ·

  BANK SERVER (Receiver Side)
  ─────────────────────────────────────────────────────────
  [1] RSA-256 decrypt( ENCRYPTED_AES_KEY , bank_PRIVATE_key )
          └─► recovers AES session key
  [2] AES-128 CBC decrypt( CIPHERTEXT , AES_key , IV )
          └─► recovers plaintext transaction
  [3] Verify & apply to ledger
""")


def aes_only():
    print(f"\n{'-'*62}")
    print(f"  AES-128 CBC  —  STANDALONE DEMO")
    print('-'*62)
    message = input(f"\n  >> Enter message to encrypt  [Enter for default]: ").strip()
    if not message:
        message = "Transfer $500 to Account #9876"

    aes_key = os.urandom(16)
    iv      = os.urandom(16)

    print(f"\n  -- Inputs --")
    print(f"  Plaintext : {message}")
    print(f"  AES Key   : {aes_key.hex()}  (128-bit random)")
    print(f"  IV        : {iv.hex()}  (128-bit random)")

    print(f"\n  -- AES-128 CBC Encryption  (10 rounds / block) --")
    aes_ciphertext    = aes_cbc_encrypt(message.encode(), aes_key, iv)
    ciphertext_base64 = base64.b64encode(aes_ciphertext).decode()
    print(f"  Each block XORed with previous ciphertext block (CBC chaining)")
    print(f"  Ciphertext (Base64): {ciphertext_base64}")

    print(f"\n  -- AES-128 CBC Decryption --")
    recovered_plaintext = aes_cbc_decrypt(aes_ciphertext, aes_key, iv)
    print(f"  Recovered : {recovered_plaintext.decode()}")
    print(f"  [OK]   AES encrypt -> decrypt successful — plaintext matches!")


def rsa_only():
    print(f"\n{'-'*62}")
    print(f"  RSA-256  —  STANDALONE DEMO")
    print('-'*62)
    print(f"  [i]    Generating 256-bit RSA key pair for speed (demo only) ...")
    public_key, private_key = generate_rsa_keys(num_bits=256)
    print(f"  [OK]   Keys generated.")

    public_exponent, modulus = public_key
    private_exponent, _ = private_key
    print(f"\n  -- Key Parameters --")
    print(f"  Public exponent  e : {public_exponent}  (standard Fermat prime)")
    print(f"  Modulus          n : {str(modulus)[:60]}...")
    print(f"  Private exponent d : {str(private_exponent)[:60]}...")

    test_value = 123456789
    print(f"\n  -- RSA Encryption   message^e mod n --")
    print(f"  Plaintext integer : {test_value}")
    rsa_ciphertext = rsa_encrypt(test_value, public_key)
    print(f"  RSA ciphertext    : {str(rsa_ciphertext)[:60]}...")

    print(f"\n  -- RSA Decryption   ciphertext^d mod n --")
    recovered_value = rsa_decrypt(rsa_ciphertext, private_key)
    print(f"  Recovered integer : {recovered_value}")
    print(f"  [OK]   RSA encrypt -> decrypt successful — values match!")


def run_bank_simulation(bank, bank_private_key):
    while True:
        print(f"\n{'-'*62}")
        print(f"  BANK TERMINAL  —  {bank.name}")
        print('-'*62)
        print("  [1] Send encrypted transaction")
        print("  [2] View account balances")
        print("  [3] View transaction log(encrypted)")
        print("  [4] Decrypt & verify a logged transaction")
        print("  [5] Back to main menu")

        choice = input(f"\n  >> Select option: ").strip()

        if choice == "1":
            print(f"\n{'-'*62}")
            print(f"  SEND ENCRYPTED TRANSACTION")
            print('-'*62)
            print(f"  Available accounts: {', '.join(bank.accounts.keys())}")
            from_account = input(f"\n  >> From account: ").strip().upper()
            to_account   = input(f"\n  >> To account:   ").strip().upper()
            try:
                amount = float(input(f"\n  >> Amount ($):   ").strip())
            except ValueError:
                print(f"  [ERR]  Invalid amount."); continue

            if from_account not in bank.accounts or to_account not in bank.accounts:
                print(f"  [ERR]  Unknown account."); continue
            if bank.accounts[from_account] < amount:
                print(f"  [ERR]  Insufficient funds. {from_account} has ${bank.accounts[from_account]:,.2f}"); continue

            transaction_data = (
                f"FROM:{from_account}  TO:{to_account}  "
                f"AMOUNT:${amount:.2f}  TS:{int(time.time())}"
            )

            encrypted_package = hybrid_encrypt(transaction_data, bank.public_key, running=True)

            print(f"\n  . . . Transmitting encrypted package to {bank.name} . . .")
            success = bank.receive_transaction(encrypted_package, from_account, to_account, amount)
            print()
            if success:
                print(f"  [OK]   Bank accepted transaction #{len(bank.transaction_log)}")
                print(f"  [OK]   ${amount:.2f} transferred: {from_account} -> {to_account}")
                print(f"  [i]    New balances: {from_account}=${bank.accounts[from_account]:,.2f}  "
                      f"{to_account}=${bank.accounts[to_account]:,.2f}")
            else:
                print(f"  [ERR]  Transaction rejected by bank.")

        elif choice == "2":
            print(f"\n{'-'*62}")
            print(f"  ACCOUNT BALANCES")
            print('-'*62)
            for account, balance in bank.accounts.items():
                bar = "#" * int(balance // 500)
                print(f"  {account:<10}  ${balance:>10,.2f}  {bar}")

        elif choice == "3":
            print(f"\n{'-'*62}")
            print(f"  TRANSACTION LOG  (ENCRYPTED)")
            print('-'*62)
            if not bank.transaction_log:
                print(f"  [i]    No transactions recorded yet."); continue
            for tx_index, transaction in enumerate(bank.transaction_log, 1):
                print("." * 62)
                print(f"  TX #{tx_index}  {transaction['from']} -> {transaction['to']}  |  ${transaction['amount']:.2f}")
                print(f"  Encrypted AES Key : {transaction['package']['encrypted_aes_key_b64'][:48]}...")
                print(f"  IV                : {transaction['package']['iv_b64']}")
                print(f"  Ciphertext        : {transaction['package']['aes_ciphertext_b64'][:48]}...")
            print("." * 62)

        elif choice == "4":
            print(f"\n{'-'*62}")
            print(f"  DECRYPT & VERIFY TRANSACTION")
            print('-'*62)
            if not bank.transaction_log:
                print(f"  [i]    No transactions to verify."); continue
            try:
                tx_index = int(input(f"\n  >> Transaction # to decrypt (1-{len(bank.transaction_log)}): ").strip()) - 1
            except ValueError:
                print(f"  [ERR]  Invalid input."); continue
            if not (0 <= tx_index < len(bank.transaction_log)):
                print(f"  [ERR]  Out of range."); continue

            transaction = bank.transaction_log[tx_index]
            print(f"  [i]    Using bank RSA private key to recover AES key, then decrypting ciphertext ...")
            hybrid_decrypt(transaction["package"], bank_private_key, running=True)

        elif choice == "5":
            break
        else:
            print(f"  [ERR]  Invalid option.")

def main():
    print("\n" + "-"*62)
    print("   SECURE BANK TRANSACTION SYSTEM")
    print("   RSA-256 + AES-128 CBC Hybrid Cryptosystem")
    print("-"*62)

    print(f"  [i]    Generating RSA-256 key pair for SecureBank ...")
    bank_public_key, bank_private_key = generate_rsa_keys(num_bits=256)
    print(f"  [OK]   RSA-256 key pair ready.\n")

    bank = Bank("SecureBank")
    bank.register_public_key(bank_public_key)
    bank.register_account("REDA",   10000.00)
    bank.register_account("BODO",      7500.00)
    bank.register_account("ALI",  5000.00)

    while True:
        print(f"\n{'-'*62}")
        print(f"  MAIN MENU")
        print('-'*62)
        print("  [1] Bank Transaction Simulation  (full encrypt / decrypt flow)")
        print("  [2] AES-128 CBC demo only")
        print("  [3] RSA-256 demo only")
        print("  [4] Show system architecture")
        print("  [5] Exit")

        choice = input(f"\n  >> Select option: ").strip()

        if   choice == "1": run_bank_simulation(bank, bank_private_key)
        elif choice == "2": aes_only()
        elif choice == "3": rsa_only()
        elif choice == "4": show_architecture()
        elif choice == "5": print("\n  Goodbye!\n"); break
        else: print(f"  [ERR]  Invalid option.")


if __name__ == "__main__":
    main()
