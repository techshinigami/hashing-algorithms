# Constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0xfc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x6ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2
]

# Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# Rotate right
def rotr(x, n):
    return (x >> n) | (x << (32 - n)) & 0xFFFFFFFF

# SHA-256 functions
def Σ0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def Σ1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def σ0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def σ1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

def Ch(x, y, z):
    return (x & y) ^ (~x & z)

def Maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


# Padding
def pad(msg: bytes) -> bytes:
    msg_len = len(msg) * 8 & 0xFFFFFFFFFFFFFFFF # 64-bit representation of message length
    msg += b'\x80'
    while len(msg) % 64 != 56:
        msg += b'\x00'
    msg += msg_len.to_bytes(8, byteorder='big')
    return msg


# Process message in 512-bit blocks
def process(msg: bytes) -> bytes:
    msg = pad(msg)
    H = H0[:]

    for i in range(0, len(msg), 64):
        block = msg[i:i+64]
        W = [0] * 64

        for t in range(16):
            W[t] = int.from_bytes(block[t*4:t*4+4], 'big')
        
        for t in range(16, 64):
            W[t] = (σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]) & 0xFFFFFFFF # 32-bit word operations
        
        a, b, c, d, e, f, g, h = H

        for t in range(64):
            T1 = (h + Σ1(e) + Ch(e, f, g) + K[t] + W[t]) & 0xFFFFFFFF
            T2 = (Σ0(a) + Maj(a, b, c)) & 0xFFFFFFFF
            h, g, f, e, d, c, b, a = g, f, e, (d + T1) & 0xFFFFFFFF, c, b, a, (T1 + T2) & 0xFFFFFFFF

        H = [(x + y) & 0xFFFFFFFF for x, y in zip(H, [a, b, c, d, e, f, g, h])]
    
    # The same process is to be performed for every 512-bit block of the message

    return b''.join(x.to_bytes(4, 'big') for x in H)


def sha256(msg: str) -> str:
    msg = msg.encode('ascii')
    return process(msg).hex()



if __name__ == '__main__':
    message = input("Enter message: ")
    print("SHA-256:", sha256(message))