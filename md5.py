import math

# This list maintains the amount by which to rotate the buffers during processing stage
rotate_by = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
			 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
			 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
			 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

# This list maintains the additive constant to be added in each processing step.
K = [int(abs(math.sin(i+1)) * 4294967296) & 0xFFFFFFFF for i in range(64)]

# Padding
def pad(msg: bytes) -> bytes:
    msg_len = len(msg) * 8 & 0xFFFFFFFFFFFFFFFF
    msg += b'\x80'

    while len(msg) % 64 != 56:
        msg += b'\x00'
    
    msg += msg_len.to_bytes(8, byteorder='little')
    return msg


# MD buffer is 4 words A, B, C and D each of 32-bits.
init_MDBuffer = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]


# Left rotate function
def rotl(x, amount):
	x &= 0xFFFFFFFF
	return (x << amount | x >> (32-amount)) & 0xFFFFFFFF


# Process message in 512-bit blocks
def process(msg:bytes) -> bytes:
    msg = pad(msg)
    H = init_MDBuffer[:]
    for offset in range(0, len(msg), 64):
        A, B, C, D = H
        block = msg[offset:offset + 64]
        
        for i in range(64):
            
            if i < 16:
                F = (B & C) | (~B & D)
                G = i
            
            elif i < 32:
                F = (D & B) | (~D & C)
                G = (5 * i + 1) % 16
            
            elif i < 48:
                F = B ^ C ^ D
                G = (3 * i + 5) % 16
            
            else:
                F = C ^ (B | ~D)
                G = (7 * i) % 16

            to_rotate = A + F + K[i] + int.from_bytes(block[4 * G:4 * G + 4], byteorder='little')
            A, B, C, D = D, (B + rotl(to_rotate, rotate_by[i])) & 0xFFFFFFFF, B, C

        H = [(x + y) & 0xFFFFFFFF for x, y in zip(H, [A, B, C, D])]
        
	 # The same process is to be performed for every 512-bit block of the message
        
    return b''.join(x.to_bytes(4, 'little') for x in H)


def md5(msg: str) -> str:
	msg = msg.encode('ascii')
	return process(msg).hex()


def md5_file(file_path: str) -> str:
    with open(file_path, 'rb') as f:
        file_content = f.read()
    return process(file_content).hex()



if __name__ == '__main__':
    print("Choose an option:")
    print("1. Hash a string")
    print("2. Hash a file")
    
    choice = input("Enter your choice (1 or 2): ").strip()

    if choice == '1':
        message = input("Enter the message to hash: ")
        print("SHA-256:", md5(message))
    elif choice == '2':
        file_path = input("Enter the file path to hash: ")
        print("SHA-256:", md5_file(file_path))
    else:
        print("Invalid choice. Please enter 1 or 2.")