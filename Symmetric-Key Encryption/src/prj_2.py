import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import argparse
import secrets
import sys
from hashlib import sha256
from base64 import b64encode, b64decode

# Add the parent directory to the sys.path to locate '/data'
os.sys.path.append('../data')
ciphertext_file = 'data/ciphertext.txt'
iv_file = 'data/iv.txt'
key_file = 'data/key.txt'
plaintext_file = 'data/plaintext.txt'
result_file = 'data/Result.txt'

# **************************************************************


# **************************************************************

# Function to perform AES encryption on a single block
def aes_encrypt_block(block, key): # block and key are bytes
    cipher = AES.new(key, AES.MODE_ECB) # Create a new AES cipher
    encrypted_block = cipher.encrypt(block) # Perform AES encryption on the block
    return encrypted_block # Return the encrypted block

# Function to perform AES decryption on a single block
def aes_decrypt_block(block, key): # block and key are bytes
    cipher = AES.new(key, AES.MODE_ECB) # Create a new AES cipher
    decrypted_block = cipher.decrypt(block) # Perform AES decryption on the block
    return decrypted_block  # Return the decrypted block

# **************************************************************
                                                                                    

# **************************************************************

# Function to perform AES encryption in CBC mode
def encrypt_aes_cbc(plaintext, key, iv): # plaintext, key, and iv are bytes
    cipher = AES.new(key, AES.MODE_CBC, iv) # Create a new AES cipher
    block_size = AES.block_size # Get the block size of the cipher
    padded_text = plaintext + (block_size - len(plaintext) % block_size) * chr(block_size - len(plaintext) % block_size) # Pad the plaintext
    ciphertext = cipher.encrypt(padded_text.encode('utf-8')) # Perform AES encryption on the padded plaintext
    return ciphertext

# Function to perform AES decryption in CBC mode
def decrypt_aes_cbc(ciphertext, key, iv): # ciphertext, key, and iv are bytes
    cipher = AES.new(key, AES.MODE_CBC, iv) # Create a new AES cipher
    plaintext = cipher.decrypt(ciphertext).decode('utf-8') # Perform AES decryption on the ciphertext
    padding_length = ord(plaintext[-1]) # Get the length of the padding
    return plaintext[:-padding_length] # Return the unpadded plaintext

# **************************************************************


# **************************************************************

# Function to generate a random initialization vector (IV)
def gen_iv(): # Returns a 16-byte random value
    return get_random_bytes(16) # Return a 16-byte random value

# **************************************************************
#                                                                                    
#
# **************************************************************

def writeKey(key):
    key_file='data/key.txt' # Set the key file path
    hexKey = key.hex() # Convert the key to a hexadecimal string
    with open(key_file, 'w') as file: # Open the key file
        file.write(hexKey) # Write the hexadecimal key to the key file


def getKey(): # Returns the key as bytes
    key_file='data/key.txt' # Set the key file path
    try: # Try to open the key file
        with open(key_file, 'r') as file: # Open the key file
            hexKey = file.read().strip()  # Read the hexadecimal key as a string
            key = bytes.fromhex(hexKey)  # Convert the hexadecimal string to bytes
        return key # Return the key as bytes
    except FileNotFoundError: # If the key file is not found
        print(f"File '{key_file}' not found.") # Print an error message
        return None # Return None
def printKey(sk): 
    if sk: 
        hexValues = ' '.join([format(byte, '02X') for byte in sk]) # Convert the key to a hexadecimal string
        print(hexValues) 


def getPlaintext(plaintext_file='data/plaintext.txt'): 
    try:
        with open(plaintext_file, 'r') as file: # Open the plaintext file
            text = file.read()
        return text
    except FileNotFoundError:
        print(f"File '{plaintext_file}' not found.")
        return None

# Function to write data to a file in hexadecimal format
def writeHex(data, filename):
    hex_data = b64encode(data).decode('utf-8') # Convert the data to a hexadecimal string
    with open(filename, 'w') as file:
        file.write(hex_data)


# Function to read data from a file in hexadecimal format
def getHex(filename):
    with open(filename, 'r') as file:
        hex_data = file.read()
    return b64decode(hex_data) # Convert the hexadecimal string to bytes

def generateKey():
    # Generate a random 256-bit key
    key = get_random_bytes(32) # Generate a 32-byte (256-bit) random value
    return key

# Function to write the writeResult to a file
def writeResult(decrypted_plaintext): # decrypted_plaintext is a string
    result_file = 'data/result.txt' # Set the writeResult file path
    with open(result_file, 'w') as file: # Open the writeResult file
        file.write(decrypted_plaintext) # Write the decrypted plaintext to the writeResult file


# **************************************************************


# **************************************************************

# Function to encrypt plaintext
def Encryption():
    print("*ENCRYPTION*")
    secret_key = getKey()
    print("SECRET KEY: ")
    printKey(secret_key)

    f = getPlaintext()
    print("PLAINTEXT: ", f)

    iv = gen_iv()
    print("IV: ", iv)

    enc_cbc = encrypt_aes_cbc(f, secret_key, iv)
    print("CIPHERTEXT: ", enc_cbc)

    # Write ciphertext to file
    writeHex(enc_cbc, ciphertext_file)

    # Write IV to file
    writeHex(iv, iv_file)


# Function to decrypt ciphertext
def Decryption():
    print("*DECRYPTION*")
    secret_key = getKey()
    print("SECRET KEY: ")
    printKey(secret_key)

    c = getHex(ciphertext_file)
    iv = getHex(iv_file)

    decrypted_plaintext = decrypt_aes_cbc(c, secret_key, iv)
    print("DECRYPTED TEXT: ", decrypted_plaintext)
    writeResult(decrypted_plaintext)

# Function to generate secret key, encrypt, and decrypt
def genKey():
    secret_key = generateKey()
    printKey(secret_key)
    writeKey(secret_key)


# Main function
def main():
    genKey()
    Encryption()
    Decryption()


if __name__ == "__main__":
    main()
