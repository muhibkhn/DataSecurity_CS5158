import binascii
import argparse
import secrets
import hashlib
import os
import sys
import base64
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from base64 import b64encode, b64decode

os.sys.path.append('../data')

tokenFile = "data/token.txt"
indexFile = "data/index.txt"

#
#*************************************************
#
#
#*************************************************
# write the key to a file
def writeKeys(key, filename): 
    hex_key = key.hex()
    write_filepath = 'data/' + filename
    with open(write_filepath, 'w') as file:
        file.write(hex_key)
# read the key from a file
def readKeys(filename):
    read_filepath = 'data/' + filename
    try:
        with open(read_filepath, 'r') as file:
            hex_key = file.read().strip()
            key = bytes.fromhex(hex_key)
        return key
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        return None
# generate a key
def generatekey(bits):
    if bits % 8 != 0:
        raise ValueError("Number of bits must be a multiple of 8")
    key = secrets.token_bytes(bits)
    return key
# print the key
def printKey(sk):
    if sk:
        print(f'key:')
        hex_values = ' '.join([format(byte, '02X') for byte in sk])
        print(hex_values)

# load the plaintext
def loadPlaintext():
    plaintext_filepath = 'data/plaintext.txt'
    word_array = []
    with open(plaintext_filepath, 'r') as file:
        words = file.read().split()
        word_array.extend(words)
    
    return word_array

#load the ciphertext
def loadCiphertxt():
    cipher_filepath = 'data/ciphertext.txt'
    try:
        with open(cipher_filepath, "r") as file:
            array = [line.strip() for line in file]
        return array
    except FileNotFoundError:
        print(f"File '{cipher_filepath}' not found.")
        return []

#writing the ciphertext
def writeCiphertxt(ciphertext):
    output_cipher_filepath = 'data/ciphertext.txt'
    with open(output_cipher_filepath, "w") as file:
        for item in ciphertext:
            file.write(str(item) + "\n")

# Find unique words in the files
def findUnique(filesFolder):
    word_to_files = {}
    for root, _, files in os.walk(filesFolder):
        for filename in files:
            with open(os.path.join(root, filename), 'r') as file:
                words = set(file.read().split())
                for word in words:
                    word_to_files.setdefault(word, []).append(filename)
    return word_to_files

#**************************************************
#
#
#**************************************************
# Function to perform XOR between two binary strings
def xor(str1, str2):
    result = ""
    # Iterate through the characters in the binary strings and perform XOR
    for i in range(len(str1)):
        if str1[i] == '0' and str2[i] == '0':
            result += '0'
        elif str1[i] == '1' and str2[i] == '1':
            result += '0'
        else:
            result += '1'
    return result

# Function to perform OTP (One-Time Pad) encryption
def otp(plaintext, secret_key):
    # Perform XOR between the plaintext and the secret key
    ciphertext = xor(plaintext, secret_key)
    return ciphertext

# Function to convert text to binary representation
def text_to_binary(text):
  binary_result = ""
  for char in text:
        # Convert each character to its ASCII value and then to binary
        binary_char = bin(ord(char))[2:].zfill(8)
        binary_result += binary_char
  return binary_result

# Function to convert binary representation back to text
def binary_to_text(binary_string):
    text_result = ""
    # Convert binary back to characters, assuming 8-bit characters
    for i in range(0, len(binary_string), 8):
        split = binary_string[i:i+8]
        text_result += chr(int(split, 2))
    return text_result

def writekeys(keys):
    output_newkey_filepath = 'data/newkey.txt'
    with open(output_newkey_filepath, "w") as file:
        file.write(str(keys) + "\n")
# perforn PRF encryption
def prfEnc(key, data):
    if isinstance(key, str):
        keyBytes = key.encode('utf-8')
    else:
        keyBytes = key
    if isinstance(data, str):
        dataBytes = data.encode('utf-8')
    else:
        dataBytes = data
    prf_result = hashlib.sha256(keyBytes + dataBytes).digest()
    return prf_result

#encrypt the keyword
def keywordEnc(keyword, sk):
    encrypted_keyword = prfEnc(keyword, sk)
    return encrypted_keyword

def genKeys(bits, filename):
    sk = generatekey(bits)
    writeKeys(sk, filename)
#********************************************************
#
#
#********************************************************

# Function to build the encrypted index
def buildEnc_index(filesFolder, sk):
    unique = findUnique(filesFolder)
    indexEnc = {}
    for word, files in unique.items():
        wordEnc = keywordEnc(word, sk)
        filesEnc = [f"{i}" for i in files]
        indexEnc[wordEnc] = filesEnc
    return indexEnc

def aes_encrypt_block(block, key): # block and key are bytes
    cipher = AES.new(key, AES.MODE_ECB) # Create a new AES cipher
    encrypted_block = cipher.encrypt(block) # Perform AES encryption on the block
    return encrypted_block # Return the encrypted block

def encrypt_aes_cbc(plaintext, key): # plaintext, key, and iv are bytes
    cipher = AES.new(key, AES.MODE_CBC) # Create a new AES cipher
    block_size = AES.block_size # Get the block size of the cipher
    padded_text = plaintext + (block_size - len(plaintext) % block_size) * chr(block_size - len(plaintext) % block_size) # Pad the plaintext
    ciphertext = cipher.encrypt(padded_text.encode('utf-8')) # Perform AES encryption on the padded plaintext
    return ciphertext

def AESEnc(sk1, f):
    printKey(sk1)
    print("PLAINTEXT: ", f)
    c = encrypt_aes_cbc(f, sk1)
    print("CIPHERTEXT: ", c)


#********************************************************
#
#
#********************************************************

def main():
    # File paths for secret keys
    sk2_file = 'skaes.txt' 
    genKeys(256, sk2_file)
    sk1_file = 'skprf.txt'
    genKeys(256, sk1_file)

    # Read secret keys from files
    sk1 = readKeys(sk1_file)
    sk2 = readKeys(sk2_file)

    # File paths for token and index
    tokenFile = 'data/token.txt'
    indexFile = 'data/index.txt'

    # Folder path for files
    filesFolder = 'data/files'
    
    # Find unique words in files and build encrypted index
    unique = findUnique(filesFolder)
    indexEnc = buildEnc_index(filesFolder, sk2)

    # Print the encrypted index
    for word, filesEnc in indexEnc.items(): 
        hex_word = binascii.hexlify(word).decode('utf-8') 
        print(f'Word: {hex_word}')
        print(f'Files it appears in: {", ".join(filesEnc)}')
        print()

    # Folder paths for original files and encrypted files
    data_directory = 'data/files' 
    ciphertextFolder = 'data/ciphertextfiles'

    # Write the encrypted index to a file and create corresponding encrypted files
    with open(indexFile, 'w') as index_file: 
        for word, filesEnc in indexEnc.items():
            hex_word = binascii.hexlify(word).decode('utf-8')
            index_file.write(f'Word: {hex_word}\n')
            index_file.write(f'Files it shows in: {", ".join(filesEnc)}\n\n')
            for i in filesEnc:
                new_file_name = newFileName(i)
                NameofFile = os.path.join(ciphertextFolder, new_file_name)
                if not os.path.exists(NameofFile):
                    with open(NameofFile, "w") as file:
                        file.write(hex_word)
                    print(f"File '{NameofFile}' has been created and appended to it")
                else:
                    with open(NameofFile, "a") as file:
                        file.write("\n" + hex_word)
                    print(f"Word added to '{NameofFile}'.")

    # Example token generation using a word "packers"
    w = "packers"
    print("TOKEN USED:", w)
    if sk1:
        genToken = hashlib.sha256(f"{w}{sk1}".encode()).hexdigest()
        print(f"Generated Token: {genToken}")
        try:
            with open(tokenFile, "w") as token_file:
                token_file.write(genToken)
            print(f"Token saved!")
        except IOError:
            print(f"Error: Writing the token.")
    else:
        print("ERROR: Token gen failed as there is a secret key missing.")
        
    # Read the generated token from the file
    try:
        with open(tokenFile, "r") as token_file:
            token = token_file.read().strip()
    except FileNotFoundError:
        print(f"Token file not found.")
        token = None

    # If token exists, decrypt the index
    if token:
        try:
            with open(indexFile, "rb") as index_file:
                indexEnc = base64.b64decode(index_file.read())
        except FileNotFoundError:
            print(f"Encrypted index file not found.")
            indexEnc = None

        # If encrypted index exists, decrypt and print it
        if indexEnc:
            encryption_key = sk1
            iv = token
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            decIndex = cipher.decrypt(indexEnc).decode('utf-8')

            fileRelated = {}
            decIndex_lines = decIndex.split('\n')
            fileNow = None
            for line in decIndex_lines:
                if line.startswith("c"):
                    fileNow = line.strip()
                    fileRelated[fileNow] = []
                elif line:
                    fileRelated[fileNow].extend(line.split())

            for file_id, content in fileRelated.items():
                print(file_id, " ".join(content))

        else:
            print("ERROR: Could not decrypt/read index.")
    else:
        print("ERROR: Token cannot be found or read.")
#********************************************************
#
#
#********************************************************

fileMap = {"f1": "c1", "f2": "c2","f3": "c3", "f4": "c4","f5": "c5", "f6": "c6"}
def newFileName(NameofFile):
    for oldFileName, newFileName in fileMap.items():
        NameofFile = NameofFile.replace(oldFileName, newFileName)
    return NameofFile


if __name__ == "__main__":
    main()