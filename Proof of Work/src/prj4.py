import sys
import hashlib
import time


# Function to write content to a file
def writeFile(pathFile, content):
    with open(pathFile, "w") as file:
        file.write(str(content))

# Function to read binary content from a file
def readBinaryFile(pathFile):
    with open(pathFile, "r") as file:
        binaryText = file.read().strip()
        # Checking if the content is a valid binary (only contains '0' and '1')
        if not set(binaryText).issubset({'0', '1'}):
            raise ValueError("The file contains wrong binary content.")
        return binaryText


# Function to convert text to binary
def TexttoBinary(pathFile, encoding="utf-8"):
    with open(pathFile, "r", encoding=encoding) as file:
        text_content = file.read().strip()
        # Converting text characters to their binary representation
        binaryText = ''.join(format(ord(char), '08b') for char in text_content)
        return binaryText

# Function to generate a target binary based on difficulty
def genTarget(difficulty):
    targetBinary = '0' * difficulty + '1' * (256 - difficulty)
    return targetBinary

# Function to find the solution nonce for a given input message and target
def soln(inputMsg, target):
    nonce = 0
    targetInt = int(target, 2)  # Converting the target binary to an integer

    while True:
        solution = inputMsg +  bin(nonce)[2:]  # Concatenating input message with nonce
        hash = hashlib.sha256(solution.encode()).hexdigest()  # Getting the hash of the solution
        binary = bin(int(hash, 16))[2:].zfill(256)  # Converting the hash to binary

        if int(binary, 2) <= targetInt:
            return nonce, nonce  # Returning the nonce if the condition is met

        nonce += 1  # Incrementing nonce if the condition is not met

# Function to verify a given solution
def verifySolution(inputMsg, solution, target):
    solution =  inputMsg +  bin(solution)[2:]  # Concatenating input message with the solution nonce
    hash = hashlib.sha256(solution.encode()).hexdigest()  # Getting the hash of the solution
    binary = bin(int(hash, 16))[2:].zfill(256)  # Converting the hash to binary

    targetInt = int(target, 2)  # Converting the target binary to an integer

    return 1 if int(binary, 2) <= targetInt else 0  # Returning 1 if the solution meets the target, else 0

def main():
    # Reading difficulty from command line arguments
    difficulty = int(sys.argv[1])
    if not (0 <= difficulty <= 255):
        print("ERROR: Difficulty should be between 0 and 255.")
        sys.exit(1)

    # Generating the target based on the difficulty and writing it to a file
    target = genTarget(difficulty)
    with open("data/target.txt", "w") as file:
        file.write(target)

    # Reading the target and input message from files
    targetFilePath = "data/target.txt"
    target = readBinaryFile(targetFilePath)
    inputFilePath = "data/input.txt"
    inputMsg = TexttoBinary(inputFilePath)

    # Finding the solution nonce
    nonce, solution = soln(inputMsg, target)

    # Verifying the solution
    validSoln = verifySolution(inputMsg, solution, target)

    # Printing the solution nonce, solution, and its validity
    print("Solution Nonce:", nonce)
    print("Solution:", solution)
    print("Valid Solution:", validSoln)

    # Writing the solution to a file
    solution_path = "data/solution.txt"
    writeFile(solution_path, solution)
    
if __name__ == "__main__":
    # Measuring the execution time of the main function
    start_time = time.time()
    main()
    end_time = time.time()
    runtime = end_time - start_time
    print("Runtime:", runtime)
