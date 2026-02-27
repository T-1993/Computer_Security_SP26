# Tori Banda; 2/26/2026; CSE 40567: Computer Security
import binascii

# DES Tables and Constants

# Initial Permutation --> found from AR-5
# for the rearrangement of the 64 bits of ciphertext
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

# Initial Permutation Inverse --> found from AR-5
# used to get the plaintext
IP_INV = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

# For subkey generations --> found from AR-5
# used to go from 64-bit key to 56 bits
PC_1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 28, 20, 12, 4]

# also for subkey generations --> found from AR-5
# used to put keys into a 48-bit round key
PC_2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

# E bit-selection table --> foudn from AR-5
# used to make R 48 bits, matching the key
E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23,
     24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

# Permutation P table --> found from AR-5
# used after s-box usage to obtain the final value of f function
P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

# S boxes 1 - 8 --> found from AR-5
# each of the boxes has an input of a 6-bit block and will output a 4-bit block
S_BOX = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

# Helper functions for computation:

# will always be done using a provided 'table' for reordering a string of given bits
def permutate(block, table): 
    return "".join(block[x - 1] for x in table)

# used to shift bits of a given bit string to the left
def left_shift(block, num_shifts):
    return block[num_shifts:] + block[:num_shifts]

# the logic for XOR on two bit strings
def xor(bits1, bits2):
    return "".join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2))


# DES Functions:

# this is meant to turn the given master key (64 bits) into 16 separate 48-bit subkeys
def generate_round_keys(key_bits):
    key_56 = permutate(key_bits, PC_1) # initial permutation to get 56 bit
    C, D = key_56[:28], key_56[28:]
    shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1] # the specified amounts for each round
    round_keys = []
    for s in shifts: # rotation of bits, then applying the PC-2 for going to 48 bits
        C, D = left_shift(C, s), left_shift(D, s)
        round_keys.append(permutate(C + D, PC_2))
    return round_keys

# The f function, as specified in AR-5
def f_function(R, K):
    expanded_R = permutate(R, E) # using e bit-selection table to make R go from 32 bits to 48 bits.
    xor_res = xor(expanded_R, K) # doing XOR using the current round key
    s_output = ""
    for i in range(8): # doing the s-box substituion so go from 48 bits to 32 bits
        block = xor_res[i*6 : (i+1)*6]
        row = int(block[0] + block[5], 2) # we know that the row is the first and last bits
        col = int(block[1:5], 2)          # we know that the col is the middle 4 bits
        s_output += bin(S_BOX[i][row][col])[2:].zfill(4)
    return permutate(s_output, P)   # doing the final permutation as the final part of the function

# this function does the 16 rounds of the DES algorithm
# deciphering DES algorithm
def des_decipher(ciphertext_bits, key_bits):
    # Initial Permutation
    block = permutate(ciphertext_bits, IP)
    L, R = block[:32], block[32:]
    
    # generating the round keys
    keys = generate_round_keys(key_bits)
    print("\n16 Generated Round Keys: \n")
    for i, k in enumerate(keys):
        print(f"Key {i+1:02}: {hex(int(k, 2))[2:].upper().zfill(12)}")
    
    print("\nDecryption Iterations: \n")
    # For decryption process, we know the keys are used in reverse order key 16 -> key 1
    for i in range(16):
        current_key = keys[15 - i]
        f_out = f_function(R, current_key)
        
        # The new L is the current R, and the new R is the output of the current L XOR'ed with f_out
        next_L = R
        next_R = xor(L, f_out)
        L, R = next_L, next_R
        
        # printing for SANITY CHECK & to show steps
        print(f"Round {i+1:02}: f_out={hex(int(f_out, 2))[2:].upper().zfill(8)}, "
              f"L{i+1}={hex(int(L, 2))[2:].upper().zfill(8)}, "
              f"R{i+1}={hex(int(R, 2))[2:].upper().zfill(8)}")

    # doing the final swap and Inverse IP permutation
    final_block = R + L
    result_bits = permutate(final_block, IP_INV)
    return result_bits

# Code in ACTION!!!

# Provided values from assignment
cipher = "1100101011101101101000100110010101011111101101110011100001110011"
key = "0100110001001111010101100100010101000011010100110100111001000100"

# doing descryption and then converting the provided binary result in ACSII text (so we can read it!)
plain_bits = des_decipher(cipher, key)
plain_hex = hex(int(plain_bits, 2))[2:].upper()
plain_text = binascii.unhexlify(plain_hex).decode('ascii')

print(f"\nFinal Deciphered Hex: {plain_hex}") # for sake of simplicity when looking at output, will output hex instead of binary
print(f"Deciphered Text: {plain_text}") # The deciphered message!!