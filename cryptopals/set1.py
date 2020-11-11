#!/usr/bin/env python3

import math
import string
import binascii
import itertools

from Crypto.Cipher import AES

def hex_to_base64(s):
    '''Return the base64 representation of the given hex encoded string.'''
    s_bytes = binascii.a2b_hex(s)
    result_bytes = binascii.b2a_base64(s_bytes, newline=False)
    return result_bytes.decode('ascii')

def fixed_xor(left, right):
    '''Return the XOR combination of two equal-length hex encoded strings.'''
    assert len(left) == len(right)
    result_bytes = bytearray()
    left_bytes, right_bytes = binascii.a2b_hex(left), binascii.a2b_hex(right)
    for (l, r) in zip(left_bytes, right_bytes):
        result_bytes.append(l ^ r)
    result_bytes = binascii.b2a_hex(result_bytes)
    return result_bytes.decode('ascii')

def crack_single_byte_xor(message, threshold=0.4, ndigits=1):
    '''Return the most likely candidates for decrypting the given hex encoded message.'''
    candidates = []
    space = string.printable
    for key in space:
        result = single_byte_xor(message, key)
        try:
            text = binascii.a2b_hex(result).decode('ascii')  # XXX (ricardoapl) Why...?
            p = probability_english(text)
            if p >= threshold:
                candidates.append({
                    'key': key,
                    'probability': round(p, ndigits),
                    'text': text
                })
        except UnicodeDecodeError:
            continue  # Ignore data we can't decode into ASCII as it probably is just garbage
    return candidates

def single_byte_xor(message, k):
    '''Return the XOR combination of a hex encoded message with an ASCII character.'''
    message_bytes = binascii.a2b_hex(message)
    key_bytes = bytes(k, 'ascii') * len(message_bytes)
    key = binascii.b2a_hex(key_bytes).decode('ascii')
    return fixed_xor(message, key)

def probability_english(s):
    '''Return the probability that the given string ``s`` is written in English.'''
    reference = [  # Adapted from https://norvig.com/mayzner.html
        ('Z', 0.0009), ('Q', 0.0012), ('J', 0.0016), ('X', 0.0023),
        ('K', 0.0054), ('V', 0.0105), ('B', 0.0148), ('Y', 0.0166),
        ('W', 0.0168), ('G', 0.0187), ('P', 0.0214), ('F', 0.0240),
        ('M', 0.0251), ('U', 0.0273), ('C', 0.0334), ('D', 0.0382),
        ('L', 0.0407), ('H', 0.0505), ('R', 0.0628), ('S', 0.0651),
        ('N', 0.0723), ('I', 0.0757), ('O', 0.0764), ('A', 0.0804),
        ('T', 0.0928), ('E', 0.1249),
    ]
    probability = 0
    sample = letter_histogram(s.upper())
    sorted_sample = sorted(sample.items(), key=lambda pair:pair[1])
    letters_sample = [letter for (letter, frequency) in sorted_sample]
    letters_reference = [letter for (letter, frequency) in reference]
    top_letters_sample = letters_sample[-5:]
    top_letters_reference = letters_reference[-5:]
    for letter in top_letters_sample:
        if letter in top_letters_reference:
            probability += (1 / 5)
    return probability

def letter_histogram(s):
    '''Return the frequency of each letter in the given text string ``s``.'''
    histogram = {}
    for letter in s:
        frequency = histogram.get(letter, 0)  # Yield a value of 0 if letter doesn't exist yet in histogram
        histogram[letter] = frequency + 1
    for (letter, frequency) in histogram.items():
        histogram[letter] = frequency / len(s)
    return histogram

def detect_single_byte_xor(lines, likelyhood=0.5):
    '''Return likely single-byte XOR encrypted text within the given hex encoded lines.'''
    candidates = []
    stripped_lines = [line.rstrip() for line in lines]  # XXX (ricardoapl) This isn't the callee's job!
    for line in stripped_lines:
        candidate = crack_single_byte_xor(line, likelyhood)
        if candidate:
            candidates += candidate
    return candidates

def repeating_key_xor(message, key):
    '''Return the XOR combination of an ASCII encoded message with an ASCII encoded key.'''
    encoding = 'ascii'
    result_bytes = bytearray()
    message_bytes = bytes(message, encoding)
    key_bytes = bytes(key, encoding) * len(message_bytes)
    for (m, k) in zip(message_bytes, key_bytes):
        result_bytes.append(m ^ k)
    result_bytes = binascii.b2a_hex(result_bytes)
    return result_bytes.decode(encoding)

def crack_repeating_key_xor(data):
    '''Return the most likely candidates for decrypting the given bytes data object.'''
    result = []
    keysizes = guess_keysize(data)  # XXX (ricardoapl) This method is also splitting data into blocks...
    for ks in keysizes:
        block_size = ks
        blocks = split(data, block_size)
        transposed_blocks = transpose(blocks)
        # Solve each block as if it was single-character XOR...
        candidates_per_block = []
        for block in transposed_blocks:
            encoded_block = binascii.b2a_hex(block).decode('ascii')
            candidates = crack_single_byte_xor(encoded_block, 0.5)  # XXX (ricardoapl) Explain this magic constant.
            candidates_per_block.append(candidates)
        # For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR byte for that block...
        keys = {}
        for block, candidates in enumerate(candidates_per_block):
            for candidate in candidates:
                k = keys.get(block, [])
                k += candidate['key']
                keys[block] = k
        result.append(keys)
    return result

def guess_keysize(data, min_keysize=2, max_keysize=40, ncandidates=3):
    '''Return best n candidates for keysize of given repeating-key XOR encrypted bytes object.'''
    candidates = []
    for keysize in range(min_keysize, max_keysize):
        block_size = keysize
        blocks = split(data, block_size)
        edit_distance = avg_hamming_distance(blocks, keysize)  # ... where keysize will be used as a scale for normalization
        candidates.append({'keysize': keysize, 'distance': edit_distance})
    sorted_candidates = sorted(candidates, key=lambda candidate:candidate['distance'])
    best_candidates = [candidate['keysize'] for candidate in sorted_candidates[:ncandidates]]
    return best_candidates

def hamming_distance(left, right):
    '''Return number of differing bits between two byte objects.'''
    distance = 0
    for l, r in zip(left, right):
        bits_l, bits_r = format(l, '>08b'), format(r, '>08b')
        for (bl, br) in zip(bits_l, bits_r):
            if bl != br:
                distance += 1
    return distance

def avg_hamming_distance(iterable, norm_scale):
    '''Return average normalized hamming distance for elements in given iterable.'''
    clength = 2
    it_combinations = itertools.combinations(iterable, clength)
    ncombinations = 0
    avg_distance = 0
    for (m, n) in it_combinations:  # For each clength-pair...
        distance = hamming_distance(m, n)
        norm_distance = distance / norm_scale
        avg_distance += norm_distance
        ncombinations += 1
    avg_distance /= ncombinations
    return avg_distance

def split(data, block_size):
    '''Return list of blocks of ``data`` each of which has length ``block_size``.'''
    blocks = []
    num_blocks = math.ceil(len(data) / block_size)
    for i in range(num_blocks):
        block_start, block_end = i * block_size, (i + 1) * block_size
        block = data[block_start:block_end]
        blocks.append(block)
    return blocks

def transpose(blocks):
    '''Return transposed copy of given list of byte blocks, i.e., first block is the first byte of every block and so on.'''
    transposed_blocks = []
    for block in blocks:
        block_size = len(block)
        for i in range(block_size):
            bits = bytes([block[i]])
            try:  # XXX (ricardoapl) This is not how you should use try/except statements!
                transposed_blocks[i] += bits
            except IndexError:
                transposed_blocks.append(bits)
    return transposed_blocks

def aes_128_ecb(ciphertext, key):
    '''Return the AES-128-ECB decrypted ``ciphertext`` bytes object.'''
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def detect_ecb(lines):
    '''Return a list of likely ECB encrypted byte objects within the given ``lines`` collection.'''
    candidates = []
    min_blocksz, max_blocksz = 16, 32
    for blocksz in range(min_blocksz, max_blocksz):
        for i, line in enumerate(lines):
            match = has_pattern(line, blocksz)
            if match:
                candidate = (i, line)
                candidates.append(candidate)
    return candidates

def has_pattern(line, sz):
    '''Return ``True`` if there exists a repeated pattern of length ``sz`` within the given ``line`` bytes.'''
    length = len(line)
    for i in range(0, length - sz, sz):  # XXX (ricardoapl) Careful! We don't want no off-by-one errors!
        p_start, p_end = i, i + sz
        p = line[p_start:p_end]
        if p in line[p_end:]:
            return True
    return False