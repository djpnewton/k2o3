#!/usr/bin/env python

import os
import binascii
from mnemonic import Mnemonic
from Levenshtein import distance

VERSION=3

def random_seed(bits):
    return os.urandom(bits/8)

def seed_to_hex(seed):
    return binascii.hexlify(seed)

def seed_to_int(seed):
    return int(seed_to_hex(seed), 16)

def int_to_buffer(value, bits):
    buf = ""
    for i in range(bits/8):
        byte = value >> (i * 8)
        byte = byte % 256
        buf = chr(byte) + buf
    return buf

def int_to_mnemonic(value, bits):
    m = Mnemonic('english')
    return m.to_mnemonic(int_to_buffer(value, bits))

def mnemonic_to_seed(mnemonic):
    m = Mnemonic('english')
    return m.to_entropy(mnemonic)

def check_mnemonic_words(mnemonic):
    m = Mnemonic('english')
    words = mnemonic.split(" ") 
    for word in words:
        if not word in m.wordlist:
            print "  '%s' not in word list" % word
            # check expand_word candidate
            expand_candidate = m.expand_word(word)
            if expand_candidate != word:
                print "    * perhaps try '%s'" % expand_candidate
            # check levenshtein distance
            min_dist = 9999
            dist_candidate = m.wordlist[0]
            for candidate in m.wordlist:
                dist = distance(candidate, word)
                if dist < min_dist:
                    min_dist = dist
                    dist_candidate = candidate
            if dist_candidate != expand_candidate:
                print "    - perhaps try '%s'" % dist_candidate

def sub(a, b, bits):
    # subtract a from b and if the result is negative
    # then roll over backward from the maximum int given the bit size
    result = a - b
    if result < 0:
        result = (2**bits) + result
    return result

def add(a, b, bits):
    # add a to b and if the result is greater then the maximum int
    # given the bit size then take the result modulo of the max int
    result = a + b
    max = 2**bits
    if result > max:
        result = result % max
    return result

def print_words(words, max_per_line=12, offset1=0, offset2=7):
    words = words.split(" ")
    c = 0
    line = " " * offset1
    for i in range(len(words)):
        line += words[i] + " "
        c += 1
        if c % max_per_line == 0:
            print line,
            line = "\n" + " " * offset2
    print

if __name__ == "__main__":
    pass
