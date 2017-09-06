#!/usr/bin/env python

import os
import binascii
from mnemonic import Mnemonic
from Levenshtein import distance

VERSION=2

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
        result = (2**bits - 1) + result
    return result

def add(a, b, bits):
    # add a to b and if the result is greater then the maximum int
    # given the bit size then take the result modulo of the max int
    result = a + b
    max = 2**bits - 1
    if result > max:
        result = result % max
    return result

def test_key_splitting(original_key, bits):
    #
    # we are going to try and create 3 parts of a key (key_a, key_b, key_c)
    # of which any 2 of the 3 parts can be used to recreate the original key
    #

    # key_a: a random number (with same num of bits as original key)
    key_a = seed_to_int(random_seed(bits))

    # key_b: another number which when added to key_a will result in original_key
    key_b = sub(original_key, key_a, bits)

    # key_c: key_a - key_b
    key_c = sub(key_a, key_b, bits)

    # test
    print "original key   :", int_to_mnemonic(original_key, bits)
    print "key_a          :", int_to_mnemonic(key_a, bits)
    print "key_b          :", int_to_mnemonic(key_b, bits)
    print "key_c          :", int_to_mnemonic(key_c, bits)
    r1 = add(key_a, key_b, bits)
    print "key_a + key_b  :", int_to_mnemonic(r1, bits)
    r2 = add(add(key_b, key_b, bits), key_c, bits)
    print "2*key_b + key_c:", int_to_mnemonic(r2, bits)
    r3 = sub(add(key_a, key_a, bits), key_c, bits)
    print "2*key_a - key_c:", int_to_mnemonic(r3, bits)

    assert(r1 == original_key)
    assert(r2 == original_key)
    assert(r3 == original_key)

    assert(original_key == seed_to_int(mnemonic_to_seed(int_to_mnemonic(original_key, bits))))
    assert(key_a == seed_to_int(mnemonic_to_seed(int_to_mnemonic(key_a, bits))))
    assert(key_b == seed_to_int(mnemonic_to_seed(int_to_mnemonic(key_b, bits))))
    assert(key_c == seed_to_int(mnemonic_to_seed(int_to_mnemonic(key_c, bits))))

def test_mnemonic_words():
    # test mnemonic word guessing
    words = "captai blag hox"
    print "checking validity of mnemonic words: '%s'" % words
    check_mnemonic_words(words)

if __name__ == "__main__":
    print "k203.py version", VERSION
    print
    print ":::"
    print
    bits = 128
    test_key_splitting(seed_to_int(random_seed(bits)), bits)
    print
    print ":::"
    print
    test_mnemonic_words()
