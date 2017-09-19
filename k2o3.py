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
    print "original key   :",
    print_words(int_to_mnemonic(original_key, bits), offset2=17)
    print "key_a          :",
    print_words(int_to_mnemonic(key_a, bits), offset2=17)
    print "key_b          :",
    print_words(int_to_mnemonic(key_b, bits), offset2=17)
    print "key_c          :",
    print_words(int_to_mnemonic(key_c, bits), offset2=17)
    r1 = add(key_a, key_b, bits)
    print "key_a + key_b  :",
    print_words(int_to_mnemonic(r1, bits), offset2=17)
    r2 = add(add(key_b, key_b, bits), key_c, bits)
    print "2*key_b + key_c:",
    print_words(int_to_mnemonic(r2, bits), offset2=17)
    r3 = sub(add(key_a, key_a, bits), key_c, bits)
    print "2*key_a - key_c:",
    print_words(int_to_mnemonic(r3, bits), offset2=17)

    assert(r1 == original_key)
    assert(r2 == original_key)
    assert(r3 == original_key)

    assert(original_key == seed_to_int(mnemonic_to_seed(int_to_mnemonic(original_key, bits))))
    assert(key_a == seed_to_int(mnemonic_to_seed(int_to_mnemonic(key_a, bits))))
    assert(key_b == seed_to_int(mnemonic_to_seed(int_to_mnemonic(key_b, bits))))
    assert(key_c == seed_to_int(mnemonic_to_seed(int_to_mnemonic(key_c, bits))))

    return key_a, key_b, key_c

def test_key_print(key_a, key_b, key_c, bits):
    apb  = "(key_a + key_b) %% 2^%d" % bits
    _2bpc = "((2*key_b %% 2^%d) + key_c) %% 2^%d" % (bits, bits)
    ##TODO: need symbol for underflow from below 0 to 2^bits!
    _2amc = "((2*key_a %% 2^%d) - key_c) ?%%? 0" % (bits,)
    print
    print "key_a:"
    print "====="
    print "bip39:",
    print_words(int_to_mnemonic(key_a, bits))
    print "hex  :", "{0:#0{1}x}".format(key_a, 2 + bits/8)
    print
    print "recover via:"
    print "============"
    print apb
    print " or"
    print _2amc
    print
    print "---8<-------------------------------------------------------"
    print
    print "key_b"
    print "====="
    print "bip39:",
    print_words(int_to_mnemonic(key_b, bits))
    print "hex  :", "{0:#0{1}x}".format(key_b, 2 + bits/4)
    print
    print "recover via:"
    print "============"
    print apb
    print " or"
    print _2bpc
    print
    print "---8<-------------------------------------------------------"
    print
    print "key_c:"
    print "====="
    print "bip39:",
    print_words(int_to_mnemonic(key_a, bits))
    print "hex  :", "{0:#0{1}x}".format(key_c, 2 + bits/8)
    print
    print "recover via:"
    print "============"
    print _2bpc
    print " or"
    print _2amc
    print

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
    bits = 256
    key_a, key_b, key_c = test_key_splitting(seed_to_int(random_seed(bits)), bits)
    print
    print ":::"
    print
    test_key_print(key_a, key_b, key_c, bits)
    print
    print ":::"
    print
    test_mnemonic_words()
