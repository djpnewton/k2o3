#!/usr/bin/env python
from __future__ import print_function

import os
import binascii
import argparse
from mnemonic import Mnemonic
from Levenshtein import distance

VERSION=4

SUPPORTED_BITS = [128, 256]

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
            print("  '%s' not in word list" % word)
            # check expand_word candidate
            expand_candidate = m.expand_word(word)
            if expand_candidate != word:
                print("    * perhaps try '%s'" % expand_candidate)
            # check levenshtein distance
            min_dist = 9999
            dist_candidate = m.wordlist[0]
            for candidate in m.wordlist:
                dist = distance(str(candidate), str(word))
                if dist < min_dist:
                    min_dist = dist
                    dist_candidate = candidate
            if dist_candidate != expand_candidate:
                print("    - perhaps try '%s'" % dist_candidate)

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
            print(line, end=" ")
            line = "\n" + " " * offset2
    print()

def remove_hex_prefix(data):
    prefix = data[:2]
    if prefix == "0x" or prefix == "0X":
        return data[2:]
    else:
        return data

def hex_bits(data):
    data = remove_hex_prefix(data.strip())
    bits = len(data) / 2 * 8
    for sb in SUPPORTED_BITS:
        if bits < sb or bits == sb:
            return sb

def mnemonic_bits(data):
    words = data.split(" ")
    if len(words) == 12:
        return 128
    if len(words) == 24:
        return 256

def split_key(original_key, bits):
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

    return key_a, key_b, key_c

def join_key_a_b(key_a, key_b, bits):
    return add(key_a, key_b, bits)

def join_key_a_c(key_a, key_c, bits):
    return sub(add(key_a, key_a, bits), key_c, bits)

def join_key_b_c(key_b, key_c, bits):
    return add(add(key_b, key_b, bits), key_c, bits)

def join_key(key_a, key_b, key_c, ishex):
    if key_a and key_b:
        if not ishex:
            bits = mnemonic_bits(key_a)
            key_a = seed_to_int(mnemonic_to_seed(key_a))
            key_b = seed_to_int(mnemonic_to_seed(key_b))
        else:
            bits = hex_bits(key_a)
            key_a = int(key_a, 16)
            key_b = int(key_b, 16)
        res = join_key_a_b(key_a, key_b, bits)
    if key_a and key_c:
        if not ishex:
            bits = mnemonic_bits(key_a)
            key_a = seed_to_int(mnemonic_to_seed(key_a))
            key_c = seed_to_int(mnemonic_to_seed(key_c))
        else:
            bits = hex_bits(key_a)
            key_a = int(key_a, 16)
            key_c = int(key_c, 16)
        res = join_key_a_c(key_a, key_c, bits)
    if key_b and key_c:
        if not ishex:
            bits = mnemonic_bits(key_b)
            key_b = seed_to_int(mnemonic_to_seed(key_b))
            key_c = seed_to_int(mnemonic_to_seed(key_c))
        else:
            bits = hex_bits(key_b)
            key_b = int(key_b, 16)
            key_c = int(key_c, 16)
        res = join_key_b_c(key_b, key_c, bits)
    return res, bits

def key_parts_print(key_a, key_b, key_c, bits):
    apb  = "key_a + key_b                  \t(mod 2^%d)" % bits
    _2bpc = "(2 * key_b mod 2^%d) + key_c  \t(mod 2^%d)" % (bits, bits)
    _2amc = "(2 * key_a mod 2^%d) - key_c  \t(mod 2^%d)" % (bits, bits)
    print()
    print("key_a:")
    print("=====")
    print("bip39:",)
    print_words(int_to_mnemonic(key_a, bits))
    print("hex  :", "{0:#0{1}x}".format(key_a, 2 + bits/8))
    print()
    print("recover via:")
    print("============")
    print(apb)
    print(" -or-")
    print(_2amc)
    print()
    print("---8<-------------------------------------------------------")
    print()
    print("key_b")
    print("=====")
    print("bip39:",)
    print_words(int_to_mnemonic(key_b, bits))
    print("hex  :", "{0:#0{1}x}".format(key_b, 2 + bits/4))
    print()
    print("recover via:")
    print("============")
    print(apb)
    print(" -or-")
    print(_2bpc)
    print()
    print("---8<-------------------------------------------------------")
    print()
    print("key_c:")
    print("=====")
    print("bip39:",)
    print_words(int_to_mnemonic(key_c, bits))
    print("hex  :", "{0:#0{1}x}".format(key_c, 2 + bits/8))
    print()
    print("recover via:")
    print("============")
    print(_2bpc)
    print(" -or-")
    print(_2amc)
    print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple 2 of 3 key splitting of secrets")
    subparsers = parser.add_subparsers(dest="subparser")
    split_parser = subparsers.add_parser("split", help="Split a secret into 3 keys")
    split_parser.add_argument("--hex", action="store_true", help="input is hex data (defaults to bip39 mnemonic)")
    split_parser.add_argument("data", help="128 or 256 bit input data")
    join_parser = subparsers.add_parser("join", help="Join 2 keys of split secret")
    join_parser.add_argument("--hex", action="store_true", help="input is hex data (defaults to bip39 mnemonic)")
    join_parser.add_argument("--key_a", action="store")
    join_parser.add_argument("--key_b", action="store")
    join_parser.add_argument("--key_c", action="store")
    checkwords_parser = subparsers.add_parser("checkwords", help="Check bip39 words")
    checkwords_parser.add_argument("words")
    seed_parser = subparsers.add_parser("key", help="Generate key")
    seed_parser.add_argument("--bits", action="store", type=int, default=256, help="Size of key in bits (defaults to 256")

    args = parser.parse_args()
    if args.subparser == "split":
        if args.hex:
            bits = hex_bits(args.data)
            key = int(args.data, 16)
        else:
            bits = mnemonic_bits(args.data)
            key = seed_to_int(mnemonic_to_seed(args.data))
        key_a, key_b, key_c = split_key(key, bits)
        key_parts_print(key_a, key_b, key_c, bits)
    if args.subparser == "join":
        c = 0
        if args.key_a:
            c += 1
        if args.key_b:
            c += 1
        if args.key_c:
            c += 1
        if c < 2:
            print("Not enough key parts")
        else:
            key, bits = join_key(args.key_a, args.key_b, args.key_c, args.hex)
            print(" -", end=" ")
            print_words(int_to_mnemonic(key, bits), offset2=3)
            print(" - %s" % seed_to_hex(int_to_buffer(key, bits)))
    if args.subparser == "checkwords":
        check_mnemonic_words(args.words)
    if args.subparser == "key":
        key = random_seed(args.bits)
        print(" -", end=" ")
        print_words(int_to_mnemonic(seed_to_int(key), args.bits), offset2=3)
        print(" - %s" % seed_to_hex(key))
