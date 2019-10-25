#!/usr/bin/env python
from __future__ import print_function

from k2o3 import *

def test_key_splitting(original_key, bits):
    # test key splitting
    key_a, key_b, key_c = split_key(original_key, bits)

    # test putting it back together
    print("original key   :", end=" ")
    print_words(int_to_mnemonic(original_key, bits), offset2=17)
    print("key_a          :", end=" ")
    print_words(int_to_mnemonic(key_a, bits), offset2=17)
    print("key_b          :", end=" ")
    print_words(int_to_mnemonic(key_b, bits), offset2=17)
    print("key_c          :", end=" ")
    print_words(int_to_mnemonic(key_c, bits), offset2=17)
    print("key_a + key_b  :", end=" ")
    r1 = join_key_a_b(key_a, key_b, bits)
    print_words(int_to_mnemonic(r1, bits), offset2=17)
    print("2*key_a - key_c:", end=" ")
    r2 = join_key_a_c(key_a, key_c, bits)
    print_words(int_to_mnemonic(r2, bits), offset2=17)
    print("2*key_b + key_c:", end=" ")
    r3 = join_key_b_c(key_b, key_c, bits)
    print_words(int_to_mnemonic(r3, bits), offset2=17)

    assert(r1 == original_key)
    assert(r2 == original_key)
    assert(r3 == original_key)

    assert(original_key == seed_to_int(mnemonic_to_seed(int_to_mnemonic(original_key, bits))))
    assert(key_a == seed_to_int(mnemonic_to_seed(int_to_mnemonic(key_a, bits))))
    assert(key_b == seed_to_int(mnemonic_to_seed(int_to_mnemonic(key_b, bits))))
    assert(key_c == seed_to_int(mnemonic_to_seed(int_to_mnemonic(key_c, bits))))

    return key_a, key_b, key_c

def test_mnemonic_words():
    # test mnemonic word guessing
    words = "captai blag hox"
    print("checking validity of mnemonic words: '%s'" % words)
    check_mnemonic_words(words)

if __name__ == "__main__":
    print("k203.py version", VERSION)
    print()
    print(":::")
    print()
    bits = 256
    key_a, key_b, key_c = test_key_splitting(seed_to_int(random_seed(bits)), bits)
    print()
    print(":::")
    print()
    key_parts_print(key_a, key_b, key_c, bits)
    print()
    print(":::")
    print()
    test_mnemonic_words()
