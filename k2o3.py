#!/usr/bin/env python

import os
import binascii

VERSION=2

def random_number(bits):
    return int(binascii.hexlify(os.urandom(bits/8)), 16)

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

def test(original_key, bits):
    #
    # we are going to try and create 3 parts of a key (key_a, key_b, key_c)
    # of which any 2 of the 3 parts can be used to recreate the original key
    #

    # key_a: a random number (with same num of bits as original key)
    key_a = random_number(bits)

    # key_b: another number which when added to key_a will result in original_key
    key_b = sub(original_key, key_a, bits)

    # key_c: key_a - key_b
    key_c = sub(key_a, key_b, bits)

    # test
    print "original key   :", hex(original_key)
    print "key_a          :", hex(key_a)
    print "key_b          :", hex(key_b)
    print "key_c          :", hex(key_c)
    r1 = add(key_a, key_b, bits)
    print "key_a + key_b  :", hex(r1)
    r2 = add(add(key_b, key_b, bits), key_c, bits)
    print "2*key_b + key_c:", hex(r2)
    r3 = sub(add(key_a, key_a, bits), key_c, bits)
    print "2*key_a - key_c:", hex(r3)

    assert(r1 == original_key)
    assert(r2 == original_key)
    assert(r3 == original_key)

if __name__ == "__main__":
    print "k203.py version", VERSION
    #test(0x4B6150645367566B597033733676397924423F4528482B4D6251655468576D5A, 256)
    test(random_number(256), 256)
