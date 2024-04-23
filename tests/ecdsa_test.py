import unittest
import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from ecdsa import *

class TestECDSAENcryptMethod(unittest.TestCase):

    def test_ECDSA_verification(self):
        message = "A very very important message !"
        m = str.encode(message)
        x, X = ECDSA_generate_keys()
        r, s = ECDSA_sign(m, x)
        print("message: ", m)
        print("r = ", hex(r))
        print("s = ", hex(s))
        self.assertTrue(ECDSA_verify(m, r, s, X))

if __name__ == '__main__':
    unittest.main()
