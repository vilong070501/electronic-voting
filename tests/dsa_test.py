import unittest
import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

import dsa

class TestDSAVerifyMethod(unittest.TestCase):
    
    def test_DSA_Verify(self):
        m = dsa.H(str.encode("An important message !"))
        x, X = dsa.DSA_generate_keys()
        r, s = dsa.DSA_sign(m, x)
        self.assertTrue(dsa.DSA_verify(X, r, s, m))

if __name__ == '__main__':
    unittest.main()