import unittest
import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

import ecelgamal
from algebra import int_to_bytes

class TestECELGammalEncryptMethod(unittest.TestCase):

    def test_EGA_Encrypt_Result_Equal_5(self):
        x, X = ecelgamal.ECEG_generate_keys()
        messages = [1, 1, 1, 1, 1]
        r, c = ecelgamal.ECEG_encrypt(messages[0], X)
        for m in messages[1:]:
            r_tmp, c_tmp = ecelgamal.ECEG_encrypt(m, X)
            r = ecelgamal.add(r[0], r[1], r_tmp[0], r_tmp[1], ecelgamal.p)
            c = ecelgamal.add(c[0], c[1], c_tmp[0], c_tmp[1], ecelgamal.p)

        m = ecelgamal.ECEG_decrypt(r, c, x)
        print("m = ", m)
        self.assertEqual(m, 5)



if __name__ == '__main__':
    unittest.main()