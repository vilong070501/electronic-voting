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
        m1, m2, m3, m4, m5 = 1, 1, 1, 1, 1
        r1, c1 = ecelgamal.ECEG_encrypt(m1, X)
        r2, c2 = ecelgamal.ECEG_encrypt(m2, X)
        r3, c3 = ecelgamal.ECEG_encrypt(m3, X)
        r4, c4 = ecelgamal.ECEG_encrypt(m4, X)
        r5, c5 = ecelgamal.ECEG_encrypt(m5, X)
        r_tmp = ecelgamal.add(r1[0], r1[1], r2[0], r2[1], ecelgamal.ORDER)
        c_tmp = ecelgamal.add(c1[0], c1[1], c2[0], c2[1], ecelgamal.ORDER)
        r_tmp2 = ecelgamal.add(r_tmp[0], r_tmp[1], r3[0], r3[1], ecelgamal.ORDER)
        c_tmp2 = ecelgamal.add(c_tmp[0], c_tmp[1], c3[0], c3[1], ecelgamal.ORDER)
        r_tmp3 = ecelgamal.add(r_tmp2[0], r_tmp2[1], r4[0], r4[1], ecelgamal.ORDER)
        c_tmp3 = ecelgamal.add(c_tmp2[0], c_tmp2[1], c4[0], c4[1], ecelgamal.ORDER)
        r = ecelgamal.add(r_tmp3[0], r_tmp3[1], r5[0], r5[1], ecelgamal.ORDER)
        c = ecelgamal.add(c_tmp3[0], c_tmp3[1], c5[0], c5[1], ecelgamal.ORDER)
        m = ecelgamal.ECEG_decrypt(r, c, x)
        self.assertEqual(m, 5)



if __name__ == '__main__':
    unittest.main()
