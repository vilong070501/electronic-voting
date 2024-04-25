from dsa import *
from ecdsa import *
from elgamal import *
from ecelgamal import *

from Voter import *

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

class VoteSystem:

    ## Constructor
    def __init__(self, encrypt_method='ElGamal', sign_method='DSA'):

        self.candidates = [ None ] * 5
        self.voters = [ None ] * 10

        self.encrypt_method = encrypt_method
        self.sign_method = sign_method

        # Generate key pair for encryption/decryption
        if encrypt_method == 'ElGamal':
            x, X = EG_generate_keys()
        elif encrypt_method == 'EC_ElGamal':
            x, X = ECEG_generate_keys()
        
        self.public_key = X
        self.private_key = x

        # Generate key pair for signature for each voter
        if sign_method == 'DSA':
            sign_keys = [DSA_generate_keys() for _ in range(10)]
        elif sign_method == 'ECDSA':
            sign_keys = [ECDSA_generate_keys() for _ in range(10)]

        # Create voters
        for i in range(10):
            self.voters[i] = (Voter(sign_keys[i][0]), sign_keys[i][1])

    ## Display the votes in plain text
    def display_votes(self):
        for voter, _ in self.voters:
            print(voter.voting())

    ## Encryption of the vote 
    def encrypt_vote(self, vote):
        if self.encrypt_method == 'ElGamal':
            return [EGA_encrypt(v, self.public_key) for v in vote]
        elif self.encrypt_method == 'EC_ElGamal':
            return [ECEG_encrypt(v, self.public_key) for v in vote]

    ## Verify the signature of the voter
    def verify_vote(self, signature, encrypted_vote, public_sign_key):
        r, s = signature
        if self.sign_method == 'DSA':
            return DSA_verify(public_sign_key, r, s, encrypted_vote)
        elif self.sign_method == 'ECDSA':
            return ECDSA_verify(encrypted_vote, r, s, public_sign_key)
        
    def add_vote(self, vote):
        for i in range(5):
            
            if self.candidates[i] == None:
                self.candidates[i] = (vote[i][0], vote[i][1])
            else:
                c1, c2 = self.candidates[i]

                if self.encrypt_method == 'ElGamal':
                    c1 *= vote[i][0]
                    c2 *= vote[i][1]
                elif self.encrypt_method == 'EC_ElGamal':
                    c1 = add(c1[0], c1[1], vote[i][0][0], vote[i][0][1], p)
                    c2 = add(c2[0], c2[1], vote[i][1][0], vote[i][1][1], p)

                self.candidates[i] = (c1, c2)
                

    def decrypt_votes(self):
        winner, votes = 0, 0
        for i in range(5):
            if self.encrypt_method == 'ElGamal':
                gm = EG_decrypt(self.candidates[i][0], self.candidates[i][1], self.private_key)
                result = bruteLog(PARAM_G, gm, PARAM_P)
            elif self.encrypt_method == 'EC_ElGamal':
                result = ECEG_decrypt(self.candidates[i][0], self.candidates[i][1], self.private_key)
            
            if result > votes:
                winner = i + 1
                votes = result
            print("Candidate %d has %d votes" % (i + 1, result))
        
        print("The candidate %d has winned the election with %d votes" % (winner, votes))
            

