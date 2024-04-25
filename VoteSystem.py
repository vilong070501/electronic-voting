from dsa import *
from ecdsa import *
from elgamal import *
from ecelgamal import *

from Voter import *

NB_CANDIDATES = 5
NB_VOTERS = 10

class VoteSystem:

    ## Constructor
    def __init__(self, encrypt_method='ElGamal', sign_method='DSA'):

        self.candidates = [ None ] * NB_CANDIDATES
        self.voters = [ None ] * NB_VOTERS

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
            sign_keys = [DSA_generate_keys() for _ in range(NB_VOTERS)]
        elif sign_method == 'ECDSA':
            sign_keys = [ECDSA_generate_keys() for _ in range(NB_VOTERS)]

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
            return DSA_verify(encrypted_vote, r, s, public_sign_key)
        elif self.sign_method == 'ECDSA':
            return ECDSA_verify(encrypted_vote, r, s, public_sign_key)
        
    ## Add the vote to the system
    def add_vote(self, vote):
        for i in range(NB_CANDIDATES):
            
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
                
    ## Decrypt and count votes
    def decrypt_votes(self):
        nb_votes = [ 0 ] * NB_CANDIDATES
        for i in range(NB_CANDIDATES):
            if self.encrypt_method == 'ElGamal':
                gm = EG_decrypt(self.candidates[i][0], self.candidates[i][1], self.private_key)
                nb_votes[i] = bruteLog(PARAM_G, gm, PARAM_P)
            elif self.encrypt_method == 'EC_ElGamal':
                nb_votes[i] = ECEG_decrypt(self.candidates[i][0], self.candidates[i][1], self.private_key)
            
        return nb_votes
    
    ## Display the result of the vote
    def display_result(self):

        print()

        nb_votes = self.decrypt_votes()

        winner, votes = 0, 0
        for i in range(NB_CANDIDATES):
            if nb_votes[i] > votes:
                winner = i + 1
                votes = nb_votes[i]
            print("Candidate %d has %d votes" % (i + 1, nb_votes[i]))

        
        print()

        if all(x == nb_votes[0] for x in nb_votes):
            print("\033[92mThe result of the vote is a tie! Please start a new vote!\033[00m")
        else:
            print("\033[92mCongratulations, the candidate \033[91m%d\033[0m \033[92mhas winned the election with \033[91m%d\033[0m \033[92mvotes !!!\033[00m" % (winner, votes))
        
        print()
            

