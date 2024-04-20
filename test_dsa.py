import dsa

# Générer une paire de clés DSA
x, y = dsa.DSA_generate_keys()
print("Clé privée (x) :", hex(x))
print("Clé publique (y) :", hex(y))

# Générer un nonce aléatoire
k = dsa.DSA_generate_nonce()
print("Nonce (k) :", hex(k))

# Définir un message à signer
message = b"An important message !"

# Signer le message
r, s = dsa.DSA_sign(message, x, k)
print("Signature (r, s) :")
print("r :", hex(r))
print("s :", hex(s))

# Vérifier la signature
verification = dsa.DSA_verify(message, r, s, y)
if verification:
    print("La signature est valide.")
else:
    print("La signature est invalide.")

