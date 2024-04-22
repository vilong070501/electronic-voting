from ecdsa import *

# Génération de clés ECDSA
private_key, public_key = ECDSA_generate_keys()

# Définir un message
message = "Hello, world!"

# Signature du message
signature = ECDSA_sign(message, private_key)

# Vérification de la signature
verification = ECDSA_verify(message, signature, public_key)

print(f"Clé privée: {private_key}")
print(f"Clé publique: {public_key}")
print(f"Signature: {signature}")
print(f"Vérification de la signature: {'valide' if verification else 'invalide'}")

