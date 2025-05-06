from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

def generate_keys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def bob_generate_challenge():
    return get_random_bytes(16)  

def alice_sign_challenge(challenge, alice_private_key):
    hash_obj = SHA256.new(challenge)
    signature = pkcs1_15.new(alice_private_key).sign(hash_obj)
    return signature

def bob_verify_response(challenge, signature, alice_public_key):
    hash_obj = SHA256.new(challenge)
    try:
        pkcs1_15.new(alice_public_key).verify(hash_obj, signature)
        print("[BOB] Autenticação bem-sucedida: Alice é autêntica.")
        return True
    except (ValueError, TypeError):
        print("[BOB] Autenticação falhou: Assinatura inválida.")
        return False

if __name__ == "__main__":
    alice_private_key, alice_public_key = generate_keys()

    challenge = bob_generate_challenge()
    print(f"[BOB] Desafio enviado: {challenge.hex()}")

    signature = alice_sign_challenge(challenge, alice_private_key)
    print(f"[ALICE] Assinatura enviada: {signature.hex()}")

    bob_verify_response(challenge, signature, alice_public_key)
