from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def get_cipher(key, iv):
    return DES.new(key, DES.MODE_CBC, iv)

def bob_generate_challenge():
    return get_random_bytes(8)

def alice_response(challenge, shared_key, iv):
    cipher = get_cipher(shared_key, iv)
    padded = pad(challenge, DES.block_size)
    return cipher.encrypt(padded)

def bob_verify(challenge, response, shared_key, iv):
    cipher = get_cipher(shared_key, iv)
    decrypted = cipher.decrypt(response)
    unpadded = unpad(decrypted, DES.block_size)
    print(f'Desafio decifrado: {unpadded.hex()}')
    return challenge == unpadded


if __name__ == "__main__":
    shared_key = b'jherison'
    iv = get_random_bytes(8)

    challenge = bob_generate_challenge()
    print(f'Desafio do Bob: {challenge.hex()} \n')

    response = alice_response(challenge, shared_key, iv)
    print(f'Resposta da Alice: {response.hex()} \n')
    
    valid = bob_verify(challenge, response, shared_key, iv)
    print(f"Autenticação: {'bem sucecida' if valid else 'falhou'}")

    