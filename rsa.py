from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_rsa(plaintext, public_key_bytes):
    public_key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def decrypt_rsa(ciphertext, private_key_bytes):
    private_key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


if __name__ == "__main__":
    plaintext =  input('Enter the plaintext: ').encode('utf-8')

    private_key, public_key = generate_keys()
    print(f'private_key: {private_key.decode()} \n')
    print(f'public_key: {public_key.decode()} \n')

    ciphertext = encrypt_rsa(plaintext, public_key)
    print(f'ciphertext: {ciphertext}\n')

    decrypted_text = decrypt_rsa(ciphertext, private_key)
    print(f'decrypted_text: {decrypted_text}')