
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

def encrypt_des(plaintext, key):
    iv = get_random_bytes(DES.block_size)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return iv + ciphertext


def decrypt_des(ciphertext, key):
    iv = ciphertext[:DES.block_size]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    plaitext = cipher.decrypt(ciphertext[DES.block_size:])
    return plaitext


if __name__ == "__main__":
    key = get_random_bytes(8)
    plaintext = input('Enter the plaintext: ').encode('utf-8')

    print(f'key: {key} \n')

    print(f'plaintext: {plaintext} \n')

    ciphertext = encrypt_des(plaintext, key)
    print(f'ciphertext: {ciphertext} \n')

    decrypted_text = decrypt_des(ciphertext, key)
    print(f'decrypted_text: {decrypted_text}')