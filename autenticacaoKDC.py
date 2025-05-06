from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

kdc_keys = {
    'Alice': b'jherison',  
    'Bob': b'nosirehj'     
}

def create_cipher(key):
    return DES.new(key, DES.MODE_ECB)

def kdc_generate_session_key(req, res):
    session_key = get_random_bytes(8)  
    print(f'Chave de sessão: {session_key.hex()}')

    cipher_bob = create_cipher(kdc_keys[res])
    ticket_for_bob = cipher_bob.encrypt(pad(session_key + req.encode(), 8))

    cipher_alice = create_cipher(kdc_keys[req])
    message_for_alice = cipher_alice.encrypt(pad(session_key + res.encode(), 8))

    return message_for_alice, ticket_for_bob, session_key

def alice_process_message(message_for_alice, ticket_for_bob):
    cipher = create_cipher(kdc_keys['Alice'])
    decrypted = unpad(cipher.decrypt(message_for_alice), 8)
    session_key = decrypted[:8]
    res_name = decrypted[8:].decode()
    print(f'Alice recebeu chave para {res_name}: {session_key.hex()}')
    return session_key, ticket_for_bob

def bob_process_ticket(ticket_for_bob):
    cipher = create_cipher(kdc_keys['Bob'])
    decrypted = unpad(cipher.decrypt(ticket_for_bob), 8)
    session_key = decrypted[:8]
    req_name = decrypted[8:].decode()
    print(f'Bob recebeu chave de {req_name}: {session_key.hex()}')
    return session_key, req_name

def verify(session_key_alice, session_key_bob):
    if session_key_alice == session_key_bob:
        print(f"[SUCESSO] Chave de sessão compartilhada com segurança entre Alice e Bob.")
    else:
        print(f"[ERRO] Falha na troca de chave.")

if __name__ == "__main__":
    msg_alice, ticket_bob, session_key = kdc_generate_session_key("Alice", "Bob")

    session_key_alice, ticket = alice_process_message(msg_alice, ticket_bob)

    session_key_bob, from_user = bob_process_ticket(ticket)

    verify(session_key_alice, session_key_bob)

