from Crypto.Hash import MD5


h = MD5.new()
h.update(b'Jherison safado')
print(h.hexdigest())