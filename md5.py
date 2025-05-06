from Crypto.Hash import MD5


h = MD5.new()
h.update(b'Jherison safado')
h1 = MD5.new()
h1.update(b'Jherison safado')
print(h.digest())
print(h.hexdigest())

print(h1.digest())
print(h1.hexdigest())

print(h == h1)
print(h.hexdigest() == h1.hexdigest())