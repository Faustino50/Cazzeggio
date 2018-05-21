def inizio():
    global hashlib
    import hashlib
    print("Benvenuto, scelga l'algoritmo di hash da usare\nLe scelte sono: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, BLAKE2, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE-128, SHAKE-256\n")
    inizio = input("Algoritmo: ")
    if inizio == "SHA-1":
        sha1()
    if inizio == "BLAKE2":
        blake2()
    if inizio == "MD5":
        md5() 
    if inizio == "SHA-224":
        sha224()
    if inizio == "SHA-256":
        sha256()
    if inizio == "SHA-384":
        sha384()
    if inizio == "SHA-512":
        sha512()
    if inizio == "SHA3-224":
        sha3_224()
    if inizio == "SHA3-256":
        sha3_256()
    if inizio == "SHA3-384":
        sha3_384()
    if inizio == "SHA3-512":
        sha3_512()
    if inizio == "SHAKE-128":
        shake_128()
    if inizio == "SHAKE-256":
        shake_256()

def sha1():
    a = input("Digita il messaggio che vuoi hashare: ")
    b = str.encode(a)
    m = hashlib.sha1
    c = m(b).hexdigest()
    print(c)

def blake2():
    x = input("OS a 64bit? [Y/N]: ")
    if x == "Y":
        m = hashlib.blake2b
    else:
        m = hashlib.blake2s
    a = input("Digita il messaggio che vuoi hashare: ")
    b = str.encode(a)
    c = m(b).hexdigest()
    print(c)

def md5():
    a = input("Digita il messaggio che vuoi hashare: ")
    b = str.encode(a)
    m = hashlib.md5
    c = m(b).hexdigest()
    print(c)

def sha224():
    a = input("Digita il messaggio che vuoi hashare:  ")
    b = str.encode(a)
    m = hashlib.sha224
    c = m(b).hexdigest()
    print(c)

def sha256():
    a = input("Digita il messaggio che vuoi hashare: ")
    b = str.encode(a)
    m = hashlib.sha256
    c = m(b).hexdigest()
    print(c)

def sha384():
    a = input("Digita il messaggio che vuoi hashare: ")
    b = str.encode(a)
    m = hashlib.sha384
    c = m(b).hexdigest()
    print(c)

def sha512():
    a = input("Digita il messaggio che vuoi hashare: ")
    b = str.encode(a)
    m = hashlib.sha512
    c = m(b).hexdigest()
    print(c)

def sha3_224():
    a = input("Digita il messaggio che vuoi hashare: ")
    b = str.encode(a)
    m = hashlib.sha3_224
    c = m(b).hexdigest()
    print(c)

def sha3_256():
    a = input("Digita il messaggio che vuoi hashare: ")
    b = str.encode(a)
    m = hashlib.sha3_256
    c = m(b).hexdigest()
    print(c)

def sha3_384():
    a = input("Digita il messaggio che vuoi hashare: ")
    b = str.encode(a)
    m = hashlib.sha3_384
    c = m(b).hexdigest()
    print(c)

def sha3_512():
    a = input("Digita il messaggio che vuoi hashare: ")
    b = str.encode(a)
    m = hashlib.sha3_224
    c = m(b).hexdigest()
    print(c)

def shake_128():
    a = input("Digita il messaggio che vuoi hashare: ")
    b = str.encode(a)
    m = hashlib.shake_128
    c = m(b).hexdigest(128)
    print(c)

def shake_256():
    a = input("Digita il messaggio che vuoi hashare: ")
    b = str.encode(a)
    m = hashlib.shake_256
    c = m(b).hexdigest(256)
    print(c)

inizio()



