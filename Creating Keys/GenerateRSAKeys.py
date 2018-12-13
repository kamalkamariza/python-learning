from Crypto.Cipher import AES
from Crypto import Random
import base64


"""
    Generate AES key of 32 bytes
"""


def generate_AES():

    aeskey = Random.new().read(32)
    iv = Random.new().read(AES.block_size)

    print ("AES\n" + aeskey)
    print ("iv\n" + iv)
    readWriteFile("\nBase 64 Aes \n" + base64.b64encode(aeskey))
    readWriteFile("\nBase 64 iv \n" + base64.b64encode(iv))


"""
    Generate an RSA keypair with an exponent of 65537 in PEM format
    param: bits The key length in bits
    Return private key and public key
"""


def generate_RSA(bits=2048):

    from Crypto.PublicKey import RSA
    new_key = RSA.generate(bits, e=65537)
    public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey("PEM")
    print ("Public Key\n" + public_key)
    print ("\n Private Key\n" + private_key)
    readWriteFile("\n" + public_key)
    readWriteFile("\n" + private_key)
    return private_key, public_key


"""
    Writing and reading from file (db)
"""


def readWriteFile(keys):
    myfile = open('keys.txt', 'a')
    myfile.write(keys + "\n")
    myfile.close()


def main():
    print "Security Test"


if __name__ == '__main__':
    main()
    generate_RSA(2048)
    generate_AES()
    myfile = open('keys.txt', 'r')
    text = myfile.read()
    myfile.close()
    print ("File \n" + text)
