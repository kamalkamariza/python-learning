from keys.models import File
from Crypto.PublicKey import RSA


def main():

    file_obj = File.objects.get(file_name="file1.jpg")
    file_key = file_obj.file_key
    my_file = open('privateKey.txt', 'r')
    text = my_file.read()
    my_file.close()
    private_key_string = text
    private_key = RSA.importKey(private_key_string)

    decrypted = private_key.decrypt(file_key)

    print (decrypted)
    print(text)


if __name__ == '__main__':
    main()