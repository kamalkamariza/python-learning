# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.views import generic
from django.http import HttpResponse
from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import *
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import ast
from base64 import b64decode, b64encode
import base64
import sys

from .models import Users, File
from .serializers import UsersSerializer, FileSerializer
import os.path


def index(request):
    return HttpResponse("Connected to keys")


@api_view(['GET', ])
def get_serverKey(request):
    if request.method == 'GET':
        exists = os.path.isfile('RSAKeys.txt')
        if exists:
            print ("Exist")
            myfile = open('RSAKeys.txt', 'r')
            text = myfile.read()
            myfile.close()

            data_file = open("RSAKeys.txt")
            block = ""
            found = False

            for line in data_file:
                if found:
                    block += line
                    if line.strip() == "-----END PUBLIC KEY-----":
                        break
                else:
                    if line.strip() == "-----BEGIN PUBLIC KEY-----":
                        found = True
                        block = "-----BEGIN PUBLIC KEY-----\n"

            data_file.close()
            print (block)

            return Response(data={"key": block})
        else:
            print ("Doesnt Exist")
            return Response(data={"status": "fail"})

    else:
        return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', ])
def get_serverPrivKey(request):
    if request.method == 'GET':
        exists = os.path.isfile('RSAKeys.txt')
        if exists:
            print ("Exist")
            myfile = open('RSAKeys.txt', 'r')
            text = myfile.read()
            myfile.close()

            data_file = open("RSAKeys.txt")
            block = ""
            found = False

            for line in data_file:
                if found:
                    block += line
                    if line.strip() == "-----END PRIVATE KEY-----":
                        break
                else:
                    if line.strip() == "-----BEGIN PRIVATE KEY-----":
                        found = True
                        block = "-----BEGIN PRIVATE KEY-----\n"

            data_file.close()
            print (block)

            return Response(data={"key": block})
        else:
            print ("Doesnt Exist")
            return Response(data={"status": "fail"})

    else:
        return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', ])
def get_allKey(request):
    if request.method == 'GET':
        all_keys = Users.objects.all()
        serializer = UsersSerializer(all_keys, many=True)

        return Response(serializer.data)

    else:
        return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', ])
def test_key(request):
    if request.method == 'GET':
        file_obj = File.objects.get(file_name="file1.jpg")
        file_key = file_obj.file_key

        print("\nfile_key\n---------\n" + str(file_key))
        print("type file key" + str(type(file_key)))
        print ("file Key size" + str(len(file_key)) + "\n")

        data_file = open("RSAKeys.txt")
        block = ""
        found = False

        for line in data_file:
            if found:
                block += line
                if line.strip() == "-----END PRIVATE KEY-----":
                    break
            else:
                if line.strip() == "-----BEGIN PRIVATE KEY-----":
                    found = True
                    block = "-----BEGIN PRIVATE KEY-----\n"

        data_file.close()
        private_key_string = block

        print ("private key\n---------\n" + str(private_key_string))
        print("type private key" + str(type(private_key_string)))
        print ("private key size" + str(len(private_key_string))  + "\n")

        private_key = RSA.importKey(private_key_string)
        print(private_key)
        print("type key" + str(type(private_key)) + "\n")

        raw_cipher_data = base64.b64decode(file_key)
        print("type raw cipher" + str(type(raw_cipher_data)))
        print ("size raw cipher" + str(len(raw_cipher_data)) + "\n")

        decrypted = private_key.decrypt(raw_cipher_data)
        print (decrypted)
        print("type decrypted" + str(type(decrypted)))
        print ("size decrypted" + str(len(decrypted)) + "\n")

        # test_decrypted = private_key.decrypt(decrypted)
        # print("type test decrypted" + str(type(test_decrypted)))
        # print ("size test decrypted" + str(len(test_decrypted)) + "\n")

        base64decrypted = base64.b64encode(decrypted)
        print ("base64decrypted\n" + base64decrypted + "\n")

        # test_base64decrypted = base64.b64encode(test_decrypted)
        # print ("Test base64decrypted\n" + test_base64decrypted + "\n")

        print ("success s")

        # import pdb; pdb.set_trace()

        # initial = 0
        # with decrypted as f:
        #
        #     byte = f.read(1)
        #     while byte != "":
        #         # Do stuff with byte.
        #         byte = f.read(1)

        # return Response(data={"answer": base64decrypted})
        return Response(status=status.HTTP_200_OK)

    else:
        return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', ])
def test_rsa(request):
    if request.method == 'GET':
        file_obj = File.objects.get(file_name="file1.jpg")
        file_key = file_obj.file_key

        print("\nfile_key\n---------\n" + str(file_key))
        print("type file key" + str(type(file_key)))
        print ("file Key size" + str(len(file_key)) + "\n")

        data_file = open("RSAKeys.txt")
        priv_block = ""
        pub_block = ""
        found = False

        for line in data_file:
            if found:
                pub_block += line
                if line.strip() == "-----END PUBLIC KEY-----":
                    break
            else:
                if line.strip() == "-----BEGIN PUBLIC KEY-----":
                    found = True
                    pub_block = "-----BEGIN PUBLIC KEY-----\n"

        for line in data_file:
            if found:
                priv_block += line
                if line.strip() == "-----END PRIVATE KEY-----":
                    break
            else:
                if line.strip() == "-----BEGIN PRIVATE KEY-----":
                    found = True
                    priv_block = "-----BEGIN PRIVATE KEY-----\n"

        data_file.close()
        private_key_string = priv_block
        public_ley_string = pub_block

        print ("private key\n---------\n" + str(private_key_string))
        print("type private key" + str(type(private_key_string)))
        print ("private key size" + str(len(private_key_string)) + "\n")

        print ("public key\n---------\n" + str(public_ley_string))
        print("type public key" + str(type(public_ley_string)))
        print ("public key size" + str(len(public_ley_string)) + "\n")

        private_key = RSA.importKey(private_key_string)
        print(private_key)
        print("private type key" + str(type(private_key)) + "\n")

        public_key = private_key.publickey()
        print(public_key)
        print("public type key" + str(type(public_key)) + "\n")

        raw_cipher_data = base64.b64decode(file_key)
        print("type raw cipher" + str(type(raw_cipher_data)))
        print ("size raw cipher" + str(len(raw_cipher_data)) + "\n")

        decrypted_string = private_key.decrypt(raw_cipher_data)
        base64string = decrypted_string.encode('base64')
        length = len(base64string)
        print(base64string)
        print (bytearray(base64string))
        print (len(base64string))
        print ("success s")

        data = base64string[0:length-66]
        sliced = base64string[length-66:length]
        print (sliced)
        print (data)

        # datadecoded = base64.decode(data)
        encoded = base64.b64decode(sliced)
        print (len(encoded))

        iv = encoded[:16].encode('base64')
        heX = encoded[-32:].encode('base64')

        print (iv)
        print (heX)

        # import pdb; pdb.set_trace()

        # initial = 0
        # with decrypted as f:
        #
        #     byte = f.read(1)
        #     while byte != "":
        #         # Do stuff with byte.
        #         byte = f.read(1)

        # return Response(data={"answer": base64decrypted})
        return Response(data={"iv": iv, "hex": heX}, status=status.HTTP_200_OK)

    else:
        return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', ])
def test_test(request):
    if request.method == 'GET':

        data_file = open("RSAKeys.txt")
        priv_block = ""
        pub_block = ""
        found = False

        for line in data_file:
            if found:
                pub_block += line
                if line.strip() == "-----END PUBLIC KEY-----":
                    break
            else:
                if line.strip() == "-----BEGIN PUBLIC KEY-----":
                    found = True
                    pub_block = "-----BEGIN PUBLIC KEY-----\n"

        for line in data_file:
            if found:
                priv_block += line
                if line.strip() == "-----END PRIVATE KEY-----":
                    break
            else:
                if line.strip() == "-----BEGIN PRIVATE KEY-----":
                    found = True
                    priv_block = "-----BEGIN PRIVATE KEY-----\n"

        data_file.close()
        private_key_string = priv_block
        public_ley_string = pub_block

        print ("private key\n---------\n" + str(private_key_string))
        print("type private key" + str(type(private_key_string)))
        print ("private key size" + str(len(private_key_string)) + "\n")

        print ("public key\n---------\n" + str(public_ley_string))
        print("type public key" + str(type(public_ley_string)))
        print ("public key size" + str(len(public_ley_string)) + "\n")

        private_key = RSA.importKey(private_key_string)
        print(private_key)
        print("private type key" + str(type(private_key)) + "\n")

        public_key = private_key.publickey()
        print(public_key)
        print("public type key" + str(type(public_key)) + "\n")

        string = "This a test"

        encrypted_string = public_key.encrypt(string.encode('base64'), 32)
        print(encrypted_string)

        decrypted_string = private_key.decrypt(encrypted_string)
        print(decrypted_string.decode('base64'))

        print ("success s")

        # import pdb; pdb.set_trace()

        # initial = 0
        # with decrypted as f:
        #
        #     byte = f.read(1)
        #     while byte != "":
        #         # Do stuff with byte.
        #         byte = f.read(1)

        # return Response(data={"answer": base64decrypted})
        return Response(status=status.HTTP_200_OK)

    else:
        return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', ])
def get_allFileKey(request):
    if request.method == 'GET':
        all_keys = File.objects.all()
        serializer = FileSerializer(all_keys, many=True)

        return Response(serializer.data)

    else:
        return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST', 'GET', ])
def upload_key(request):
    if request.method == 'POST':
        new_user = request.data['user_number']

        exist_result = Users.objects.filter(user_number=new_user).exists()

        if exist_result:
            print ("User Exist")
            # users = Users.objects.all()
            # users = users.get(user_number=new_user)
            user = Users.objects.get(user_number=new_user)
            user.user_publicKey = request.data['user_publicKey']
            user.save()
            return Response(status=status.HTTP_200_OK)

        else:
            print ("User Null")
            serializer = UsersSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    else:
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['POST', 'GET', ])
def upload_filekey(request):
    print("FileKey")

    if request.method == 'POST':
        print("FileKey Post")

        try:
            print(request.data)
            filename = request.data['file_name']
        except Exception as e:
            raise e

        print("FileKey test 1")

        exist_result = File.objects.filter(file_name=filename).exists()
        print(filename)

        print("FileKey test 2")

        if exist_result:
            print ("Key Exist")
            return Response(data={'error': 'Key exist'}, status=status.HTTP_403_FORBIDDEN)

        else:
            print ("Key Null")

            serializer = FileSerializer(data=request.data)
            if serializer.is_valid():
                print("FileKey test 3")
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                print("FileKey test 4")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    else:
        print ("Method not allowed")
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['GET', ])
def get_key(request):
    if request.method == 'GET':
        # users = Users.objects.all()
        number = request.GET.get('user_number', '')
        print ("number " + number)

        if number is not None:
            string = "+"+number
            print ("string " + string)

            exist_result = Users.objects.filter(user_number=string).exists()

            # noinspection PyBroadException
            # try:
            #             #     users = users.get(user_number=string)
            #             # except Exception:
            #             #     return Response(status=status.HTTP_404_NOT_FOUND)

            if exist_result:
                user = Users.objects.get(user_number=string)
                serializer = UsersSerializer(user, many=False)
                return Response(serializer.data)

            else:
                return Response(status=status.HTTP_404_NOT_FOUND)

        else:
            return Response(status=status.HTTP_406_NOT_ACCEPTABLE)

    else:
        return Response(status=status.HTTP_403_FORBIDDEN)


@api_view(['GET', ])
def get_filekey(request):
    if request.method == 'GET':
        filename = request.GET.get('file_name', '')
        print ("file Name " + filename)

        if filename is not None:
            exist_result = File.objects.filter(file_name=filename).exists()

            if exist_result:
                print ("Key db Exist")
                file_object = File.objects.get(file_name=filename)
                serializer = FileSerializer(file_object, many=False)
                return Response(serializer.data)

            else:
                print ("Key db Null")
                return Response(status=status.HTTP_404_NOT_FOUND)

        else:
            return Response(status=status.HTTP_406_NOT_ACCEPTABLE)

    else:
        return Response(status=status.HTTP_403_FORBIDDEN)