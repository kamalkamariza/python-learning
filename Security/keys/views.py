# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.views import generic
from django.http import HttpResponse
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .models import Users
from .serializers import UsersSerializer


def index(request):
    return HttpResponse("Connected to keys")


@api_view(['GET', ])
def get_allKey(request):
    if request.method == 'GET':
        all_keys = Users.objects.all()
        serializer = UsersSerializer(all_keys, many=True)

        return Response(serializer.data)

    else:
        return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST', 'GET', ])
def upload_key(request):
    if request.method == 'POST':
        serializer = UsersSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

    else:
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['GET', ])
def get_key(request):
    if request.method == 'GET':
        users = Users.objects.all()
        number = request.GET.get('user_number', '')
        print ("number " + number)

        if number is not None:
            string = "+"+number
            print ("string " + string)

            # noinspection PyBroadException
            try:
                users = users.get(user_number=string)
            except Exception:
                return Response(status=status.HTTP_404_NOT_FOUND)

            if users is not None:
                serializer = UsersSerializer(users, many=False)
                return Response(serializer.data)

            else:
                return Response(status=status.HTTP_404_NOT_FOUND)

        else:
            return Response(status=status.HTTP_406_NOT_ACCEPTABLE)

    else:
        return Response(status=status.HTTP_403_FORBIDDEN)