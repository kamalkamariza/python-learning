from rest_framework import serializers
from . models import Users, File


class UsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = [
            'user_number',
            'user_publicKey',
        ]


class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = [
            'file_name',
            'file_key',
        ]
