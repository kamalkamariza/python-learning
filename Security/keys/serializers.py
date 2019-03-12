
from rest_framework import serializers
from .models import *


class PreKeyV1Serializer(serializers.Serializer):
    keyId = serializers.IntegerField()
    publicKey = serializers.CharField()
    deviceId = serializers.IntegerField(required=False)
    identityKey = serializers.CharField(required=False)
    registrationId = serializers.IntegerField(required=False)

    def create(self, validated_data):
        pre_key_object = PreKeyV1(**validated_data)
        return pre_key_object

    def update(self, instance, validated_data):
        instance.keyId = validated_data.get('keyId', instance.keyId)
        instance.publicKey = validated_data.get('publicKey', instance.publicKey)
        instance.deviceId = validated_data.get('deviceId', instance.deviceId)
        instance.identityKey = validated_data.get('identityKey', instance.identityKey)
        instance.registrationId = validated_data.get('registrationId', instance.registrationId)
        return instance

class PreKeyV2Serializer(serializers.Serializer):
    keyId = serializers.IntegerField()
    publicKey = serializers.CharField()

    def create(self, validated_data):
        pre_key_object = PreKeyV2(**validated_data)
        return pre_key_object

    def update(self, instance, validated_data):
        instance.keyId = validated_data.get('keyId', instance.keyId)
        instance.publicKey = validated_data.get('publicKey', instance.publicKey)
        return instance

class SignedPreKeySerializer(serializers.Serializer):
    signature = serializers.CharField(required=False)
    keyId = serializers.IntegerField(required=False)
    publicKey = serializers.CharField(required=False)
    deviceId = serializers.IntegerField(required=False)
    identityKey = serializers.CharField(required=False)
    registrationId = serializers.IntegerField(required=False)

    def save(self, **kwargs):
        return None

class SignedPreKeySerializerV2(serializers.Serializer):
    signature = serializers.CharField(required=False, allow_blank=True)
    keyId = serializers.IntegerField(required=False)
    publicKey = serializers.CharField(required=False, allow_blank=True)

    def create(self, validated_data):
        signedkey_object = SignedPreKeyV2(**validated_data)
        return signedkey_object

    def update(self, instance, validated_data):
        instance.signature = validated_data.get('signature', instance.signature)
        instance.keyId = validated_data.get('keyId', instance.keyId)
        instance.publicKey = validated_data.get('publicKey', instance.publicKey)
        return instance

class PreKeyStateSerializer(serializers.Serializer):
    identityKey = serializers.CharField()
    preKeys = PreKeyV1Serializer(many=True)
    signedPreKey = SignedPreKeySerializer()
    lastResortKey = PreKeyV1Serializer()

    def create(self, validated_data):
        pre_key_object = PreKeyState(**validated_data)
        return pre_key_object

    def update(self, instance, validated_data):
        instance.identityKey = validated_data.get('identityKey', instance.identityKey)
        instance.preKeys = validated_data.get('preKeys', instance.preKeys)
        instance.signedPreKey = validated_data.get('signedPreKey', instance.signedPreKey)
        instance.lastResortKey = validated_data.get('lastResortKey', instance.lastResortKey)
        return instance


class PreKeyStateSerializerV2(serializers.Serializer):
    preKeys = PreKeyV2Serializer(many=True)
    signedPreKey = SignedPreKeySerializerV2(required=False)
    lastResortKey = PreKeyV2Serializer()
    identityKey = serializers.CharField()

    def create(self, validated_data):
        pre_key_object = PreKeyState(**validated_data)
        return pre_key_object

    def update(self, instance, validated_data):
        instance.identityKey = validated_data.get('identityKey', instance.identityKey)
        instance.preKeys = validated_data.get('preKeys', instance.preKeys)
        instance.signedPreKey = validated_data.get('signedPreKey', instance.signedPreKey)
        instance.lastResortKey = validated_data.get('lastResortKey', instance.lastResortKey)
        return instance


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


