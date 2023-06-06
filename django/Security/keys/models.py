from django.db import models
# Create your models here.
from django.conf import settings
from django.contrib.auth.models import AbstractUser

from rest_framework.authtoken.models import Token


def get_truncated_element(element, length):
    assert isinstance(length, int)
    new_element = element
    return new_element[:length]


def java_string_hashcode(s):
    h = 0
    for c in s:
        h = (31 * h + ord(c)) & 0xFFFFFFFF
    return ((h + 0x80000000) & 0xFFFFFFFF) - 0x80000000


class Keys(models.Model):
    username = models.CharField(max_length=255)
    key_id = models.BigIntegerField()
    public_key = models.TextField()
    last_resort = models.BooleanField(default=False)
    device_id = models.BigIntegerField(default=1)

    @staticmethod
    def get_available_keys_count(user, device_id):
        return Keys.objects.filter(username=user.get_username(),
                                      device_id=device_id).count()

    @classmethod
    def store_keys(cls, username, device_id, keys, last_resort_key):
        cls.objects.filter(username=username, device_id=device_id).delete()
        records = list()
        for key in keys:
            records.append(cls.objects.create(username=username, device_id=device_id, key_id=key.get('keyId'),
                                               public_key=key.get('publicKey'), last_resort=False))
        records.append(cls.objects.create(username=username, device_id=device_id, key_id=last_resort_key.get('keyId'),
                                           public_key=last_resort_key.get('publicKey'), last_resort=True))


class PreKeyBase(models.Model):

    class Meta:
        abstract=True

    def get_public_key(self):
        raise AssertionError('this function needs to be overriden')

    def get_key_id(self):
        raise AssertionError('this function needs to be overriden')


class PreKeyV2(PreKeyBase):
    keyId = models.BigIntegerField(null=False)
    publicKey = models.TextField()

    def get_public_key(self):
        return self.publicKey

    def get_key_id(self):
        return self.keyId

    def __eq__(self, other):
        if not isinstance(other, PreKeyV2):
            return False
        if self._meta.concrete_model != other._meta.concrete_model:
            return False
        if not self.publicKey:
            return (self.keyId == other.keyId) and (not other.publicKey)
        else:
            return (self.keyId == other.keyId) and (self.publicKey == other.publicKey)

    def hash_code(self):
        if not self.publicKey:
            return int(self.keyId)
        else:
            return int(self.keyId)^java_string_hashcode(self.publicKey)

    class Meta:
        abstract=True


class PreKeyV1(PreKeyBase):
    keyId = models.BigIntegerField(null=False)
    publicKey = models.TextField()
    deviceId = models.BigIntegerField()
    identityKey = models.TextField()
    registrationId = models.IntegerField()

    class Meta:
        abstract=True


    def __eq__(self, other):
        if not isinstance(other, PreKeyBase):
            return False
        if self._meta.concrete_model != other._meta.concrete_model:
            return False
        if not self.publicKey:
            return (self.keyId == other.keyId) and (not other.publicKey)
        else:
            return (self.keyId == other.keyId) and (self.publicKey == other.publicKey)

    def hash_code(self):
        if not self.publicKey:
            return int(self.keyId)
        else:
            return int(self.keyId)^java_string_hashcode(self.publicKey)

    def get_public_key(self):
        return self.publicKey

    def get_key_id(self):
        return self.keyId


class SignedPreKey(PreKeyV1):
    signature = models.TextField()

    class Meta:
        abstract=True

    def __eq__(self, other):
        if not isinstance(other, SignedPreKey):
            return False
        if self._meta.concrete_model != other._meta.concrete_model:
            return False
        equal = super(SignedPreKey, self).__eq__(other)
        if not self.signature:
            return equal and (not other.signature)
        else:
            return equal and (self.signature == other.signature)

    def hash_code(self):
        if not self.signature:
            return super(SignedPreKey, self).hash_code()
        else:
            return super(SignedPreKey, self).hash_code()^java_string_hashcode(self.signature)


class SignedPreKeyV2(PreKeyV2):
    signature = models.TextField()

    class Meta:
        abstract=True

    def __eq__(self, other):
        if not isinstance(other, SignedPreKey):
            return False
        if self._meta.concrete_model != other._meta.concrete_model:
            return False
        equal = super(SignedPreKeyV2, self).__eq__(other)
        if not self.signature:
            return equal and (not other.signature)
        else:
            return equal and (self.signature == other.signature)

    def hash_code(self):
        if not self.signature:
            return super(SignedPreKeyV2, self).hash_code()
        else:
            return super(SignedPreKeyV2, self).hash_code()^java_string_hashcode(self.signature)


class PreKeyState(object):

    def __init__(self,identityKey, preKeys, signedPreKey, lastResortKey):
        self.identityKey = identityKey
        self.preKeys = preKeys
        self.signedPreKey = signedPreKey
        self.lastResortKey = lastResortKey


class TargetKeys(models.Model):

    def __init__(self, destination, keys=None, *args, **kwargs):
        super(TargetKeys, self).__init__(*args, **kwargs)
        # destination is a user's username
        self.destination = destination
        # keys consist of a list of Key object
        if len(keys) > 0:
            for key in keys:
                if not isinstance(key, Keys):
                    raise TypeError('member of key must be a Key model instance')
        self.keys = keys

    class Meta:
        abstract = True


class Users(models.Model):
    user_number = models.TextField()
    user_publicKey = models.TextField()
    objects = models.Manager()

    def __unicode__(self):
        return self.user_number


class File(models.Model):
    file_name = models.TextField()
    file_key = models.TextField()
    objects = models.Manager()

    def __unicode__(self):
        return self.file_name





