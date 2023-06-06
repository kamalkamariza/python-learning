from rest_framework import serializers
from models import *
from django.core.validators import RegexValidator, MinLengthValidator
from rest_framework.validators import UniqueValidator


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


# class UsersSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Users
#         fields = [
#             'user_number',
#             'user_publicKey',
#         ]
#
#
# class FileSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = File
#         fields = [
#             'file_name',
#             'file_key',
#         ]


class CreateDeviceSerializer(serializers.Serializer):
    signalingKey = serializers.CharField(required=True)
    registrationId = serializers.IntegerField(required=True)


class GetUserDevicesSerializer(serializers.Serializer):
    username = serializers.CharField(validators=[
                                                 MinLengthValidator(3, message='username must be at least 3 characters'),
                                                 ])


class MyUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyUser
        fields = ('id','username', 'email', 'first_name', 'last_name', 'dob', 'gender', 'auth_token', 'fb_uid')
        read_only_fields = ('id','username', 'email', 'first_name', 'last_name', 'dob', 'gender', 'auth_token','fb_uid')


# class TokenSerializer(serializers.ModelSerializer):
#     """
#     Serializer for Token model.
#     """
#     class Meta:
#         model = Token
#         fields = ('key', 'created',)



# class CheckTokenSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Token
#         fields = ('key','created')


class CheckUserNameSerializer(serializers.ModelSerializer):
    username = serializers.CharField(help_text='Required. 30 characters or fewer. Alphanumerics only.',
                                     max_length=30,
                                     validators=[RegexValidator(regex='^[a-zA-Z0-9]*$',
                                                                message='No Special Symbols/Spac allowed.Alphanumerics only',
                                                                code='invalid_username'),
                                                 UniqueValidator(queryset=MyUser.objects.all(),
                                                                 message='This username has been taken.Try another one.'),
                                                 MinLengthValidator(3, message='username must be at least 3 characters'),
                                                 ]
                                     )
    class Meta:
        model = MyUser
        fields = ('username',)


class CheckEmailSerializer (serializers.ModelSerializer):
    email = serializers.EmailField(label='Email address',
                                   max_length=254,
                                   required=True,
                                   validators=[UniqueValidator(queryset=MyUser.objects.all(),
                                                               message='This email has been taken.Please choose another one.')]
                                   )

    class Meta:
        model = MyUser
        fields = ('email',)


class VerifyBackupEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.IntegerField()

    def save(self, **kwargs):
        return self

class BackupEmailSerializer(serializers.ModelSerializer):

    class Meta:
        model = MyUser
        fields = ('email',)

# class RequestPhoneRegistrationSerializer(serializers.ModelSerializer):
#
#     class Meta:
#         model = PhoneNumberEmailVerification
#         fields = ('id', 'full_phone_number',)
#         read_only_fields = ('id',)

# class RequestEmailRegistrationSerializer(serializers.ModelSerializer):
#
#     class Meta:
#         model = PhoneNumberEmailVerification
#         fields = ('id', 'email')
#         read_only_fields = ( 'id',)

"""
data={'signalingKey': 'XXX', 'registrationId': 12, 'fetchesMessages': True}
"""
class DeviceRecordSerializer(serializers.Serializer):
    authToken = serializers.CharField(max_length=255, required=False,  allow_blank=True)
    salt = serializers.CharField(max_length=255, read_only=True)
    signalingKey = serializers.CharField(max_length=255)
    gcmId = serializers.CharField(required=False,  allow_blank=True)
    apnId = serializers.CharField(required=False, allow_blank=True)
    voipApnId = serializers.CharField(required=False,  allow_blank=True)
    pushTimestamp = serializers.IntegerField(required=False, allow_null=True)
    fetchesMessages = serializers.BooleanField(default=False)
    registrationId = serializers.IntegerField()
    device_id = serializers.IntegerField(default=1)
    signedPreKey = SignedPreKeySerializer(required=False)
    lastSeen = serializers.DateTimeField(required=False, allow_null=True)
    created = serializers.DateTimeField(read_only=True, default=datetime.now())
    voice = serializers.BooleanField(default=False)
    userAgent = serializers.CharField(required=False, allow_blank=True)

    def save(self, **kwargs):
        device = kwargs.get('device', None)
        if device and isinstance(device, Device):
            device.authToken = self.validated_data.get('authToken', device.authToken)
            device.salt = self.validated_data.get('salt', device.salt)
            device.signalingKey = self.validated_data.get('signalingKey', device.signalingKey)
            device.gcmId = self.validated_data.get('gcmId', device.gcmId)
            device.apnId = self.validated_data.get('apnId', device.apnId)
            device.voipApnId = self.validated_data.get('voipApnId', device.voipApnId)
            device.pushTimestamp = self.validated_data.get('pushTimestamp', device.pushTimestamp)
            device.fetchesMessages = self.validated_data.get('fetchesMessages', device.fetchesMessages)
            device.registrationId = self.validated_data.get('registrationId', device.registrationId)
            device.device_id = self.validated_data.get('device_id', device.device_id)
            device.signedPreKey = self.validated_data.get('signedPreKey', device.signedPreKey)
            device.lastSeen = self.validated_data.get('lastSeen', device.lastSeen)
            device.created = self.validated_data.get('created', device.created)
            device.voice = self.validated_data.get('voice', device.voice)
            device.userAgent = self.validated_data.get('userAgent', device.userAgent)
            return device
        return self

class AccountDataSerializer(serializers.ModelSerializer):
    identityKey = serializers.CharField(required=False, allow_blank=True)
    devices = DeviceRecordSerializer(many=True)

    class Meta:
        model = MyUser
        fields = ('id', 'full_phone_number', 'identityKey', 'devices')
        read_only_fields = ('id',)


# class SignUpSerializer(serializers.ModelSerializer):
#     id = serializers.IntegerField(read_only=True)
#     username = serializers.CharField(help_text='Required. 30 characters or fewer. Alphanumerics only.',
#                                      max_length=30,
#                                      validators=[RegexValidator(regex='^[a-zA-Z0-9_-]{3,31}$',
#                                                                 message='No Special Symbols/Spaces allowed.Alphanumerics only',
#                                                                 code='invalid'),
#                                                  UniqueValidator(queryset=MyUser.objects.all())
#                                                  ]
#                                      )
#     password = serializers.CharField(max_length=128, style={'input_type': 'password'}, write_only=True)
#     email = serializers.EmailField(label='Email address',
#                                    max_length=254,
#                                    required=True,
#                                    validators=[UniqueValidator(queryset=MyUser.objects.all(),
#                                                                message='This email has been taken.Please choose another one.')]
#                                    )
#     first_name = serializers.CharField(allow_blank=True, max_length=30, required=False)
#     last_name = serializers.CharField(allow_blank=True, max_length=30, required=False)
#     dob = serializers.DateField(required=True)
#     gender = serializers.CharField(max_length=2,
#                                    required=True,
#                                    validators=[RegexValidator(regex='^([M|m]|[F|f])$',
#                                                               message='Please input M or F only. M for Male, F for Female',
#                                                               code='invalid')
#                                                ]
#                                    )
#     auth_token = TokenSerializer(read_only=True)
#
#
#     class Meta:
#         model = MyUser
#         fields = ('id','username', 'password', 'email', 'first_name', 'last_name', 'dob', 'gender', 'auth_token',)
#
#
#     def create(self, validated_data):
#         user = MyUser.objects.create(**validated_data)
#         user.set_password(validated_data['password'])
#         user.save()
#         Token.objects.get_or_create(user=user)
#         return user
#
#     def update(self, instance, validated_data):
#         instance.username = validated_data.get('username', instance.username)
#         instance.email = validated_data.get('email', instance.email)
#         instance.first_name = validated_data.get('first_name', instance.first_name)
#         instance.last_name = validated_data.get('last_name', instance.last_name)
#         instance.dob = validated_data.get('dob', instance.dob)
#         instance.gender = validated_data.get('gender', instance.gender)
#         token_data = validated_data.pop('auth_token')
#         auth_token = instance.auth_token
#         # Unless the application properly enforces that this field is
#         # always set, the follow could raise a `DoesNotExist`, which
#         # would need to be handled.
#         instance.auth_token = validated_data.get('auth_token', instance.auth_token)
#         auth_token.key = token_data.get(
#             'key',
#             auth_token.key
#         )
#         auth_token.created = token_data.get(
#             'created',
#             auth_token.created
#         )
#         instance.save()
#         return instance


'''class TestSignUpSerializer(serializers.ModelSerializer):
    auth_token = TokenSerializer(read_only=True)

    class Meta:
        model = MyUser
        fields = ('id','username', 'password', 'email', 'auth_token')


    def create(self, validated_data):
        user = MyUser(email=validated_data['email'],
                      username=validated_data['username']
                     # first_name=validated_data['first_name'],
                     # last_name=validated_data['last_name'],
                     # dob=validated_data['dob']
                     # gender=validated_data['gender']
                      )
        user.set_password(validated_data['password'])
        user.save()
        Token.objects.get_or_create(user=user)
        #user = MyUser(auth_token=self.validate(auth_token))
        return user

    def validate(self, attrs):
        raise serializers.ValidationError("error")
        return attrs'''

# class FBTokenSerializer(serializers.ModelSerializer):
#
#     class Meta:
#         model = FbAccount
#         fields = ('facebook_token',)


# class FBDetailSerializer(serializers.ModelSerializer):
#
#     user = serializers.IntegerField(read_only=True)
#     expires_at = serializers.FloatField()
#
#     class Meta:
#         model = FbAccount
#         fields = ('id', 'user', 'uid', 'date_joined', 'expires_at')
#         read_only_fields = ('id', 'date_joined')



# class FBAccountSerializer(serializers.ModelSerializer):
#
#     user = serializers.IntegerField(read_only=True)
#
#     class Meta:
#         model = FbAccount
#         fields = ('id', 'user', 'facebook_token', 'uid', 'date_joined', 'extra_data', 'expires_at')
#         read_only_fields = ('id', 'user', 'uid', 'date_joined', 'extra_data', 'expires_at')


# class FBExtraDataSerializer(serializers.ModelSerializer):
#
#     user = serializers.IntegerField(read_only=True)
#
#     class Meta:
#         model = FbAccount
#         fields = ('id', 'user', 'extra_data')
#         read_only_fields = ('id', 'user')



'''    def validate(self, attrs):
        access_token = attrs.get('access_token')
        json = auth_user.views.get_user_facebook_token(access_token)

        if json['data']['error']:
            raise serializers.ValidationError('There is error in the access token')

        return attrs

    def create(self, validated_data):
        access_token=validated_data.pop['access_token']
        token = FbAccount(access_token=access_token)
        token.save()
        json = get_user_facebook_token(access_token)
        extra_data = FbAccount(uid=json['data']['user_id'],
                               expires_at=json['data']['expires_at'],
                               extra_data=json['data']['app_id']
                               )
        extra_data.save()
        return token'''

class VerifyPhoneNumberSerializer(serializers.ModelSerializer):

    class Meta:
        model = MyUser
        fields = ('id', 'phone_number_raw', 'phone_number_country', 'sms_code', 'sms_code_expiry')
        read_only_fields = ( 'id', 'sms_code', 'sms_code_expiry')

'''
    format = "%Y-%m-%d %H:%M:%S"
    def create(self, validated_data):
        user = MyUser.objects.get(username = validated_data['username'])
        user.phone_number_raw=validated_data['phone_number_raw']
        user.phone_number_country=validated_data['phone_number_country']
        sms_code = random.randrange(1000, 9999)
        user.sms_code = sms_code
        expiry = datetime.now() + datetime.timedelta(minutes=5)
        user.sms_code_expiry = expiry.strftime(self.format)
        user.save()
        return user

'''

'''    def validate(self, data):
        user = MyUser.objects.get(username=data['username'])
        if user.sms_code_expiry is not None:
            expiry_date = datetime.datetime.strptime(user.sms_code_expiry, self.format)
            if  datetime.now() <= expiry_date:
                time_left = expiry_date - datetime.now()
                raise serializers.ValidationError('Wait for %d second(s) to request SMS code again' % time_left.seconds)
            else:
                user.sms_code_expiry = None
                user.save()
            return data'''


'''
    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        instance.phone_number_raw = validated_data.get('phone_number_raw', instance.phone_number_raw)
        instance.phone_number_country = validated_data.get('phone_number_country', instance.phone_number_country)
        instance.sms_code = validated_data.get('sms_code', instance.sms_code)
        instance.sms_code_expiry = validated_data.get('sms_code_expiry', instance.sms_code_expiry)
        instance.save()
        return instance
'''


class CheckPhoneNumberSerializer(serializers.ModelSerializer):

    class Meta:
        model = MyUser
        fields = ('id', 'sms_code', 'sms_code_expiry', 'phone_verified',
                  'phone_number_raw', 'phone_number_country', 'full_phone_number')
        read_only_fields = ( 'id', 'sms_code_expiry', 'phone_verified', 'full_phone_number')
