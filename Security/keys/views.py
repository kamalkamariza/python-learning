import requests, json, base64
import sys
sys.path.append("../")
sys.path.insert(0, '/Users/Kamal/Documents/Pycharm/Self-Learning-Django-Python/Security/auth_user')

# Create your views here.
from django.shortcuts import render
from django.template import loader
from django.http import HttpResponse
from rest_framework.decorators import api_view
from rest_framework.parsers import JSONParser, FormParser, MultiPartParser
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import *
from .serializers import *
from django.http import Http404, JsonResponse
from rest_framework.views import APIView
from rest_framework.parsers import JSONParser
from django.conf import settings
from auth_user.models import MyUser, Device
from auth_user.serializers import DeviceRecordSerializer
from keys.models import Keys
from django.forms.models import model_to_dict
# from web_message.models import WebIdentityKeyStore, \
#     WebIdentityKeyStoreModel, WebSignedPreKeyStore, KeyStorageManager
from axolotl.state.signedprekeyrecord import SignedPreKeyRecord
from axolotl.state.prekeyrecord import PreKeyRecord
# from Helper.keypair_helper import *
import os.path


# def test_generate_prekeys_mobile(request, user):
#     assert isinstance(user, MyUser)
#     key_storage = KeyStorageManager(user)
#     preKeys = key_storage.generate_user_pre_keys()
#     serialized_prekeys = []
#     for p in preKeys:
#         assert isinstance(p, PreKeyRecord)
#         prekey = KeyStorageManager.dict_from_prekey(p)
#         serialized_prekeys.append(prekey)
#         # save the own prekeys also
#     last_resort_key = KeyStorageManager.generate_last_resort_key()
#     # prekey_store.storePreKey(last_resort_key.getId(), last_resort_key)
#     last_resort_key = KeyStorageManager.dict_from_prekey(last_resort_key)
#     data = {"preKeys": serialized_prekeys,
#                           "lastResortKey": last_resort_key,
#                           "signedPreKey": {'publicKey': '', 'signature': '', 'keyId': 0},
#                           "identityKey": user.get_identity_key()}
#     return json.dumps(data)



# class GetWebClientKeys(APIView):
#     authentication_classes = (EnhancedBasicAuthentication,)
#     parser_classes = (JSONParser, FormParser, MultiPartParser,)
#     permission_classes = (IsAuthenticated,)
#
#     def get(self, request, username, format=None):
#         user = request.user
#         assert isinstance(user, MyUser)
#         destination_user = MyUser.objects.get(username=username)
#         if not destination_user.is_active:
#             raise MyUser.DoesNotExist
#         targetKeys = self.get_local_keys(username, 2)
#         if not isinstance(targetKeys, TargetKeys):
#             return Response(data={'error': 'Target Key not found'}, status=status.HTTP_400_BAD_REQUEST)
#         device = destination_user.get_web_client()
#         if device.is_active():
#             signed_preKeys = device.signedPreKey
#             prekeys = dict()
#             if len(targetKeys.keys) > 0:
#                 for key in targetKeys.keys:
#                     assert isinstance(key, Keys)
#                     if key.device_id == device.device_id:
#                         prekeys = {'keyId': key.key_id, 'publicKey': key.public_key}
#             if not signed_preKeys:
#                 signed_prekey_store = WebSignedPreKeyStore(destination_user)
#                 signed_preKeys = signed_prekey_store.loadSignedPreKeys()[0]
#                 assert isinstance(signed_preKeys, SignedPreKeyRecord)
#
#                 signed_preKeys = {'keyId': signed_preKeys.getId(),
#                                   'signature': base64.b64encode(signed_preKeys.getSignature()),
#                                   'publicKey': base64.b64encode(signed_preKeys.getKeyPair().getPublicKey().getPublicKey())}
#
#             if signed_preKeys is not None or prekeys is not None:
#                 mydevice = {'deviceId': device.device_id, 'registrationId': device.registrationId,
#                  'signedPreKey': signed_preKeys, 'preKey': prekeys}
#                 encoded_id = request.user.get_web_client_identity_key_for_user(username)
#                 return Response(data={'identityKey': encoded_id , 'devices': [mydevice]},
#                                 status=status.HTTP_200_OK)
#             return Response(data={'message': 'no prekeys and signed prekeys'}, status=400)
#         return Response(data={'message': 'no active web device'}, status=400)
#
#     def get_local_keys(self, username, deviceIdSelector):
#         destination = MyUser.objects.get(username=username)
#         if not destination.is_active:
#             raise MyUser.DoesNotExist
#         if deviceIdSelector == '*':
#             pre_keys = self.get_key_by_username(username)
#             if pre_keys:
#                 return TargetKeys(destination=destination, keys=pre_keys)
#             else:
#                 return None
#         device_id = deviceIdSelector
#         devices = destination.data.get('devices', None)
#         device = None
#         for d in devices:
#             if d.get('device_id') == int(device_id):
#                 device = Device(**d)
#         if device is None or not device.is_active():
#             pass
#             # raise MyUser.DoesNotExist
#         for i in range(20):
#             try:
#                 p_keys = self.get_keys_by_username_and_id(username, device.device_id)
#                 if p_keys:
#                     return TargetKeys(destination, p_keys)
#             except Exception:
#                 pass
#         return None
#
#
#     def get_key_by_username(self, username):
#         my_key_dict = Keys.objects.filter(username=username)\
#             .distinct('username', 'device_id').order_by('username', 'device_id', 'key_id')
#         if my_key_dict.count() > 0:
#             preKeys = list()
#             for my_key in my_key_dict:
#                 key_dict = model_to_dict(my_key)
#                 new_key = Keys(**key_dict)
#                 preKeys.append(new_key)
#                 if not my_key.last_resort:
#                     my_key.delete()
#
#             return preKeys
#         return None
#
#     def get_keys_by_username_and_id(self, username, device_id):
#         preKeys = list()
#         my_key = Keys.objects.filter(username=username, device_id=device_id).order_by('key_id').first()
#         if my_key:
#             key_dict = model_to_dict(my_key)
#             new_key = Keys(**key_dict)
#             preKeys.append(new_key)
#             if not my_key.last_resort:
#                 my_key.delete()
#             return preKeys
#         return None


class VerificationOfCode(APIView):
    parser_classes = (JSONParser, FormParser, MultiPartParser,)

    def invalidate_old_users(self, user):
        if user.username == user.email:
            pass
        elif user.email:
            user.username = user.email
            user.full_phone_number = ' '
            user.phone_number_country = ' '
            user.phone_number_raw = ' '
            user.phone_verified = False
            user.authenticated_device = None
            user.save()
            return True
        else:
            user.username = MyUser.get_random_username()
            user.full_phone_number = ' '
            user.phone_number_country = ' '
            user.phone_number_raw = ' '
            user.change_username_now = True
            user.phone_verified = False
            user.authenticated_device = None
            user.save()
            return True

    def create_account(self, password, data, phone=None, email=None, username=None, verification_obj=None):
        if phone is not None:
            username = phone
        elif email is not None:
            username = email
        else:
            raise ValueError('username could not be set')

        def create_new_user():
            user = MyUser.objects.create(username=username, password=hashers.make_password(password))
            if phone is not None:
                user.full_phone_number = phone
                user.phone_number_country = verification_obj.phone_number_country
                user.phone_number_raw = verification_obj.phone_number_raw
                user.phone_verified = True
            if email is not None:
                user.email = email
            assert data['signalingKey']
            assert data['registrationId']
            assert data['voice']

            newDevice = Device(authToken=password, signalingKey=data.get('signalingKey'),
                registrationId=data.get('registrationId'), voice=data.get('voice'))
            # Called set_authentication_credentials to generate hash codes
            newDevice.set_authentication_credentials()
            deviceSerializer = DeviceRecordSerializer(newDevice)
            accountDataSerializer = AccountDataSerializer(data={
                'full_phone_number': user.full_phone_number,
                'email': user.email,
                'devices': [deviceSerializer.data]
            })
            user.data = json.dumps(accountDataSerializer.get_initial())
            user.authenticated_device = json.dumps(deviceSerializer.data)
            user.save()
            return user
        try:
            # if user exists, we need to change the users' username
            # and warn him to re-verify his account
            user = MyUser.objects.get(username=username)
            succeeded = self.invalidate_old_users(user)
            if succeeded:
                user = create_new_user()
                user.update_directory(username_changed=True)
                return user

        except MyUser.DoesNotExist:
            user = create_new_user()
            user.update_directory()
            return user

    def post(self, request, format=None):

        auth = authenticate(request)
        userid = auth[0]
        authToken = auth[1]
        phone = None
        email = None

        request_serializer = DeviceRecordSerializer(data={'signalingKey': request.data.get('signalingKey'),
                                                          'registrationId': request.data.get('registrationId'),
                                                          'voice': request.data.get('voice')})

        if request_serializer.is_valid():
            user = self.create_account(authToken, request_serializer.validated_data, phone=phone,
                                       email=email, verification_obj=verify_obj)
            if user:
                print ('User is created')
            else:
                return Response(status=status.HTTP_406_NOT_ACCEPTABLE)
            return Response(status=status.HTTP_200_OK, data={"success": 1})
        return Response(status=status.HTTP_400_BAD_REQUEST, data=request_serializer.errors)


class GetDeviceKeysV2(APIView):
    authentication_classes = (EnhancedBasicAuthentication,)
    parser_classes = (JSONParser, FormParser, MultiPartParser,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, username, device_id, format=None):
        targetKeys = self.get_local_keys(username, device_id)
        if not targetKeys:
            return Response(data={'message': 'prekeys not available'}, status=400)
        try:
            destination_user = MyUser.objects.get(username=targetKeys.destination)
        except MyUser.DoesNotExist:
            return Response(data={'details': 'Destination User not found'} ,status=status.HTTP_404_NOT_FOUND)
        devices = list()
        if not isinstance(targetKeys, TargetKeys):
            return Response(data={'error': 'Target Key not found'}, status=status.HTTP_400_BAD_REQUEST)
        for device in destination_user.get_devices():
            assert isinstance(device, Device)
            if device.is_active() and ( device_id == '*' or device.device_id == int(device_id)):
                signed_preKeys = [device.signedPreKey]
                signed_preKeys = signed_preKeys[0] if len(signed_preKeys) > 0 else None
                prekeys =  dict()
                if len(targetKeys.keys) > 0:
                    for key in targetKeys.keys:
                        assert isinstance(key, Keys)
                        if key.device_id == device.device_id:
                            prekeys = {'keyId': key.key_id , 'publicKey': key.public_key}

                if signed_preKeys is not None or prekeys is not None:
                    devices.append({'deviceId': device.device_id, 'registrationId': device.registrationId,
                                    'signedPreKey': signed_preKeys, 'preKey': prekeys})
                else:
                    return Response(data={'message': 'no signed prekey or prekeys'}, status=400)
        if len(devices) == 0:
            return Response(status=status.HTTP_200_OK)
        return Response(data={'identityKey': destination_user.get_identity_key(), 'devices': devices},
                        status=status.HTTP_200_OK)

    def get_local_keys(self, username, deviceIdSelector):
        destination = MyUser.objects.get(username=username)
        if not destination.is_active:
            raise MyUser.DoesNotExist
        if deviceIdSelector == '*':
            pre_keys = self.get_key_by_username(username)
            if pre_keys:
                return TargetKeys(destination=destination, keys=pre_keys)
            else:
                return None
        device_id = deviceIdSelector
        devices = destination.data.get('devices', None)
        device = None
        for d in devices:
            if d.get('device_id') == int(device_id):
                device = Device(**d)
        if device is None or not device.is_active():
            pass
            # raise MyUser.DoesNotExist
        for i in range(20):
            try:
                p_keys = self.get_keys_by_username_and_id(username, device.device_id)
                if p_keys:
                    return TargetKeys(destination, p_keys)
            except Exception:
                pass
        return None

    def get_key_by_username(self, username):
        my_key_dict = Keys.objects.filter(username=username)\
            .distinct('username', 'device_id').order_by('username', 'device_id', 'key_id')
        if my_key_dict.count() > 0:
            preKeys = list()
            for my_key in my_key_dict:
                key_dict = model_to_dict(my_key)
                new_key = Keys(**key_dict)
                preKeys.append(new_key)
                if not my_key.last_resort:
                    my_key.delete()

            return preKeys
        return None

    def get_keys_by_username_and_id(self, username, device_id):
        preKeys = list()
        my_key = Keys.objects.filter(username=username, device_id=device_id).order_by('key_id').first()
        if my_key:
            key_dict = model_to_dict(my_key)
            new_key = Keys(**key_dict)
            preKeys.append(new_key)
            if not my_key.last_resort:
                my_key.delete()
            return preKeys
        return None


class GetDeviceKeys(APIView):
    authentication_classes = (EnhancedBasicAuthentication,)
    parser_classes = (JSONParser, FormParser, MultiPartParser,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, username, device_id, format=None):
        targetKeys = self.get_local_keys(username, device_id)
        if not isinstance(targetKeys, TargetKeys):
            return Response(data={'error': 'Target Key not found'},status=status.HTTP_400_BAD_REQUEST)
        try:
            if not targetKeys.keys:
                return Response('invalid', status=400)
        except (TypeError, AttributeError) as e:
            return Response(data={'error': 'Target Keys invalid'},status=status.HTTP_400_BAD_REQUEST)
        pre_keys = []
        user = MyUser.objects.get(username=username)
        for key in targetKeys.keys:
            device = user.get_device(key.device_id)
            if device and device.is_active():
                serializer = PreKeyV1Serializer(data={'keyId':key.key_id,
                                                      'publicKey': key.public_key,
                                                      'deviceId':key.device_id,
                                                      'identityKey': user.data.get('identityKey'),
                                                      'registrationId': device.registrationId})
                if serializer.is_valid():
                    pre_keys.append(serializer.data)
                else:
                    return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)
        if len(pre_keys) > 0:
            return Response(status=status.HTTP_200_OK, data={'keys': pre_keys})
        return Response(status=status.HTTP_400_BAD_REQUEST, data={'error': 'no prekey found'})



    def get_key_by_username(self, username):
        preKeys = Keys.objects.filter(username=username).distinct().order_by('username', 'device_id', 'key_id')
        if len(preKeys) > 0:
            for prekey in preKeys:
                if not prekey.last_resort:
                    prekey.delete()
        return preKeys if preKeys else None

    def get_keys_by_username_and_id(self, username, device_id):
        preKeys = Keys.objects.filter(username=username, device_id=device_id).order_by('key_id')
        if len(preKeys)>0:
            for k in preKeys:
                if not k.last_resort:
                    k.delete()
        else:
            return None
        return preKeys

    def get_local_keys(self, username, deviceIdSelector):
        destination = MyUser.objects.get(username=username)
        if not destination.is_active:
            raise MyUser.DoesNotExist
        if deviceIdSelector == '*':
            pre_keys = self.get_key_by_username(username)
            if pre_keys:
                return TargetKeys(destination=destination, keys=pre_keys)
            else:
                return None
        device_id = deviceIdSelector
        devices = destination.data.get('devices', None)
        device = None
        for d in devices:
            if d.get('device_id') == int(device_id):
                device = Device(**d)
        if device is None or not device.is_active():
            raise MyUser.DoesNotExist
        for i in range(20):
            try:
                p_keys = self.get_keys_by_username_and_id(username, device.device_id)
                if p_keys:
                    return TargetKeys(destination, p_keys)
            except Exception:
                pass
        return None


class PreKeysRegistration(APIView):
    authentication_classes = (EnhancedBasicAuthentication,)
    parser_classes = (JSONParser, FormParser, MultiPartParser,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, format=None):
        prekeys = Keys.objects.filter(username=request.user.get_username(),
                                      device_id=request.user.get_authenticated_device().device_id)
        return Response(data={'count': prekeys.count()}, status=status.HTTP_200_OK)


    def put(self, request, format=None):
        return self.save_key(request)

    def post(self, request, format=None):
        return self.save_key(request)

    def save_key(self, request):
        user = request.user
        assert isinstance(user, MyUser)
        device = user.get_authenticated_device()
        updateAccount = False
        serializer = PreKeyStateSerializer(data=request.data)
        if serializer.is_valid():
            prekeystate = serializer.save()
            if isinstance(prekeystate, PreKeyState):
                if not (prekeystate.signedPreKey == device.signedPreKey):
                    device.signedPreKey = prekeystate.signedPreKey
                    updateAccount = True
                if not (prekeystate.identityKey == request.user.get_identity_key()):
                    user = user.set_identity_key(prekeystate.identityKey)
                    updateAccount = True
            if updateAccount:
                device_serializer = DeviceRecordSerializer(device)
                try:
                    user.set_authenticated_device(device, device_serializer.data)
                except AttributeError, TypeError:
                    return Response(status=400, data={'error': 'invalid request'})
                user.save()

            old_key_record = Keys.objects.filter(username=user.get_username(), device_id=device.device_id)
            if old_key_record.count() > 0:
                for record in old_key_record:
                    record.delete()

            for key in prekeystate.preKeys:
                try:
                    new_key = Keys(username=user.get_username(), device_id=key.get('deviceId', 1), key_id=key.get('keyId'),
                               public_key=key.get('publicKey'), last_resort=False)
                    new_key.save()
                except:
                    return Response(status=204, data={"error": key})
            new_last_resort_key = Keys(username=user.get_username(), device_id=prekeystate.lastResortKey.get('deviceId', 1),
                                       key_id=prekeystate.lastResortKey.get('keyId'),
                                       public_key=prekeystate.lastResortKey.get('publicKey'), last_resort=True)
            new_last_resort_key.save()
            return Response(status=201)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SetKeys(APIView):
    authentication_classes = (EnhancedBasicAuthentication,)
    parser_classes = (JSONParser, FormParser, MultiPartParser,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, format=None):
        prekeys = Keys.objects.filter(username=request.user.get_username(),
                                      device_id=request.user.get_authenticated_device().device_id)
        return Response(data={'count': prekeys.count()}, status=status.HTTP_200_OK)

    def put(self, request, format=None):
        current_user = request.user
        assert isinstance(current_user, MyUser)
        device = current_user.get_authenticated_device()
        if device.device_id and Keys.get_available_keys_count(current_user, device.device_id) > 15:
            return Response(data={'message': 'you have enough prekeys'}, status=400)
        updateAccount = False
        serializer = PreKeyStateSerializerV2(data=request.data)
        if serializer.is_valid():
            prekey_object = serializer.save()
            assert isinstance(prekey_object, PreKeyState)
            if not (prekey_object.signedPreKey == device.signedPreKey):
                device.signedPreKey = prekey_object.signedPreKey
                device_serializer = DeviceRecordSerializer(device)
                # user.authenticated_device = json.dumps(deviceSerializer.data)
                try:
                    current_user.set_authenticated_device(device, device_serializer.data)
                # except AttributeError, TypeError:
                #     return Response(status=400, data={'error': 'invalid request'})
                except Exception as e:
                    return Response(status=400, data={'error': 'invalid request'})
                updateAccount = True

            if not (prekey_object.identityKey == request.user.get_identity_key()):
                current_user.set_identity_key(prekey_object.identityKey)
                updateAccount = True
            if updateAccount:
                current_user.save()
            Keys.store_keys(current_user.get_username(), device.device_id,
                            prekey_object.preKeys, prekey_object.lastResortKey)
            return Response(data=serializer.data ,status=status.HTTP_201_CREATED)
        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SetWebClientKeys(APIView):
    authentication_classes = (EnhancedBasicAuthentication,)
    parser_classes = (JSONParser, FormParser, MultiPartParser,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, format=None):
        prekey_count = Keys.get_available_keys_count(request.user, 2)
        return Response(data={'count': prekey_count}, status=status.HTTP_200_OK)

    def put(self, request, format=None):
        current_user = request.user
        assert isinstance(current_user, MyUser)
        device = current_user.get_web_client()
        # updateAccount = False
        if Keys.get_available_keys_count(current_user, 2) > 15:
            return Response(data={'message': 'you have enough prekeys'}, status=status.HTTP_400_BAD_REQUEST)
        serializer = PreKeyStateSerializerV2(data=request.data)
        if serializer.is_valid():
            prekey_object = serializer.save()
            assert isinstance(prekey_object, PreKeyState)
            # if not (prekey_object.signedPreKey == device.signedPreKey):
            #     device.signedPreKey = prekey_object.signedPreKey
            #     device_serializer = DeviceRecordSerializer(device)
            #     # user.authenticated_device = json.dumps(deviceSerializer.data)
            #     try:
            #         device.set_as_web_authenticated_client(current_user)
            #     except AttributeError, TypeError:
            #         return Response(status=400, data={'error': 'invalid request'})
            #     updateAccount = True
            # old_identity_key_model = current_user.web_id_key_store.filter(
            #     type=WebIdentityKeyStoreModel.IDENTITY_KEY_STORE_IDENTITY_KEYPAIR).first()
            # identity_store = WebIdentityKeyStore(current_user)
            # if not (prekey_object.identityKey == identity_store.getIdentityKeyPair().getPublicKey().getPublicKey()):
            #
            #     current_user.set_identity_key(prekey_object.identityKey)
            #     updateAccount = True
            # if updateAccount:
            #     current_user.save()
            Keys.store_keys(current_user.get_username(), device.device_id,
                            prekey_object.preKeys, prekey_object.lastResortKey)
            return Response(data=serializer.data ,status=status.HTTP_201_CREATED)
        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SignedKeyView(APIView):
    authentication_classes = (EnhancedBasicAuthentication,)
    parser_classes = (JSONParser, FormParser, MultiPartParser,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, format=None):
        current_user = request.user
        device = current_user.get_authenticated_device()
        signed_pre_key = device.signedPreKey
        if signed_pre_key:
            return Response(data={'signature': signed_pre_key}, status=status.HTTP_200_OK)
        return Response(data={'details': 'signedPreKey not available'}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, format=None):
        current_user = request.user
        assert isinstance(current_user, MyUser)
        device = current_user.get_authenticated_device()
        serializer = SignedPreKeySerializerV2(data=request.data)
        if serializer.is_valid():
            signed_prekey = serializer.save()
            assert isinstance(signed_prekey, SignedPreKeyV2)
            device.signedPreKey = model_to_dict(signed_prekey)
            device_serializer = DeviceRecordSerializer(device)
            try:
                current_user.set_authenticated_device(device, device_serializer.data)
            except Exception as e:
                return Response(status=400, data={'error': 'invalid request'})
            # except AttributeError, TypeError:
            #     return Response(status=400, data={'error': 'invalid request'})
            current_user.update_directory()
            current_user.save()
            return Response(status=status.HTTP_200_OK)
        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class WebSignedKeyView(APIView):
    authentication_classes = (EnhancedBasicAuthentication,)
    parser_classes = (JSONParser, FormParser, MultiPartParser,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, format=None):
        current_user = request.user
        device = current_user.get_web_client()
        signed_pre_key = device.signedPreKey
        if signed_pre_key:
            return Response(data={'signature': signed_pre_key}, status=status.HTTP_200_OK)
        return Response(data={'details': 'signedPreKey not available'}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, format=None):
        current_user = request.user
        assert isinstance(current_user, MyUser)
        device = current_user.get_web_client()
        serializer = SignedPreKeySerializerV2(data=request.data)
        if serializer.is_valid():
            signed_prekey = serializer.save()
            assert isinstance(signed_prekey, SignedPreKeyV2)
            device.signedPreKey = model_to_dict(signed_prekey)
            device_serializer = DeviceRecordSerializer(device)
            try:
                device.set_as_web_authenticated_client(current_user)
            except Exception as e:
                return Response(status=400, data={'error': 'invalid request'})
            # except AttributeError, TypeError:
            #     return Response(status=400, data={'error': 'invalid request'})
            current_user.update_directory()
            current_user.save()
            return Response(status=status.HTTP_200_OK)
        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class GetEncryptedMessage(APIView):
#     authentication_classes = (EnhancedBasicAuthentication,)
#     parser_classes = (JSONParser, FormParser, MultiPartParser,)
#     permission_classes = (IsAuthenticated,)
#
#     def get(self, request, username, device_id, format=None):
#         targetKeys = self.get_local_keys(username, device_id)
#         if not targetKeys:
#             return Response(data={'message': 'prekeys not available'}, status=400)
#         try:
#             destination_user = MyUser.objects.get(username=targetKeys.destination)
#         except MyUser.DoesNotExist:
#             return Response(data={'details': 'Destination User not found'} ,status=status.HTTP_404_NOT_FOUND)
#         devices = list()
#         if not isinstance(targetKeys, TargetKeys):
#             return Response(data={'error': 'Target Key not found'}, status=status.HTTP_400_BAD_REQUEST)
#         for device in destination_user.get_devices():
#             assert isinstance(device, Device)
#             if device.is_active() and ( device_id == '*' or device.device_id == int(device_id)):
#                 signed_preKeys = [device.signedPreKey]
#                 signed_preKeys = signed_preKeys[0] if len(signed_preKeys) > 0 else None
#                 prekeys =  dict()
#                 if len(targetKeys.keys) > 0:
#                     for key in targetKeys.keys:
#                         assert isinstance(key, Keys)
#                         if key.device_id == device.device_id:
#                             prekeys = {'keyId': key.key_id , 'publicKey': key.public_key}
#
#                 if signed_preKeys is not None or prekeys is not None:
#                     devices.append({'deviceId': device.device_id, 'registrationId': device.registrationId,
#                                     'signedPreKey': signed_preKeys, 'preKey': prekeys})
#                 else:
#                     return Response(data={'message': 'no signed prekey or prekeys'}, status=400)
#         if len(devices) == 0:
#             return Response(status=status.HTTP_200_OK)
#         return Response(data={'identityKey': destination_user.get_identity_key(), 'devices': devices},
#                         status=status.HTTP_200_OK)
#
#     def get_local_keys(self, username, deviceIdSelector):
#         destination = MyUser.objects.get(username=username)
#         if not destination.is_active:
#             raise MyUser.DoesNotExist
#         if deviceIdSelector == '*':
#             pre_keys = self.get_key_by_username(username)
#             if pre_keys:
#                 return TargetKeys(destination=destination, keys=pre_keys)
#             else:
#                 return None
#         device_id = deviceIdSelector
#         devices = destination.data.get('devices', None)
#         device = None
#         for d in devices:
#             if d.get('device_id') == int(device_id):
#                 device = Device(**d)
#         if device is None or not device.is_active():
#             pass
#             # raise MyUser.DoesNotExist
#         for i in range(20):
#             try:
#                 p_keys = self.get_keys_by_username_and_id(username, device.device_id)
#                 if p_keys:
#                     return TargetKeys(destination, p_keys)
#             except Exception:
#                 pass
#         return None
#
#     def get_key_by_username(self, username):
#         my_key_dict = Keys.objects.filter(username=username)\
#             .distinct('username', 'device_id').order_by('username', 'device_id', 'key_id')
#         if my_key_dict.count() > 0:
#             preKeys = list()
#             for my_key in my_key_dict:
#                 key_dict = model_to_dict(my_key)
#                 new_key = Keys(**key_dict)
#                 preKeys.append(new_key)
#                 if not my_key.last_resort:
#                     my_key.delete()
#
#             return preKeys
#         return None
#
#     def get_keys_by_username_and_id(self, username, device_id):
#         preKeys = list()
#         my_key = Keys.objects.filter(username=username, device_id=device_id).order_by('key_id').first()
#         if my_key:
#             key_dict = model_to_dict(my_key)
#             new_key = Keys(**key_dict)
#             preKeys.append(new_key)
#             if not my_key.last_resort:
#                 my_key.delete()
#             return preKeys
#         return None


@api_view(['GET', ])
def get_serverKey(request):
    if request.method == 'GET':
        exists = os.path.isfile('kaichat.RSA')
        if exists:
            print ("Exist")
            # block = get_server_publickey()

            # return Response(data={"key": block})
        else:
            print ("Doesnt Exist")

            from Crypto.PublicKey import RSA
            new_key = RSA.generate(2048, e=65537)
            public_key = new_key.publickey().exportKey()
            private_key = new_key.exportKey()
            print ("Public Key\n" + public_key)
            print ("Private Key\n" + private_key)

            my_file = open('kaichat.RSA', 'a')
            my_file.write(public_key + "\n" + private_key)
            my_file.close()

            return Response(data={"key": public_key})

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
