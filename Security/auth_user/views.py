
import requests

# Create your views here.
from django.shortcuts import render
from django.template import loader
from django.http import HttpResponse
from rest_framework.parsers import JSONParser, FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from authentication import EnhancedBasicAuthentication, WebClientAuthentication,\
    KeyPairTokenClientAuthentication
from rest_framework import status
from rest_framework.response import Response
from .voice_api import make_call
from .models import *
from serializers import *
from rest_framework.decorators import api_view, authentication_classes, parser_classes, permission_classes
from django.http import Http404, JsonResponse, HttpResponseBadRequest
from rest_framework.views import APIView
from rest_framework.parsers import JSONParser
from rest_framework.authtoken.models import Token
from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
from django.conf import settings
from rest_auth.serializers import TokenSerializer
from authentication import TokenAuthentication
import random, base64 ,phonenumbers, json
from rest_framework import HTTP_HEADER_ENCODING
from datetime import datetime, timedelta
from django.utils import timezone
from django.db import connection
# from message.views import success_response, error_response
# from user_profile.models import GroupUserID
from django.core.mail import send_mail
from rest_framework.authentication import get_authorization_header
from django.contrib.auth import hashers
# from Helper.time_helper import current_time_in_milis
# from Helper.phone_helper import generate_verification_code, send_code
from push_notifications.models import APNSDevice
from random import SystemRandom
from django.core.cache import cache
from celery import shared_task
# from message_v2.push_sender import PushSender
# from kaichatweb_socket_model import WebLoginTokenModel
from Crypto.PublicKey import RSA
from django.forms import extras, model_to_dict
import time

#from django.views.decorators.csrf import csrf_protect, csrf_exempt
#from rest_framework.authentication import SessionAuthentication, BasicAuthentication
#from rest_framework.decorators import api_view, permission_classes
#from rest_framework.permissions import IsAuthenticated, IsAdminUser, IsAuthenticatedOrReadOnly


#@api_view(['GET', 'POST'])
#@csrf_exempt
#@permission_classes((IsAdminUser, ))
def default(request, format=None):
    return HttpResponse("<h1>Hello world!</h1>")

@shared_task
def delete_user_message(message_instance):
    #assert isinstance(message_instance, Messages)
    pass


def authenticate(request):
    """
    Returns a `User` if a correct username and password have been supplied
    using HTTP Basic authentication.  Otherwise returns `None`.
    """
    auth = get_authorization_header(request).split()

    if not auth or auth[0].lower() != b'basic':
        return None

    if len(auth) == 1:
        msg = {'error': 'Invalid basic header. No credentials provided.'}
        return Response(data=msg, status=status.HTTP_401_UNAUTHORIZED)
    elif len(auth) > 2:
        msg = {'error': 'Invalid basic header. Credentials string should not contain spaces.'}
        return Response(data=msg, status=status.HTTP_401_UNAUTHORIZED)

    try:
        auth_parts = base64.b64decode(auth[1]).decode(HTTP_HEADER_ENCODING).partition(':')
    except (TypeError, UnicodeDecodeError):
        msg = {'error': 'Invalid basic header. Credentials not correctly base64 encoded.'}
        return Response(data=msg, status=status.HTTP_401_UNAUTHORIZED)

    userid, password = auth_parts[0], auth_parts[2]
    return userid, password


## Username == full_phone_number for contact2contact conversation
def create_crypto_random_number_string(nrange=None):
    cryptogen = SystemRandom()
    if nrange is not None:
        nrange = int(nrange)
        return str(int(cryptogen.random()*(10**nrange)))
    return str(int(cryptogen.random()*(10**6)))

# def create_xmpp_user(username, password):
#     try:
#         userObj = MyUser.objects.get(full_phone_number=username, phone_verified=True)
#     except MyUser.DoesNotExist:
#         return False
#     GroupUserID.objects.create(entity_id='{}@{}'.format(username,settings.DOMAIN_NAME),
#                                user=userObj)
#     cursor = connection.cursor()
#     try:
#         cursor.execute("SELECT username FROM users WHERE username = %s" , [username])
#         xmppuser = cursor.fetchone()
#         if not xmppuser:
#             cursor.execute("INSERT INTO users(username, password) VALUES (%s, %s)", [username, password])
#             username = username.lower()
#             cursor.execute("INSERT INTO users(username, password) VALUES (%s, %s)", [username, password])
#
#             return True
#
#     except Exception:
#         raise Exception

def get_fb_app_access_token(cid, secret):
    req = requests.get('https://graph.facebook.com/v2.3/oauth/access_token?',
                       params={
                           'client_id':cid,
                           'client_secret':secret,
                           'grant_type':'client_credentials'
                       })
    json_resp = req.json()
    return json_resp['access_token']


def get_user_facebook_token(token):
        req = requests.get('https://graph.facebook.com/v2.2/debug_token?',
                           params={
                               'input_token': token,
                               'access_token': get_fb_app_access_token(settings.SOCIAL_AUTH_FACEBOOK_KEY,
                                                                       settings.SOCIAL_AUTH_FACEBOOK_SECRET
                                                                      )})
        json_resp = req.json()
        return json_resp

def get_fb_user_id(token):
    return get_user_facebook_token(token).get('data').get('user_id')

def check_if_fb_user_exists(token):
    fb_data = get_user_facebook_token(token)
    try:
        dt = fb_data['data']
        if 'data' in fb_data and 'error' not in dt:
            fb_uid = dt.get('user_id')
            try:
                MyUser.objects.get(fb_uid=fb_uid)
                return True
            except MyUser.DoesNotExist:
                return False
        else:
            return False
    except:
        return False


def set_fb_user_id(username, token):
    user = MyUser.objects.get(username=username)
    user.fb_uid = get_fb_user_id(token)
    user.save()


def get_ident(request):
    """
    Identify the machine making the request by parsing HTTP_X_FORWARDED_FOR
    if present and number of proxies is > 0. If not use all of
    HTTP_X_FORWARDED_FOR if it is available, if not use REMOTE_ADDR.
    """
    from rest_framework.settings import api_settings
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    remote_addr = request.META.get('REMOTE_ADDR')
    num_proxies = api_settings.NUM_PROXIES

    if num_proxies is not None:
        if num_proxies == 0 or xff is None:
            return remote_addr
        addrs = xff.split(',')
        client_addr = addrs[-min(num_proxies, len(addrs))]
        return client_addr.strip()

    return ''.join(xff.split()) if xff else remote_addr

@api_view(['GET'])
@parser_classes((JSONParser, FormParser, MultiPartParser,))
@authentication_classes([EnhancedBasicAuthentication])
@permission_classes((IsAuthenticated,))
def get_devices_auth(request):
    username = request.query_params.get('username', None)
    serializer = GetUserDevicesSerializer(data={"username": username})
    if serializer.is_valid():
        user = MyUser.objects.get(username=username)
        devices = user.get_devices()
        if len(devices) > 0:
            device_response = [model_to_dict(device) for device in devices]
            return Response(data=device_response, status=status.HTTP_200_OK)
        return Response(data={'message': 'No device available'}, status=status.HTTP_400_BAD_REQUEST)
    return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['GET'])
@parser_classes((JSONParser, FormParser, MultiPartParser,))
@authentication_classes([EnhancedBasicAuthentication])
@permission_classes((IsAuthenticated,))
def verify_master_passcode_set(request):
    user = request.user
    assert isinstance(user, MyUser)
    if not user.master_passcode.strip():
        return Response(status=status.HTTP_404_NOT_FOUND)
    return Response(status=status.HTTP_200_OK)

def email_verification_view(request):
    code = request.GET.get('code', None)
    if code is not None:
        context = {'verification_code': code, 'main_url': settings.API_DOMAIN}
        return render(request, 'auth_user/backup_email_confirmation.html', context)
    raise Http404("Code does not exist")


@api_view(['POST'])
@parser_classes((JSONParser, FormParser, MultiPartParser,))
@authentication_classes([EnhancedBasicAuthentication])
@permission_classes((IsAdminUser,))
def reset_authentication_tokens_for_login(request):
    """
    If need to change password, only admins can do it.
    TODO: write the wrapper whereby users can request admins to do it and let admin use
    logic to allow requests
    :param request:
    :return:
    """
    username_to_change = request.data.get('username', None)
    new_auth_token = request.data.get('authToken', None)
    if new_auth_token is None:
        new_auth_token = MyUser.gen_random_auth_token()
    if username_to_change is not None :
        try:
            user_to_change = MyUser.objects.get(username=username_to_change)
            device = user_to_change.get_authenticated_device()
            device.authToken = new_auth_token
            # Called set_authentication_credentials to generate hash codes
            device.set_authentication_credentials()
            deviceSerializer = DeviceRecordSerializer(device)
            device_data = user_to_change.data
            device_data['devices'][0] = deviceSerializer.data
            user_to_change.data = device_data
            user_to_change.authenticated_device = deviceSerializer.data
            user_to_change.save()
            return Response(data={'new_token': new_auth_token}, status=status.HTTP_200_OK)
        except MyUser.DoesNotExist:
            return Response(data={'message': 'user does not exist'})
    return Response(data={'message': 'no username specificed'}, status=status.HTTP_400_BAD_REQUEST)



class VerificationOfRequestCode(APIView):
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

    def create_account(self, password, data, phone=None, email=None, username=None):
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
                                       email=email)
            if user:
                print('User created')
            else:
                # return error_response('error. no user.{}'.format(user))
                return Response(status=status.HTTP_406_NOT_ACCEPTABLE)
            return Response(status=status.HTTP_200_OK, data={"success": 1})
        return Response(status=status.HTTP_400_BAD_REQUEST, data=request_serializer.errors)


class BackupEmailView(APIView):
    authentication_classes = (EnhancedBasicAuthentication,)
    parser_classes = (JSONParser, FormParser, MultiPartParser,)
    permission_classes = (IsAuthenticated,)
    key_constant = 'BACKUPEMAIL_'
    valid_time_in_seconds = 5*60
    email_subject = 'Please verify your email for KaiChat'
    email_from = 'admin@kaichat.com'


    def put(self, request, format=None):
        """
        Setting backup email
        :param request: email, code
        :param format: kai@kaichat.com
        :return:
        """
        backup_email = request.data.get('email', None)
        verify_code = request.data.get('code', None)
        user = request.user
        serializer = VerifyBackupEmailSerializer(data={'email': backup_email, 'code': verify_code})
        if serializer.is_valid():
            # check whether code exists
            our_key = "{}{}".format(self.key_constant, serializer.validated_data.get('code'))
            our_value = cache.get(our_key)
            if our_value is not None:
                # check whether our value is the same as the backup email
                if our_value == serializer.validated_data.get('email'):
                    user.email = serializer.validated_data.get('email')
                    user.save(update_fields=('email',))
                    cache.delete(our_key)
                    return Response(status=status.HTTP_201_CREATED)
                return Response(data={'message': 'wrong email'}, status=status.HTTP_400_BAD_REQUEST)
            return Response(data={'message': 'Wrong code.'},
                            status=status.HTTP_400_BAD_REQUEST)
        return Response(data={'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, format=None):
        backup_email = request.data.get('email', None)
        serializer = BackupEmailSerializer(data={'email': backup_email})
        if serializer.is_valid():
            my_backup_email = serializer.validated_data.get('email')
            if my_backup_email is not None:
                # key will be prepended with 'BACKUPEMAIL_'
                # value will be '<6-digit code><email>'
                our_code = self.generate_unique_verification_code()
                our_key = "{}{}".format(self.key_constant, our_code)
                cache.set(our_key, my_backup_email, self.valid_time_in_seconds)
                self.send_verification_email(our_code, my_backup_email)
                return Response(data={'message': 'verification code sent'}, status=status.HTTP_200_OK)
            return Response(data={'message': 'email invalid'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(data={'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def send_verification_email(self, code, email):
        assert code
        template = loader.get_template('auth_user/backup_email_confirmation.html')
        context = {'verification_code': code}
        s = template.render(context)
        send_mail(
            self.email_subject,
            'This is your verification code',
            self.email_from,
            [email],
            fail_silently=False,
            html_message=s,
        )

    def generate_unique_verification_code(self):
        # must ensure such code does not exist in cache
        my_code = create_crypto_random_number_string()
        my_key = "{}{}".format(self.key_constant, my_code)
        my_cache = cache.get(my_key)
        if my_cache is not None: return self.generate_unique_verification_code()
        return my_code


class RequestPhoneEmailRegistration(APIView):

    parser_classes = (JSONParser, FormParser, MultiPartParser,)
    sms_requests_limit = 10
    format = "%Y-%m-%d %H:%M:%S"
    verification_code = None
    email_subject = 'Confirm Your Email Now'
    email_from = 'admin@kaichat.com'
    full_phone_number = None

    def get(self, request, format=None):
        return Response('GET Method Not Allowed. Only POST method allowed.')

    def post(self, request, format=None):
        """

        :param request: account_type(phone/email), phone_number_raw, phone_number_country(MY, SG, US),
                        transport(sms, call), email
        :param format:
        :return:
        """
        account_type = request.data.get('account_type', None)
        ipaddress = get_ident(request)
        if self.sms_count(ipaddress) >= self.sms_requests_limit:
            return Response(data={'exceeded SMS request limit'}, status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
        if account_type == 'phone':
            serializer = RequestPhoneRegistrationSerializer(
                data={'full_phone_number':request.data['full_phone_number']}
            )
            if serializer.is_valid() :
                full_number = serializer.validated_data.get('full_phone_number')
                self.full_phone_number = full_number
                phone_number = phonenumbers.parse(full_number)
                raw_phone_number = str(phone_number.national_number)
                country_iso = PhoneNumberEmailVerification.get_country_iso_code(phone_number)
                phone_obj = dict()
                phone_obj['full_phone_number'] = full_number
                phone_obj['phone_raw'] = raw_phone_number
                phone_obj['phone_country_code'] = country_iso
                verification_obj = self.get_or_create_request_record(ip=ipaddress, phone_obj=phone_obj)
                transport = request.data.get('transport')
                verification_obj = self.generate_code(verification_obj)
                if transport == 'sms':
                    self.send_request_code(ip=ipaddress, phone=phone_obj['full_phone_number'],
                                           code=verification_obj)
                    verification_obj.verify_type = 'sms'
                    verification_obj.save()
                elif transport == 'call':
                    self.call_request_code(ip=ipaddress, phone=phone_obj['full_phone_number'],
                                           code=verification_obj)
                self.increase_verify_request_count(ip=ipaddress, phone=phone_obj['full_phone_number'])
                return Response(status=status.HTTP_200_OK)
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)
        elif account_type == 'email':
            serializer = RequestEmailRegistrationSerializer(data={'email': request.data['email']})
            if serializer.is_valid():
                verification_obj = self.get_or_create_request_record(ip=ipaddress,
                                                                     email=serializer.validated_data.get('email'))
                verification_obj = self.generate_code(verification_obj)
                self.send_request_code(ip=ipaddress, code=verification_obj, email=serializer.validated_data.get('email'))
                return Response(status=status.HTTP_200_OK)
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)
        return Response(data={'invalid transport'}, status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)

    def sms_count(self, ip):
        verify_list = PhoneNumberEmailVerification.objects.filter(ip_address=ip)
        if len(verify_list) > 0:
            verify = verify_list[0]
            return int(verify.number_of_requests)
        return 0

    def increase_verify_request_count(self, ip=None, phone=None, email=None):
        if ip is not None:
            if phone is not None:
                verify = PhoneNumberEmailVerification.objects.get(ip_address=ip, full_phone_number=phone)
            elif email is not None:
                verify = PhoneNumberEmailVerification.objects.get(ip_address=ip, email=email)
            else:
                raise ValueError('phone or email not set')
            print('What is current number of requests {}'.format(verify.number_of_requests))
            verify.number_of_requests += 1
            verify.save()
        else:
            print('request count not increased')

    def get_or_create_request_record(self, ip, phone_obj=None, email=None):
        """

        :param ip : ip address string:
        :param phone_obj dictionary with full_phone_number, phone_raw, phone_country_code:
        :param email email address to be verified
        :return: PhoneNumberEmailVerification object
        """
        if phone_obj is not None:
            record = PhoneNumberEmailVerification.objects.get_or_create(ip_address=ip,
                                                                        full_phone_number=phone_obj[
                                                                            'full_phone_number'])
            record[0].phone_number_raw = phone_obj['phone_raw']
            record[0].phone_number_country = phone_obj['phone_country_code']
            record[0].save()
            return record[0]
        elif email is not None:
            record = PhoneNumberEmailVerification.objects.get_or_create(ip_address=ip,
                                                                        email=email)
            record[0].verify_type = 'email'
            record[0].save()
            return record[0]
        return None

    # def generate_code(self, verification_obj, type=None):
    #     self.check_sms_code(verification_obj)
    #     if self.full_phone_number not in settings.DEMO_ACCOUNTS:
    #         sms_code = generate_verification_code()
    #     else:
    #         sms_code = '6666'
    #     verification_obj.verification_code = sms_code
    #     # the type is certainly verification via phone number(call/sms)
    #     if type is not 'email':
    #         expiry = datetime.now() + timedelta(minutes=5)
    #         verification_obj.verification_code_expiry = expiry.strftime(self.format)
    #     verification_obj.save()
    #     return verification_obj

    def check_sms_code(self, verification_obj):
        if verification_obj.verify_type is not 'email':
            if verification_obj.verification_code_expiry is not None:
                current_time = timezone.make_aware(datetime.now(), timezone.get_default_timezone())
                if current_time <= verification_obj.verification_code_expiry:
                    time_left = verification_obj.verification_code_expiry - current_time
                    return Response({
                        'error': True,
                        'message': 'Please wait for %d second(s) to request SMS code again' % time_left.seconds,
                        'data': ' '
                    }, status=status.HTTP_400_BAD_REQUEST)
                else:
                    verification_obj.verification_code_expiry = None
                    verification_obj.save()


    def get_message(self, verification_obj):
        return 'Welcome to %s. Your code is %s. It will expire in 5 minutes.' %\
               (settings.APP_NAME, verification_obj.verification_code)

    # def send_request_code(self, ip, code, phone=None, email=None):
    #     error = 'phone: %s, code object: %s' % (phone, code)
    #     message = self.get_message(code)
    #     # raise ValueError(error)
    #     if phone is not None and not settings.TESTING_APP:
    #         if phone not in settings.DEMO_ACCOUNTS:
    #             return send_code(message, phone)
    #         else:
    #             return send_code('Someone creating a demo acount phone: {}'.format(phone), phone='+60122097305')
    #     elif email is not None:
    #         template = loader.get_template('auth_user/emailconfirmation.html')
    #         context = {'verification_code': code.verification_code}
    #         s = template.render(context)
    #         send_mail(
    #             self.email_subject,
    #             'This is your verification num',
    #             self.email_from,
    #             [email],
    #             fail_silently=False,
    #             html_message=s,
    #         )
    #     if phone is not None or email is not None:
    #         self.increase_verify_request_count(ip=ip, phone=phone, email=email)

    # def call_request_code(self,ip, code, phone=None):
    #     phone = phonenumbers.parse(phone, None)
    #     formatted_number = phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.E164)
    #     code.verify_type = "call"
    #     code.save()
    #     if phone is not None and not settings.TESTING_APP:
    #         if formatted_number not in settings.DEMO_ACCOUNTS:
    #             make_call(code.verification_code , formatted_number.replace("+", ""))
    #         else:
    #             send_code('Someone is trying to create a demo account with code: {}'.format(code),
    #                       phone=formatted_number)
    #     print 'call_request_code ip is %s' % (ip)
    #     self.increase_verify_request_count(ip=ip, phone=formatted_number)

    def check_for_error(self, request):
        if 'error_text' in request:
            return Response({'error':True, 'message': 'Error is %s ' % request['error_text']},
                            status=status.HTTP_400_BAD_REQUEST)


class VerificationOfRequestCode(APIView):
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

    # def post(self, request, code, format=None):
    #     auth = authenticate(request)
    #     userid = auth[0]
    #     authToken = auth[1]
    #     phone = None
    #     email = None
    #     verification_code = code
    #
    #     verification_obj_list = PhoneNumberEmailVerification.objects.filter(full_phone_number=userid)
    #     if len(verification_obj_list) < 1:
    #         verification_obj_list = PhoneNumberEmailVerification.objects.filter(email=userid)
    #         if len(verification_obj_list) < 1:
    #             msg = {'error': 'Invalid username/password.'}
    #             return Response(data=msg, status=status.HTTP_401_UNAUTHORIZED)
    #         email = verification_obj_list[0].email
    #     else:
    #         phone = verification_obj_list[0].full_phone_number
    #     for verify_obj in verification_obj_list:
    #         if (verification_code == verify_obj.verification_code) and \
    #                 not (timezone.now() >= verify_obj.verification_code_expiry):
    #             request_serializer = DeviceRecordSerializer(data={'signalingKey': request.data.get('signalingKey'),
    #                                                               'registrationId': request.data.get('registrationId'),
    #                                                               'voice': request.data.get('voice')})
    #             if request_serializer.is_valid():
    #                 user = self.create_account(authToken, request_serializer.validated_data, phone=phone,
    #                                            email=email, verification_obj=verify_obj)
    #                 if user:
    #                     verify_obj.delete()
    #                 else:
    #                     return error_response('error. no user.{}'.format(user))
    #                 return Response(status=status.HTTP_200_OK, data={"success": 1})
    #             return Response(status=status.HTTP_400_BAD_REQUEST, data=request_serializer.errors)
    #     return Response(data={"error": "incorrect verification_code"}, status=status.HTTP_403_FORBIDDEN)


class AccountPushRegistration(object):

    @staticmethod
    @api_view(['PUT', 'DELETE'])
    @parser_classes((JSONParser, FormParser, MultiPartParser,))
    @authentication_classes([EnhancedBasicAuthentication])
    @permission_classes((IsAuthenticated,))
    def apn_id_controller(request):
        if request.method == 'PUT':
            return AccountPushRegistration.set_apn_registration_id(request)
        elif request.method == 'DELETE':
            return AccountPushRegistration.delete_apn_registration_id(request)
        return Response(data={'detail': 'Invalid Request for APN'}, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def delete_apn_registration_id(request):
        user = request.user
        assert isinstance(user, MyUser)
        device_instance = Device()
        try:
            device_instance = user.get_authenticated_device()
            device_instance.apnId = ''
            device_instance.fetchesMessages = False
            device_serializer = DeviceRecordSerializer(device_instance)
            try:
                user.set_authenticated_device(device_instance, device_serializer.data)
            except AttributeError, TypeError:
                return Response(status=400, data={'error': 'invalid request'})
            user.save()
            new_apns_device, created = APNSDevice.objects.get_or_create(user=user)
            if created or not new_apns_device.name :
                new_apns_device.name = 'Apple notification device {}'.format(user.get_username())
            new_apns_device.registration_id = ''
            new_apns_device.save()
            return Response(status=status.HTTP_200_OK, data={})
        except device_instance.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST, data={})

    # @staticmethod
    # def set_apn_registration_id(request):
    #     user = request.user
    #     assert isinstance(user, MyUser)
    #     device_instance = user.get_authenticated_device()
    #     if isinstance(device_instance, Device):
    #         apn_id = request.data.get('apnRegistrationId', None)
    #         if apn_id is not None:
    #             device_instance.apnId = apn_id
    #             device_instance.fetchesMessages = True
    #             device_instance.pushTimestamp = current_time_in_milis()
    #             device_serializer = DeviceRecordSerializer(device_instance)
    #             # user.authenticated_device = json.dumps(deviceSerializer.data)
    #             try:
    #                 user.set_authenticated_device(device_instance, device_serializer.data)
    #             except Exception as e:
    #                 return Response(status=400, data={'error': 'What? {} and DATA {}'.format(e, device_serializer.data)})
    #             user.save()
    #             # create APNSDevice object for Push notification
    #             new_apns_device, created = APNSDevice.objects.get_or_create(user=user)
    #             new_apns_device.name = 'Apple notification device {}'.format(user.get_username())
    #             new_apns_device.registration_id = apn_id
    #             new_apns_device.save()
    #             return Response(status=status.HTTP_200_OK, data={})
    #         return Response(data={'detail': 'apnRegistrationId is not set'},status=status.HTTP_400_BAD_REQUEST)
    #     return Response('Authenticated Device not set error', status=status.HTTP_400_BAD_REQUEST)


class check_token(APIView):

    parser_classes = (JSONParser, FormParser, MultiPartParser,)

    def get(self, request, format=None):
        user = TokenAuthentication().authenticate(request)
        content = {
            'error':False,
            'message': 'User found',
            'data':{
                'id': user[0].id,
                'username': user[0].username,
                'email': user[0].email,
                'gender':user[0].gender,
                'token': CheckTokenSerializer(user[1]).data,
                #'token': CheckTokenSerializer(Token.objects.get(user_id = user[0].id)).data
            }
        }
        return Response(content)

    def post(self, request, format=None):

        serializer = TokenSerializer(request.META.get('HTTP_AUTHORIZATION', b''))
        if serializer.is_valid():
           return Response({'key': serializer.data, 'user': request.user, 'error':False}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CheckAuthentication(APIView):
    authentication_classes = (EnhancedBasicAuthentication,)
    parser_classes = (JSONParser, FormParser, MultiPartParser,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, format=None):
        return Response(status=status.HTTP_200_OK)

    def post(self, request, format=None):
        return Response(status=status.HTTP_200_OK)

    def put(self, request, format=None):
        return Response(status=status.HTTP_200_OK)



# class CheckUserName(APIView):
#     #
#     # Check username's availability, validate username
#     #
#     parser_classes = (JSONParser, FormParser, MultiPartParser,)
#
#     def get(self, request, format=None):
#         return Response('GET Method Not Allowed. Only POST method allowed.')
#
#     def post(self, request, format=None):
#         serializer = CheckUserNameSerializer(data=request.data)
#         if serializer.is_valid():
#             return success_response('Success', 'Your username is good to go', status.HTTP_200_OK)
#         return error_response(serializer.errors)


class CheckEmailAddress(APIView):
    #
    # Check username's availability, validate username
    #
    parser_classes = (JSONParser, FormParser, MultiPartParser,)

    def get(self, request, format=None):
        return Response('GET Method Not Allowed. Only POST method allowed.')

    # def post(self, request, format=None):
    #     serializer = CheckEmailSerializer(data=request.data)
    #     if serializer.is_valid():
    #         return success_response('Success', 'Great! Your email address looks good!', status.HTTP_200_OK)
    #     return error_response(serializer.errors)


class TestVerificationCode(APIView):
    parser_classes = (JSONParser, FormParser, MultiPartParser,)

    def get(self, request, format=None):
        context = {'verification_code': 1234}
        return render(request, 'auth_user/emailconfirmation.html', context)


class RegisterUser(APIView):

    parser_classes = (JSONParser, FormParser, MultiPartParser,)

    def get(self, request, format=None):
        return Response('GET Method Not Allowed. Only POST method allowed.')

    def post(self, request, format=None):
        facebook_token = request.data.get('facebook_token')
        serializer = SignUpSerializer(data={'username': request.data['username'],
                                            'password': request.data['password'],
                                            'gender': request.data['gender'],
                                            'email': request.data['email'],
                                            'dob': request.data['dob']})
        if serializer.is_valid():
            if facebook_token:
                if check_if_fb_user_exists(facebook_token):
                    return Response({'error': True, 'message': facebook_token, 'data': {'Your facebook token might be invalid or your have already registered using your facebook'}}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    serializer.save()
                    set_fb_user_id(serializer.data['username'], facebook_token)
                    return Response({'error': False, 'message': 'success', 'data': serializer.data}, status=status.HTTP_201_CREATED)
            else:
                serializer.save()
                return Response({'error': False,'message': 'successfully registered user without fb','data': serializer.data}, status=status.HTTP_201_CREATED)

        return Response({'error': True, 'message': 'N/A', 'data': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)



# class FacebookLogin(APIView):
#
#     serializer_class = FBTokenSerializer
#     parser_classes = (JSONParser, FormParser, MultiPartParser,)
#     response_serializer = TokenSerializer
#
#
#     def fb_login(self, token):
#         self.fb_uid = get_fb_user_id(token)
#         try:
#             self.user = MyUser.objects.get(fb_uid = self.fb_uid)
#             self.token_object = Token.objects.get(user_id = self.user.id)
#         except MyUser.DoesNotExist:
#             return self.get_response_error(token)
#
#
#
#     def get_response(self):
#         return Response(self.response_serializer(self.token_object).data,
#                         status=status.HTTP_200_OK)
#
#     def get_response_error(self, token):
#         return Response({'error':True,
#                          'message':'Facebook user NOT registered',
#                          'data': token},
#                         status=status.HTTP_400_BAD_REQUEST)
#
#     def get(self, request, format=None):
#         return Response('GET Method Not Allowed. Only POST method allowed.')
#
#     def post(self, request, *args, **kwargs):
#         serializer = self.serializer_class(data=request.data)
#         fb_exist = check_if_fb_user_exists(request.data['facebook_token'])
#         if serializer.is_valid() is False or fb_exist is False:
#         #    self.get_response_error(serializer.data['facebook_token'])
#             return Response({'error':True,
#                              'message':'Facebook user NOT registered',
#                              'data': serializer.data['facebook_token']},
#                             status=status.HTTP_400_BAD_REQUEST)
#         else:
#             self.fb_login(serializer.data['facebook_token'])
#             return Response(self.response_serializer(self.token_object).data,
#                             status=status.HTTP_200_OK)

'''
    def post(self, request, format=None):
        access_serializer = FBAccountSerializer(data=request.data)
        if access_serializer.is_valid():
            fb_detail = get_user_facebook_token(access_serializer.data['facebook_token'])
            dt = fb_detail.get('data')
            extra_serializer = FBExtraDataSerializer(data={'extra_data': fb_detail})
            if extra_serializer.is_valid():
                if 'error' in extra_serializer.data['extra_data']:
                    return Response({'error': True, 'message': 'token error', 'data': extra_serializer.data}, status=status.HTTP_400_BAD_REQUEST)

                else:
                    serializer = FBDetailSerializer(data={'uid': dt.get('user_id'),
                                                          'expires_at': dt.get('expires_at')
                                                          })
                    if serializer.is_valid():
                        try:
                            FbAccount.objects.get(uid=serializer.data['uid'])
                        except FbAccount.DoesNotExist:
                            return Response({'error': True, 'message': 'User is Not Registered', 'data': access_serializer.data}, status=status.HTTP_400_BAD_REQUEST)

                        return Response({'error': False, 'message': 'User is Registered.', 'data': serializer.data}, status=status.HTTP_201_CREATED)

                    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(access_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

'''

class user_list(APIView):
    """
    List all snippets, or create a new snippet.
    """
    permission_classes = ()
    def get(self, request, format=None):
        users = MyUser.objects.all()
        serializer = MyUserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        serializer = MyUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class user_detail(APIView):
    """
    Retrieve, update or delete a snippet instance.
    """
    def get_object(self, pk):
        try:
            return MyUser.objects.get(pk=pk)
        except MyUser.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        users = self.get_object(pk)
        serializer = MyUserSerializer(users)
        return Response(serializer.data)

    def put(self, request, pk, format=None):
        users = self.get_object(pk)
        serializer = MyUserSerializer(users, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        users = self.get_object(pk)
        users.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class enterPhoneNumber(APIView):

    parser_classes = (JSONParser, FormParser, MultiPartParser,)
    sms_requests_limit = 10
    sms_count = 0
    format = "%Y-%m-%d %H:%M:%S"


    def get(self, request, format=None):
        return Response('GET Method Not Allowed. Only POST method allowed.')

    def post(self, request, format=None):
        token = TokenAuthentication().authenticate(request)
        phone_number = request.data['phone_number_raw']
        country_code = request.data['phone_number_country']
        parse_phone_number = phonenumbers.parse(phone_number, country_code)
        full_phone_number = phonenumbers.format_number(parse_phone_number, phonenumbers.PhoneNumberFormat.E164)
        serializer = VerifyPhoneNumberSerializer(data=request.data)
        if serializer.is_valid() and self.sms_count <= self.sms_requests_limit:
            self.generate_sms(token[0])
            self.get_request_id_nexmo(full_phone_number, self.get_message(token[0]))
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def generate_sms(self, user):
        self.check_sms_code(user)
        sms_code = random.randrange(1000, 9999)
        user.sms_code = sms_code
        expiry = datetime.now() + timedelta(minutes=5)
        user.sms_code_expiry = expiry.strftime(self.format)
        user.save()

    def check_sms_code(self, user):
        if user.sms_code_expiry is not None:
            current_time = timezone.make_aware(datetime.now(), timezone.get_default_timezone())
            if  current_time <= user.sms_code_expiry:
                time_left = user.sms_code_expiry - current_time
                return Response({
                    'error':True,
                    'message': 'Please wait for %d second(s) to request SMS code again' % time_left.seconds,
                    'data': ' '
                }, status=status.HTTP_400_BAD_REQUEST)
            else:
                user.sms_code_expiry = None
                user.save()

    def get_message(self, user):
        return 'Welcome to %s. Your code is %s. It will expire in 5 minutes.' % (settings.APP_NAME, user.sms_code)

    # def get_request_id_nexmo(self, phone, message):
    #     self.sms_count += 1
    #     return send_code(message, phone)

    def check_for_error(self, request):
        if 'error_text' in request:
            return Response({'error':True, 'message': 'Error is %s ' % request['error_text']},
                            status=status.HTTP_400_BAD_REQUEST)



class CheckSMSCode(APIView):

    parser_classes = (JSONParser, FormParser, MultiPartParser,)

    def get(self, request, format=None):
        return Response('GET Method Not Allowed. Only POST method allowed.')

    # def post(self, request, format=None):
    #     token = TokenAuthentication().authenticate(request)
    #     phone_number = request.data['phone_number_raw']
    #     country_code = request.data['phone_number_country']
    #     parse_phone_number = phonenumbers.parse(phone_number, country_code)
    #     full_phone_number = phonenumbers.format_number(parse_phone_number, phonenumbers.PhoneNumberFormat.E164)
    #     serializer = CheckPhoneNumberSerializer(data=request.data)
    #     if serializer.is_valid():
    #         if serializer.data['sms_code'] == token[0].sms_code:
    #             # After the SMS_code is correct, then invalidate other users with same number
    #             self.invalidate_same_phone_entry(serializer.data['phone_number_country'],
    #                                              serializer.data['phone_number_raw'],
    #                                              full_phone_number)
    #             token[0].phone_verified = True
    #             token[0].is_authenticated = True
    #             token[0].phone_number_raw = serializer.data['phone_number_raw']
    #             token[0].phone_number_country = serializer.data['phone_number_country']
    #             token[0].full_phone_number = full_phone_number
    #             token[0].save()
    #             if not create_xmpp_user(full_phone_number, request.user.password):
    #                 return Response({'error':True,
    #                                  'message':'Unable to create xmpp user',
    #                                  'data': ''
    #                      }, status=status.HTTP_400_BAD_REQUEST)
    #             dict_for_full_phone_number = {'full_phone_number': full_phone_number}
    #             return Response({'error':False,
    #                              'message': 'Token is entered correctly.',
    #                              'data': serializer.data.update(dict_for_full_phone_number)
    #                              }, status=status.HTTP_201_CREATED)
    #     return Response({'error':True,
    #                      'message':'Wrong code. Try again.',
    #                      'data': serializer.errors
    #                      }, status=status.HTTP_400_BAD_REQUEST)

    def invalidate_same_phone_entry(self, country_code, phone_number, full_number):
        try:
            existing_user = MyUser.objects.get(full_phone_number=full_number,
                                               phone_number_country=country_code,
                                               phone_number_raw=phone_number)
            existing_user.phone_verified = False
            existing_user.phone_number_raw = ' '
            existing_user.phone_number_country = ' '
            existing_user.full_phone_number = ' '
            existing_user.save(force_update=True)
        except MyUser.DoesNotExist:
            pass


class InformsFailureOfMobileCode(APIView):
    authentication_classes = (TokenAuthentication,)
    parser_classes = (JSONParser, FormParser, MultiPartParser,)


class UserWebCheckIn(object):


    @staticmethod
    @api_view(['POST'])
    @parser_classes((JSONParser, FormParser, MultiPartParser,))
    def set_web_login_code(request):
        """
        POST from the web client to record their session tokens
        :param request: client_secure_key, public_key, private_key
        :return:
        """
        if request.method == 'POST':
            # client_secure_key is also the session for login code for websocket/redis of browser
            # web client will use the same token for this API and websocket
            client_secure_key = request.data.get('client_secure_key', None)
            if client_secure_key is not None:
                # we will store the temporary session key to verify web login session in redis
                is_redis_key_set = UserWebCheckIn.set_session_key_in_redis(client_secure_key)
                if is_redis_key_set[0]:
                    return Response(status=status.HTTP_201_CREATED)
                return HttpResponseBadRequest(is_redis_key_set[1])
            return Response(data={'error': 'no key input'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(data={'error': 'Invalid Request'}, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    # def set_session_key_in_redis(client_secure_key):
    #     try:
    #         UserWebCheckIn.validate_client_secure_key(client_secure_key)
    #     except Exception as e:
    #         return False, e.message
    #     # forming redis key, value
    #     redis_token_key = WebLoginTokenModel.get_class_redis_key(client_token=client_secure_key)
    #     token_value = WebLoginTokenModel.get_key_value_from_secure_token(client_secure_key)[1]
    #     # setting key, value in redis
    #     cache.set(redis_token_key, token_value,
    #               WebLoginTokenModel.WEB_CHECK_IN_CODE_TIME_EXPIRE_SECONDS)
    #     print('Setting session key in redis: {}'.format(redis_token_key))
    #     return True, None

    @staticmethod
    def validate_client_secure_key( key):
        # make sure it's utf-8 for redis
        try:
            key.decode('utf-8')
            print "string is UTF-8, length %d bytes" % len(key)
        except UnicodeError:
            message = "string is not UTF-8"
            raise UnicodeError(message)

        if len(key) < 41: raise ValueError('Key not long enough')

    @staticmethod
    @api_view(['POST'])
    @parser_classes((JSONParser, FormParser, MultiPartParser,))
    @authentication_classes([EnhancedBasicAuthentication])
    @permission_classes((IsAuthenticated,))
    # def verify_web_login_code(request):
    #     """
    #     POST from mobile client to authenticate web client
    #     :param request:
    #     :return:
    #     """
    #     client_secure_key = request.data.get('client_secure_key', None)
    #     browser_token_secure_key = request.data.get('token_id', None)
    #     ws_session_id = request.data.get('ws_session', None)
    #     encrypted_token = request.data.get('encrypted_token', None)
    #     debug = request.data.get('debug', False)
    #     if ws_session_id is None:
    #         return Response(data={'error': 'no valid socket session'}, status=status.HTTP_400_BAD_REQUEST)
    #     user = request.user
    #     print("user's id:{}".format(user.get_username()))
    #     key_model = None
    #     if browser_token_secure_key is not None:
    #         try:
    #             key_model = WebLoginTokenKeys.objects.get(session_key=browser_token_secure_key)
    #         except WebLoginTokenKeys.DoesNotExist:
    #             return Response(data={'error':'authentication problem'}, status=status.HTTP_400_BAD_REQUEST)
    #     if client_secure_key is not None:
    #         # first get the token key from client secure key
    #         token_key, token_value = WebLoginTokenModel.get_key_value_from_secure_token(
    #             client_token=client_secure_key)
    #         redis_token_key = WebLoginTokenModel.get_class_redis_key(client_key=token_key)
    #         redis_token_value = cache.get(redis_token_key)
    #         print('getting session key in redis: {}'.format(redis_token_value))
    #         if redis_token_value is not None:
    #             if redis_token_value == token_value:
    #                 print("redis_token_value == token_value")
    #                 # Upon successful authentication, send a push notification to the
    #                 # web browser to log user in
    #                 p = PushSender()
    #                 auth_message = WebLoginTokenModel.create_auth_message(user, client_secure_key, ws_session_id)
    #                 if debug and debug == 'rJw74275':
    #                     encrypted_token = UserWebCheckIn.encrypt_token(key_model.public_key)
    #                     is_delivered = p.send_login_auth_message(user, auth_message, encrypted_token)
    #                 elif encrypted_token is not None:
    #                     is_delivered = p.send_login_auth_message(user, auth_message, encrypted_token)
    #                 else:
    #                     return Response(data={'error': 'please provide an encrypted token'},
    #                                     status=status.HTTP_400_BAD_REQUEST)
    #                 if is_delivered:
    #                     print("is_delivered")
    #                     assert key_model is not None, 'key is None. Error!'
    #                     key_model.verified = True
    #                     key_model.save()
    #                     return Response(data={'success': True}, status=status.HTTP_200_OK)
    #                 print('unable to send')
    #                 return Response(data={'error': 'unable to send'}, status=status.HTTP_400_BAD_REQUEST)
    #             return Response(data={'error': 'corrupted'}, status=status.HTTP_400_BAD_REQUEST)
    #         return Response(data={'error': 'entry error'}, status=status.HTTP_400_BAD_REQUEST)
    #     return Response(data={'error': 'Invalid Request'}, status=status.HTTP_400_BAD_REQUEST)

    # for debug & testing use only.
    # simulate a user to provide token info
    @classmethod
    def encrypt_token(cls, client_public_key):
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        token = "KzYwMTIyMDk3MzA1OjlISlNpM2QmUzkybkRUUGc5NigoKl5CSEdKa3dITk9VSE9IODIxOTgzMjEzMjEwMzgyMDEzOTgwZA==".encode('utf8')
         # get web client's publicKey
        key_object = RSA.importKey(client_public_key)
        cipher = PKCS1_OAEP.new(key_object)
        ciphertext = cipher.encrypt(token)
        return base64.standard_b64encode(ciphertext)


@api_view(['POST'])
@parser_classes((JSONParser, FormParser, MultiPartParser,))
@authentication_classes([EnhancedBasicAuthentication])
@permission_classes((IsAuthenticated,))
def retrieve_web_keypair_request(request):
    """
    For Mobile Client to retrieve public keypairs
    :param request:
    :return:
    """
    token_id = request.data.get('token_id', None)
    print(token_id)
    print("request is {}".format(request.data))
    try:
        key_obj = WebLoginTokenKeys.objects.get(session_key=token_id)
        return Response(data={'public_key': key_obj.public_key}, status=status.HTTP_200_OK)
    except WebLoginTokenKeys.DoesNotExist:
        return Response(data={'error': 'unable to retrieve'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PUT'])
@parser_classes((JSONParser, FormParser, MultiPartParser,))
def web_set_session_tokens(request):
    """
    PUT from the web client to record their session tokens
    :param request: client_secure_key, public_key, private_key
    :return:
    """
    rsa_public_key = request.data.get('public_key', None)
    rsa_private_key = request.data.get('private_key', None)
    if rsa_public_key is not None and rsa_private_key is not None:
        # we are going to set the web browser's rsa key pairs in order
        # to safely transmit the token from the user's mobile devices
        # returns : an ID to enable retrieval of the private key/public key
        new_id = WebLoginTokenKeys.generate_session_key()
        web_token_model = WebLoginTokenKeys.objects.create(
            session_key=new_id,
            public_key=rsa_public_key,
            private_key=rsa_private_key,
            expiry_date=WebLoginTokenKeys.get_expiry_date_from_now())
        return Response(data={'u_id': web_token_model.session_key}, status=status.HTTP_201_CREATED)
    return Response(data={'error': 'param not available'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@parser_classes((JSONParser, FormParser, MultiPartParser,))
def generate_keypair(request):
    """

    :param request:
    :return: a random keypair consists of public_key and private_key
    """
    key = RSA.generate(2048)
    randomKeyPair = key.publickey().exportKey(), key.exportKey('PEM')
    resp = {'public_key': randomKeyPair[0], 'private_key': randomKeyPair[1]}
    return Response(data=resp, status=status.HTTP_200_OK)


class WebUserKeyPair(APIView):

    authentication_classes = (WebClientAuthentication,)
    parser_classes = (JSONParser, FormParser, MultiPartParser,)
    permission_classes = (AllowAny,)

    def get(self, request, format=None):
        return Response('GET Method Not Allowed.')


    def post(self, request, format=None):
        """
        returns the keypair from the uid - unique web id
        Only For use of web client
        :param request: uid
        :param format:
        :return: public_key:'', private_key: ''
        """
        uid = request.data.get('uid', None)
        if uid is not None:
            try:
                web_model = WebLoginTokenKeys.objects.get(session_key=uid)
            except WebLoginTokenKeys.DoesNotExist:
                # Generate a fake key even though session_key does not exist
                # for security purpose
                fake_key = RSA.generate(2048)
                randomKeyPair = fake_key.publickey().exportKey(),fake_key.exportKey('PEM')
                resp = {'public_key': randomKeyPair[0], 'private_key': randomKeyPair[1]}
                return Response(data=resp, status=status.HTTP_200_OK)
            resp = {'public_key': web_model.public_key, 'private_key': web_model.private_key}
            response = Response(data=resp, status=status.HTTP_200_OK)
            return response
        return Response(data={'error': 'no unique ID'})


class CreateWebDevice(APIView):
    authentication_classes = (EnhancedBasicAuthentication,)
    parser_classes = (JSONParser, FormParser, MultiPartParser,)
    permission_classes = (IsAuthenticated,)

    def delete(self, request, format=None):
        user = request.user
        data = user.data
        auth_web_client = user.authenticated_web_client
        if auth_web_client is not None:
            for device in data['devices']:
                if auth_web_client['device_id'] == device['device_id']:
                    user_device = [d for d in data['devices'] if d['device_id'] != auth_web_client['device_id']]
                    data['devices'] = user_device
                    user.data = data
                    user.authenticated_web_client = None
                    user.web_client_identity_key = ''
                    user.save()
                    return Response(data={'message': 'deleted web device'}, status=status.HTTP_200_OK)
        if user.web_client_identity_key != '':
            user.web_client_identity_key = ''
            user.save()
            return Response(data={'message': 'deleted web device'}, status=status.HTTP_200_OK)
        return Response(status=400)

    def post(self, request, format=None):
        data = request.data
        password = authenticate(request)[1]
        user = request.user
        serializer = CreateDeviceSerializer(data={'signalingKey':data.get('signalingKey', None),
                                                     'registrationId':data.get('registrationId', None)})
        if serializer.is_valid():
            if user.authenticated_web_client is None:

                newDevice = Device(authToken=password, signalingKey=serializer.validated_data.get('signalingKey'),
                                   registrationId=serializer.validated_data.get('registrationId'),
                                   voice=False, device_id=2, fetchesMessages=True)
                # Called set_authentication_credentials to generate hash codes
                newDevice.set_authentication_credentials()
                newDevice.save()
                newDevice.set_as_web_authenticated_client(user)
                return Response(data={'message': 'created web device'}, status=status.HTTP_201_CREATED)
            return Response(data={'message': 'web device already created'}, status=status.HTTP_200_OK)
        return Response(data=serializer.errors, status=400)




