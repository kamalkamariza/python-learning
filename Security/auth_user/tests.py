from django.test import TestCase

# Create your tests here.

from django.contrib.auth import hashers
from django.contrib.auth import get_user_model
from models import MyUser
from models import PhoneNumberEmailVerification
from authentication import EnhancedBasicAuthentication
from rest_framework.test import APITestCase, APIClient
from django.test import Client
import base64, datetime, json, os, binascii
from django.utils import timezone


class UserAuthenticationTest(APITestCase):
    """
    Test for Custom User authentication
    """

    @classmethod
    def setUpTestData(cls):
        cls.testVerificationCode = '2341'
        cls.username = '+60122026666'
        cls.password = '3l008IDTPg96((*^BHGJkwHNOUHOH821983213210382013980d'
        cls.user = get_user_model().objects.create(username=cls.username)
        cls.auth_headers = {
            'HTTP_AUTHORIZATION': 'Basic ' + base64.b64encode('+60122026666:{}'.format(cls.password)),
        }
        cls.c = Client(**cls.auth_headers)
        cls.parameters = {'signalingKey': '3992893PPBABA*29Oeqw3923203028930902','voice': 1,'registrationId': 2}
        cls.apnRegistrationId = '78G*739hdHDU3898hSj'
        cls.apnData = {'apnRegistrationId': cls.apnRegistrationId}
        cls.prekeydata = {'preKeys':
                    [{'keyId': 20,
                      'publicKey': '-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBzoqQuwZ9e\
                             KMOU0OXWJ4ISj+2YEk8l4OmBoC9Y2wNEe4PcjzmCF/f9aZDyH6znh0G6gmb/yrTvuNLYkTUgiFNm0yJ2rSzlgmJZHk\
                             WykRkjKr4V04iAaHdU4ORre7Ms9eln7k8CeVQFpCjM51HOLkp8IhnAVrkOhSbHI4vxprbQIDAQAB - \
                             ----END PUBLIC KEY-----'}
                     ], 'lastResortKey': {'keyId': 9, 'publicKey': '-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA\
                     4GNADCBiQKBgQDBzoqQuwZ9/eyH6znh0G6gmb/yrTvuNLYkTUgiFNm0yJ2rSzlgmJHdu&3ZHkWykRKMOU0OXWJ4ISj + 2YEk\
                     8l4OmBoC9Y2wNEe4PcjzmCF/f9aZD4iAaHdU4ORre7Ms9eln7k8CeVQFpCjM51HOLkp8IhnAVrkOhSbHI4vxprbQIDAQAB\
                      -----ENDPUBLIC KEY-----' },
                'signedPreKey': {'keyId': 20, 'publicKey': '-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA73e8HD\
                HgQDBzoqQuwZ9/eKMOU0OXWJ4ISj+2YEk8l4OmBoC9Y2wNEe4PcjzmCF/f9aZDyH6znh0G6gmb/yrTvuNLYkTUgiFNm0yJ2rSzlgm\
                JZHkWykRkjKr4V04iAaHdU4ORre7Ms9eln7k8CeVQFpCjM51HOLkp8IhnAVrkOhSbHI4vxprbQIDAQAB\
                -----END PUBLIC KEY - ----','signature': '9H83jsHS2891HSie8'},
                'identityKey': '8329yDjde88'}


    def test_verification_of_code(self):

        url = '/api/v1/accounts/code/{}'.format(self.testVerificationCode)
        future_time = timezone.now() + datetime.timedelta(minutes=5)
        try:
            p = PhoneNumberEmailVerification.objects.get(ip_address='123.23.20.11', full_phone_number='+60122026666')
            p.delete()
        except PhoneNumberEmailVerification.DoesNotExist:
            PhoneNumberEmailVerification.objects.create(ip_address='123.23.20.11', verify_type='sms',
                                                        verification_code=self.testVerificationCode,
                                                        full_phone_number=self.username, phone_number_raw='122026666',
                                                        phone_number_country='MY', verification_code_expiry=future_time,
                                                        verified=False)
        response = self.c.post(url, self.parameters)
        self.assertEqual(url, '/api/v1/accounts/code/2341')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, '{"success":1}')
        # Try and Authenticate
        new_user = MyUser.objects.get(username=self.username)
        self.assertEqual(new_user.check_password(self.password), True)
        authenticator = EnhancedBasicAuthentication()
        auth_status = authenticator.verify_for_authenticate(self.password, new_user.data['devices'][0]['salt'],
                                              new_user.data['devices'][0]['authToken'])
        self.assertEqual(auth_status, True)

    @staticmethod
    def generate_prekeys_data():
        from Crypto.PublicKey import RSA
        import uuid, os, binascii
        from random import SystemRandom
        cry = SystemRandom()
        my_list = []
        for i in range(10):
            keyId = cry.randint(10, 200)
            publicKey = RSA.generate(2048).exportKey()
            deviceId = 1
            registrationId = (i + 20) * 2
            identityKey = str(uuid.uuid4())
            my_dict = {'keyId': keyId, 'publicKey': publicKey, 'deviceId': deviceId,
                       'registrationId': registrationId, 'identityKey': identityKey}
            my_list.append(my_dict)
        mySignedKey = my_list.pop(0)
        signed_key = binascii.hexlify(os.urandom(24))
        mySignedKey['signature'] = signed_key
        last_resort_key = my_list.pop(0)
        request_object = {'identityKey': '079f3d6e-2a74-47dc-a79d-a9a15e73e6eb', 'preKeys': my_list,
                          'signedPreKey': mySignedKey, 'lastResortKey': last_resort_key}
        return request_object


    def test_prekeys_registration(self):
        """
        data format is {'preKeys':[{'keyId': 2,'publicKey': 'XX'}], 'lastResortKey': {'keyId': 2,'publicKey': 'XX'},
        'signedPreKey':{'keyId': 2,'publicKey': 'XX', 'signature': 'XHD'},
         'identityKey': 'XXXXX'}
        :return:
        """
        # test for sign up
        # testing all sms, call and email api to be working
        url = '/api/v1/accounts/signup_request'
        email = 'kcemail4u@gmail.com'
        paramters = {'account_type': 'email', 'email': email}
        response = self.c.post(url, json.dumps(paramters), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        paramters = {'account_type': 'phone', 'transport': 'sms', 'full_phone_number': self.username}
        response = self.c.post(url, json.dumps(paramters), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        paramters = {'account_type': 'phone', 'transport': 'call', 'full_phone_number': self.username}
        response = self.c.post(url, json.dumps(paramters), content_type='application/json')
        self.assertEqual(response.status_code, 200)


        with self.settings(TESTING_APP=True):
            paramters = {'account_type': 'phone', 'transport': 'sms', 'full_phone_number': self.username}
            response = self.c.post(url, json.dumps(paramters), content_type='application/json')
            self.assertEqual(response.status_code, 200)
            paramters = {'account_type': 'phone', 'transport': 'call', 'full_phone_number': self.username}
            response = self.c.post(url, json.dumps(paramters), content_type='application/json')
            self.assertEqual(response.status_code, 200)


        # test for Verifying SMS code
        phone_verification_obj = PhoneNumberEmailVerification.objects.get(full_phone_number=self.username)
        print('verification code is {}'.format(phone_verification_obj.verification_code))
        url = '/api/v1/accounts/code/{}'.format(phone_verification_obj.verification_code)
        parameters = {'signalingKey': '3992893PPBABA*29Oeqw3923203028930902', 'voice': 1, 'registrationId': 2}
        response = self.c.post(url, json.dumps(parameters), content_type='application/json')
        self.assertEqual(response.status_code, 200)

        # test for setting encryption keys
        url = '/api/v1/keys/'
        response = self.c.put(url, json.dumps(self.generate_prekeys_data()), content_type='application/json')
        print(response.content)
        self.assertEqual(response.status_code, 201)
        response = self.c.get(url)
        self.assertEqual(response.status_code, 200)

        # Test Getting Keys for our own number and a device
        # TODO: get keys for other numbers and devices
        #device_id = '*'
        #url = '/api/v1/keys/%2B60122026666/*'
        #print('This URL is being processed: {}'.format(url))
        #response = self.c.get(url, content_type='application/json')
        #self.assertEqual(response.status_code, 200)



    def test_push_registration(self):
        url = '/api/v1/accounts/code/{}'.format(self.testVerificationCode)
        future_time = timezone.now() + datetime.timedelta(minutes=5)
        try:
            p = PhoneNumberEmailVerification.objects.get(ip_address='123.23.20.11', full_phone_number=self.username)
            p.delete()
        except PhoneNumberEmailVerification.DoesNotExist:
            PhoneNumberEmailVerification.objects.create(ip_address='123.23.20.11', verify_type='sms',
                                                        verification_code=self.testVerificationCode,
                                                        full_phone_number=self.username, phone_number_raw='122026666',
                                                        phone_number_country='MY', verification_code_expiry=future_time,
                                                        verified=False)
        self.c.post(url, self.parameters)

        url = '/api/v1/keys'
        self.c.put(url, json.dumps(self.prekeydata), content_type='application/json')
        url = '/api/v1/accounts/apn'
        response = self.c.put(url, json.dumps(self.apnData), content_type='application/json')
        self.assertEqual(response.status_code, 200)

    def test_setting_web_login_token(self):
        new_client = Client()
        url = '/web/session'
        client_secure_key = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        request_data = {'client_secure_key': client_secure_key}
        response = new_client.post(url, json.dumps(request_data), content_type='application/json')
        self.assertEqual(response.status_code, 201)
        client_secure_key = 'e3b0c44298fc1c149afbf4c79y9d'
        if len(client_secure_key) < 40:
            request_data = {'client_secure_key': client_secure_key}
            response = new_client.post(url, json.dumps(request_data), content_type='application/json')
            self.assertEqual(response.status_code, 400)

    def test_set_get_keypair(self):
        url = '/web/keypair/set'
        # first, test setting keypair with PUT request
        request_data = {
            'private_key': '-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAk3sXtliq2CUeTOmRZDO+CvWNn0MRS97YDaO6U3cyzm6UDAYI\ncI+H9cIRWfyN0sHpv3Tdg7wAguNvd/fcPNvf9CNwKeKvoyerx2N+MrGAIro6iLnK\nm9CCIlMi7Ro3lp0asDBMWpDCbH3w2kUgsnbGhI9s71A7ZVuKGlvz0sC6jEaR1hic\nsQ8PkHVHqKItxnu9rwb2Tg8nXHc9uKQtghuW+KBaRE40OEtSBcqFxDS6vu61ihW4\nDSAkB/X6Z/KWzNBn4ijGt6MD+M3UFtT0R6Jq/3WVrK7tTKzZyU+yWnpOWK5hRXyL\naUGd5gyefW90jfPkAIzhoUIukAkfM+X1/icuiQIDAQABAoIBADaGCoUykK7qQiKD\nM2pNKtRYZexcWjengk7AmjEjX1gsT3WGgXZDyisUfV+8XB5v7GAI76A1UCcTuHEs\n5HJng4t50ozZrr9t+jbz1IMfVlUAboV/0qT6WDIidEYeLDD1khlTMddFr2t2wCWh\n6u2vtcLqV4a+LcdSKWOHXUQsVotnN/QnvsaA2Aixhp8kl12lUc87QtZ2ROHOYny8\n4c0I2V5r9jGj3Yv9lEQqi4xrFgAq+QJ1kmbg+MbteVmH3ZnH0h5DgXlLEEOSQ9sO\nIzyQDNY79CfwguGoOkPLGHO6n2Glh7eE5g4vSN7e3ShhvAefLkUbhpPfd6VaKU81\nmOLwppUCgYEAw9FCGDNMsJRAatwfpkgkixvzg2fPceQZg/4aLkKWMRf7IlsG8jRB\nm3Y6ONyL7yhPIeeAP86W2ybFAKAG+l/Xr1xfMODlmaniHbaHMYlrseJiPVW79YfL\nxubvq5C5j/XHkhWzcWSLRUaTesqk6x1DOhK6WKsqLn+3Md1TlWlZ//MCgYEAwM7B\nKilB8rCqUdnSEv3v6VugKgIvEGN2y5AB8gqspVVJ9GOb8PINtE1psiBL0mlGZie1\nGvbVG97E4lXT+U2g+PPILBkRDykZmGsqX2KKmeYoD4KnKOYDNn2wdjT0B3eszIi7\nonm5ugcjN7fVC6kZVIsWMQR75RdOXAL0YpVFcpMCgYBiQPmdEwCECZ9Y/yKSWNid\nRGUnpkscpot3A2U3mQmrkJDeaDZQCZBx5RzJs0AzvFIYfQSI/6wKQqXO7n0R3E1p\nHDxXVkFenTNsHU4wuPdkxmbsx7wMMxs4rl/MAk5ZwcVls6XaW8zV8dfGYS/nGUPG\nO+ds3lXIByVwy9FIwxf5qQKBgGHfkobIcsWzkIIERHOHnGWlMWShvypek0s6SwKH\nEKTM6sG4Xsys0vAX6/OUGWkyL55jwbdyXTPMnb0XPIdtNK2rco2QG+zKPEf2/od1\nCk6dWvCkrh5AxJjArPcUYlv4ECuzrSwJBpK8VNBP7UICEO2tvRIc6JeegRSMG2p/\nw8UpAoGAKcOiuVlpfi/7rbkoC0W71xHxRRZYRMp815TG/Rf4eQYgJFck+EIorS/q\neRVlI0zscK9ZqKXeziLuDRqVs3k18oK/ITuQ65ivykydITuBlQjjG9zrHqO1w0+X\nKtj0R1QmvCCUhfC3EKZ3Bw4lgg7duN18DfczBrxQUkodSNna7tQ=\n-----END RSA PRIVATE KEY-----',
            'public_key': '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk3sXtliq2CUeTOmRZDO+\nCvWNn0MRS97YDaO6U3cyzm6UDAYIcI+H9cIRWfyN0sHpv3Tdg7wAguNvd/fcPNvf\n9CNwKeKvoyerx2N+MrGAIro6iLnKm9CCIlMi7Ro3lp0asDBMWpDCbH3w2kUgsnbG\nhI9s71A7ZVuKGlvz0sC6jEaR1hicsQ8PkHVHqKItxnu9rwb2Tg8nXHc9uKQtghuW\n+KBaRE40OEtSBcqFxDS6vu61ihW4DSAkB/X6Z/KWzNBn4ijGt6MD+M3UFtT0R6Jq\n/3WVrK7tTKzZyU+yWnpOWK5hRXyLaUGd5gyefW90jfPkAIzhoUIukAkfM+X1/icu\niQIDAQAB\n-----END PUBLIC KEY-----'
        }
        response = self.c.put(url, json.dumps(request_data),content_type='application/json')
        self.assertEqual(response.status_code, 201)
        uid = response.data.get('u_id', None)
        self.assertNotEqual(uid, None)

        # Next retrieve the same keypair
        auth_header = {
            'HTTP_X_WEB_SESSION': '{}'.format(uid),
        }
        new_client = Client(**auth_header)
        url = '/web/keypair'
        response = new_client.post(url, json.dumps({'uid': uid}), content_type='application/json')
        self.assertEqual(response.data, request_data)
        self.assertEqual(response.status_code, 200)

        # check if wrong uid
        uid = '224TEST'
        response = self.c.post(url, json.dumps({'uid': uid}), content_type='application/json')
        self.assertEqual(response.status_code, 200)

    # TODO: Do a backup plan (email) if websocket can't be connected and delivery failed.
    # this will happen when there is no listener to redis channel- thread is not run
    def test_verifying_web_login_token(self):
        url = '/web/keypair/set'
        # first, set keypair with PUT request
        request_data = {
            'private_key': '-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAk3sXtliq2CUeTOmRZDO+CvWNn0MRS97YDaO6U3cyzm6UDAYI\ncI+H9cIRWfyN0sHpv3Tdg7wAguNvd/fcPNvf9CNwKeKvoyerx2N+MrGAIro6iLnK\nm9CCIlMi7Ro3lp0asDBMWpDCbH3w2kUgsnbGhI9s71A7ZVuKGlvz0sC6jEaR1hic\nsQ8PkHVHqKItxnu9rwb2Tg8nXHc9uKQtghuW+KBaRE40OEtSBcqFxDS6vu61ihW4\nDSAkB/X6Z/KWzNBn4ijGt6MD+M3UFtT0R6Jq/3WVrK7tTKzZyU+yWnpOWK5hRXyL\naUGd5gyefW90jfPkAIzhoUIukAkfM+X1/icuiQIDAQABAoIBADaGCoUykK7qQiKD\nM2pNKtRYZexcWjengk7AmjEjX1gsT3WGgXZDyisUfV+8XB5v7GAI76A1UCcTuHEs\n5HJng4t50ozZrr9t+jbz1IMfVlUAboV/0qT6WDIidEYeLDD1khlTMddFr2t2wCWh\n6u2vtcLqV4a+LcdSKWOHXUQsVotnN/QnvsaA2Aixhp8kl12lUc87QtZ2ROHOYny8\n4c0I2V5r9jGj3Yv9lEQqi4xrFgAq+QJ1kmbg+MbteVmH3ZnH0h5DgXlLEEOSQ9sO\nIzyQDNY79CfwguGoOkPLGHO6n2Glh7eE5g4vSN7e3ShhvAefLkUbhpPfd6VaKU81\nmOLwppUCgYEAw9FCGDNMsJRAatwfpkgkixvzg2fPceQZg/4aLkKWMRf7IlsG8jRB\nm3Y6ONyL7yhPIeeAP86W2ybFAKAG+l/Xr1xfMODlmaniHbaHMYlrseJiPVW79YfL\nxubvq5C5j/XHkhWzcWSLRUaTesqk6x1DOhK6WKsqLn+3Md1TlWlZ//MCgYEAwM7B\nKilB8rCqUdnSEv3v6VugKgIvEGN2y5AB8gqspVVJ9GOb8PINtE1psiBL0mlGZie1\nGvbVG97E4lXT+U2g+PPILBkRDykZmGsqX2KKmeYoD4KnKOYDNn2wdjT0B3eszIi7\nonm5ugcjN7fVC6kZVIsWMQR75RdOXAL0YpVFcpMCgYBiQPmdEwCECZ9Y/yKSWNid\nRGUnpkscpot3A2U3mQmrkJDeaDZQCZBx5RzJs0AzvFIYfQSI/6wKQqXO7n0R3E1p\nHDxXVkFenTNsHU4wuPdkxmbsx7wMMxs4rl/MAk5ZwcVls6XaW8zV8dfGYS/nGUPG\nO+ds3lXIByVwy9FIwxf5qQKBgGHfkobIcsWzkIIERHOHnGWlMWShvypek0s6SwKH\nEKTM6sG4Xsys0vAX6/OUGWkyL55jwbdyXTPMnb0XPIdtNK2rco2QG+zKPEf2/od1\nCk6dWvCkrh5AxJjArPcUYlv4ECuzrSwJBpK8VNBP7UICEO2tvRIc6JeegRSMG2p/\nw8UpAoGAKcOiuVlpfi/7rbkoC0W71xHxRRZYRMp815TG/Rf4eQYgJFck+EIorS/q\neRVlI0zscK9ZqKXeziLuDRqVs3k18oK/ITuQ65ivykydITuBlQjjG9zrHqO1w0+X\nKtj0R1QmvCCUhfC3EKZ3Bw4lgg7duN18DfczBrxQUkodSNna7tQ=\n-----END RSA PRIVATE KEY-----',
            'public_key': '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk3sXtliq2CUeTOmRZDO+\nCvWNn0MRS97YDaO6U3cyzm6UDAYIcI+H9cIRWfyN0sHpv3Tdg7wAguNvd/fcPNvf\n9CNwKeKvoyerx2N+MrGAIro6iLnKm9CCIlMi7Ro3lp0asDBMWpDCbH3w2kUgsnbG\nhI9s71A7ZVuKGlvz0sC6jEaR1hicsQ8PkHVHqKItxnu9rwb2Tg8nXHc9uKQtghuW\n+KBaRE40OEtSBcqFxDS6vu61ihW4DSAkB/X6Z/KWzNBn4ijGt6MD+M3UFtT0R6Jq\n/3WVrK7tTKzZyU+yWnpOWK5hRXyLaUGd5gyefW90jfPkAIzhoUIukAkfM+X1/icu\niQIDAQAB\n-----END PUBLIC KEY-----'
        }
        response = self.c.put(url, json.dumps(request_data),content_type='application/json')
        self.assertEqual(response.status_code, 201)
        uid = response.data.get('u_id', None)
        self.assertNotEqual(uid, None)
        # second, create session with security code
        new_client = Client()
        url1 = '/web/session'
        client_secure_key = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        request_data = {'client_secure_key': client_secure_key}
        new_client.post(url1, json.dumps(request_data), content_type='application/json')

        # third, enforce verification via mobile app
        user = MyUser.objects.all()[0]
        client = APIClient()
        client.force_authenticate(user=user)
        url2 = '/web/session_verify/'
        verify_request = {'client_secure_key': client_secure_key, 'token_id': uid, 'ws_session': '1984HD8d(*'}
        response = client.post(url2, verify_request, format='json')
        print('{}'.format(response))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {"success":True})










