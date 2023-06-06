from rest_framework.authentication import BaseAuthentication
from rest_framework.authentication import get_authorization_header as authorization_header
from rest_framework.authtoken.models import Token
from rest_framework import exceptions, HTTP_HEADER_ENCODING
from models import *
import json, os, base64, datetime, hashlib, hmac, urllib
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import authenticate, get_user_model


class AuthenticationCredentials(object):

    def __init__(self, authenticationToken, hashedAuthenticationToken=None, salt=None):
        if hashedAuthenticationToken is not None and salt is not None:
            self.hashedAuthenticationToken = hashedAuthenticationToken
            self.salt = salt
        else:
            self.salt = str(abs(int(hashlib.sha1(os.urandom(128)).hexdigest(), 16) >> 3))
            self.hashedAuthenticationToken = self.getHashedValue(self.salt, authenticationToken)

    @staticmethod
    def getHashedValue(salt, password):
        return str(hashlib.sha1((salt + password).encode('utf-8')).hexdigest())

    def verify(self, authenticationToken):
        theirValue = self.getHashedValue(self.salt, authenticationToken)
        return theirValue == self.hashedAuthenticationToken

    def getHashedAuthenticationToken(self):
        return self.hashedAuthenticationToken

    def getSalt(self):
        return self.salt



def get_authorization_header(request):
    """
    Return request's 'X-Auth-Token:' header, as a bytestring.

    Hide some test client ickyness where the header can be unicode.
    """
    auth = request.META.get('HTTP_X_AUTH_TOKEN', b'')
    if isinstance(auth, type('')):
        # Work around django test client oddness
        auth = auth.encode(HTTP_HEADER_ENCODING)
    return auth


# class WebClientAuthentication(BaseAuthentication):
#     def authenticate(self, request):
#         session_id = request.META.get('HTTP_X_WEB_SESSION')
#         if not session_id:
#             return None
#         from models import WebClientSessions, WebLoginTokenKeys
#         try:
#             client = WebClientSessions.objects.get(session_key=session_id)
#         except WebClientSessions.DoesNotExist:
#             try:
#                 client = WebLoginTokenKeys.objects.get(session_key=session_id)
#             except WebLoginTokenKeys.DoesNotExist:
#                 raise exceptions.AuthenticationFailed('No such client')
#
#         return client, None


# class KeyPairTokenClientAuthentication(BaseAuthentication):
#     def authenticate(self, request):
#         session_id = request.META.get('HTTP_X_WEB_SESSION')
#         if not session_id:
#             return None
#         from models import WebLoginTokenKeys
#         try:
#             client = WebLoginTokenKeys.objects.get(session_key=session_id)
#         except WebLoginTokenKeys.DoesNotExist:
#             raise exceptions.AuthenticationFailed('No such client')
#         return client, None


class EnhancedBasicAuthentication(BaseAuthentication):
    www_authenticate_realm = 'api'

    @staticmethod
    def getHashedValue(salt, token):
        return str(hashlib.sha1((salt + token).encode('utf-8')).hexdigest())

    def verify_for_authenticate(self, password, salt, authenticationToken):
        theirValue = self.getHashedValue(salt, password)
        return theirValue == authenticationToken

    def authenticate(self, request):
        auth = authorization_header(request).split()

        if not auth or auth[0].lower() != b'basic':
            return None

        if len(auth) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            auth_parts = base64.b64decode(auth[1]).decode(HTTP_HEADER_ENCODING).partition(':')
        except (TypeError, UnicodeDecodeError):
            msg = _('Invalid basic header. Credentials not correctly base64 encoded.')
            raise exceptions.AuthenticationFailed(msg)

        userid, password = auth_parts[0], auth_parts[2]

        return self.authenticate_credentials(userid, password)

    def authenticate_credentials(self, key=None, password=None):
        try:
            user = get_user_model().objects.get(username=key)
        except get_user_model().DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid user.'))

        if not user.is_active:
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))
        try:
            result = user.data['devices'][0]
        except TypeError:
            raise exceptions.AuthenticationFailed(_('Invalid Authentication Tokens'))
        if not self.verify_for_authenticate(password, result['salt'], result['authToken']):
            raise exceptions.AuthenticationFailed(_('Invalid Authentication'))
        #Add authenticated device
        if user.authenticated_device != json.dumps(result):
            user.authenticated_device = json.dumps(result)
            user.save()
        return user, None

    def authenticate_header(self, request):
        return 'Basic realm="%s"' % self.www_authenticate_realm


class TokenAuthentication(BaseAuthentication):
    """
    Simple token based authentication.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Token ".  For example:

        X-Auth-Token: Token 401f7ac837da42b97f613d789819ff93537bee6a
    """

    model = Token
    """
    A custom token model may be used, but must have the following properties.

    * key -- The string identifying the token
    * user -- The user to which the token belongs
    """

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'token':
            return None

        if len(auth) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        return self.authenticate_credentials(auth[1])

    def authenticate_credentials(self, key):
        try:
            token = self.model.objects.select_related('user').get(key=key)
        except self.model.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

        user = (token.user, token)

        return user

    def authenticate_header(self, request):
        return 'Token'


class TokenBasedAuth(object):

    def authenticate(self, key=None):

        auth = get_authorization_header(key).split()

        if not auth or auth[0].lower() != b'token':
            return None

        if key:
            try:
                t = Token.objects.select_related('user').get(key=key[1])
            except IndexError:
                return None
        else:
            return None

        return t.user

    def get_user(self, user_id):
        try:
            return MyUser.objects.get(id=user_id)
        except:
            return None



