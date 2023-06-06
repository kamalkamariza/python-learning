from django.db import models
# Create your models here.
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.utils.translation import ugettext_lazy as _
from django.core.validators import RegexValidator
from django.contrib.auth.forms import UserCreationForm
from django import forms
from django.utils.timezone import datetime
from datetime import timedelta
import datetime as Datetimes
from django.forms import extras, model_to_dict
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
from fields import JSONField
import phonenumbers, uuid, json
from phonenumbers.phonenumberutil import region_code_for_number
from authentication import AuthenticationCredentials
from django.core.cache import cache

# from user_profile.models import DirectoryManager, ClientContact

import base64

#@receiver(post_save, sender=settings.AUTH_USER_MODEL)
#def create_auth_token(sender, instance=None, created=False, **kwargs):
#   if created:
#        Token.objects.create(user=instance)


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def run_after_saving_user(sender, instance=None, created=False, **kwargs):
    """
    This function will be run after user model is saved
    """
    # print("Request finished! {}, {}, {}, {}".format(sender, instance, created, kwargs))
    key = '{}_should_change_ID_now'.format(instance.username)
    cache_value = cache.get(key)
    if cache_value is None:
        cache.set(key, Datetimes.datetime.now())
    else:
        if Datetimes.datetime.now() - cache_value >= Datetimes.timedelta(weeks=1):
            print("action should be done to remind user again")


class MyUser(AbstractUser):
    gender = models.CharField(max_length=6, blank=True)
    dob = models.DateField(null=True, blank=True)
    agree_toc = models.BooleanField(default=True)
    full_phone_number = models.CharField(max_length=100, default=' ')
    image = models.ImageField(upload_to='profile_pictures', max_length=500)
    fb_uid = models.CharField(max_length=250, default=' ')
    master_passcode = models.CharField(verbose_name=_('master_passcode'), max_length=128, default=' ')
    phone_number_raw = models.CharField(max_length=100, default=' ')
    phone_number_country = models.CharField(max_length=5, default=' ')
    sms_code = models.CharField(max_length=5, default=' ')
    sms_code_expiry = models.DateTimeField(null=True)
    phone_verified = models.BooleanField(default=False)
    about_me = models.TextField(verbose_name=_('User About Me'), default=' ', blank=True)
    change_username_now = models.BooleanField(default=False)
    data = JSONField(blank=True, null=True)
    authenticated_device = JSONField(blank=True, null=True)
    authenticated_web_client = JSONField(blank=True, null=True)
    web_client_identity_key = models.CharField(max_length=100, default='')

    @staticmethod
    def get_random_username():
        #Get total number of users plus some random number so that
        # user ID has no chance of clashing
        number_id = MyUser.objects.all().order_by('-id')[0].pk + int(str(uuid.uuid4().int)[:10])
        return 'user' + str(number_id)

    def get_bare_jid(self):
        return self.full_phone_number + '@' + settings.DOMAIN_NAME

    def get_image_url(self):
        return settings.MEDIA_URL + self.image.name.strip()

    def get_cover_photo(self):
        try:
            image = self.cover_photos
            if image.image_600.name.strip():
                return settings.MEDIA_URL + image.image_600.name
            else:
                return ' '
        except AttributeError:
            return ' '

    @staticmethod
    def get_full_phone_number(phone_raw, phone_country_code):
        parse_phone_number = phonenumbers.parse(phone_raw, phone_country_code)
        return phonenumbers.format_number(parse_phone_number, phonenumbers.PhoneNumberFormat.E164)

    # def get_web_client(self):
    #     return Device(**self.authenticated_web_client).save()

    def get_authenticated_device(self):
        return Device(**self.authenticated_device).save()

    def set_authenticated_device(self, device, device_dict):
        assert isinstance(device, Device)
        if device_dict['lastSeen'] is not None and isinstance(device_dict['lastSeen'], datetime):
            device_dict['lastSeen'] = device_dict['lastSeen'].isoformat()
        if device_dict['created'] is not None and isinstance(device_dict['created'], datetime):
            device_dict['created'] = device_dict['created'].isoformat()
        found_entry = False
        for i in range(len(self.data['devices'])):
            if self.data['devices'][i]['device_id'] == device.device_id:
                self.data['devices'][i] = device_dict
                found_entry = True
        if not found_entry:
            self.data['devices'].append(device_dict)
        self.authenticated_device = json.dumps(device_dict)

    # def get_web_signedPreKey(self):
    #     from web_message.models import WebSignedPreKeyStore
    #     signed_key_store = WebSignedPreKeyStore(self)
    #     return signed_key_store.loadSignedPreKeys()
    #
    # def get_web_client_identity_key_for_user(self, username):
    #     from web_message.models import WebIdentityKeyStore
    #     user = MyUser.objects.get(username=username)
    #     return user.web_client_identity_key

    def get_identity_key(self):
        return self.data.get('identityKey', None)

    def set_identity_key(self, idKey):
        self.data['identityKey'] = idKey
        return self

    def set_device_instance(self, device_dict, replace=True):
        if replace:
            for i in range(len(self.data['devices'])):
                if self.data['devices'][i]['device_id'] == device_dict.get('device_id'):
                    self.data['devices'][i] = device_dict
        else:
            self.data['devices'].append(device_dict)
        return self

    def get_devices(self):
        devices = list()
        for i in range(len(self.data['devices'])):
            devices.append(Device(**self.data['devices'][i]))
        return devices

    def get_device(self, device_id):
        for device in self.data.get('devices'):
            if device['device_id'] == int(device_id):
                return Device(**device)
        return None

    def is_voice_supported(self):
        devices = self.get_devices()
        for device in devices:
            if device.is_active() and device.voice:
                return True
        return False

    # def update_directory(self, username_changed=False):
    #     dir_manager = DirectoryManager()
    #     if self.is_active:
    #         if username_changed:
    #             dir_manager.remove_client_contact(self.get_username())
    #         new_contact_to_be_added = ClientContact(token=dir_manager.get_contact_token(self.get_username()),
    #                                                 voice=self.is_voice_supported(),relay=None)
    #         dir_manager.add_client_contact(new_contact_to_be_added)
    #
    #     else:
    #         dir_manager.remove_client_contact(self.get_username())
    #     return True

    def get_active_device_count(self):
        count = 0
        for device in self.get_devices():
            assert isinstance(device, Device)
            if device.is_active(): count += 1
        return count

    def username_is_email(self):
        if self.change_username_now:
            return False
        import re
        pattern = re.compile("[\w.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}")
        result = pattern.match(self.username)
        if result is not None:
            return True
        return False

    def username_is_phone(self):
        if self.change_username_now:
            return False
        import re
        pattern = re.compile("\+[0-9]{7,15}")
        result = pattern.match(self.username)
        if result is not None:
            return True
        return False

    def get_active_users(self):
        myusers = MyUser.objects.filter(change_username_now=False, phone_verified=True,
                                        username__iregex=r'^\+').exclude(full_phone_number=' ')
        return myusers

    @classmethod
    def gen_random_auth_token(cls):
        import os
        return cls.toHex(os.urandom(16))

    @staticmethod
    # convert string to hex
    def toHex(s):
        lst = []
        for ch in s:
            hv = hex(ord(ch)).replace('0x', '')
            if len(hv) == 1:
                hv = '0' + hv
            lst.append(hv)
        return reduce(lambda x, y: x + y, lst)



# class FbAccount(models.Model):
#     user = models.OneToOneField('auth_user.MyUser', related_name='user_fb')
#     facebook_token = models.TextField(verbose_name=_('Facebook User \'s Access Token'))
#     uid = models.CharField(max_length=255)
#     date_joined = models.DateTimeField(auto_now_add=True)
#     extra_data = JSONField(verbose_name=_('extra data'), default='{}')
#     expires_at = models.DateTimeField(null=True,
#                                       verbose_name=_('expires at'))


# class RegisterForm(UserCreationForm):
#
#     dob = forms.DateField(label='Date of Birth', required=False,
#                           widget=extras.SelectDateWidget(years=[y for y in range(1900, datetime.now().year + 1)])
#                           )
#     SEX = (
#         ('M', 'Male'),
#         ('F', 'Female'),
#     )
#     username_validator = RegexValidator(regex='^[a-z0-9_-]{3,16}$',
#                                         message='No Special Symbols allowed. Alphanumerics only',
#                                         code='invalid',
#                                         )
#     gender = forms.ChoiceField(label='Gender', choices=SEX, widget=forms.Select(attrs={'class': 'regDropDown'}))
#     # agree_toc = forms.BooleanField(label='', help_text='Do you agree with our Terms and Conditions?', initial=True, required=False)
#     username = forms.CharField(label="Username", widget=forms.TextInput(), max_length=15, help_text='Required. less than 30 characters. Alphanumerics only.', validators=[username_validator])
#     first_name = forms.CharField(label="First Name", widget=forms.TextInput(), required=True)
#     last_name = forms.CharField(label="Last Name", widget=forms.TextInput(), required=True)
#     email = forms.EmailField(label="Email Address", widget=forms.TextInput(), required=True)
#
#     class Meta:
#         model = MyUser
#         fields = ('username', 'password1', 'password2', 'email', 'first_name', 'last_name', 'dob', 'gender')
#
#     def clean_username(self):
#         username = self.cleaned_data['username']
#         if MyUser.objects.exclude(pk=self.instance.pk).filter(username=username).exists():
#             raise forms.ValidationError(_('Username "%s" is already in use.' % username), code='invalid')
#         return username
#
#
#     def clean_email(self):
#         email = self.cleaned_data['email']
#         if MyUser.objects.exclude(pk=self.instance.pk).filter(email=email).exists():
#             raise forms.ValidationError(_('Email address "%s" is already in use.' % email), code='invalid')
#         return email
#
#     def save(self,commit=True):
#         new_user = MyUser.objects.create_user(self.cleaned_data['username'],
#                                           self.cleaned_data['email'],
#                                           self.cleaned_data['password2'])
#         new_user.first_name = self.cleaned_data['first_name']
#         new_user.last_name = self.cleaned_data['last_name']
#         new_user.dob = self.cleaned_data['dob']
#         new_user.gender = self.cleaned_data['gender']
#         new_user.save()


class Device(models.Model):
    MASTER_ID = 1
    name = models.CharField(max_length=255)
    authToken = models.CharField(max_length=255)
    salt = models.CharField(max_length=255)
    signalingKey = models.CharField(max_length=255)
    gcmId = models.TextField()
    apnId = models.TextField()
    voipApnId = models.TextField()
    pushTimestamp = models.BigIntegerField()
    fetchesMessages = models.BooleanField(default=False)
    registrationId = models.IntegerField()
    device_id = models.IntegerField(default=MASTER_ID)
    signedPreKey = JSONField(null=True, blank=True)
    support_sms = models.BooleanField(default=False)
    lastSeen = models.DateTimeField()
    created = models.DateTimeField()
    voice = models.BooleanField(default=False)
    userAgent = models.TextField()

    class Meta:
        abstract = True

    def __str__(self):
        return "authToken: {} fetchesMessage: {} device_id:{}".format(self.authToken,
                                                                      self.fetchesMessages, self.device_id)

    def __init__(self, *args, **kwargs):
        # assert kwargs['registrationId'], 'registrationId value not added'
        assert kwargs['signalingKey'], 'signalingKey value not added'
        assert kwargs['authToken'], 'authToken value not added'
        super(Device, self).__init__(*args, **kwargs)
        self.password = kwargs.get('authToken')
        if not self.created:
            self.created = datetime.now()

    def __getattribute__(self, attr):
        if attr == 'password':
            return self.authToken
        return super(Device, self).__getattribute__(attr)

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        if not isinstance(self.created, datetime) and self.created is not None:
            self.created = datetime.strptime(unicode(self.created), '%Y-%m-%dT%H:%M:%S.%f')
        if not isinstance(self.lastSeen, datetime) and self.lastSeen is not None:
            self.lastSeen = datetime.strptime(unicode(self.lastSeen), '%Y-%m-%dT%H:%M:%S.%f')
        return self

    def set_authentication_credentials(self):
        credential = AuthenticationCredentials(authenticationToken=self.password)
        if isinstance(credential, AuthenticationCredentials):
            self.authToken = credential.getHashedAuthenticationToken()
            self.salt = credential.getSalt()

    def get_authentication_credentials(self):
        assert self.authToken, "you need to call setAuthenticationCredentials first"
        assert self.salt, "you need to call setAuthenticationCredentials first"
        return AuthenticationCredentials(self.authToken, self.salt)

    @staticmethod
    def get_time_stamp(time_object):
        epoch = datetime.utcfromtimestamp(0)

        def unix_time_millis(dt):
            return (dt - epoch).total_seconds() * 1000.0
        return int(unix_time_millis(time_object))

    def is_active(self):
        channel_is_available = self.fetchesMessages is True or self.gcmId != '' or self.apnId != ''
        if settings.DEBUG:
             channel_is_available = True
        return (self.device_id == self.MASTER_ID and channel_is_available) or \
               (self.device_id != self.MASTER_ID and channel_is_available )
    # self.lastSeen > (datetime.now() - timedelta(days=30))

    def set_as_authenticated_device(self, user):
        assert isinstance(user, MyUser)
        device_dict = model_to_dict(self)
        device_dict['lastSeen'] = device_dict['lastSeen'].isoformat()
        device_dict['created'] = device_dict['created'].isoformat()
        found_entry = False
        for i in range(len(user.data['devices'])):
            if user.data['devices'][i].device_id == self.device_id:
                user.data['devices'][i] = device_dict
                found_entry = True
        if not found_entry:
            user.data['devices'].append(device_dict)
        user.authenticated_device = json.dumps(device_dict)

    def set_as_web_authenticated_client(self, user):
        assert isinstance(user, MyUser)
        device_dict = model_to_dict(self)
        last_seen = device_dict['lastSeen']
        if last_seen is not None and isinstance(last_seen, datetime):
            device_dict['lastSeen'] = device_dict['lastSeen'].isoformat()
        created_time = device_dict['created']
        if created_time is not None and isinstance(created_time, datetime):
            device_dict['created'] = device_dict['created'].isoformat()
        found_entry = False
        for i in range(len(user.data['devices'])):
            if user.data['devices'][i]['device_id'] == self.device_id:
                user.data['devices'][i] = device_dict
                found_entry = True
        if not found_entry:
            user.data['devices'].append(device_dict)
        user.authenticated_web_client = json.dumps(device_dict)
        user.save()

    # def get_signed_prekeys(self, user=None):
    #     try:
    #         id_num = int(self.device_id)
    #     except ValueError:
    #         raise ValueError('invalid device id')
    #     if id_num == 2:
    #         from web_message.models import WebSignedPreKeyStore, KeyStorageManager
    #         if not self.signedPreKey:
    #             signed_prekeys = WebSignedPreKeyStore(user).loadSignedPreKeys()
    #             return [KeyStorageManager.dict_from_signed_prekey(signed_prekey) for signed_prekey in signed_prekeys]
    #         return [self.signedPreKey]
    #     elif id_num == 1:
    #         return [self.signedPreKey]


class PhoneNumberEmailVerification(models.Model):
    TRANSPORT = (
        ('sms', 'Sms'),
        ('call', 'Phone Verification'),
        ('email', 'Email Verification'),
    )
    ip_address = models.GenericIPAddressField(default='0.0.0.0')
    verify_type = models.CharField(choices=TRANSPORT, max_length=10)
    verification_code = models.CharField(max_length=10)
    email = models.EmailField()
    full_phone_number = models.CharField(max_length=100, default=' ')
    phone_number_raw = models.CharField(max_length=100, default=' ')
    phone_number_country = models.CharField(max_length=5, default=' ')
    verification_code_expiry = models.DateTimeField(null=True)
    number_of_requests = models.IntegerField(default=0)
    verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @staticmethod
    def get_country_iso_code(phone_object):
        return region_code_for_number(phone_object)

    @staticmethod
    def get_raw_phone(phone_object):
        return str(phone_object.national_number)


class WebLoginTokenKeys(models.Model):
    session_key = models.CharField(unique=True, max_length=255)
    public_key = models.TextField()
    private_key = models.TextField()
    expiry_date = models.DateTimeField()
    verified = models.BooleanField(default=False)
    format = "%Y-%m-%d %H:%M:%S"
    expiry_duration_in_seconds = 10*60 #10 minutes

    @property
    def is_authenticated(self):
        """
        Always return True. This is a way to tell if the user has been
        authenticated in templates.
        """
        return True

    @classmethod
    def generate_session_key(cls):
        import uuid

        def create_session_id():
            session_id = uuid.uuid4().hex
            try:
                cls.objects.get(session_key=session_id)
                return create_session_id()
            except cls.DoesNotExist:
                return session_id
        return create_session_id()

    @classmethod
    def get_expiry_date_from_now(cls):
        from django.utils import timezone
        expiry = timezone.now() + timezone.timedelta(seconds=cls.expiry_duration_in_seconds)
        return expiry.strftime(cls.format)

    @classmethod
    def clear_expired(cls):
        return cls.objects.filter(expiry_date__lt=datetime.now()).delete()


def get_session_expiry():
    return datetime.now() + timedelta(days=1.0)


class WebClientSessions(models.Model):
    session_key = models.CharField(unique=True, max_length=255)
    expiry_date = models.DateTimeField(default=get_session_expiry)

    @property
    def is_authenticated(self):
        """
        Always return True. This is a way to tell if the user has been
        authenticated in templates.
        """
        return True

