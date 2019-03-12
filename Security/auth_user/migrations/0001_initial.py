# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import django.contrib.auth.models
import auth_user.fields
import django.utils.timezone
from django.conf import settings
import django.core.validators


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0006_require_contenttypes_0002'),
    ]

    operations = [
        migrations.CreateModel(
            name='MyUser',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(null=True, verbose_name='last login', blank=True)),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(error_messages={'unique': 'A user with that username already exists.'}, max_length=30, validators=[django.core.validators.RegexValidator('^[\\w.@+-]+$', 'Enter a valid username. This value may contain only letters, numbers and @/./+/-/_ characters.', 'invalid')], help_text='Required. 30 characters or fewer. Letters, digits and @/./+/-/_ only.', unique=True, verbose_name='username')),
                ('first_name', models.CharField(max_length=30, verbose_name='first name', blank=True)),
                ('last_name', models.CharField(max_length=30, verbose_name='last name', blank=True)),
                ('email', models.EmailField(max_length=254, verbose_name='email address', blank=True)),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('gender', models.CharField(max_length=6, blank=True)),
                ('dob', models.DateField(null=True, blank=True)),
                ('agree_toc', models.BooleanField(default=True)),
                ('full_phone_number', models.CharField(default=b' ', max_length=100)),
                ('image', models.ImageField(max_length=500, upload_to=b'profile_pictures')),
                ('fb_uid', models.CharField(default=b' ', max_length=250)),
                ('master_passcode', models.CharField(default=b' ', max_length=128, verbose_name='master_passcode')),
                ('phone_number_raw', models.CharField(default=b' ', max_length=100)),
                ('phone_number_country', models.CharField(default=b' ', max_length=5)),
                ('sms_code', models.CharField(default=b' ', max_length=5)),
                ('sms_code_expiry', models.DateTimeField(null=True)),
                ('phone_verified', models.BooleanField(default=False)),
                ('about_me', models.TextField(default=b' ', verbose_name='User About Me', blank=True)),
                ('change_username_now', models.BooleanField(default=False)),
                ('data', auth_user.fields.JSONField(null=True, blank=True)),
                ('authenticated_device', auth_user.fields.JSONField(null=True, blank=True)),
                ('groups', models.ManyToManyField(related_query_name='user', related_name='user_set', to='auth.Group', blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(related_query_name='user', related_name='user_set', to='auth.Permission', blank=True, help_text='Specific permissions for this user.', verbose_name='user permissions')),
            ],
            options={
                'abstract': False,
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='FbAccount',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('facebook_token', models.TextField(verbose_name="Facebook User 's Access Token")),
                ('uid', models.CharField(max_length=255)),
                ('date_joined', models.DateTimeField(auto_now_add=True)),
                ('extra_data', auth_user.fields.JSONField(default=b'{}', verbose_name='extra data')),
                ('expires_at', models.DateTimeField(null=True, verbose_name='expires at')),
                ('user', models.OneToOneField(related_name='user_fb', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='PhoneNumberEmailVerification',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('ip_address', models.GenericIPAddressField(default=b'0.0.0.0')),
                ('verify_type', models.CharField(max_length=10, choices=[(b'sms', b'Sms'), (b'call', b'Phone Verification'), (b'email', b'Email Verification')])),
                ('verification_code', models.CharField(max_length=10)),
                ('email', models.EmailField(max_length=254)),
                ('full_phone_number', models.CharField(default=b' ', max_length=100)),
                ('phone_number_raw', models.CharField(default=b' ', max_length=100)),
                ('phone_number_country', models.CharField(default=b' ', max_length=5)),
                ('verification_code_expiry', models.DateTimeField(null=True)),
                ('number_of_requests', models.IntegerField(default=0)),
                ('verified', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='WebLoginTokenKeys',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('session_key', models.CharField(unique=True, max_length=255)),
                ('public_key', models.TextField()),
                ('private_key', models.TextField()),
                ('expiry_date', models.DateTimeField()),
            ],
        ),
    ]
