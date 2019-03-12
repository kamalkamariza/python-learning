from django.conf.urls import url, patterns
from rest_framework.urlpatterns import format_suffix_patterns
from rest_framework.authtoken import views as tokenview
from . import views
# from views import verify_master_passcode_set

urlpatterns = [
    # Examples:
    # url(r'^$', 'magstreet_abstract.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^create_user/$', views.VerificationOfRequestCode),
    url(r'^$', 'auth_user.views.default'),
    url(r'^check_authenticate$', views.CheckAuthentication),
    url(r'^users/$', views.user_list),
    url(r'^users/(?P<pk>[0-9]+)$', views.user_detail),
    # url('', include('social.apps.django_app.urls', namespace='social')),
    # url(r'^is_mastercode_set/$', verify_master_passcode_set),
    url(r'^view_email_code_web/$', views.email_verification_view, name='email_verification_view'),
    # url(r'^web/session_verify', views.UserWebCheckIn.verify_web_login_code, name='web_session_verify'),
    url(r'^web/session', views.UserWebCheckIn.set_web_login_code, name='web_session_set'),
    url(r'^web/keypair$', views.WebUserKeyPair.as_view(), name='web_keypair'),
    url(r'^web/keypair/set$', views.web_set_session_tokens),
    url(r'^web/gen_keypair$', views.generate_keypair),
    url(r'^web/init_device$', views.CreateWebDevice, name='create_device'),
    # some hack to make it work on mobile
    # url(r'^api/v1/web/session_verify$', views.UserWebCheckIn.verify_web_login_code),
    url(r'^api/v1/keypair$', views.retrieve_web_keypair_request),
    url(r'^api/v1/get_user_devices$', views.get_devices_auth),
    # only for admin use
    # TODO: move to main url.py file
    url(r'^api/v1/reset_password$', views.reset_authentication_tokens_for_login),
]


# urlpatterns += [
#     url(r'^api-token-auth/', tokenview.obtain_auth_token),
#     #url(r'^rest-auth/facebook/$', views.FacebookLogin2.as_view(), name='fb_login')
# ]
#
# urlpatterns = format_suffix_patterns(urlpatterns)