from django.conf.urls import url, include
from rest_framework import routers
from sss import views as account
from loginsvc.views import login, logout, refresh_access_token, reset_password, current_user


member_router = routers.DefaultRouter()

member_router.register(r'^register',  # member register
                       account.MemberRegisterViewSet,
                       base_name='register')
member_router.register(r'checkname',   # check name or phone
                       account.ChecknameMemberViewSet,
                       base_name='checkname')
member_router.register(r'sendmessage',  # use ali_pay send message
                       account.SendMessagenameMemberViewSet,
                       base_name='sendmessage')


urlpatterns = [
    url(r'^member/', include(member_router.urls)),
    url(r'^member/login/$', login, name='member_login'),
    url(r'^member/password/$', reset_password,
        name='member_reset_password'),
    url(r'^my/$', current_user, name='current_user'),

    # url(r'^manage/login/$', login, name='dashboard_login'),
    url(r'^login/refresh/', refresh_access_token,
        name='refresh'),
    url(r'^logout/$', logout, name='account_logout'),
    url(r'^o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
]
