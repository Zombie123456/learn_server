import hashlib
import logging
import random
import requests
import re
import string

from django.contrib.auth.models import Group
from django.conf import settings
from django.contrib.auth import authenticate
from django.core.cache import cache
from django.http import JsonResponse, HttpResponseForbidden
from django.http.request import QueryDict
from django.urls import resolve
from django.utils import timezone
from django.utils.datastructures import MultiValueDictKeyError
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from oauth2_provider.models import AccessToken, Application, RefreshToken
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.throttling import AnonRateThrottle

from loginsvc.permissions import IsMember
from sss.models import Member
from demo.lib import constans
from demo.utils import (get_user_type,
                        get_ip_addr,
                        vertify_code,
                        is_black_listed,
                        parse_request_for_token)


logger = logging.getLogger(__name__)


def random_token_generator(length):
    seq = string.ascii_lowercase + string.digits

    return ''.join(random.choices(seq, k=length))


def generate_token(string_0, string_1):

    salt = random_token_generator(4)
    token = f'{string_0}.{string_1}.{salt}'

    return hashlib.md5(token.encode('utf-8')).hexdigest()


def generate_response(code, msg=None, data=None):
    response = {'code': code,
                'msg': msg,
                'data': data}

    return JsonResponse(response, status=200)


@csrf_exempt
def logout(request):

    if request.method != 'POST':
        return generate_response(constans.NOT_ALLOWED, _('Not Allowed'))

    access_token = (request.META.get('HTTP_AUTHORIZATION') or '').split(' ')
    if access_token and len(access_token) == 2 \
            and access_token[0] == 'Bearer':
        access_token = access_token[1]
    else:
        return generate_response(constans.NOT_OK, _('Request failed.'))

    token_obj = AccessToken.objects.filter(token=access_token).first()
    try:
        user = token_obj.user
        user_type = get_user_type(user)
        token_obj.delete()

        if user_type == 'staff':
            staff = user.staff_user
            staff.is_logged_in = False
            staff.save()

        return generate_response(constans.ALL_OK)
    except:
        return generate_response(constans.NOT_OK, _('Request failed.'))


@csrf_exempt
@api_view(['GET'])
def current_user(request):
    user, user_grp = parse_request_for_token(request)
    if not user:
        return JsonResponse(data=constans.NOT_OK,
                            status=404)
    return JsonResponse({'username': user.username,
                         'type': get_user_type(user)},
                        status=200)


@api_view(['POST'])
@permission_classes([])
@csrf_exempt
def refresh_access_token(request):
    refresh_token = request.data.get('refresh_token') or \
        request.POST.get('refresh_token')
    print(refresh_token)
    refresh_token_obj = \
        RefreshToken.objects.filter(token=refresh_token).first()

    if not refresh_token_obj:
        return generate_response(constans.NOT_OK,
                                 _('Please make sure you are logged in'))

    client_id = refresh_token_obj.application.client_id
    client_secret = refresh_token_obj.application.client_secret
    user_obj = refresh_token_obj.user

    if not user_obj.is_active:
        return generate_response(constans.NOT_ALLOWED,
                                 _('This account has been suspended'))

    url = f'{request.scheme}://{request.get_host()}/v1/o/token/'

    data = {'grant_type': 'refresh_token',
            'client_id': client_id,
            'client_secret': client_secret,
            'refresh_token': refresh_token}

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    try:
        response = requests.post(url, data=data, headers=headers)
        tokens = response.json()
        new_access_tk = tokens.get('access_token')
        new_refresh_tk = tokens.get('refresh_token')
    except:
        return generate_response(constans.NOT_OK, _('Refresh failed'))

    if response.status_code == 200 and new_access_tk and new_refresh_tk:
        expires_in = AccessToken.objects.filter(token=new_access_tk).\
            values('expires').first()
        if not expires_in:
            return generate_response(constans.NOT_OK, _('Refresh failed'))

        expires = timezone.localtime(expires_in['expires'])

        new_token = {
            'access_token': new_access_tk,
            'token_type': 'Bearer',
            'expires_in': expires.strftime('%Y-%m-%d %H:%M:%S'),
            'refresh_token': new_refresh_tk,
        }

        response = generate_response(constans.ALL_OK, data=new_token)
        response.set_cookie(key='access_token', value=new_access_tk)
        response.set_cookie(key='refresh_token', value=new_refresh_tk)
        return response

    return generate_response(constans.NOT_OK, _('Refresh failed'))


@api_view(['POST'])
@throttle_classes([AnonRateThrottle])
@permission_classes([])
@csrf_exempt
def login(request):
    ipaddr = get_ip_addr(request)
    if is_black_listed(ipaddr):
        return HttpResponseForbidden('IP is not allowed')
    sessionid = request.COOKIES.get('sessionid')

    if not sessionid or cache.get(sessionid) is None:
        try:
            request.session.create()
            sessionid = request.session.session_key
            cache.set(sessionid, 0, 3600)  # 1 hour
        except Exception as e:
            logging.error(str(e))

    data = request.POST or QueryDict(request.body)  # to capture data in IE

    try:
        user = authenticate(username=data['username'],
                            password=data['password'],
                            is_admin=False)
    except MultiValueDictKeyError:
        return generate_response(constans.NOT_ALLOWED,
                                 _('Not Allowed Login'))

    user_type = get_user_type(user)
    url_name = resolve(request.path).url_name
    if (url_name == 'member_login' and user_type is not 'member') or \
            (url_name == 'dashboard_login' and user_type is 'member'):
        msg = _('Invalid username or password')
        return set_auth(sessionid, msg)
    if user_type in {'staff', 'admin'}:
        otp_token = data.get('otp_token', None)
        if user_type is not None:
            if otp_token is None:
                msg = _('Please enter OTP Token')
                return set_auth(sessionid, msg)
            else:  # verify otp token
                totp_devices = user.totpdevice_set.filter(confirmed=True)
                otp_passed = False
                for d in totp_devices:
                    if d.verify_token(otp_token):
                        otp_passed = True
                        break
                if not otp_passed:
                    msg = _('Invalid OTP Token')
                    return set_auth(sessionid, msg)

    is_active = __get_status(user, user_type)

    if is_active:
        cache.delete(sessionid)

        token = create_token(user, user_type)
        if user_type == 'staff' or user_type == 'member':
            try:
                staff = user.staff_user
            except:
                staff = user.member_user
            staff.is_logged_in = True
            staff.last_logged_in = timezone.now()
            staff.save()

        response = generate_response(constans.ALL_OK, data=token)
        response.set_cookie(key='access_token',
                            value=token['access_token'])
        response.set_cookie(key='refresh_token',
                            value=token['refresh_token'])
        response.set_cookie(key='auth_req', value='')

        return response
    else:
        return generate_response(constans.NOT_ALLOWED, _('This account has been suspended'))


@csrf_exempt
@api_view(['POST'])
@permission_classes([IsMember])
def reset_password(request):
    if request.method == 'POST':
        token_obj = get_valid_token(request)

        if token_obj:
            user_tok = token_obj.user
            member = user_tok.member_user
            member_phone = member.phone


            if request.POST:
                phone = request.POST.get('phone')
                verfification_code = request.POST.get('verification_code')
                new_password = request.POST.get('password')
            else:
                phone = request.data.get('phone')
                verfification_code = request.data.get('verification_code')
                new_password = request.data.get('password')
            if not member_phone == phone:
                msg = _('not self phone')
                return generate_response(constans.FIELD_ERROR, msg)
            if not vertify_code(phone, verfification_code):
                msg = _('Incorrect verification code')
                return generate_response(constans.FIELD_ERROR, msg)
            pattern = re.compile('^[a-zA-Z0-9]{6,15}$')
            if not pattern.match(new_password):
                msg = _('Password must be 6 to 15 alphanumeric characters')
                return generate_response(constans.FIELD_ERROR, msg)

            user_tok.set_password(new_password)
            user_tok.save()

            force_logout(user_tok)

            return generate_response(constans.ALL_OK)

    return generate_response(constans.NOT_ALLOWED, _('Not Allowed'))


def set_auth(sessionid, message):
    data = {
        'sessionid': sessionid,
    }

    cache.incr(sessionid)

    response = generate_response(constans.FIELD_ERROR,
                                 msg=message,
                                 data=data)

    response.set_cookie(key='sessionid', value=sessionid)

    return response


def create_token(user, user_type):
    expire_seconds = settings.OAUTH2_PROVIDER['ACCESS_TOKEN_EXPIRE_SECONDS']
    scopes = settings.OAUTH2_PROVIDER['SCOPES']

    application = __get_application(user.groups.all())

    AccessToken.objects.filter(user=user, application=application).delete()

    expires = timezone.localtime() + timezone.timedelta(seconds=expire_seconds)

    user_token = generate_token(user.username, user.date_joined.strftime('%Y-%m-%d %H:%M:%S'))

    access_token = AccessToken.objects.create(user=user,
                                              application=application,
                                              token=user_token,
                                              expires=expires,
                                              scope=scopes)

    refresh_token = RefreshToken.objects.create(user=user,
                                                application=application,
                                                token=user_token,
                                                access_token=access_token)

    token = {
        'access_token': access_token.token,
        'token_type': 'Bearer',
        'expires_in': expires.strftime('%Y-%m-%d %H:%M:%S'),
        'refresh_token': refresh_token.token,
        'type': user_type
    }

    return token


def __get_status(user, user_type):
    if user:
        if user_type == 'admin':
            return user.is_active
        elif user_type == 'member':
            member = Member.objects.filter(username=user).first()
            return member and member.status == 1

    return False


def force_logout(user):
    token_obj = AccessToken.objects.filter(user=user).first()
    try:
        user = token_obj.user
        user_type = get_user_type(user)
        token_obj.delete()
        if user_type == 'staff':
            staff = user.staff_user
            staff.is_logged_in = False
            staff.save()
        return generate_response(constans.ALL_OK)
    except:
        generate_response(constans.NOT_OK, _('Request failed.'))


def __get_application(user_groups):
    if Group.objects.get(name='member_grp') in user_groups:
        return Application.objects.get(name="lion")
    else:
        return Application.objects.get(name="dashboard")


def get_valid_token(request, try_cookies=False, select_related_user=True):
    auth_str = request.META.get('HTTP_AUTHORIZATION') or ''
    auth_segments = auth_str.split(' ')
    if len(auth_segments) >= 2 and auth_segments[0] == 'Bearer':
        access_token_str = auth_segments[1]
    elif try_cookies:
        access_token_str = request.COOKIES.get('access_token')
    else:
        return None

    if select_related_user:
        access_token = AccessToken.objects.select_related('user') \
            .filter(token=access_token_str) \
            .first()
    else:
        access_token = AccessToken.objects.filter(token=access_token_str) \
            .first()
    if not access_token or access_token.is_expired():
        return None
    return access_token


def is_self_phonenum(request, phone):
    token = get_valid_token(request)
    try:
        member_phone = token.user.member_user.phone
        if not member_phone == phone:
            return True
    except:
        return None



