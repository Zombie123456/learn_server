from configset.models import GlobalPreferences
from oauth2_provider.models import AccessToken

from sss.models import AlipayCode


def get_ip_addr(request):
    ipaddr = request.META.get('HTTP_MARTY_IP')
    if ipaddr:
        return ipaddr
    ipaddr = request.META.get('HTTP_X_FORWARDED_FOR', None)
    if ipaddr:
        # X_FORWARDED_FOR returns client1, proxy1, proxy2,...
        ipaddr = ipaddr.split(', ')[0]
    else:
        ipaddr = request.META.get('REMOTE_ADDR', '')

    return ipaddr


def is_black_listed(ipaddr):
    try:
        black_list = GlobalPreferences.objects.filter(
            key='black_list').first().value.split(';')
    except:
        black_list = []

    return ipaddr in black_list


def get_user_type(user):
    if user:
        if hasattr(user, 'member_user'):
            return 'member'
        if hasattr(user, 'staff_user'):
            return 'staff'
        else:
            return 'admin'
    return None


def vertify_code(phone, code):
    try:
        AlipayCode.objects.get(status=1, phone=phone, code=code)
        return True
    except:
        return False


def parse_request_for_token(request):
    token = (request.META.get('HTTP_AUTHORIZATION') or '').split(' ')

    if len(token) < 2 or token[0] != 'Bearer':
        return None, None

    access_token = token[1]
    token_obj = AccessToken.objects.filter(token=access_token). \
        select_related('user').first()

    if not token_obj:
        return None, None

    user = token_obj.user

    if not user:
        return None, None

    user_group = (user.groups.filter(name='member_grp').first() or None)

    return user, user_group
