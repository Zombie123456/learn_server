from rest_framework import mixins, viewsets
from rest_framework.response import Response
from django.http import HttpResponseForbidden
from django.utils.translation import ugettext as _
from django.contrib.auth.models import User

from sss.models import (Member,
                        AlipayCode)
from demo.utils import get_ip_addr, is_black_listed
from demo.lib import constans
from demo.throttling import CustomAnonThrottle
from sss.serializer import (MemberRegisterSerializer,
                            SendMessageSerializer)


class MemberRegisterViewSet(mixins.CreateModelMixin,
                            viewsets.GenericViewSet):
    model = Member
    permission_classes = []
    queryset = Member.objects.all().order_by('username')
    serializer_class = MemberRegisterSerializer

    def create(self, request):
        ipaddr = get_ip_addr(request)
        if is_black_listed(ipaddr):
            return HttpResponseForbidden('IP is not allowed')

        ret = super(MemberRegisterViewSet, self).create(request)

        if ret.status_code == 201:
            ret.data = {'code': constans.ALL_OK, 'message': _('Registration successful')}

        return ret


class ChecknameMemberViewSet(mixins.ListModelMixin,
                             viewsets.GenericViewSet):
    model = User
    permission_classes = []

    def list(self, request):
        data = request.GET
        print(data)
        username = data.get('username')
        phone = data.get('phone')
        if not username and not phone:
            return Response({'code': constans.FIELD_ERROR,
                             'msg': 'FIELD_ERROR'})

        if username:
            filed_exists = User.objects.filter(username=username).exists()
        elif phone:
            filed_exists = Member.objects.filter(phone=phone).exists()
        return Response({'code': constans.ALL_OK,
                         'existed': filed_exists})


class SendMessagenameMemberViewSet(mixins.CreateModelMixin,
                                   viewsets.GenericViewSet):
    model = AlipayCode
    queryset = AlipayCode.objects.all()
    permission_classes = []
    serializer_class = SendMessageSerializer
    throttle_classes = (CustomAnonThrottle,)

    def create(self, request):
        ret = super(SendMessagenameMemberViewSet, self).create(request)

        if ret.status_code == 201:
            ret.data = {'code': constans.ALL_OK, 'message': _('send successful')}

        return ret











