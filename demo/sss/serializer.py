import re
import random

from rest_framework import serializers
from django.contrib.auth.models import User, Group
from django.utils.translation import ugettext as _

from .message import AlipayMessageProvider
from demo.utils import get_ip_addr, vertify_code
from loginsvc.views import is_self_phonenum
from demo.lib import constans
from sss.models import Member, AlipayCode


class MemberRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Member
        fields = '__all__'

    def to_internal_value(self, data):
        request = self.context.get('request')
        data = request.data
        phone = data.get('phone')
        verification_code = data.get('verification_code')
        code_obj = vertify_code(phone, verification_code)
        if not code_obj:
            raise serializers.ValidationError({
                'code': constans.FIELD_ERROR,
                'error': [{'verfification_code_field':
                               _('Incorrect verification code')}]})
        code_obj.delete()
        ret = super(MemberRegisterSerializer, self).to_internal_value(data)
        ret['password'] = request.data.get('password')
        ret['verification_code'] = request.data.get('verification_code')
        return ret

    def validate(self, data):
        request = self.context.get('request')
        validated_data = {}
        if request.method == 'POST':

            user_check = User.objects.filter(username=data.get('username'))

            if user_check:
                raise serializers.ValidationError({
                    'code': constans.FIELD_ERROR,
                    'error': [{'username_field': _('Username already in use')}]
                })
            validated_data['username'] = data.get('username')
            password = data.get('password')
            pattern = re.compile('^[a-zA-Z0-9]{6,15}$')
            if not pattern.match(password):
                msg = _('Password must be 6 to 15 alphanumeric characters')
                raise serializers.ValidationError({
                    'code': constans.FIELD_ERROR,
                    'error': [{'password_field': msg}]
                })
            validated_data['password'] = password
            validated_data['phone'] = data.get('phone')
            ipaddr = get_ip_addr(request)
            validated_data['register_ip'] = ipaddr

        return validated_data

    def create(self, validated_data):
        '''
        '''

        password = validated_data.pop('password')

        member = Member.objects.create(**validated_data)

        if member:
            user = User.objects.create_user(
                username=validated_data['username'],
                password=password)

            member_grp = Group.objects.filter(name='member_grp').first()

            user.groups.add(member_grp)
            member.user = user
            member.save()

        return member


class SendMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlipayCode
        fields = '__all__'

    def validate(self, data):
        request = self.context.get('request')
        validated_data = {}
        if request.method == 'POST':
            phone = data.get('phone')
            code_type = data.get('code_type')
            if not phone:
                raise serializers.ValidationError({
                    'code': constans.FIELD_ERROR,
                    'error': [{'phone_field': _('need phone filed')}]
                })
            if not code_type == 'register' and not is_self_phonenum(request, phone):
                raise serializers.ValidationError({
                    'code': constans.FIELD_ERROR,
                    'error': [{'phone_field': _('not self phone')}]
                })
            if Member.objects.filter(phone=phone).exists():
                raise serializers.ValidationError({
                    'code': constans.FIELD_ERROR,
                    'error': [{'phone_field': _('phone already in use')}]
                })
            v_code = ''.join(str(i) for i in random.sample(range(0, 9), 6))
            amp_obj = AlipayMessageProvider()
            res = amp_obj.send_message(phone, v_code)
            code = res.get('code')
            if not code == constans.ALL_OK:
                msg = res.get('msg')
                raise serializers.ValidationError({
                        'error': [{'code': code, 'msg': msg}]
                    })
            validated_data['code'] = v_code
            validated_data['phone'] = phone
            validated_data['alipay_account'] = res.get('ali_obj')
            return validated_data
