import json
import time
import logging
from urllib import parse
import hashlib
import base64
import hmac
import requests
from uuid import uuid4
from .models import AlipayAccount
from demo.lib import constans


logger = logging.getLogger(__name__)


class AlipayMessageProvider(object):
    OK = constans.ALL_OK
    NOT_OK = constans.NOT_OK
    def sign(self, data, token):
        sign_str = '&'.join([f'{key}={value}' for key, value in sorted(data.items())])
        hmac_s2 = 'GET&%2F&' + parse.quote(parse.quote(sign_str, safe='=&'))
        hmac_s1 = token + '&'
        res_s = hmac.new(hmac_s1.encode(), hmac_s2.encode(), hashlib.sha1).digest()
        return base64.b64encode(res_s).decode()

    def send_message(self, phone, code):
        alipay = AlipayAccount.objects.filter(status=1).order_by('?').first()
        if not alipay:
            logger.info('no alipay account')
            return {'code': self.NOT_OK, 'msg': 'No Account'}
        a_id = alipay.accesskeyid
        s_id = alipay.secret_key

        params = {
            'AccessKeyId': a_id,
            'Timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.localtime(time.time() - (60 * 60 * 8))),
            'Format': 'json',
            'SignatureMethod': 'HMAC-SHA1',
            'SignatureVersion': '1.0',
            'SignatureNonce': hashlib.md5(uuid4().__str__().encode()).hexdigest(),
            'Action': 'SendSms',
            'Version': '2017-05-25',
            'RegionId': 'cn-hangzhou',
            'PhoneNumbers': phone,
            'SignName': '乐理二手',
            'TemplateCode': 'SMS_163438002',
            'TemplateParam': json.dumps({'code': code})
            }

        params['Signature'] =  self.sign(params, s_id)

        logger.info(params)

        url_data = parse.urlencode(params)
        url = f'http://dysmsapi.aliyuncs.com/?{url_data}'
        try:
            res = requests.get(url)
            logger.info(res.text)
            res_json = res.json()
            if res_json.get('Code') == 'OK':
                return {'code': self.OK, 'msg': 'OK', 'ali_obj': alipay}
            else:
                return {'code': self.NOT_OK, 'msg': res_json.get('Message', 'NOT_OK')}
        except:
            return {'code': self.NOT_OK, 'msg': 'Unkonwn Error'}
