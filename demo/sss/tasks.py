from .models import AlipayCode, Member
from demo.celery import app
from oauth2_provider.models import AccessToken, RefreshToken
from datetime import datetime
from django.contrib.auth.models import User
import logging


logger = logging.getLogger(__name__)


@app.task(name='deal_overdue')
def deal_overdue(code_id):
    code = AlipayCode.objects.filter(pk=code_id).first()
    if code and code.status == 1:
        code.status = 0
        code.save()


@app.task(name='delete_expired_token', queue='delete_expire')
def delete_expired_token():
    logger.info('Check online members')
    tokens = AccessToken.objects.filter(expires__lt=datetime.now())
    for token in tokens:
        if token:
            user = User.objects.filter(id=token.user_id).first()
            member_check = Member.objects.filter(user=user).first()
            if member_check:
                member_check.is_logged_in = False
                member_check.save()
            token.delete()
            RefreshToken.objects.filter(user=user).delete()
    member_logged_in = Member.objects.filter(is_logged_in=True)
    for member in member_logged_in:
        user_id = User.objects.filter(id=member.user_id).first().id
        token_found = AccessToken.objects.filter(user_id=user_id)
        if not token_found:
            member.is_logged_in = False
            member.save()
