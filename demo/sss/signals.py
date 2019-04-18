# -*- coding: utf-8 -*-
import logging

from datetime import timedelta
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils.timezone import now, localtime
from .models import AlipayCode
from .tasks import deal_overdue


logger = logging.getLogger(__name__)


@receiver(post_save, sender=AlipayCode, dispatch_uid='transaction_follow_up')
def transaction_follow_up(sender, instance, created, **kwargs):
    """
    """
    expired_in_minutes = 5
    alipayaccount = instance.alipay_account
    if instance.status == 1:
        if alipayaccount:
            expired_in_minutes = alipayaccount.expired_in
        deal_overdue.apply_async((instance.id,),
                                 eta=localtime() + timedelta(minutes=expired_in_minutes))
