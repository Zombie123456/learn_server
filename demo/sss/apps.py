from __future__ import unicode_literals

from django.apps import AppConfig


class TransactionConfig(AppConfig):
    name = 'sss'

    def ready(self):
        import sss.signals
