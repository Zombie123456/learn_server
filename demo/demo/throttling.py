from rest_framework.throttling import AnonRateThrottle
from configset.models import GlobalPreferences
from demo.settings import DEFAULT_REQUEST_RATE_LIMIT


class CustomAnonThrottle(AnonRateThrottle):
    def get_rate(self):
        t_rate = None
        throttling_rate = \
            GlobalPreferences.objects.filter(key='throttling_rate').first()
        if throttling_rate:
            t_rate = throttling_rate.value
        return t_rate or DEFAULT_REQUEST_RATE_LIMIT

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            return None  # Only throttle unauthenticated requests.
        view_name = view.__class__.__name__ if view else ''
        return self.cache_format % {
            'scope': f'{self.scope}{view_name}',
            'ident': self.get_ident(request)
        }
