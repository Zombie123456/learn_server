from django.contrib.auth.backends import ModelBackend
from sss.models import Member
from django.db.models import Q


class EmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, is_admin=True, **kwargs):
        if not is_admin:
            try:
                user = Member.objects.get(Q(phone=username) | Q(username=username))
            except Member.DoesNotExist:
                return None
            user = user.user
            if user and user.check_password(password):
                return user
        else:
            return super(EmailBackend, self).authenticate(request, username, password)
