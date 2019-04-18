from oauth2_provider.models import AccessToken
from rest_framework import permissions
from django.utils.translation import ugettext_lazy as _


def is_member(user):
    return user and user.groups.filter(name='member_grp').exists() and \
                hasattr(user, 'member_user')


class IsMember(permissions.BasePermission):
    message = _('Must be atleast a registered member to access API')

    def has_permission(self, request, view):
        user = request.user

        return is_member(user)
