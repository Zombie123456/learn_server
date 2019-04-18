from django.db import models
from django.core.validators import RegexValidator
from django.contrib.auth.models import User, Group


STATUS_OPTIONS = (
    (0, 'Rejected'),
    (1, 'Active'),
    (2, 'Inactive'),
    (3, 'Pending')
)


AlipayCode_STATUS_OPTIONS = (
    (0, 'Inactive'),
    (1, 'Active'),
)


class Member(models.Model):
    '''
    @class Member
    @brief
        Member model class
    '''

    user = models.OneToOneField(User,
                                null=True, blank=True,
                                related_name='member_user',
                                on_delete=models.SET_NULL)
    username = models.CharField(unique=True,
                                null=True, blank=False,
                                max_length=100, validators=[RegexValidator(
                                    regex='^[a-zA-Z0-9][a-zA-Z0-9_\-]+$',
                                    message='Username should contain Alphanumeric, _ or - and should start with letter or digit')])
    phone = models.CharField(max_length=50, blank=True, null=True, unique=True,
                             validators=[RegexValidator(
                                 regex='^(13[0-9]|14[579]|15[0-3,5-9]|16[6]|17[0135678]|18[0-9]|19[89])\\d{8}$',
                                 message='Phone number not allowd'
                             )])
    memo = models.TextField(null=True, blank=True)

    status = models.IntegerField(default=1,
                                 null=True, blank=True,
                                 choices=STATUS_OPTIONS)
    register_ip = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now=False, auto_now_add=True,
                                      db_index=True)
    updated_at = models.DateTimeField(auto_now=True, auto_now_add=False,
                                      null=True, blank=True)
    updated_by = models.ForeignKey(User,
                                   null=True, blank=True,
                                   related_name='member_updated_by',
                                   on_delete=models.SET_NULL)
    is_logged_in = models.BooleanField(default=False)
    loggedin_ip = models.CharField(max_length=50, blank=True, null=True)

    class Meta:
        db_table = 'account_member'
        permissions = (('list_member', 'Can list member'),)

    def __str__(self):
        return self.username


class AlipayAccount(models.Model):
    name = models.CharField(max_length=50, blank=True, null=True)
    accesskeyid = models.CharField(max_length=50, blank=True, null=True)
    secret_key = models.CharField(max_length=50, blank=True, null=True)
    status = models.IntegerField(default=1, null=True, blank=True,
                                 choices=AlipayCode_STATUS_OPTIONS)
    sign_name = models.CharField(max_length=50, blank=True, null=True)
    template_code = models.CharField(max_length=50, blank=True, null=True)
    expired_in = models.IntegerField(null=True, blank=True)

    def __str__(self):
        return self.name


class AlipayCode(models.Model):
    phone = models.CharField(max_length=50, blank=True, null=True, unique=True,
                             validators=[RegexValidator(
                                 regex='^(13[0-9]|14[579]|15[0-3,5-9]|16[6]|17[0135678]|18[0-9]|19[89])\\d{8}$',
                                 message='Phone number not allowd'
                             )])
    code = models.CharField(max_length=10, blank=True, null=True)
    status = models.IntegerField(default=1, null=True, blank=True,
                                 choices=AlipayCode_STATUS_OPTIONS)
    alipay_account = models.ForeignKey(AlipayAccount,
                                       null=True, blank=True,
                                       on_delete=models.SET_NULL)

