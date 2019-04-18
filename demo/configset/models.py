from django.db import models
from django.core.validators import RegexValidator
from django.utils.translation import ugettext as _


class GlobalPreferences(models.Model):

    key = models.CharField(max_length=50, unique=True,
                           validators=[RegexValidator(
                               regex='^[a-z\d]+[a-z\d_]*[a-z\d]+$',
                               message=_('Key should be in snake case'))])
    value = models.TextField(blank=True)
    display_name = models.CharField(max_length=255)
    to_display = models.BooleanField(default=True)

    class Meta:
        db_table = 'configsettings_globalpreferences'

    def __str__(self):
        return self.key
