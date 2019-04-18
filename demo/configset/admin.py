from django.contrib import admin
from configset.models import GlobalPreferences


class GlobalPreferencesAdmin(admin.ModelAdmin):
    list_display = ('key', 'value', 'display_name', 'to_display')


admin.site.register(GlobalPreferences, GlobalPreferencesAdmin)
