from django.contrib import admin

from sss.models import Member, AlipayCode, AlipayAccount


class MemberAdmin(admin.ModelAdmin):
    list_display = ('username', 'user', 'status',
                    'is_logged_in', 'updated_by')


class AlipayCodeAdmin(admin.ModelAdmin):
    list_display = ('phone', 'code', 'status')


class AlipayAccountAdmin(admin.ModelAdmin):
    list_display = ('name',)


admin.site.register(Member, MemberAdmin)
admin.site.register(AlipayCode, AlipayCodeAdmin)
admin.site.register(AlipayAccount, AlipayAccountAdmin)
