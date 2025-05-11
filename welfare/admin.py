from django.contrib import admin

from welfare.models import Member, PendingMember, AdminUser, Contribution, WelfareRequest, Disbursement

# Register your models here.
admin.site.register(Member)
admin.site.register(PendingMember)
admin.site.register(AdminUser)
admin.site.register(Contribution)
admin.site.register(WelfareRequest)
admin.site.register(Disbursement)
