
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import MemberViewSet, ContributionViewSet, WelfareRequestViewSet, DisbursementViewSet, AdminUserViewSet, \
    MemberProfileView, ForgotPasswordView, ResetPasswordView, ChangePasswordView, AdminDashboardView, \
    PendingMemberViewSet, PendingRecordsView, send_verification_code, verify_email_code, RequestAccountStatementView, \
    NotificationViewSet, save_fcm_token, FinanceSummaryView, FinanceTransactionsView, ExportFinanceReportView, \
    SystemSettingViewSet

router = DefaultRouter()
router.register(r'members', MemberViewSet)
router.register(r'contributions', ContributionViewSet)
router.register(r'welfare-requests', WelfareRequestViewSet)
router.register(r'disbursements', DisbursementViewSet)
router.register(r'admin-users', AdminUserViewSet)
router.register(r'pending-members', PendingMemberViewSet)
router.register(r'notifications', NotificationViewSet, basename='notification')
router.register(r'settings', SystemSettingViewSet, basename='settings')


urlpatterns = [
    path('api/', include(router.urls)),
    path('api/member/profile/', MemberProfileView.as_view(), name='member_profile'),
    path('api/forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('api/reset-password/', ResetPasswordView.as_view(), name='reset_password'),
    path('api/change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('api/admin/dashboard/', AdminDashboardView.as_view(), name='admin_dashboard'),
    path('api/pending-records/', PendingRecordsView.as_view(), name='pending-records'),
    path('api/auth/send-verification-code/', send_verification_code),
    path('api/auth/verify-email-code/', verify_email_code),
    path('api/member/request-statement/', RequestAccountStatementView.as_view(), name='request_account_statement'),
    path('api/save-fcm-token/', save_fcm_token),
    path('api/finance/summary/', FinanceSummaryView.as_view(), name='finance-summary'),
    path('api/finance/transactions/', FinanceTransactionsView.as_view(), name='finance-transactions'),
    path('api/finance/export/', ExportFinanceReportView.as_view(), name='finance-export'),

]
