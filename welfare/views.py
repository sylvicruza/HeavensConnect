from django.db.models import Sum
from rest_framework import viewsets, permissions, filters
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated,BasePermission, SAFE_METHODS
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status
from django.utils.timezone import now
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .models import Member, Contribution, WelfareRequest, Disbursement, AdminUser, PendingMember, Notification, \
    SystemSetting
from .serializers import MemberSerializer, ContributionSerializer, WelfareRequestSerializer, DisbursementSerializer, \
    AdminUserSerializer, CustomTokenObtainPairSerializer, PendingMemberSerializer, NotificationSerializer, \
    SystemSettingSerializer
from .utils import create_admin_user, send_membership_email, send_password_reset_email, send_verification_code_email, \
    generate_statement_pdf, send_statement_email, create_notification, send_finance_report, generate_finance_report_pdf, \
    generate_finance_report_excel
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.core.cache import cache
from datetime import datetime
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import ValidationError
from django.db.models import Sum
from django.db.models.functions import TruncMonth
from django.utils.dateparse import parse_date
from django.conf import settings
import uuid
from calendar import month_name



class IsAdminOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.method in permissions.SAFE_METHODS or request.user and request.user.is_staff

class AdminDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        total_contributions = Contribution.objects.filter(status='verified').aggregate(Sum('amount'))['amount__sum'] or 0
        total_expenses = Disbursement.objects.aggregate(Sum('amount'))['amount__sum'] or 0
        member_count = Member.objects.count()
        contribution_count = Contribution.objects.count()
        request_count = WelfareRequest.objects.count()
        disbursement_count = Disbursement.objects.count()
        admin_user_count = AdminUser.objects.count()

        # 👇 Updated pending counts
        pending_members = PendingMember.objects.count()
        pending_contributions = Contribution.objects.filter(status='pending').count()
        pending_welfare_requests = WelfareRequest.objects.filter(status='pending').count()
        total_pending = pending_members + pending_contributions + pending_welfare_requests

        return Response({
            "balance": total_contributions - total_expenses,
            "income": total_contributions,
            "expenses": total_expenses,
            "members": member_count,
            "contributions": contribution_count,
            "welfare_requests": request_count,
            "disbursements": disbursement_count,
            "pending_requests": total_pending,  # total count for badge
            "pending_breakdown": {
                "pending_members": pending_members,
                "pending_contributions": pending_contributions,
                "pending_welfare_requests": pending_welfare_requests,
            },
            "admin_users": admin_user_count
        })

class MemberProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            member = Member.objects.get(user=request.user)
            serializer = MemberSerializer(member)
            return Response(serializer.data)
        except Member.DoesNotExist:
            return Response({'detail': 'Member profile not found.'}, status=404)

    def put(self, request):
        try:
            member = Member.objects.get(user=request.user)
            serializer = MemberSerializer(member, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)
        except Member.DoesNotExist:
            return Response({'detail': 'Member profile not found.'}, status=404)


class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        identifier = request.data.get('identifier')
        user = User.objects.filter(username=identifier).first() or User.objects.filter(email=identifier).first()

        if not user:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        frontend_base = request.headers.get('X-Frontend-URL', getattr(settings, 'FRONTEND_RESET_URL', 'https://heavensconnect-83e8c.web.app')).rstrip('/')
        reset_link = f"{frontend_base}/reset-password?uid={uidb64}&token={token}"

        send_password_reset_email(user.email, user.username, reset_link)

        return Response({'message': 'Password reset link sent to your email.'})


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        uidb64 = request.data.get('uid')
        token = request.data.get('token')
        new_password = request.data.get('new_password')

        if not all([uidb64, token, new_password]):
            return Response({'detail': 'Missing required fields.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError):
            return Response({'detail': 'Invalid reset link.'}, status=status.HTTP_400_BAD_REQUEST)

        if not default_token_generator.check_token(user, token):
            return Response({'detail': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password reset successful.'})

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')

        if not request.user.check_password(current_password):
            return Response({'detail': 'Current password incorrect.'}, status=400)

        request.user.set_password(new_password)
        request.user.save()
        return Response({'message': 'Password changed successfully.'})

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            token = RefreshToken(refresh_token)
            token.blacklist()  # blacklist the token
            return Response({'message': 'Logged out successfully.'})
        except Exception as e:
            return Response({'detail': 'Invalid token.'}, status=400)

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

class AdminUserViewSet(viewsets.ModelViewSet):
    queryset = AdminUser.objects.all()
    serializer_class = AdminUserSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['post'])
    def create_admin(self, request):
        full_name = request.data.get('full_name')
        email = request.data.get('email')
        phone_number = request.data.get('phone_number')
        role = request.data.get('role')

        if not full_name or not phone_number or not role or not email:
            return Response(
                {"detail": "Full name, email, phone number, and role are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if role == 'viewer':
            return Response(
                {"detail": "You cannot create a Viewer. Only Admin or Finance roles are allowed."},
                status=status.HTTP_400_BAD_REQUEST
            )

        admin_profile = create_admin_user(full_name, phone_number, role, email)

        # Send approval email
        send_membership_email(
            subject='Membership Creation',
            to_email=admin_profile.email,
            context={
                'title': 'Membership Creation',
                'message': f'Dear {admin_profile.full_name}, your membership has been created.',
                'username': admin_profile.user.username,
                'password': admin_profile.phone_number,  # If generated for them
            }
        )

        create_notification(
            admin_profile.user,
            "Membership Creation",
            "Your membership account has been created. Welcome!"
        )

        return Response(AdminUserSerializer(admin_profile).data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['get', 'patch'], url_path='my-profile')
    def my_profile(self, request):
        try:
            admin = AdminUser.objects.get(user=request.user)

            if request.method == 'GET':
                serializer = self.get_serializer(admin)
                return Response(serializer.data)

            if request.method == 'PATCH':
                # Allow updating only certain fields
                allowed_fields = ['full_name', 'email', 'phone_number']
                data = {key: value for key, value in request.data.items() if key in allowed_fields}
                serializer = self.get_serializer(admin, data=data, partial=True)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                return Response(serializer.data)

        except AdminUser.DoesNotExist:
            return Response({'detail': 'Admin profile not found.'}, status=404)

class MemberViewSet(viewsets.ModelViewSet):
    queryset = Member.objects.all()
    serializer_class = MemberSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ['full_name', 'phone_number']

    @action(detail=True, methods=['get'])
    def dashboard(self, request, pk=None):
        member = self.get_object()

        # Balance
        balance = Contribution.objects.filter(member=member, status='verified') \
                      .aggregate(total=Sum('amount'))['total'] or 0

        # Requests count
        requests_count = WelfareRequest.objects.filter(member=member).count()

        # Total spent (disbursements)
        total_spent = Disbursement.objects.filter(member=member) \
                          .aggregate(total=Sum('amount'))['total'] or 0

        # Contributions timeline (grouped by year & month)
        contributions = Contribution.objects.filter(member=member, status='verified') \
            .values('year', 'month') \
            .annotate(total=Sum('amount')) \
            .order_by('year', 'month')

        # Requests timeline (corrected to amount_requested)
        requests = WelfareRequest.objects.filter(member=member) \
            .values('requested_at', 'amount_requested') \
            .order_by('requested_at')

        return Response({
            'balance': balance,
            'requests_count': requests_count,
            'total_spent': total_spent,
            'contributions': list(contributions),
            'requests': list(requests),
        })

class PendingMemberViewSet(viewsets.ModelViewSet):
    queryset = PendingMember.objects.all()
    serializer_class = PendingMemberSerializer

    def get_permissions(self):
        if self.action == 'create':
            return [AllowAny()]  # Allow unauthenticated users to create
        return [IsAuthenticated()]  # Require authentication for listing, approving, rejecting, etc.

    def create(self, request, *args, **kwargs):
        mutable_data = request.data.copy()
        if mutable_data.get('profile_picture') == '':
            mutable_data['profile_picture'] = None

        email = mutable_data.get('email')
        phone = mutable_data.get('phone_number')
        full_name = mutable_data.get('full_name')

        # 🚨 Check if email or phone or full_name already exists in approved members
        if Member.objects.filter(email=email).exists():
            raise ValidationError({'email': 'This email is already registered.'})
        if Member.objects.filter(phone_number=phone).exists():
            raise ValidationError({'phone_number': 'This phone number is already registered.'})
        if Member.objects.filter(full_name__iexact=full_name).exists():
            raise ValidationError({'full_name': 'This full name is already registered.'})

        # 🚨 Also check if already pending
        if PendingMember.objects.filter(email=email).exists():
            raise ValidationError({'email': 'This email is already pending approval.'})
        if PendingMember.objects.filter(phone_number=phone).exists():
            raise ValidationError({'phone_number': 'This phone number is already pending approval.'})
        if PendingMember.objects.filter(full_name__iexact=full_name).exists():
            raise ValidationError({'full_name': 'This full name is already pending approval.'})

        # ✅ Proceed to save
        serializer = self.get_serializer(data=mutable_data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    # Approve action
    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        pending_member = self.get_object()

        # Create the approved Member record
        member = Member.objects.create(
            full_name=pending_member.full_name,
            email=pending_member.email,
            phone_number=pending_member.phone_number,
            address=pending_member.address,
            profile_picture=pending_member.profile_picture
        )

        # Delete the pending member
        pending_member.delete()

        # Send approval email
        send_membership_email(
            subject='Membership Approved',
            to_email=member.email,
            context={
                'title': 'Membership Approved',
                'message': f'Dear {member.full_name}, your membership has been approved.',
                'username': member.user.username,
                'password': member.phone_number,  # If generated for them
            }
        )

        create_notification(
            member.user,
            "Membership Approved",
            "Your membership request has been approved. Welcome!"
        )

        return Response({'detail': 'Member approved successfully.'})

    # Reject action
    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        pending_member = self.get_object()
        reason = request.data.get('reason')

        if not reason:
            return Response({'detail': 'Rejection reason is required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Send rejection email
        send_membership_email(
            subject='Membership Rejected',
            to_email=pending_member.email,
            context={
                'title': 'Membership Request Rejected',
                'message': f'Dear {pending_member.full_name}, your membership request was rejected.<br><strong>Reason:</strong> {reason}',
                'current_year': datetime.now().year,
            }
        )


        pending_member.delete()

        return Response({'detail': 'Member rejected with reason.'})

class ContributionViewSet(viewsets.ModelViewSet):
    queryset = Contribution.objects.all().order_by('-created_at')
    serializer_class = ContributionSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]  # Add SearchFilter
    filterset_fields = ['status', 'member', 'payment_method', 'month', 'year']
    search_fields = ['member__full_name']  # Enable search by member full name


    def perform_create(self, serializer):
        serializer.save(recorded_by=self.request.user)

    def create(self, request, *args, **kwargs):
        number_of_months = int(request.data.get('number_of_months', 1))
        base_month = int(request.data.get('month', now().month))
        base_year = int(request.data.get('year', now().year))

        # Validate and parse the total amount
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        total_amount = float(serializer.validated_data['amount'])
        if number_of_months < 1:
            return Response({'detail': 'Number of months must be at least 1.'}, status=status.HTTP_400_BAD_REQUEST)

        monthly_amount = round(total_amount / number_of_months, 2)  # Round to 2 decimal places

        shared_batch_id = uuid.uuid4()
        contributions = []
        month = base_month
        year = base_year

        for i in range(number_of_months):
            contribution_data = serializer.validated_data.copy()
            contribution = Contribution.objects.create(
                member=contribution_data['member'],
                amount=monthly_amount,
                payment_method=contribution_data['payment_method'],
                transaction_ref=contribution_data.get('transaction_ref', None),
                proof_of_payment=contribution_data.get('proof_of_payment', None),
                status=contribution_data.get('status', 'pending'),
                recorded_by=request.user,
                month=month,
                year=year,
                batch_id=shared_batch_id,
            )
            contributions.append(contribution)

            # Increment month with year rollover
            month += 1
            if month > 12:
                month = 1
                year += 1

        return Response({'detail': f'{number_of_months} contribution(s) created successfully.'},
                        status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['get'], url_path='my')
    def my_contributions(self, request):
        user = request.user
        if hasattr(user, 'member_profile'):
            contributions = Contribution.objects.filter(member=user.member_profile)
            filter_backends = DjangoFilterBackend()
            filtered_qs = filter_backends.filter_queryset(request, contributions, self)
            page = self.paginate_queryset(filtered_qs)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)
            serializer = self.get_serializer(filtered_qs, many=True)
            return Response(serializer.data)
        return Response({'detail': 'You are not a member.'}, status=status.HTTP_403_FORBIDDEN)

    @action(detail=False, methods=['get'], url_path='by-username/(?P<username>[^/.]+)')
    def contributions_by_username(self, request, username=None):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        if not hasattr(user, 'member_profile'):
            return Response({'detail': 'This user is not a member.'}, status=status.HTTP_403_FORBIDDEN)

        contributions = Contribution.objects.filter(member=user.member_profile).order_by('-created_at')
        filter_backends = DjangoFilterBackend()
        filtered_qs = filter_backends.filter_queryset(request, contributions, self)
        page = self.paginate_queryset(filtered_qs)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(filtered_qs, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        contribution = self.get_object()
        if contribution.status == 'verified':
            return Response({'detail': 'Contribution already verified.'}, status=status.HTTP_400_BAD_REQUEST)
        contribution.status = 'verified'
        contribution.rejection_reason = ''
        contribution.save()

        # Optionally notify member via email/SMS
        send_membership_email(
            subject='Contribution Verified',
            to_email=contribution.member.email,
            context={
                'title': 'Contribution Verified',
                'message': f'Dear {contribution.member.full_name}, your contribution verified successfully.',
            }
        )
        create_notification(
            contribution.member.user,
            "Contribution Verified",
            f"Your contribution of £{contribution.amount} has been verified."
        )

        return Response({'detail': 'Contribution verified successfully.'})

    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        contribution = self.get_object()
        reason = request.data.get('rejection_reason')
        if not reason:
            return Response({'detail': 'Rejection reason is required.'}, status=status.HTTP_400_BAD_REQUEST)
        contribution.status = 'rejected'
        contribution.rejection_reason = reason
        contribution.save()

        # Optionally notify member via email/SMS
        send_membership_email(
            subject='Contribution Rejected',
            to_email=contribution.member.email,
            context={
                'title': 'Membership Request Rejected',
                'message': f'Dear {contribution.member.full_name}, your contribution was rejected.<br><strong>Reason:</strong> {reason}',
            }
        )

        create_notification(
            contribution.member.user,
            "Contribution Rejected",
            f"Your contribution was rejected. Reason: {reason}"
        )

        return Response({'detail': 'Contribution rejected with reason.'})

    @action(detail=False, methods=['get'], url_path='pending-batches')
    def pending_batches(self, request):
        contributions = Contribution.objects.filter(status='pending')
        grouped = {}

        for c in contributions:
            key = str(c.batch_id)
            if key not in grouped:
                grouped[key] = {
                    'batch_id': key,
                    'member': c.member.id,
                    'member_name': c.member.full_name,
                    'transaction_ref': c.transaction_ref,
                    'proof_of_payment': c.proof_of_payment.url if c.proof_of_payment else None,
                    'total_amount': 0,
                    'months': [],
                    'contribution_ids': [],
                }
            grouped[key]['total_amount'] += float(c.amount)
            grouped[key]['months'].append(f"{month_name[c.month]} {c.year}")
            grouped[key]['contribution_ids'].append(c.id)

        return Response(list(grouped.values()))

    @action(detail=False, methods=['post'], url_path='verify-batch')
    def verify_batch(self, request):
        batch_id = request.data.get('batch_id')
        if not batch_id:
            return Response({'detail': 'Batch ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

        contributions = Contribution.objects.filter(batch_id=batch_id, status='pending')
        if not contributions.exists():
            return Response({'detail': 'No pending contributions for this batch.'}, status=404)

        for c in contributions:
            c.status = 'verified'
            c.rejection_reason = ''
            c.save()

        member = contributions.first().member
        send_membership_email(
            subject='Contribution Verified',
            to_email=member.email,
            context={
                'title': 'Contribution Verified',
                'message': f'Dear {member.full_name}, your contribution of £{sum(c.amount for c in contributions)} has been verified.',
            }
        )
        return Response({'detail': 'Batch verified successfully.'})


class IsAdminOrMemberOwner(BasePermission):
    """
    Admins have full access.
    Members can read, create, and update their own welfare requests.
    """

    def has_permission(self, request, view):
        if request.user.is_staff:
            return True  # Admins can do anything
        if request.method in SAFE_METHODS or request.method == 'POST':
            return request.user.is_authenticated  # Members can read or create
        return True  # Allow object-level checks for update/delete

    def has_object_permission(self, request, view, obj):
        if request.user.is_staff:
            return True  # Admins can modify any request
        # Members can update/delete only their own requests
        return hasattr(request.user, 'member_profile') and obj.member == request.user.member_profile

class WelfareRequestViewSet(viewsets.ModelViewSet):
    queryset = WelfareRequest.objects.all()
    serializer_class = WelfareRequestSerializer
    permission_classes = [IsAuthenticated, IsAdminOrMemberOwner]
    filter_backends = [filters.SearchFilter, DjangoFilterBackend]
    search_fields = ['member__full_name', 'category']
    filterset_fields = ['status', 'category', 'member']

    def perform_create(self, serializer):
        if hasattr(self.request.user, 'member_profile'):
            serializer.save(member=self.request.user.member_profile)
        else:
            raise PermissionDenied("Only members can create welfare requests.")

    @action(detail=False, methods=['get'], url_path='by-username/(?P<username>[^/.]+)')
    def by_username(self, request, username=None):
        try:
            user = User.objects.get(username=username)
            if hasattr(user, 'member_profile'):
                requests = WelfareRequest.objects.filter(member=user.member_profile)
                filter_backends = DjangoFilterBackend()
                filtered_qs = filter_backends.filter_queryset(request, requests, self)
                page = self.paginate_queryset(filtered_qs)
                if page is not None:
                    serializer = self.get_serializer(page, many=True)
                    return self.get_paginated_response(serializer.data)
                serializer = self.get_serializer(filtered_qs, many=True)
                return Response(serializer.data)
            else:
                return Response({'detail': 'User is not a member.'}, status=status.HTTP_403_FORBIDDEN)
        except User.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=['post'], url_path='update-status')
    def update_status(self, request, pk=None):
        welfare_request = self.get_object()
        status_value = request.data.get('status')
        new_note = request.data.get('admin_note', '').strip()

        if status_value not in ['approved', 'declined', 'under_review']:
            return Response({'detail': 'Invalid status.'}, status=status.HTTP_400_BAD_REQUEST)

        previous_note = welfare_request.admin_note or ''

        if new_note:
            admin_name = request.user.adminuser.full_name if hasattr(request.user,
                                                                     'adminuser') else request.user.get_full_name()
            timestamp = timezone.now().strftime('%Y-%m-%d %H:%M')
            formatted_note = f"--- {admin_name} on {timestamp} ---\n{new_note}"
            updated_note = previous_note + ("\n\n" if previous_note else "") + formatted_note
            welfare_request.admin_note = updated_note

        welfare_request.status = status_value
        welfare_request.reviewed_at = timezone.now()
        welfare_request.save()

        send_membership_email(
            subject=f'Welfare Request {status_value.capitalize()}',
            to_email=welfare_request.member.email,
            context={
                'title': f'Welfare Request {status_value.capitalize()}',
                'message': f'Dear {welfare_request.member.full_name}, your welfare request has been {status_value}.',
            }
        )

        create_notification(
            welfare_request.member.user,
            f"Welfare Request {status_value.capitalize()}",
            f"Your welfare request has been {status_value}."
        )

        return Response({'detail': f'Request {status_value} successfully.'})


class DisbursementViewSet(viewsets.ModelViewSet):
    queryset = Disbursement.objects.all()
    serializer_class = DisbursementSerializer
    permission_classes = [IsAuthenticated, IsAdminOrReadOnly]
    filter_backends = [filters.SearchFilter, DjangoFilterBackend]
    search_fields = ['member__full_name']
    filterset_fields = ['payment_method', 'member', 'category']



    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        file = request.FILES.get('attachment')

        # If linked to a WelfareRequest
        request_id = data.get('request')
        if request_id:
            try:
                welfare_request = WelfareRequest.objects.get(pk=request_id)
                data['category'] = welfare_request.category
                data['description'] = welfare_request.description
                data['amount'] = welfare_request.amount_requested
                data['member'] = welfare_request.member.id
            except WelfareRequest.DoesNotExist:
                return Response({'detail': 'Invalid welfare request ID'}, status=400)
        else:
            # Validate required fields for manual disbursement
            required_fields = ['category', 'description', 'amount']
            for field in required_fields:
                if not data.get(field):
                    return Response({'detail': f"'{field}' is required for unlinked disbursement."}, status=400)

        # Assign disbursed_by
        data['disbursed_by'] = request.user.id

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        disbursement = serializer.save()

        # Save attachment manually if provided
        if file:
            disbursement.attachment = file
            disbursement.save()

        return Response(self.get_serializer(disbursement).data, status=status.HTTP_201_CREATED)

class PendingRecordsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        pending_members = PendingMember.objects.all()
        pending_contributions = Contribution.objects.filter(status='pending')
        pending_welfare_requests = WelfareRequest.objects.filter(status='pending')

        return Response({
            "pending_members": PendingMemberSerializer(pending_members, many=True).data,
            "pending_contributions": ContributionSerializer(pending_contributions, many=True).data,
            "pending_welfare_requests": WelfareRequestSerializer(pending_welfare_requests, many=True).data,
        })

@api_view(['POST'])
@permission_classes([AllowAny])
def send_verification_code(request):
    email = request.data.get('email')
    if not email:
        return Response({'detail': 'Email is required'}, status=400)

    # Check if email already exists in approved members
    if Member.objects.filter(email=email).exists():
        return Response({'detail': 'This email is already registered.'}, status=400)

    # Check if email already exists in pending members
    if PendingMember.objects.filter(email=email).exists():
        return Response({'detail': 'This email is already pending approval.'}, status=400)

    code = get_random_string(length=6, allowed_chars='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    cache.set(f'verify_code_{email}', code, timeout=10 * 60)  # valid for 10 mins

    # Use the new utility
    send_verification_code_email(email, code)

    return Response({'detail': 'Verification code sent'}, status=200)


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_email_code(request):
    email = request.data.get('email')
    code = request.data.get('code')

    if not email or not code:
        return Response({'detail': 'Email and code are required'}, status=400)

    cached_code = cache.get(f'verify_code_{email}')
    if cached_code is None:
        return Response({'detail': 'Code expired or not found.'}, status=400)

    if code != cached_code:
        return Response({'detail': 'Invalid verification code.'}, status=400)

    return Response({'detail': 'Email verified successfully.'}, status=200)

class RequestAccountStatementView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from_date = request.data.get('from_date')
        to_date = request.data.get('to_date')
        format_type = request.data.get('format', 'pdf')

        if not from_date or not to_date:
            return Response({'detail': 'From and To dates are required.'}, status=400)

        member = request.user.member_profile
        from_dt = datetime.strptime(from_date, '%Y-%m-%d')
        to_dt = datetime.strptime(to_date, '%Y-%m-%d')

        contributions = Contribution.objects.filter(
            member=member,
            created_at__date__gte=from_dt,
            created_at__date__lte=to_dt,
            status='verified'
        ).order_by('created_at')

        if not contributions.exists():
            return Response({'detail': 'No contributions found for this period.'}, status=404)

        # 1️⃣ Generate PDF or Excel
        if format_type == 'pdf':
            file_path = generate_statement_pdf(member, contributions, from_dt, to_dt)
        else:
            # For now, we'll start with PDF. Excel can be added later if needed.
            return Response({'detail': 'Only PDF format is supported at the moment.'}, status=400)

        # 2️⃣ Email the statement
        send_statement_email(member, file_path, from_dt, to_dt)

        return Response({'detail': 'Your account statement has been sent to your email.'})


class NotificationViewSet(viewsets.ModelViewSet):
    queryset = Notification.objects.all().order_by('-created_at')
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user).order_by('-created_at')

    @action(detail=False, methods=['post'], url_path='mark-read')
    def mark_all_read(self, request):
        Notification.objects.filter(user=request.user, read=False).update(read=True)
        return Response({'detail': 'All notifications marked as read.'})

    @action(detail=False, methods=['get'])
    def unread_count(self, request):
        count = self.get_queryset().filter(read=False).count()
        return Response({'unread': count})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def save_fcm_token(request):
    token = request.data.get('fcm_token')
    if not token:
        return Response({'detail': 'FCM token is required.'}, status=400)

    user = request.user
    if hasattr(user, 'member_profile'):
        user.member_profile.fcm_token = token
        user.member_profile.save()
    elif hasattr(user, 'adminuser'):
        user.adminuser.fcm_token = token
        user.adminuser.save()
    else:
        return Response({'detail': 'No associated profile found.'}, status=400)

    return Response({'detail': 'FCM token saved successfully.'})

class FinanceSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        year = request.GET.get('year')

        income_qs = Contribution.objects.filter(status='verified')
        if year:
            income_qs = income_qs.filter(created_at__year=year)

        income = (income_qs
                  .annotate(month_value=TruncMonth('created_at'))  # avoid "month"
                  .values('month_value')
                  .annotate(total=Sum('amount'))
                  .order_by('month_value'))

        expense_qs = Disbursement.objects.all()
        if year:
            expense_qs = expense_qs.filter(disbursed_at__year=year)

        expenses = (expense_qs
                    .annotate(month_value=TruncMonth('disbursed_at'))
                    .values('month_value')
                    .annotate(total=Sum('amount'))
                    .order_by('month_value'))

        # New total aggregations
        total_income = income_qs.aggregate(total=Sum('amount'))['total'] or 0
        total_expense = expense_qs.aggregate(total=Sum('amount'))['total'] or 0

        return Response({
            'income': list(income),
            'expenses': list(expenses),
            'total_income': total_income,
            'total_expense': total_expense
        })


class FinanceTransactionsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Fetch contributions
        contributions = Contribution.objects.filter(status='verified').values(
            'id', 'amount', 'created_at', 'payment_method'
        )
        contrib_list = [{
            'type': 'income',
            'amount': c['amount'],
            'date': c['created_at'],
            'payment_method': c['payment_method']
        } for c in contributions]

        # Fetch disbursements
        disbursements = Disbursement.objects.all().values(
            'id', 'amount', 'disbursed_at', 'payment_method', 'category'
        )
        disb_list = [{
            'type': 'expense',
            'amount': d['amount'],
            'date': d['disbursed_at'],
            'payment_method': d['payment_method'],
            'category': d['category']
        } for d in disbursements]

        # Combine & sort
        transactions = contrib_list + disb_list
        transactions.sort(key=lambda x: x['date'], reverse=True)

        return Response({'transactions': transactions})

class ExportFinanceReportView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from_date = parse_date(request.data.get('from_date'))
        to_date = parse_date(request.data.get('to_date'))
        export_format = request.data.get('format', 'pdf')

        if not from_date or not to_date:
            return Response({'detail': 'Both from_date and to_date are required.'}, status=400)

        # Use select_related for performance
        contributions = Contribution.objects.select_related('member').filter(
            status='verified',
            created_at__date__range=(from_date, to_date)
        )

        disbursements = Disbursement.objects.select_related('member').filter(
            disbursed_at__date__range=(from_date, to_date)
        )

        transactions = []

        # Process contributions
        for c in contributions:
            transactions.append({
                'type': 'income',
                'amount': c.amount,
                'date': c.created_at,
                'payment_method': c.payment_method,
                'category': 'Contribution',
                'description': f"{c.payment_method.capitalize()} contribution by {c.member.full_name}"
            })

        # Process disbursements
        for d in disbursements:
            recipient = d.member.full_name if d.member else d.recipient_name or "Unregistered Recipient"
            transactions.append({
                'type': 'expense',
                'amount': d.amount,
                'date': d.disbursed_at,
                'payment_method': d.payment_method,
                'category': d.category or "Other",
                'description': f"{d.category.capitalize() if d.category else 'General'} disbursement to {recipient}"
            })

        # Sort by date
        transactions.sort(key=lambda x: x['date'])

        # Trigger the report generator
        send_finance_report(
            request.user.email,
            transactions,
            from_date,
            to_date,
            export_format
        )

        return Response({'detail': 'Your report is being generated and will be emailed shortly.'})

class SystemSettingViewSet(viewsets.ModelViewSet):
    queryset = SystemSetting.objects.all()
    serializer_class = SystemSettingSerializer
    permission_classes = [IsAuthenticated]