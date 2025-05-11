
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Member, Contribution, WelfareRequest, Disbursement, AdminUser, PendingMember, Notification
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        # Force the username to lowercase
        username = attrs.get('username').lower()
        password = attrs.get('password')

        # Try to fetch the user ignoring case sensitivity
        try:
            user_obj = User.objects.get(username__iexact=username)
            username = user_obj.username  # Get the exact casing from the database
        except User.DoesNotExist:
            # Fall back — invalid credentials
            raise serializers.ValidationError({'detail': 'No active account found with the given credentials'})

        # Authenticate with the correct casing username
        user = authenticate(username=username, password=password)
        if not user:
            raise serializers.ValidationError({'detail': 'No active account found with the given credentials'})

        # Set the user so the parent validate() works
        self.user = user

        # Now proceed with JWT token generation
        data = super().validate({'username': username, 'password': password})

        # Attach additional data
        data['user_id'] = user.id
        data['username'] = user.username
        data['email'] = user.email
        data['is_superuser'] = user.is_superuser

        if hasattr(user, 'adminuser'):
            data['user_type'] = 'admin'
            data['role'] = user.adminuser.role
        elif hasattr(user, 'member_profile'):
            data['user_type'] = 'member'
        elif user.is_superuser:
            data['user_type'] = 'superuser'
        else:
            data['user_type'] = 'unknown'

        return data


class AdminUserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = AdminUser
        fields = ['id', 'full_name', 'email', 'phone_number', 'role', 'user', 'username', 'password']
        read_only_fields = ['user']  # We'll set this manually

    def create(self, validated_data):
        username = validated_data.pop('username')
        password = validated_data.pop('password')

        # Create User
        user = User.objects.create_user(
            username=username,
            password=password,
            email=validated_data['email'],
            first_name=validated_data['full_name']
        )

        validated_data['user'] = user
        return super().create(validated_data)


class MemberSerializer(serializers.ModelSerializer):
    profile_picture = serializers.ImageField(max_length=None, use_url=True)
    username = serializers.SerializerMethodField()

    class Meta:
        model = Member
        fields = '__all__'
        read_only_fields = ['member_id', 'user', 'joined_date']

    def get_username(self, obj):
        return obj.user.username if obj.user else None

class PendingMemberSerializer(serializers.ModelSerializer):
    profile_picture = serializers.ImageField(required=False, allow_null=True, use_url=True)

    class Meta:
        model = PendingMember
        fields = '__all__'


    def validate_profile_picture(self, value):
        # Ignore empty strings
        if value == '':
            return None
        return value


class ContributionSerializer(serializers.ModelSerializer):
    member_name = serializers.CharField(source='member.full_name', read_only=True)
    proof_of_payment = serializers.ImageField(required=False)

    class Meta:
        model = Contribution
        fields = '__all__'
        read_only_fields = ['recorded_by', 'status', 'rejection_reason']


class WelfareRequestSerializer(serializers.ModelSerializer):
    member_name = serializers.CharField(source='member.full_name', read_only=True)

    class Meta:
        model = WelfareRequest
        fields = ['id', 'category', 'description', 'amount_requested', 'attachment',
                  'status', 'admin_note', 'requested_at', 'reviewed_at', 'member_name']



class DisbursementSerializer(serializers.ModelSerializer):
    member_name = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Disbursement
        fields = '__all__'

    def get_member_name(self, obj):
        return obj.member.full_name if obj.member else None

    def create(self, validated_data):
        disbursement = super().create(validated_data)

        # If it's tied to a WelfareRequest, update its status
        if disbursement.request:
            disbursement.request.status = 'paid'
            disbursement.request.save(update_fields=['status'])

        return disbursement

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'title', 'message', 'created_at', 'read']



