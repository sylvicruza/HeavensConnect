
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.utils.text import slugify


class AdminUser(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('finance', 'Finance'),
        ('viewer', 'Viewer'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='admin_profile')
    full_name = models.CharField(max_length=255, unique=True)  # Unique & required
    email = models.EmailField(unique=True)  # ✅ Added email
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    phone_number = models.CharField(max_length=15, unique=True)  # Unique & required
    last_login_at = models.DateTimeField(auto_now=True)
    fcm_token = models.CharField(max_length=255, blank=True, null=True)

    def delete(self, *args, **kwargs):
        user = self.user
        super().delete(*args, **kwargs)
        user.delete()

    def __str__(self):
        return self.full_name


class Member(models.Model):
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('deceased', 'Deceased')
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='member_profile', null=True, blank=True)
    full_name = models.CharField(max_length=255, unique=True)  # Unique & required
    email = models.EmailField(unique=True)  # NOW compulsory and unique
    phone_number = models.CharField(max_length=15, unique=True)  # Unique & required
    member_id = models.CharField(max_length=30, unique=True, blank=True)
    profile_picture = models.ImageField(upload_to='profiles/', blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    joined_date = models.DateField(auto_now_add=True)
    address = models.TextField(blank=True, null=True)
    fcm_token = models.CharField(max_length=255, blank=True, null=True)

    def save(self, *args, **kwargs):
        # Generate member_id
        if not self.member_id:
            today = timezone.now().date()
            count_today = Member.objects.filter(joined_date=today).count() + 1
            date_str = today.strftime('%Y%m%d')
            self.member_id = f"MBR-{date_str}-{str(count_today).zfill(4)}"

        # Create User if not already linked
        if not self.user:
            username_base = slugify(self.full_name)
            username = username_base
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{username_base}{counter}"
                counter += 1

            new_user = User.objects.create_user(
                username=username,
                password=self.phone_number,
                email=self.email
            )
            new_user.first_name = self.full_name  # optional
            new_user.save()
            self.user = new_user

        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        user = self.user
        super().delete(*args, **kwargs)
        user.delete()

    def __str__(self):
        return self.full_name



class PendingMember(models.Model):
    STATUS_CHOICES = [('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected')]

    full_name = models.CharField(max_length=255)
    email = models.EmailField(blank=True, null=True)
    phone_number = models.CharField(max_length=15)
    address = models.TextField(blank=True, null=True)
    profile_picture = models.ImageField(upload_to='pending_profiles/', blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)


class Contribution(models.Model):
    PAYMENT_METHODS = [
        ('cash', 'Cash'),
        ('transfer', 'Transfer')
    ]
    STATUS = [
        ('pending', 'Pending'),
        ('received', 'Received'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
    ]

    member = models.ForeignKey(Member, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    month = models.IntegerField()
    year = models.IntegerField()
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHODS)
    status = models.CharField(max_length=20, choices=STATUS, default='pending')
    transaction_ref = models.CharField(max_length=100, blank=True, null=True)
    proof_of_payment = models.ImageField(upload_to='contribution_proofs/', blank=True, null=True)
    rejection_reason = models.TextField(blank=True, null=True)
    recorded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.member.full_name} - {self.amount} ({self.get_status_display()})"


class WelfareRequest(models.Model):
    CATEGORY = [
        ('school_fees', 'School Fees'),
        ('marriage', 'Marriage'),
        ('funeral', 'Funeral'),
        ('job_loss', 'Job Loss'),
        ('medical', 'Medical'),
        ('baby_dedication', 'Baby Dedication'),
        ('food', 'Food'),
        ('rent', 'House Rent'),
        ('others', 'Others'),
    ]
    STATUS = [
        ('pending', 'Pending'),
        ('under_review', 'Under Review'),  # New status added
        ('approved', 'Approved'),
        ('declined', 'Declined'),
        ('paid', 'Paid'),
    ]

    member = models.ForeignKey(Member, on_delete=models.CASCADE)
    category = models.CharField(max_length=50, choices=CATEGORY)
    description = models.TextField()
    amount_requested = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    attachment = models.FileField(upload_to='welfare_attachments/', blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS, default='pending')
    admin_note = models.TextField(blank=True, null=True)
    requested_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(blank=True, null=True)

class Disbursement(models.Model):
    CATEGORY = WelfareRequest.CATEGORY  # Reuse categories

    member = models.ForeignKey(Member, on_delete=models.SET_NULL, null=True, blank=True)
    request = models.ForeignKey(WelfareRequest, on_delete=models.SET_NULL, null=True, blank=True)

    recipient_name = models.CharField(max_length=255, blank=True, null=True)
    recipient_phone = models.CharField(max_length=20, blank=True, null=True)

    category = models.CharField(max_length=50, choices=CATEGORY, blank=True, null=True)
    description = models.TextField(blank=True, null=True)

    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=20, choices=Contribution.PAYMENT_METHODS)

    attachment = models.FileField(upload_to='disbursement_receipts/', blank=True, null=True)

    disbursed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    disbursed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        if self.member:
            return f"{self.member.full_name} - £{self.amount}"
        return f"{self.recipient_name or 'Unregistered Recipient'} - £{self.amount}"


class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=200)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.title} - {self.user.username}"


class SystemSetting(models.Model):
    key = models.CharField(max_length=50, unique=True)
    value = models.TextField()
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.key
