from django.db import models
from django.utils import timezone
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
import secrets
from datetime import timedelta
from uuid import uuid1
from django.core.exceptions import PermissionDenied, ObjectDoesNotExist

# Create your models here.

OTP_EXPIRY_MINUTES = 2

class CustomProfileManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not username or not email or not password:
            return f"Missing required field"
        
        email = self.normalize_email(email).lower()
        username = username.strip()

        user = self.model(username=username, email=email, **extra_fields)

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        
        user.authority = 'Lobby'
        
        user.save(using=self._db)
        return user
    

    def update_user_authority(self, admin_user, to_user, authority):
        if not UserProfile.objects.filter(id__iexact=admin_user.id):
            raise PermissionDenied("User cannot alter status")
        
        if not UserProfile.objects.filter(id__iexact=to_user.id):
            raise ObjectDoesNotExist("USer not found")
        
        to_user.authority = authority

    
    def get_userlobby(self):
        users = UserProfile.objects.filter(authority__iexact="Lobby", is_active=True)
        return users ## Paginations will be beter
    
    
    def get_viewers(self):
        users = UserProfile.objects.all(authority__iexact="Viewer", is_active=True)
        return users
    

    def get_analysts(self):
        users = UserProfile.objects.all(authority__iexact="Analyst", is_active=True)
        return users
    

    def get_admins(self):
        users = UserProfile.objects.all(authority__iexact="Admin", is_active=True)
        return users


# Core Data
class UserProfile(AbstractBaseUser):
    AUTHORITY_CHOICES = (
        ('Admin', 'Admin'),
        ('Analyst', 'Analyst'),
        ('Viewer', 'Viewer'),
        ('Lobby', 'Lobby')
    )
    id = models.UUIDField(primary_key=True, default=uuid1)
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField(unique=True)
    
    first_name = models.CharField(max_length=50, null=True, blank=True)
    last_name = models.CharField(max_length=50, null=True, blank=True)
    
    is_active = models.BooleanField(default=False)
    authority = models.CharField(max_length=10, choices=AUTHORITY_CHOICES, default='Lobby')
    
    date_joined = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    date_approved = models.DateTimeField(null=True, blank=True)

    objects = CustomProfileManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email"]

    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"
        ordering = ["id"]

    
    def __str__(self):
        return f"{self.username} userid {self.id}"
    
    def full_name(self):
        return f"{self.first_name or ''} {self.last_name or ''}".strip() or self.username


class OTPVerificationManager(models.Manager):
    def create_otp(self, user, purpose):
        self.filter(user=user).delete()
        return self.create(user=user, otp=self._generate_otp(), purpose=purpose)

    def get_valid(self, email, purpose):
        record = (
            self.filter(user__email=email, purpose=purpose)
            .select_related("user")
            .order_by("-created_at")
            .first()
        )
        if record is None or record.is_expired():
            return None
        return record

    def purge_expired(self):
        cutoff = timezone.now() - timedelta(minutes=OTP_EXPIRY_MINUTES)
        deleted, _ = self.filter(created_at__lt=cutoff).delete()
        return deleted

    @staticmethod
    def _generate_otp():
        return f"{secrets.randbelow(900_000) + 100_000:06d}"
    


class OTPVerification(models.Model):
    PURPOSECHOICES = (
        ('signup', 'signup'),
        ('deactivate', 'deactivate'),
        ('reactivate', 'reactivate'),
        ('password', 'password'), # Password is for both password changes logged in and loggedout ones as there there will not be a mixup between them
        ('email', 'email')
    )

    user = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name="otps",
    )
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    purpose = models.CharField(choices=PURPOSECHOICES, null=False, blank=False)

    objects = OTPVerificationManager()

    class Meta:
        verbose_name = "OTP Verification"
        verbose_name_plural = "OTP Verifications"
        ordering = ["-created_at"]

    def __str__(self):
        return f"OTP for {self.user.email}"

    def is_expired(self) -> bool:
        return timezone.now() > self.created_at + timedelta(minutes=OTP_EXPIRY_MINUTES)



# Meta data
