from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.db.models import Q
from UserAuth.models import UserProfile, OTPVerification
import jwt
from UserAuth.exceptions import UserNotFound
from django.conf import settings
import uuid



class SignupSerializer(serializers.Serializer):
    username = serializers.CharField(min_length=4, max_length=100, required=True)
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=100, required=False)
    last_name = serializers.CharField(max_length=100, required=False)
    password = serializers.CharField(min_length=8, max_length=15, write_only=True, validators=[validate_password])

    def validate_username(self, username):
        username = username.strip()
        if UserProfile.objects.filter(username__iexact=username).exists():
            raise serializers.ValidationError("Username Taken")
        return username

    def validate_email(self, email):
        email = email.strip().lower()
        if UserProfile.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError("Account with Email exists")
        return email


class OTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    purpose = serializers.ChoiceField(choices=[
        "signup",
        "deactivate",
        'reactivate',
        'password', # Reset
        'email'
    ])
    otp = serializers.CharField(min_length=6, max_length=6)

    def validate(self, data):
        email = data.get("email").strip().lower()
        print(email)
        otp_input = data.get("otp").strip()
        purpose = data.get("purpose")
        
        user = UserProfile.objects.filter(email__iexact=email).first()
        if not user:
            raise serializers.ValidationError({"detail": "Account with this email does not exist"})

        if not otp_input.isdigit():
            raise serializers.ValidationError("OTP is inappropriate")

        otp_record = OTPVerification.objects.filter(
            user=user,
            otp__iexact=otp_input,
            purpose=purpose
        ).first()

        if not otp_record:
            raise serializers.ValidationError("Invalid or expired OTP")

        data["user"] = user
        data["otp_record"] = otp_record
        return data
    

class OTPResendSerializer(serializers.Serializer):
    email = serializers.EmailField()
    purpose = serializers.ChoiceField(choices=[
        "signup",
        "deactivate",
        'reactivate',
        'password', # Reset
        'email'
    ])

    def validate(self, data):
        email = data.get("email").strip().lower()
        purpose = data.get("purpose")

        try:
            user = UserProfile.objects.get(email__iexact=email)
        except UserProfile.DoesNotExist:
            raise serializers.ValidationError("Invalid credential")
        
        if purpose in ["signup", "reactivate"]:
            if user.is_active :
                raise serializers.ValidationError("User is alredy active")
            
        elif purpose == "deactivate":
            if user.is_active == False:
                raise serializers.ValidationError("User is alredy deactivated")
            
        elif purpose == "email":
            if not user.is_active:
                raise serializers.ValidationError("Inactive users cannot reset password")

        data["user"] = user
        return data


class LoginSerializer(serializers.Serializer):
    username_email = serializers.CharField(max_length=150, required=True, write_only=True)
    password = serializers.CharField(min_length=8, max_length=15, required=True, write_only=True)

    def validate(self, data):
        identifier = data.get("username_email").strip()
        password = data.get("password")

        user = UserProfile.objects.filter(
            Q(email__iexact=identifier.lower()) |
            Q(username__iexact=identifier)
        ).first()

        if not user:
            raise serializers.ValidationError("Invalid Credentials")

        if not user.check_password(password):
            raise serializers.ValidationError("Invalid Credentials")
        
        if not user.is_active:
            raise serializers.ValidationError("User is inactive")

        data["user"] = user
        return data


class PasswordResetSerializer(serializers.Serializer):
    username_email = serializers.CharField()

    def validate(self, data):
        identifier = data.get("username_email").strip()

        user = UserProfile.objects.filter(
            Q(email__iexact=identifier.lower()) |
            Q(username__iexact=identifier)
        ).first()

        if not user:
            raise serializers.ValidationError("Invalid Credentials")
        
        data["email"] = user.email
        data["user"] = user

        return data


class PasswordResetConformationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(min_length=6, max_length=6)
    new_password = serializers.CharField(min_length=8, max_length=15, validators=[validate_password])

    def validate(self, data):
        email = data.get("email").strip().lower()
        otp = data.get("otp").strip()
        new_password = data.get("new_password")

        if not otp.isdigit():
            raise serializers.ValidationError("OTP is inappropriate")

        otp = OTPVerification.objects.filter(
            email__iexact=email,
            otp=otp,
            puorpose="password"
        ).first()

        if not otp:
            raise serializers.ValidationError("Invalid or expired OTP")

        validate_password(new_password)

        data["email"] = email
        data["otp"] = otp
        return data


class CoreProfileUpdateSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=100, required=False)
    last_name = serializers.CharField(max_length=100, required=False)



class AuthenticatedPasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(min_length=8, max_length=15, required=True)
    new_password = serializers.CharField(min_length=8, max_length=15, required=True)

    def validate(self, data):
        user = self.context.get("request").user

        old_password = data.get("old_password")
        new_password = data.get("new_password")

        if not user.check_password(old_password):
            raise serializers.ValidationError("Old password is incorrect")

        if old_password == new_password:
            raise serializers.ValidationError("New password cannot be same as old password")

        validate_password(new_password, user=user)

        return data



class EmailChangeSerializer(serializers.Serializer):
    new_email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        user = self.context['request'].user
        new_email = data.get("new_email")
        password = data.get("password")

        if not user.check_password(password):
            raise serializers.ValidationError("Password is incorrect")

        if UserProfile.objects.filter(email__iexact=new_email).exists():
            raise serializers.ValidationError("Email already in use")

        data["user"] = user
        return data


class RefreshAccessTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, data):
        token = data.get("refresh_token")

        if not token or not isinstance(token, str):
            raise serializers.ValidationError("Refresh token not provided")
        
        if len(token) < 20:
            raise serializers.ValidationError("Invalid Token")
        
        parts = token.split(".")
        if len(parts) != 3:
            raise serializers.ValidationError("Invalid token format")
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])

        except jwt.ExpiredSignatureError:
            raise serializers.ValidationError("Refresh token expired")
        
        except jwt.InvalidTokenError:
            raise serializers.ValidationError("Invalid refresh token")

        user_id = payload.get("user_id")
        try:
            user_uuid = uuid.UUID(user_id)
        except (ValueError, TypeError):
            raise serializers.ValidationError("Invalid user ID in token")

        user = UserProfile.objects.filter(id=user_uuid, is_active=True).first()
        if not user:
            raise serializers.ValidationError("User does not exist or is inactive")

        return data


class DeactivateSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8, max_length=15)

    def validate(self, data):
        request = self.context.get("request")
        user = request.user

        password = data.get("password")
        
        if user.is_active == False:
            raise serializers.ValidationError("User is deactivated")

        if not user.check_password(password):
            raise serializers.ValidationError("Incorrect password.")

        data["user"] = user
        return data

class DeactivateOtpVerificationSerializer(serializers.Serializer):
    otp = serializers.CharField(min_length=6, max_length=6)

    def validate(self, data):
        request = self.context.get("request")
        user = request.user


        otp = data.get("password")

        try:
            otp_record = OTPVerification.objects.get(user=user)
        except serializers.ValidationError:
            raise serializers.ValidationError("User never demanded a otp")
        
        return data
    

class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, data):
        token = data.get("refresh_token")

        if not token or not isinstance(token, str):
            raise serializers.ValidationError("Refresh token not provided")
        
        if len(token) < 20:
            raise serializers.ValidationError("Invalid Token")
        
        parts = token.split(".")
        if len(parts) != 3:
            raise serializers.ValidationError("Invalid token format")
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])

        except jwt.ExpiredSignatureError:
            raise serializers.ValidationError("Refresh token expired")
        
        except jwt.InvalidTokenError:
            raise serializers.ValidationError("Invalid refresh token")

        user_id = payload.get("user_id")
        try:
            user_uuid = uuid.UUID(user_id)
        except (ValueError, TypeError):
            raise serializers.ValidationError("Invalid user ID in token")

        user = UserProfile.objects.filter(id=user_uuid, is_active=True).first()
        if not user:
            raise serializers.ValidationError("User does not exist or is inactive")

        return data
    

class ReactivateRequestSeializer(serializers.Serializer):
    username_email = serializers.CharField()
    password = serializers.CharField(min_length=8, max_length=15)

    def validate(self, data):
        identifier = data.get("username_email").strip()
        password = data.get("password")

        user = UserProfile.objects.filter(
            Q(email__iexact=identifier.lower()) |
            Q(username__iexact=identifier)
        ).first()

        if not user:
            raise serializers.ValidationError("Invalid Credentials")

        if not user.check_password(password):
            raise serializers.ValidationError("Invalid Credentials")
        
        if user.is_active:
            raise serializers.ValidationError("User is alredy acitve")

        data["user"] = user
        return data
    

class UseProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['id', 'username', 'email', 'first_name', 'last_name']


class AuthoritySerializer(serializers.Serializer):
    userid = serializers.CharField(max_length=100)
    authority = serializers.CharField(min_length=3, max_length=10)

    AUTHORITY_CHOICES = ["Admin", "Viewer", "Analyst", "Lobby"]

    def validate(self, data):
        to_userid = data.get("userid")
        authority = data.get("authority")

        if authority not in self.AUTHORITY_CHOICES:
            raise serializers.ValidationError(
                {"error": "Invalid authority. There is no such access level"}
            )

        try:
            to_user = UserProfile.objects.get(id__iexact=to_userid)
        except UserProfile.DoesNotExist:
            raise serializers.ValidationError({"error": "User not found"})

        data["update_user"] = to_user
        return data



