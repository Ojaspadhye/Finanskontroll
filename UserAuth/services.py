import secrets
import logging
from django.db import transaction
from django.core.mail import send_mail
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from UserAuth.models import UserProfile, OTPVerification
from UserAuth.exceptions import OTPExpiredException, OTPInvalidException, AcountActiveException, UserInactiveException, MissingTokenException, InvalidTokenException
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.exceptions import TokenError
from asgiref.sync import sync_to_async

logger = logging.getLogger(__name__)


async def _send_otp_email(email, otp):
    await sync_to_async(send_mail)(
        subject="Your verification code",
        message=(
            f"Your verification code is: {otp}\n\n"
            f"It expires in 2 minutes.\n"
            "Never share this code with anyone.\n\n"
            "If you didn't request this, you can safely ignore this email."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        fail_silently=False,
    )


async def _resend_otp_services(user, purpose):

    if not user:
        raise ValueError("User missing")
    

    await sync_to_async(OTPVerification.objects.filter(user=user, purpose=purpose).delete())
    new_otp = await sync_to_async(OTPVerification.objects.create_otp(user, purpose=purpose))

    try:
        await _send_otp_email(user.email, new_otp.otp)
    except Exception as e:
        logger.error("Failed to send OTP | user_id=%s error=%s", user.pk, str(e))
        raise

    logger.info("Otp resent | email=%s user_id=%s", user.email, user.pk)
    return user


async def _send_password_reset_email(email):
    await sync_to_async(send_mail)(
        subject="This is about your reset password",
        message=(
            f"This is link for your reset password"
            f"Never share this code with anyone"
            f"If you didn't request this, you can safely ignore this email."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        fail_silently=False,
    )

async def _send_user_coredata_email(email):
    sync_to_async(send_mail)(
        subject="User data Update",
        message=(
            f"Your core data was changed."
            f"If you made the change Ingnore this Mail."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        fail_silently=False,
    )

async def send_password_change_email(user):
    await sync_to_async(send_mail)(
        subject="Your password has been changed",
        message=(
            f"Hi {user.username},\n\n"
            "Your account password has just been changed.\n"
            "If you did not perform this action, please contact support immediately!"
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )

def _send_alterration_email(user, new_authority):
    send_mail(
        subject=f"Your position is alterd to {new_authority}!!",
        message=(
            f"Hi {user.username},\n\n"
            f"Your account is updated to {new_authority} status"
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False

    )

async def sign_up_services(validated_data):

    @sync_to_async
    def create_inactive_user(validated_data):
        with transaction.atomic():
            user = UserProfile.objects.create_user(
                username   = validated_data["username"],
                email      = validated_data["email"],
                password   = validated_data["password"],
                first_name = validated_data.get("first_name") or None,
                last_name  = validated_data.get("last_name") or None,
                is_active  = False,
            )
            otp_record = OTPVerification.objects.create_otp(user, purpose='signup')

            return user, otp_record
        
    user, otp_record = await create_inactive_user(validated_data)

    await _send_otp_email(user.email, otp_record.otp)
    logger.info("Signup OTP dispatched | email=%s user_id=%s", user.email, user.pk)
    return {"message": "User is succesfully created"}


async def signup_resend_otp_services(validated_data):
    user = validated_data["user"]
    purpose = "signup"

    return await _resend_otp_services(user=user, purpose=purpose)


async def reactivate_resend_otp_services(validated_data):
    user = validated_data["user"]
    purpose = "reactivate"

    return await _resend_otp_services(user=user, purpose=purpose)


async def deactivate_resend_otp_services(validated_data):
    user = validated_data["user"]
    purpose = "deactivate"

    return await _resend_otp_services(user=user, purpose=purpose)


async def password_reset_otp_services(validated_data):
    user = validated_data["user"]
    purpose = "password"

    return await _resend_otp_services(user=user, purpose=purpose)


async def validate_otp_activate_services(validated_data):
    user = validated_data["user"]
    otp_input = str(validated_data["otp"]).strip()

    @sync_to_async
    def check_activate_user(user, otp_input):
        otp_record = OTPVerification.objects.filter(
            user=user,
            otp__iexact=otp_input
        ).first()

        if otp_record is None:
            raise OTPExpiredException("OTP expired or invalid")

        db_otp = str(otp_record.otp).strip()

        if not secrets.compare_digest(db_otp, otp_input):
            raise OTPInvalidException("OTP mismatch")


        if user.is_active:
            raise AcountActiveException()

        user.is_active = True
        user.save(update_fields=["is_active"])

        otp_record.delete()
        return {"message": "User is successfully activated"}
    
    result = await check_activate_user(user=user, otp_input=otp_input)
    logger.info("Account activated | email=%s user_id=%s", user.email, user.pk)
    return result


def login_services(validated_data):
    user = validated_data["user"]

    if user.is_active == False:
        raise UserInactiveException()
    
    refresh_token = RefreshToken.for_user(user)
    access_token = refresh_token.access_token

    return {
        "access_token": str(access_token),
        "refresh_token": str(refresh_token)
    }


def logout_services(validated_data):
    refresh_token = validated_data["refresh_token"]

    if not refresh_token:
        raise MissingTokenException()

    try:
        token = RefreshToken(refresh_token)
        jti = token['jti']

        outstanding_token = OutstandingToken.objects.filter(jti=jti).first()

        if not outstanding_token:
            raise InvalidTokenException("Token not recognized")
        
        if BlacklistedToken.objects.filter(token=outstanding_token).exists():
            raise InvalidTokenException("Token already blacklisted")

        token.blacklist()
    except TokenError:
        raise InvalidTokenException("Invalid or expired token")
    

# For now
async def reset_password_services(validated_data):
    email = validated_data["email"]
    user = validated_data["user"]
    await _send_password_reset_email(email)
    logger.info("password reset email dispatched | email=%s user_id=%s", user.email, user.pk)


async def core_data_update_services(validated_data, user):
    if not user:
        raise ValueError("User not found")
    
    
    @sync_to_async
    def update_db(validated_data):
        result = {}

        first_name = validated_data.get("first_name")
        last_name = validated_data.get("last_name")

        if first_name:
            user.first_name = first_name
            result["first_name"] = first_name
        if last_name:
            user.last_name = last_name
            result["last_name"] = last_name

        user.save()

        return result

    result = await update_db(validated_data)

    await _send_user_coredata_email(email=user.email)
    
    return result


def refresh_accesstoken_services(validated_data):
    refresh_token_str = validated_data["refresh_token"]

    try:
        refresh_token = RefreshToken(refresh_token_str)

        new_access_token = str(refresh_token.access_token)
        return {
            "access_token": new_access_token
        }
    
    except TokenError:
        raise ValueError(f"Invalid or expired refresh token")


async def request_deactivation_service(validated_data):
    user = validated_data["user"]
    purpose="deactivate"

    try:
        otp_record =await sync_to_async(OTPVerification.objects.create_otp)(user, purpose=purpose)
        await _send_otp_email(user.email, otp_record.otp)

        return {"message": "OTP sent to your email"}

    except Exception as e:
        raise ValueError(f"Failed to initiate deactivation: {str(e)}")


async def deactivate_services(validated_data):
    user = validated_data["user"]
    otp_record = validated_data["otp_record"]
    
    @sync_to_async
    def deactivate_account(user, otp_record):
        otp_record.delete()
        user.is_active = False
        user.save()
        return {"message": "User successfully deactivated"}

    result = await deactivate_account(user, otp_record)

    logger.info(
        "Account deactivated | email=%s user_id=%s",
        user.email,
        user.pk
    )

    return result


async def request_reactivation_services(validated_data):
    user = validated_data["user"]
    purpose = "reactivate"

    try:
        create_otp = sync_to_async(OTPVerification.objects.create_otp)
        otp_record = await create_otp(user, purpose=purpose)

        await _send_otp_email(user.email, otp_record.otp)

        return {"message": "OTP sent to your email"}
    
    except Exception:
        raise ValueError(f"Failed to initiate reactivation")


async def reactivate_account_services(validated_data):
    user = validated_data["user"]
    otp_record = validated_data["otp_record"]

    @sync_to_async
    def reactivate_account(user, otp_record):
        user.is_active=True
        otp_record.delete()
        user.save(update_fields=["is_active"])

    await reactivate_account(user, otp_record)

    logger.info(
        "Account activated | email=%s user_id=%s",
        user.email,
        user.pk
    )
    
    return {"message": "User is reactivated"}



async def email_change_service(validated_data):
    user = validated_data["user"]
    new_email = validated_data["new_email"]

    otp_record =await sync_to_async(OTPVerification.objects.create_otp(
        user=user,
        purpose="email"
    ))

    _send_otp_email(user.email, otp=otp_record.otp)

    return {
        "message": f"OTP sent to {new_email}",
    }


def give_authority(validated_data):
    user = validated_data.get("update_user")
    authority = validated_data.get("authority")

    valid_roles = ["Lobby", "Viewer", "Analyst", "Admin"]
    if authority not in valid_roles:
        raise ValueError(f"Invalid authority: {authority}")

    user.authority = authority
    user.save()
    _send_alterration_email(user, authority)

    return {"message": "Change is successful!"}