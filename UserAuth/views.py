from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from UserAuth.serializer import SignupSerializer, OTPVerifySerializer, OTPResendSerializer, LoginSerializer, PasswordResetSerializer, LogoutSerializer, CoreProfileUpdateSerializer, RefreshAccessTokenSerializer, DeactivateSerializer, ReactivateRequestSeializer, AuthenticatedPasswordChangeSerializer, EmailChangeSerializer, UseProfileSerializer, AuthoritySerializer
from UserAuth.services import sign_up_services, validate_otp_activate_services, signup_resend_otp_services, login_services, logout_services, reset_password_services, core_data_update_services, refresh_accesstoken_services, request_deactivation_service, deactivate_services, request_reactivation_services, reactivate_account_services, reactivate_resend_otp_services, deactivate_resend_otp_services, password_reset_otp_services, send_password_change_email, email_change_service, give_authority
import logging
from rest_framework_simplejwt.tokens import RefreshToken
from UserAuth.throttling import SignupThrottle, OTPVerificationThrottle, OTPResendThrottle, LoginThrottle, AnonPasswordChangeThrottle, PasswordChangeThrottle, CoreDataUpdateThrottle, UserRateThrottle, AccessTokenThrottle, AnonRateThrottle, UpdateEmailThrottle
import asyncio
from asgiref.sync import sync_to_async
from decorators import role_requirements
from UserAuth.models import UserProfile
from UserAuth.pagination import UserLimitOffsetPagination

# Create your views here.
logger = logging.getLogger(__name__)


PURPOSE_SERVICES = {
    "signup": signup_resend_otp_services,
    "reactivate": reactivate_resend_otp_services,
    "deactivate": deactivate_resend_otp_services,
    "password": password_reset_otp_services,
}

VERIFICATION_SERVICES = {
    "signup": validate_otp_activate_services, # Async
    "reactivate": reactivate_account_services, # Async
    "deactivate": deactivate_services, # Async
#    "password": reset_password_services
}


@api_view(["POST"])
@throttle_classes([SignupThrottle])
def signup_view(request): # Async services
    serializer = SignupSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    asyncio.run(sign_up_services(serializer.validated_data))
    return Response(
        {"message": "A verification code has been sent to your email."},
        status=status.HTTP_201_CREATED,
    )


@api_view(["POST"])
@throttle_classes([OTPVerificationThrottle])
def verify_otp(request): #
    serializer = OTPVerifySerializer(
        data=request.data,
        context={"request": request}
    )
    serializer.is_valid(raise_exception=True)
    
    purpose = serializer.validated_data["purpose"]

    verification_func = VERIFICATION_SERVICES.get(purpose)

    if not verification_func:
        return Response(
            {"message": "Invalid Purpose"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    response = asyncio.run(verification_func(serializer.validated_data))
    
    return Response(response, status=status.HTTP_200_OK)



@api_view(["POST"])
@throttle_classes([OTPResendThrottle])
def resend_otp(request): #
    serializer = OTPResendSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    purpose = serializer.validated_data["purpose"]

    service_func = PURPOSE_SERVICES.get(purpose)

    if not service_func:
        return Response(
            {"error": "Invalid purpose"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    service_func(serializer.validated_data)

    return Response(
        {"message": f"OTP has been sent for {purpose}."},
        status=status.HTTP_201_CREATED
    )


@api_view(["POST"])
@throttle_classes([LoginThrottle])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    tokens = login_services(serializer.validated_data)
    return Response(tokens, status=status.HTTP_200_OK)


@api_view(["POST"])
@throttle_classes([AnonPasswordChangeThrottle])
def reset_password(request):
    serializer = PasswordResetSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    asyncio.run(reset_password_services(serializer.validated_data))
    return Response(
        {"message": "Password reset link sent to the email"},
        status=status.HTTP_200_OK
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([UserRateThrottle])
def logout_view(request):
    serializer = LogoutSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    logout_services(serializer.validated_data)
    
    return Response(
        {"message": "User logged out"},
        status=status.HTTP_200_OK
    )


@api_view(["POST", "PATCH", "PUT"]) # Prefer Patch as takes less bandwidth
@permission_classes([IsAuthenticated])
@throttle_classes([CoreDataUpdateThrottle])
def core_data_update(request):
    serializer = CoreProfileUpdateSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = request.user
    response = asyncio.run(core_data_update_services(serializer.validated_data, user))
      
    return Response(
        {
            "message": "Data updated successfully",
            "updated_data": response
        },
        status=status.HTTP_200_OK
    )


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([AccessTokenThrottle])
def refresh_access_token(request):
    serializer = RefreshAccessTokenSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    new_access_token = refresh_accesstoken_services(serializer.validated_data)
    return Response(new_access_token, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([UserRateThrottle])
def request_deactivate_account(request):
    serializer = DeactivateSerializer(
        data=request.data,
        context={"request": request}
    )
    serializer.is_valid(raise_exception=True)

    response = asyncio.run(request_deactivation_service(serializer.validated_data))

    return Response(response, status=status.HTTP_200_OK)


@api_view(["POST"])
@throttle_classes([AnonRateThrottle])
def request_reactivate_account(request):
    serializer = ReactivateRequestSeializer(
        data=request.data,
        context={"request": request}
    )
    serializer.is_valid(raise_exception=True)

    response = asyncio.run(request_reactivation_services(serializer.validated_data))

    return Response(response, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([PasswordChangeThrottle])
def change_password(request):
    serializer = AuthenticatedPasswordChangeSerializer(data=request.data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    
    user = request.user
    user.set_password(serializer.validated_data['new_password'])
    user.save()

    asyncio.run(send_password_change_email(user))

    return Response({"message": "Password changed successfully"}, status=200)


@api_view(["POST"])
@throttle_classes([UpdateEmailThrottle])
def request_email_change(request):
    serializer = EmailChangeSerializer(data=request.data, context={"request": request})
    serializer.is_valid(raise_exception=True)

    response = email_change_service(serializer.validated_data)
    return Response(response, status=status.HTTP_200_OK)


@api_view(["GET"])
@throttle_classes([])
@permission_classes([IsAuthenticated])
def request_users(request):
    users = UserProfile.objects.all()

    role = request.user.authority
    if role == "Admin":
        pass  # sees all
    elif role == "Analyst":
        users = users.exclude(authority="Lobby")
    elif role == "Viewer":
        users = users.filter(authority__in=["Analyst", "Admin"])
    else:
        users = users.filter(authority="Lobby")

    role_filter = request.query_params.get("role")
    if role_filter:
        users = users.filter(authority__iexact=role_filter)

    active_filter = request.query_params.get("active")
    if active_filter is not None:
        users = users.filter(is_active=active_filter.lower() == "true")
    
    username_filter = request.query_params.get("username")
    if username_filter:
        users = users.filter(username__iexact=username_filter)

    sort_by = request.query_params.get("sort")
    order = request.query_params.get("order", "asc")
    if sort_by:
        if order == "desc":
            sort_by = f"-{sort_by}"
        users = users.order_by(sort_by)

    paginator = UserLimitOffsetPagination()
    paginated_users = paginator.paginate_queryset(users, request)
    serializer = UseProfileSerializer(paginated_users, many=True)
    return paginator.get_paginated_response(serializer.data)


@api_view(["PATCH"])
@throttle_classes([])
@permission_classes([IsAuthenticated])
@role_requirements(["Admin"])
def alter_user_authority(request):
    serializer = AuthoritySerializer(data=request.data, context={"request": request})
    serializer.is_valid(raise_exception=True)

    response = give_authority(serializer.validated_data)
    return Response(response)