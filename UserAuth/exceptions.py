from rest_framework.exceptions import APIException
from rest_framework import status

class OTPExpiredException(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = "OTP Expired or Invalid"
    default_code = "OTP_Expired"


class OTPInvalidException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "OTP Invalid"
    default_code = "OTP-Invalid"


class AcountActiveException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Account status is alredy active"
    default_code = "Active-Account"


class UserNotFound(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Acount with this email doesnot exist"
    default_code = "Invalid-Accoun"


class UserInactiveException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Account is deactive"
    default_code = "Deactivated-Account"


class MissingTokenException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "No Refresh token provided"
    default_code = "No-Token"


class InvalidTokenException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "The is invalid"
    default_code = "Invalid-Token"