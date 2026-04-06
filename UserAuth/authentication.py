from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.settings import api_settings
from .models import UserProfile

class UUIDJWTAuthentication(JWTAuthentication):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # make sure the claim attribute exists
        self.user_id_claim = api_settings.USER_ID_CLAIM

    def get_user(self, validated_token):
        """
        Overrides the default to support UUID primary keys.
        """
        try:
            user_id = validated_token[self.user_id_claim]
        except KeyError:
            return None

        try:
            return UserProfile.objects.get(id=user_id)
        except UserProfile.DoesNotExist:
            return None