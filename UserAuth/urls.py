from django.urls import path
from UserAuth import views

urlpatterns = [
    path('signup/', views.signup_view, name="signup"), ## Async Works
    path('verify_otp/', views.verify_otp, name="veryfy_otp"), ## Async Works for all verification and services
    path('resend_otp/', views.resend_otp, name="resend_otp"), ## Async
    path('login/', views.login_view, name="login"), ##
    path('logout/', views.logout_view, name="logout"), ##
    path('reset_password/', views.reset_password, name="reset_password"), # When some one is not logged in  # Async
    path('core_update/', views.core_data_update, name="update_profile"), ## 
    path('change_email/', views.request_email_change, name="update_email"), ## Async
    path('refresh_access_token/', views.refresh_access_token, name="refresh_token"), ##
    path('deactivate_account_request/', views.request_deactivate_account, name="deactivate_account_request"), ## Async
    path('reactivate_account_request/', views.request_reactivate_account, name="reactivate_account_request"), ## Async Works
    path('change_password/', views.change_password, name="change_password"), # During person logged in # Async
]




