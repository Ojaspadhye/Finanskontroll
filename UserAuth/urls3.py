from django.urls import path
from UserAuth import views


urlpatterns = [
    path('alter_athority/', views.alter_user_authority, name="alter_authority")
]