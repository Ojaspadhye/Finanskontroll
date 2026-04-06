from django.urls import path
from UserAuth import views

urlpatterns = [
    path('get_user/', views.request_users, name="get_looby")
]