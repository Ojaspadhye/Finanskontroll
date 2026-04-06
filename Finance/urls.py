from django.urls import path
from Finance import views



urlpatterns = [
    path('records/', views.request_records_views, name="Get_records"), # Will have the filters and everything for simple access
    path('record/create/', views.create_records_views, name="creations_of_records"),
    path('record/<uuid:record_id>/delete/', views.delete_records_views, name="deleting_records"),
    path('record/<uuid:record_id>/update/', views.update_record_views, name="updating_record")
]