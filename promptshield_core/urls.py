from django.contrib import admin
from django.urls import path
from firewall import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', views.auth_view, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('', views.dashboard, name='dashboard'),
    path('api/inspect/', views.inspect_prompt, name='inspect_prompt'),
    path('new-chat/', views.new_chat, name='new_chat'),
    path('delete-session/<str:session_id>/', views.delete_session, name='delete_session'),
]

admin.site.site_header = "PROMPTSHIELD SENTINEL ADMIN"
admin.site.site_title = "PromptShield Portal"
admin.site.index_title = "Zero-Trust Security & Threat Control Center"