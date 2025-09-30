from django.urls import path
from . import views

urlpatterns = [
    path("register/", views.register_view, name="register"),
    path('admin_dashboard', views.admin_dashboard, name='admin_dashboard'),
    path('display_sqliwebsites', views.display_sqliwebsites, name='display_sqliwebsites'),
    path('display_suspicious_websites', views.display_suspicious_websites, name='display_suspicious_websites'),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout"),
    path('', views.index, name='index'),
    path('check_phishing',views.check_phishing, name='check_phishing'),
    path('sql_injection/',views.check_sqlinjection, name='sql_injection'),
    
    path('list-website/', views.list_suspicious_websites, name='list_website'),
    path('list_sqli/', views.list_sqliwebsites, name='list_sqli'),
    
    path('login', views.login, name='login'),
    path('enquiry_list', views.enquiry_list, name='enquiry_list'),
    path('delete_enquiry/<int:id>', views.delete_enquiry, name='delete_enquiry'),
    
    path('user_list_view', views.user_list_view, name='user_list_view'),
    path('user_list_view', views.user_list_view, name='user_list_view'),
    path('delete_user/<int:id>', views.delete_user, name='delete_user'),
        
    path('suspicious_list', views.suspicious_list, name='suspicious_list'),
]