# shop/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # Main pages
    path('', views.home, name='home'),
    path('products/', views.products_page, name='products'),
    path('dashboard/', views.dashboard_page, name='dashboards'),
    
    # Auth paths
    path('auth/login/', views.signin_page, name='signin'),
    path('auth/register/', views.register_page, name='register'),
    path('auth/logout/', views.logout_user, name='logout'),
    
    # Email verification
    path('auth/verify-code/<int:user_id>/', views.verify_email_code, name='verify_email_code'),
    path('auth/resend-code/<int:user_id>/', views.resend_verification_code, name='resend_verification_code'),

    # 2FA
    path('auth/setup-2fa/', views.setup_2fa, name='setup_2fa'),
    path('auth/2fa-verify/', views.two_factor_verify, name='two_factor_verify'),

    # Password reset
    path('auth/reset-password/', views.password_reset_request, name='password_reset'),
    path('auth/reset-password/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
    
   # Additional pages
    path('profile/', views.profile_page, name='profile'),
    path('subscriptions/', views.subscriptions_page, name='subscriptions'),
    path('orders/', views.orders_page, name='orders'),

    # Payment URLs
path('checkout/<int:product_id>/', views.checkout, name='checkout'),
path('payment/success/', views.success, name='payment_success'),
path('payment/cancel/', views.payment_cancel, name='payment_cancel'),
]

