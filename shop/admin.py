# shop/admin.py - SIMPLER VERSION
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, Product, Order

# Register CustomUser with custom admin
@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'username', 'is_email_verified', 'is_2fa_enabled', 'is_staff')
    list_filter = ('is_email_verified', 'is_2fa_enabled', 'is_staff')
    
    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Verification & Security', {
            'fields': ('is_email_verified', 'email_verification_code', 'email_verification_expires_at',
                      'is_2fa_enabled', 'totp_secret'),
            'classes': ('collapse',)
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2'),
        }),
    )
    
    search_fields = ('email', 'username')
    ordering = ('email',)

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ("name", "category", "price", "active", "created_at")
    list_filter = ("category", "active")
    search_fields = ("name", "category")

@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "product", "status", "total_price", "created_at")
    list_filter = ("status", "created_at")
    search_fields = ("user__username", "product__name")
    date_hierarchy = "created_at"