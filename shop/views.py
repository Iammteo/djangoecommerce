# shop/views.py
import random
from django.utils import timezone
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMultiAlternatives, send_mail
from django.shortcuts import get_object_or_404, render, redirect
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
import pyotp 
import stripe




stripe.api_key = settings.STRIPE_SECRET_KEY

from .models import Order, Product, CustomUser
from .forms import SignUpForm

User = get_user_model()


def home(request):
    products = Product.objects.filter(active=True).order_by('-created_at')[:3]
    return render(request, "shop/home.html", {"products": products})


def products_page(request):
    products = Product.objects.filter(active=True).order_by('-created_at')
    return render(request, "shop/products.html", {"products": products})


@login_required(login_url="signin")
def dashboard_page(request):
    # Get user's orders
    total_orders = Order.objects.filter(user=request.user).count()
    
    context = {
        'total_orders': total_orders,
    }
    return render(request, "shop/dashboard.html", context)


def signin_page(request):
    if request.user.is_authenticated:
        return redirect("dashboards")
        
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            messages.error(request, "Invalid email or password")
            return render(request, "shop/signin.html")

      
        user = authenticate(request, username=email, password=password)
        
        if user is None:
            messages.error(request, "Invalid email or password")
            return render(request, "shop/signin.html")

        if not user.is_email_verified:
            messages.error(request, "Please verify your email first.")
            # Generate and send verification code
            code = f"{random.randint(0, 999999):06d}"
            user.email_verification_code = code
            user.email_verification_expires_at = timezone.now() + timezone.timedelta(minutes=10)
            user.save()
            
            # Send verification email
            send_mail(
                "Your TerraScope Verification Code",
                f"Your verification code is: {code}",
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            
            return redirect("verify_email_code", user_id=user.id)

        if user.is_2fa_enabled and user.totp_secret:
            request.session["2fa_user_id"] = user.id
            return redirect("two_factor_verify")

        login(request, user)
        return redirect("dashboards")

    return render(request, "shop/signin.html")









def register_page(request):
    if request.user.is_authenticated:
        return redirect("dashboards")
        
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            # Save the user first (this hashes the password)
            user = form.save()
            
            # Now update the verification fields
            user.is_email_verified = False
            code = f"{random.randint(0, 999999):06d}"
            user.email_verification_code = code
            user.email_verification_expires_at = timezone.now() + timezone.timedelta(minutes=10)
            user.save()
            
            # Send welcome email
            subject = "Welcome to TerraScope 🌍 - Verify Your Email"
            message = f"Hi {user.username},\n\nThanks for creating an account with TerraScope.\n\nYour verification code is: {code}\n\nThis code will expire in 10 minutes.\n\n– The TerraScope team"
            
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            
            messages.success(request, "Account created! Please check your email for the verification code.")
            return redirect("verify_email_code", user_id=user.id)
    else:
        form = SignUpForm()

    return render(request, "shop/register.html", {"form": form})


def verify_email_code(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    
    if request.method == "POST":
        code = request.POST.get("code", "").strip()
        
        if not user.email_verification_code:
            messages.error(request, "No verification code found. Please request a new one.")
            return redirect("resend_verification_code", user_id=user.id)
        
        if timezone.now() > user.email_verification_expires_at:
            messages.error(request, "This code has expired. Please request a new one.")
            return redirect("resend_verification_code", user_id=user.id)
        
        if code != user.email_verification_code:
            messages.error(request, "Invalid verification code.")
            return render(request, "shop/verify_code.html", {"user": user})
        
        # Success - verify email
        user.is_email_verified = True
        user.email_verification_code = None
        user.email_verification_expires_at = None
        user.save()
        
        messages.success(request, "Email verified successfully! You can now sign in.")
        return redirect("signin")
    
    return render(request, "shop/verify_code.html", {"user": user})


def resend_verification_code(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    
    # Generate new code
    code = f"{random.randint(0, 999999):06d}"
    user.email_verification_code = code
    user.email_verification_expires_at = timezone.now() + timezone.timedelta(minutes=10)
    user.save()
    
    # Send email
    subject = "Your new TerraScope verification code"
    message = f"Hi {user.username},\n\nYour new verification code is: {code}\n\nThis code will expire in 10 minutes.\n\n– The TerraScope team"
    
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )
    
    messages.success(request, "We sent you a new verification code.")
    return redirect("verify_email_code", user_id=user.id)


def password_reset_request(request):
    if request.method == "POST":
        email = request.POST.get("email")
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            messages.error(request, "We couldn't find an account with that email.")
            return redirect("password_reset")

        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_url = request.build_absolute_uri(
            reverse("password_reset_confirm", kwargs={"uidb64": uidb64, "token": token})
        )

        # Send reset email
        subject = "Reset your TerraScope password"
        message = f"Click the link below to reset your password:\n\n{reset_url}\n\nIf you didn't request this, please ignore this email."
        
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )

        messages.success(request, "We emailed you a password reset link.")
        return redirect("signin")

    return render(request, "shop/password_reset.html")


def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = CustomUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
        user = None

    if user is None or not default_token_generator.check_token(user, token):
        messages.error(request, "This password reset link is invalid or expired.")
        return redirect("password_reset")

    if request.method == "POST":
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")

        if password1 != password2:
            messages.error(request, "Passwords don't match.")
        else:
            user.set_password(password1)
            user.save()
            messages.success(request, "Password updated! You can now sign in.")
            return redirect("signin")

    return render(request, "shop/reset_password.html", {"uidb64": uidb64, "token": token})


@login_required(login_url="signin")
def setup_2fa(request):
    user = request.user

    if request.method == "POST":
        code = request.POST.get("code", "").strip()

        if not user.totp_secret:
            messages.error(request, "Something went wrong. Refresh the page to get a new QR code.")
            return redirect("setup_2fa")

        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(code):
            user.is_2fa_enabled = True
            user.save()
            messages.success(request, "2FA enabled successfully 🎉")
            return redirect("dashboards")
        else:
            messages.error(request, "Invalid code. Try again.")

    # GET – show QR code / secret
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        user.save()

    totp = pyotp.TOTP(user.totp_secret)
    otp_auth_url = totp.provisioning_uri(name=user.email, issuer_name="TerraScope")

    context = {
        "otp_auth_url": otp_auth_url,
        "secret": user.totp_secret,
    }
    return render(request, "shop/setup_2fa.html", context)


def two_factor_verify(request):
    user_id = request.session.get("2fa_user_id")
    if not user_id:
        return redirect("signin")

    user = get_object_or_404(CustomUser, id=user_id)

    if request.method == "POST":
        code = request.POST.get("code", "").strip()
        totp = pyotp.TOTP(user.totp_secret)

        if totp.verify(code):
            # success
            login(request, user)
            request.session.pop("2fa_user_id", None)
            messages.success(request, "Logged in with 2FA ✅")
            return redirect("dashboards")
        else:
            messages.error(request, "Invalid 2FA code.")

    return render(request, "shop/two_factor_verify.html")

@login_required(login_url="signin")
def profile_page(request):
    total_orders = Order.objects.filter(user=request.user).count()
    
    context = {
        'total_orders': total_orders,
    }
    return render(request, "shop/profile.html", context)

@login_required(login_url="signin")
def subscriptions_page(request):
    return render(request, "shop/subscriptions.html")   

@login_required(login_url="signin")
def orders_page(request):
    orders = Order.objects.filter(user=request.user).select_related('product').order_by('-created_at')
    paid_orders = orders.filter(status='paid')
    
    # Calculate stats
    paid_orders_count = paid_orders.count()
    total_spent = sum(order.total_price for order in paid_orders)
    
    context = {
        'orders': orders,
        'paid_orders_count': paid_orders_count,
        'total_spent': total_spent,
    }
    return render(request, "shop/orders.html", context)



@login_required(login_url="signin")
def logout_user(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect("signin")



@login_required(login_url="signin")
def checkout(request, product_id):
    product = get_object_or_404(Product, id=product_id, active=True)
    
    if request.method == "POST":
        try:
            # Create Stripe Checkout Session
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'usd',
                        'unit_amount': int(product.price * 100),  # Convert to cents
                        'product_data': {
                            'name': product.name,
                            'description': product.description,
                        },
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=request.build_absolute_uri(reverse('payment_success')) + '?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=request.build_absolute_uri(reverse('payment_cancel')),
                client_reference_id=str(request.user.id),
                metadata={
                    'product_id': product.id,
                    'user_id': request.user.id,
                }
            )
            return redirect(checkout_session.url)
        except Exception as e:
            messages.error(request, f"Payment error: {str(e)}")
            return redirect('products')
    
    context = {
        'product': product,
        'stripe_publishable_key': settings.STRIPE_PUBLISHABLE_KEY,
    }
    return render(request, 'shop/checkout.html', context)


@login_required(login_url="signin")
def payment_success(request):
    print("=" * 50)
    print("PAYMENT SUCCESS VIEW CALLED")
    print(f"User: {request.user.email}")
    print(f"GET params: {request.GET}")
    
    session_id = request.GET.get('session_id')
    print(f"Session ID: {session_id}")
    
    if session_id:
        try:
            # Retrieve the Stripe session
            print("Retrieving Stripe session...")
            session = stripe.checkout.Session.retrieve(session_id)
            print(f"Stripe session retrieved: {session.id}")
            print(f"Metadata: {session.metadata}")
            print(f"Payment status: {session.payment_status}")
            
            # Get product
            product_id = session.metadata.get('product_id')
            print(f"Product ID from metadata: {product_id}")
            
            product = Product.objects.get(id=product_id)
            print(f"Product found: {product.name}")
            
            # Create order
            print("Creating order...")
            order = Order.objects.create(
                user=request.user,
                product=product,
                status='paid',
                total_price=product.price
            )
            print(f"✅ ORDER CREATED: #{order.id}")
            print(f"Order details: User={order.user.email}, Product={order.product.name}, Price=${order.total_price}")
            
            messages.success(request, f"Payment successful! Order #{order.id} created.")
                
        except Product.DoesNotExist:
            print(f"❌ PRODUCT NOT FOUND with ID: {product_id}")
            messages.error(request, "Product not found.")
        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
            import traceback
            print(traceback.format_exc())
            messages.error(request, f"Error processing order: {str(e)}")
    else:
        print("❌ NO SESSION ID IN REQUEST")
        messages.warning(request, "No payment session found.")
    
    print("=" * 50)
    return render(request, 'shop/payment_success.html')


def payment_cancel(request):
    messages.warning(request, "Payment was cancelled.")
    return render(request, 'shop/payment_cancel.html')

def success(request):
    return render(request, "shop/success.html")

@login_required(login_url="signin")
def orders_page(request):
    orders = Order.objects.filter(user=request.user).order_by('-created_at')
    paid_orders = orders.filter(status='paid')
    
    # Calculate stats
    paid_orders_count = paid_orders.count()
    total_spent = sum(order.total_price for order in paid_orders)
    
    context = {
        'orders': orders,
        'paid_orders_count': paid_orders_count,
        'total_spent': total_spent,
    }
    return render(request, "shop/orders.html", context)