# test_django_all.py
"""
Comprehensive Django Tests for TerraScope
All tests in a single file for easy management
Run with: pytest test_django_all.py -v
"""
import pytest
import jwt
import pyotp
import json
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from shop.models import Product, Order, ActivityLog

User = get_user_model()

# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def user_data():
    """Sample user data"""
    return {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'TestPassword123!',
    }


@pytest.fixture
def create_user(db, user_data):
    """Factory to create users"""
    def make_user(**kwargs):
        data = {**user_data, **kwargs}
        password = data.pop('password')
        user = User.objects.create_user(**data)
        user.set_password(password)
        user.is_email_verified = True
        user.save()
        return user
    return make_user


@pytest.fixture
def user(create_user):
    """Basic verified user"""
    return create_user()


@pytest.fixture
def verified_user(create_user):
    """Verified user"""
    return create_user(is_email_verified=True)


@pytest.fixture
def unverified_user(create_user):
    """Unverified user"""
    return create_user(is_email_verified=False)


@pytest.fixture
def user_with_2fa(create_user):
    """User with 2FA enabled"""
    user = create_user()
    user.totp_secret = pyotp.random_base32()
    user.is_2fa_enabled = True
    user.save()
    return user


@pytest.fixture
def authenticated_client(client, user):
    """Authenticated client"""
    client.force_login(user)
    return client


@pytest.fixture
def product_data():
    """Sample product data"""
    return {
        'name': 'Test Product',
        'description': 'Test description',
        'price': 99.99,
        'category': 'Analytics',
        'active': True
    }


@pytest.fixture
def create_product(db, product_data):
    """Factory to create products"""
    def make_product(**kwargs):
        data = {**product_data, **kwargs}
        return Product.objects.create(**data)
    return make_product


@pytest.fixture
def product(create_product):
    """Basic product"""
    return create_product()


@pytest.fixture
def multiple_products(create_product):
    """Multiple products"""
    return [
        create_product(name='Starter Plan', price=29.99),
        create_product(name='Pro Plan', price=99.99),
        create_product(name='Enterprise Plan', price=299.99),
    ]


@pytest.fixture
def paid_order(db, user, product):
    """Paid order"""
    return Order.objects.create(
        user=user,
        product=product,
        status='paid',
        total_price=product.price
    )


@pytest.fixture
def mock_send_mail(mocker):
    """Mock email sending"""
    return mocker.patch('django.core.mail.send_mail', return_value=1)


@pytest.fixture
def mock_stripe_session(mocker):
    """Mock Stripe session"""
    mock = mocker.Mock()
    mock.id = 'cs_test_123'
    mock.url = 'https://checkout.stripe.com/test'
    mock.metadata = {'product_id': '1', 'user_id': '1'}
    mock.payment_status = 'paid'
    mocker.patch('stripe.checkout.Session.create', return_value=mock)
    mocker.patch('stripe.checkout.Session.retrieve', return_value=mock)
    return mock


@pytest.fixture
def api_credentials():
    """API credentials"""
    return {
        'jwt_secret': 'xK9mP4nF2vL8wQ7rT6sY3hU5jB1cA0dE9gH8fI7kJ6mN5oP4qR3sT2uV1wX0yZ',
    }


# ============================================================================
# MODEL TESTS
# ============================================================================

@pytest.mark.django_db
class TestModels:
    """All model tests"""
    
    # CustomUser Tests
    def test_create_user(self, user_data):
        """Test creating basic user"""
        user = User.objects.create_user(**user_data)
        assert user.email == user_data['email']
        assert user.check_password(user_data['password'])
        assert user.is_active
    
    def test_create_superuser(self, user_data):
        """Test creating superuser"""
        user = User.objects.create_superuser(**user_data)
        assert user.is_staff
        assert user.is_superuser
    
    def test_user_str(self, user):
        """Test user string representation"""
        assert str(user) == user.email
    
    def test_email_unique(self, user_data):
        """Test email uniqueness"""
        User.objects.create_user(**user_data)
        with pytest.raises(Exception):
            User.objects.create_user(**user_data)
    
    def test_user_2fa_fields(self, user):
        """Test 2FA fields"""
        assert not user.is_2fa_enabled
        user.totp_secret = "TEST123"
        user.is_2fa_enabled = True
        user.save()
        assert user.is_2fa_enabled
    
    # Product Tests
    def test_create_product(self, product_data):
        """Test creating product"""
        product = Product.objects.create(**product_data)
        assert product.name == product_data['name']
        assert product.price == product_data['price']
    
    def test_product_str(self, product):
        """Test product string representation"""
        assert str(product) == product.name
    
    def test_product_defaults(self):
        """Test product defaults"""
        product = Product.objects.create(name="Test", price=50.00)
        assert product.active is True
        assert product.description == ""
    
    # Order Tests
    def test_create_order(self, user, product):
        """Test creating order"""
        order = Order.objects.create(
            user=user,
            product=product,
            status='pending',
            total_price=product.price
        )
        assert order.user == user
        assert order.product == product
        assert order.status == 'pending'
    
    def test_order_str(self, paid_order):
        """Test order string representation"""
        expected = f"Order #{paid_order.id} - {paid_order.user}"
        assert str(paid_order) == expected
    
    def test_order_cascade_delete(self, user, product):
        """Test order deleted with user"""
        order = Order.objects.create(
            user=user,
            product=product,
            status='paid',
            total_price=product.price
        )
        order_id = order.id
        user.delete()
        assert not Order.objects.filter(id=order_id).exists()
    
    # ActivityLog Tests
    def test_create_activity_log(self, user):
        """Test creating activity log"""
        log = ActivityLog.objects.create(
            user=user,
            activity_type='token_generated',
            description='Test activity'
        )
        assert log.user == user
        assert log.created_at is not None
    
    def test_activity_log_ordering(self, user):
        """Test activity logs ordered newest first"""
        log1 = ActivityLog.objects.create(
            user=user,
            activity_type='order_placed',
            description='First'
        )
        log2 = ActivityLog.objects.create(
            user=user,
            activity_type='token_generated',
            description='Second'
        )
        logs = ActivityLog.objects.all()
        assert logs[0] == log2  # Most recent first


# ============================================================================
# AUTHENTICATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestAuthentication:
    """All authentication tests"""
    
    # Registration Tests
    def test_register_page_loads(self, client):
        """Test registration page loads"""
        response = client.get(reverse('register'))
        assert response.status_code == 200
        assert 'Create Account' in response.content.decode()
    
    def test_successful_registration(self, client, user_data, mock_send_mail):
        """Test successful registration"""
        response = client.post(reverse('register'), data=user_data)
        assert response.status_code == 302
        user = User.objects.get(email=user_data['email'])
        assert user.username == user_data['username']
        assert not user.is_email_verified
        assert mock_send_mail.called
    
    def test_registration_duplicate_email(self, client, user, user_data):
        """Test registration with existing email"""
        response = client.post(reverse('register'), data=user_data)
        assert response.status_code == 200  # Stays on page with error
    
    # Login Tests
    def test_login_page_loads(self, client):
        """Test login page loads"""
        response = client.get(reverse('signin'))
        assert response.status_code == 200
        assert 'Welcome back' in response.content.decode()
    
    def test_successful_login(self, client, verified_user, user_data):
        """Test successful login"""
        response = client.post(reverse('signin'), {
            'email': user_data['email'],
            'password': user_data['password']
        })
        assert response.status_code == 302
        assert response.url == reverse('dashboards')
    
    def test_login_invalid_credentials(self, client, verified_user):
        """Test login with wrong password"""
        response = client.post(reverse('signin'), {
            'email': verified_user.email,
            'password': 'WrongPassword!'
        })
        assert response.status_code == 200
        assert 'Invalid' in response.content.decode()
    
    def test_login_unverified_email(self, client, unverified_user, user_data):
        """Test unverified user redirected to verification"""
        response = client.post(reverse('signin'), {
            'email': unverified_user.email,
            'password': user_data['password']
        })
        assert response.status_code == 302
        assert 'verify-code' in response.url
    
    def test_login_with_2fa(self, client, user_with_2fa, user_data):
        """Test login with 2FA redirects"""
        response = client.post(reverse('signin'), {
            'email': user_with_2fa.email,
            'password': user_data['password']
        })
        assert response.status_code == 302
        assert response.url == reverse('two_factor_verify')
    
    # Email Verification Tests
    def test_verify_email_success(self, client, unverified_user):
        """Test email verification success"""
        code = "123456"
        unverified_user.email_verification_code = code
        unverified_user.email_verification_expires_at = timezone.now() + timedelta(minutes=10)
        unverified_user.save()
        
        response = client.post(
            reverse('verify_email_code', args=[unverified_user.id]),
            {'code': code}
        )
        assert response.status_code == 302
        unverified_user.refresh_from_db()
        assert unverified_user.is_email_verified
    
    def test_verify_email_wrong_code(self, client, unverified_user):
        """Test verification with wrong code"""
        unverified_user.email_verification_code = "123456"
        unverified_user.email_verification_expires_at = timezone.now() + timedelta(minutes=10)
        unverified_user.save()
        
        response = client.post(
            reverse('verify_email_code', args=[unverified_user.id]),
            {'code': '999999'}
        )
        assert response.status_code == 200
        assert 'Invalid' in response.content.decode()
    
    def test_resend_verification_code(self, client, unverified_user, mock_send_mail):
        """Test resending verification code"""
        response = client.get(reverse('resend_verification_code', args=[unverified_user.id]))
        assert response.status_code == 302
        unverified_user.refresh_from_db()
        assert unverified_user.email_verification_code is not None
        assert mock_send_mail.called
    
    # 2FA Tests
    def test_setup_2fa_page(self, authenticated_client):
        """Test 2FA setup page loads"""
        response = authenticated_client.get(reverse('setup_2fa'))
        assert response.status_code == 200
        assert 'Two-Factor' in response.content.decode()
    
    def test_enable_2fa_valid_code(self, authenticated_client, user):
        """Test enabling 2FA with valid code"""
        secret = pyotp.random_base32()
        user.totp_secret = secret
        user.save()
        
        totp = pyotp.TOTP(secret)
        code = totp.now()
        
        response = authenticated_client.post(reverse('setup_2fa'), {'code': code})
        assert response.status_code == 302
        user.refresh_from_db()
        assert user.is_2fa_enabled
    
    def test_enable_2fa_invalid_code(self, authenticated_client, user):
        """Test enabling 2FA with invalid code"""
        user.totp_secret = pyotp.random_base32()
        user.save()
        
        response = authenticated_client.post(reverse('setup_2fa'), {'code': '000000'})
        assert response.status_code == 200
        user.refresh_from_db()
        assert not user.is_2fa_enabled
    
    # Password Reset Tests
    def test_password_reset_page(self, client):
        """Test password reset page loads"""
        response = client.get(reverse('password_reset'))
        assert response.status_code == 200
    
    def test_password_reset_request(self, client, verified_user, mock_send_mail):
        """Test password reset request"""
        response = client.post(reverse('password_reset'), {
            'email': verified_user.email
        })
        assert response.status_code == 302
        assert mock_send_mail.called
    
    # Logout Test
    def test_logout(self, authenticated_client):
        """Test logout"""
        response = authenticated_client.post(reverse('logout'))
        assert response.status_code == 302
        assert response.url == reverse('signin')


# ============================================================================
# VIEW TESTS
# ============================================================================

@pytest.mark.django_db
class TestViews:
    """All view tests"""
    
    # Home Page Tests
    def test_home_page_loads(self, client):
        """Test home page loads"""
        response = client.get(reverse('home'))
        assert response.status_code == 200
        assert 'TerraScope' in response.content.decode()
    
    def test_home_shows_products(self, client, multiple_products):
        """Test home shows products"""
        response = client.get(reverse('home'))
        for product in multiple_products[:3]:
            assert product.name in response.content.decode()
    
    # Products Page Tests
    def test_products_page_loads(self, client):
        """Test products page loads"""
        response = client.get(reverse('products'))
        assert response.status_code == 200
    
    def test_products_shows_active_only(self, client, create_product):
        """Test only active products shown"""
        active = create_product(name='Active', active=True)
        inactive = create_product(name='Inactive', active=False)
        
        response = client.get(reverse('products'))
        content = response.content.decode()
        assert active.name in content
        assert inactive.name not in content
    
    # Dashboard Tests
    def test_dashboard_requires_auth(self, client):
        """Test dashboard requires authentication"""
        response = client.get(reverse('dashboards'))
        assert response.status_code == 302
        assert 'signin' in response.url
    
    def test_dashboard_loads(self, authenticated_client):
        """Test dashboard loads for authenticated user"""
        response = authenticated_client.get(reverse('dashboards'))
        assert response.status_code == 200
        assert 'Welcome back' in response.content.decode()
    
    def test_dashboard_shows_stats(self, authenticated_client, paid_order):
        """Test dashboard shows statistics"""
        response = authenticated_client.get(reverse('dashboards'))
        content = response.content.decode()
        assert 'Total Orders' in content
    
    # Profile Tests
    def test_profile_requires_auth(self, client):
        """Test profile requires authentication"""
        response = client.get(reverse('profile'))
        assert response.status_code == 302
    
    def test_profile_loads(self, authenticated_client, user):
        """Test profile page loads"""
        response = authenticated_client.get(reverse('profile'))
        assert response.status_code == 200
        assert user.email in response.content.decode()
    
    def test_profile_shows_verification_status(self, authenticated_client, user):
        """Test profile shows verification status"""
        user.is_email_verified = True
        user.save()
        response = authenticated_client.get(reverse('profile'))
        assert 'Verified' in response.content.decode()
    
    # Orders Tests
    def test_orders_requires_auth(self, client):
        """Test orders requires authentication"""
        response = client.get(reverse('orders'))
        assert response.status_code == 302
    
    def test_orders_shows_user_orders(self, authenticated_client, user, product):
        """Test orders shows user's orders"""
        Order.objects.create(
            user=user,
            product=product,
            status='paid',
            total_price=product.price
        )
        response = authenticated_client.get(reverse('orders'))
        assert product.name in response.content.decode()
    
    def test_orders_empty_state(self, authenticated_client):
        """Test orders empty state"""
        response = authenticated_client.get(reverse('orders'))
        assert 'No Orders' in response.content.decode() or 'no orders' in response.content.decode().lower()
    
    # Checkout Tests
    def test_checkout_requires_auth(self, client, product):
        """Test checkout requires authentication"""
        response = client.get(reverse('checkout', args=[product.id]))
        assert response.status_code == 302
    
    def test_checkout_loads(self, authenticated_client, product):
        """Test checkout page loads"""
        response = authenticated_client.get(reverse('checkout', args=[product.id]))
        assert response.status_code == 200
        assert product.name in response.content.decode()
    
    def test_checkout_invalid_product(self, authenticated_client):
        """Test checkout with invalid product"""
        response = authenticated_client.get(reverse('checkout', args=[99999]))
        assert response.status_code == 404
    
    def test_checkout_post_stripe(self, authenticated_client, product, mock_stripe_session):
        """Test checkout creates Stripe session"""
        response = authenticated_client.post(reverse('checkout', args=[product.id]))
        assert response.status_code == 302
    
    # Payment Tests
    def test_payment_success_requires_auth(self, client):
        """Test payment success requires auth"""
        response = client.get(reverse('payment_success'))
        assert response.status_code == 302
    
    def test_payment_success_loads(self, authenticated_client):
        """Test payment success page loads"""
        response = authenticated_client.get(reverse('payment_success'))
        assert response.status_code == 200
    
    def test_payment_cancel_loads(self, client):
        """Test payment cancel page loads"""
        response = client.get(reverse('payment_cancel'))
        assert response.status_code == 200


# ============================================================================
# API TESTS
# ============================================================================

@pytest.mark.django_db
class TestAPI:
    """All API tests"""
    
    # Token Generation Tests
    def test_generate_token_requires_auth(self, client):
        """Test token generation requires authentication"""
        response = client.post(reverse('generate_api_token'))
        assert response.status_code == 302
    
    def test_generate_token_success(self, authenticated_client, paid_order):
        """Test successful token generation"""
        response = authenticated_client.post(
            reverse('generate_api_token'),
            {'token_name': 'Test Token'}
        )
        data = json.loads(response.content)
        assert data['success'] is True
        assert 'token' in data
    
    def test_generate_token_without_subscription(self, authenticated_client):
        """Test token generation without subscription"""
        response = authenticated_client.post(
            reverse('generate_api_token'),
            {'token_name': 'Test Token'}
        )
        data = json.loads(response.content)
        assert response.status_code == 403
        assert data['success'] is False
    
    def test_token_is_valid_jwt(self, authenticated_client, user, paid_order, api_credentials):
        """Test generated token is valid JWT"""
        response = authenticated_client.post(
            reverse('generate_api_token'),
            {'token_name': 'Test Token'}
        )
        data = json.loads(response.content)
        token = data['token']
        
        decoded = jwt.decode(
            token,
            api_credentials['jwt_secret'],
            algorithms=["HS256"]
        )
        assert decoded['sub'] == user.email
        assert decoded['user_id'] == user.id
    
    def test_token_expires_24_hours(self, authenticated_client, paid_order, api_credentials):
        """Test token expires in 24 hours"""
        response = authenticated_client.post(
            reverse('generate_api_token'),
            {'token_name': 'Test Token'}
        )
        data = json.loads(response.content)
        token = data['token']
        
        decoded = jwt.decode(
            token,
            api_credentials['jwt_secret'],
            algorithms=["HS256"]
        )
        exp_time = timezone.datetime.fromtimestamp(decoded['exp'], tz=timezone.utc)
        iat_time = timezone.datetime.fromtimestamp(decoded['iat'], tz=timezone.utc)
        difference = exp_time - iat_time
        assert difference.total_seconds() == 86400
    
    # API Documentation Tests
    def test_api_docs_requires_auth(self, client):
        """Test API docs requires authentication"""
        response = client.get(reverse('api_documentation'))
        assert response.status_code == 302
    
    def test_api_docs_loads(self, authenticated_client):
        """Test API docs page loads"""
        response = authenticated_client.get(reverse('api_documentation'))
        assert response.status_code == 200
    
    def test_api_docs_shows_base_url(self, authenticated_client):
        """Test API docs shows Flask API URL"""
        response = authenticated_client.get(reverse('api_documentation'))
        content = response.content.decode()
        assert '127.0.0.1:5000' in content or 'API Base URL' in content
    
    def test_api_docs_shows_swagger_link(self, authenticated_client):
        """Test API docs shows Swagger link"""
        response = authenticated_client.get(reverse('api_documentation'))
        content = response.content.decode()
        assert '/docs' in content
        assert 'Swagger' in content
    
    def test_api_docs_shows_endpoints(self, authenticated_client):
        """Test API docs shows endpoints"""
        response = authenticated_client.get(reverse('api_documentation'))
        content = response.content.decode()
        assert '/api/observations' in content
        assert 'GET' in content or 'POST' in content


# ============================================================================
# SUMMARY
# ============================================================================

"""
Test Summary:
- Models: 12 tests (User, Product, Order, ActivityLog)
- Authentication: 16 tests (Registration, Login, 2FA, Password Reset, Logout)
- Views: 20 tests (Home, Products, Dashboard, Profile, Orders, Checkout, Payment)
- API: 10 tests (Token Generation, Documentation)
- TOTAL: 58 comprehensive tests

Run with:
    pytest test_django_all.py -v          # Verbose
    pytest test_django_all.py -q          # Quiet
    pytest test_django_all.py --cov=shop  # With coverage
"""