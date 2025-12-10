from django.test import TestCase, Client
from django.urls import reverse
from shop.models import Product


class SecurityMiddlewareTests(TestCase):
    """
    US-18: Security Middleware (Should Have, NF)

    AC1: Given enabled middleware, when CSRF is attempted, then blocked.
    """

    def setUp(self):
        # Enforce real CSRF checks in the client
        self.client = Client(enforce_csrf_checks=True)

        # Simple product so the checkout URL is valid
        self.product = Product.objects.create(
            name="CSRF Test Product",
            description="Used to test CSRF protection on checkout",
            price=10.00,
        )

    def test_csrf_blocks_unsafe_checkout_post(self):
        """
        We POST to the checkout view WITHOUT a csrf_token.
        Expected: 403 Forbidden (blocked by CsrfViewMiddleware).
        """
        url = reverse("checkout", args=[self.product.id])  # name=checkout in urls.py

        response = self.client.post(url, {})  # no csrf_token in data

        self.assertEqual(response.status_code, 403)


class SqlInjectionPreventionTests(TestCase):
    """
    US-18: Security Middleware (Should Have, NF)

    AC2: Given malicious query, when executed, then prevented by ORM.
    """

    def setUp(self):
        self.client = Client()
        self.product = Product.objects.create(
            name="Normal Product",
            description="Safe item for SQL injection test",
            price=5.00,
        )

    def test_sql_injection_like_input_does_not_break_products_page(self):
        """
        We send an SQL-injection-style string into the products search query.
        Expected:
        - View still returns 200 OK.
        - Product table is not damaged (same count before and after).
        """
        malicious_input = "'; DROP TABLE shop_product; --"

        count_before = Product.objects.count()

        # products/ → name='products' in urls.py
        url = reverse("products")
        response = self.client.get(url, {"q": malicious_input})

        count_after = Product.objects.count()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(count_before, count_after)
