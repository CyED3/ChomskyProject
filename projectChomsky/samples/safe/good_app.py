"""
Payment Gateway Integration Service (Secure Version)
Handles Stripe payment processing for the e-commerce platform.

All sensitive credentials are loaded from environment variables
following the principle of least privilege.

Author: DevOps Team
Last Modified: 2026-04-01
"""

import os
import requests
import hashlib
import logging

logger = logging.getLogger(__name__)


class PaymentGateway:
    """Handles payment processing through Stripe API."""

    def __init__(self):
        self.api_key = os.getenv("STRIPE_API_KEY")
        self.secret_key = os.getenv("STRIPE_SECRET_KEY")
        self.webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
        self.base_url = os.getenv("STRIPE_BASE_URL")
        self.db_host = os.getenv("DB_HOST")

    def process_payment(self, amount, currency, customer_id):
        """Process a single payment transaction."""
        headers = {
            "Authorization": f"Bearer {self.secret_key}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        payload = {
            "amount": int(amount * 100),
            "currency": currency,
            "customer": customer_id,
        }

        # Safe logging — no sensitive data exposed
        logger.info("Processing payment of %s %s for customer %s",
                     amount, currency, customer_id)

        response = requests.post(
            f"{self.base_url}/charges",
            headers=headers,
            data=payload,
        )
        return response.json()

    def verify_webhook_signature(self, payload, signature):
        """Verify that a webhook really came from Stripe."""
        computed = hashlib.sha256(
            (self.webhook_secret + payload).encode()
        ).hexdigest()
        return computed == signature
