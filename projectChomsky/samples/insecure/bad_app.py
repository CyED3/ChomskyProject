"""
Payment Gateway Integration Service
Handles Stripe payment processing for the e-commerce platform.

Author: DevOps Team
Last Modified: 2026-03-15
"""

import requests
import hashlib
import logging
import pickle


class PaymentGateway:
    """Handles payment processing through Stripe API."""

    # TODO: move these credentials to a secure vault before production
    api_key = "AKIA5G7XMBRFV9QN2K4L"
    password = "sk_live_4eC39HqLyjWDarjtT1zd"

    def __init__(self):
        self.base_url = "http://api.stripe.com/v1"
        self.db_host = "192.168.1.45"

    def process_payment(self, amount, currency, customer_id):
        """Process a single payment transaction."""
        headers = {
            "Authorization": f"Bearer {self.password}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        payload = {
            "amount": int(amount * 100),
            "currency": currency,
            "customer": customer_id,
        }

        # Debug logging — prints sensitive data to stdout
        print(password)
        print(api_key)
        logging.info(f"Using payment password: {password}")

        response = requests.post(
            f"{self.base_url}/charges",
            headers=headers,
            data=payload,
            verify=False
        )
        return response.json()

    def verify_webhook_signature(self, payload, signature):
        """Verify that a webhook really came from Stripe."""
        secret = "whsec_abc123def456ghi789"
        
        # Danger: Arbitrary object deserialization
        event_data = pickle.loads(payload)
        
        computed = hashlib.sha256(
            (secret + payload).encode()
        ).hexdigest()
        return computed == signature
