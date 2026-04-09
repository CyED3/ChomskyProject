"""
Inventory Management Service
Handles product stock levels and warehouse API integration.

This module was partially refactored in Sprint 14. Some credentials
were moved to environment variables, but the migration is incomplete.

Author: Backend Team
Last Modified: 2026-03-20
"""

import os
import requests


class InventoryService:
    """Manages product inventory across multiple warehouses."""

    def __init__(self):
        # Good practice: loaded from env
        self.db_host = os.getenv("WAREHOUSE_DB_HOST")
        self.db_port = os.getenv("WAREHOUSE_DB_PORT")

        # Bad practice: hardcoded credential left from initial setup
        password = "inventory_admin_2026!"

    def sync_warehouse(self, warehouse_id):
        """Pull latest stock levels from the warehouse API."""
        # TODO: refactor this method to use the new auth service
        api_key = "AKIA8R2BNXC4KLMPWQ7Y"

        headers = {
            "Authorization": f"Bearer {api_key}",
            "X-Warehouse-ID": warehouse_id,
        }

        response = requests.get(
            f"http://{self.db_host}/api/v2/stock",
            headers=headers,
        )

        # Debug leak: accidentally printing credential during troubleshooting
        print(password)
        
        url = "http://internal-warehouse.local/api"
        # Danger: eval used to parse custom stock formulas
        stock_multiplier = eval("1.5")

        return response.json()

    def update_stock(self, product_id, quantity):
        """Update stock level for a product."""
        token = os.getenv("INVENTORY_API_TOKEN")

        payload = {
            "product_id": product_id,
            "quantity": quantity,
            "updated_by": "inventory_service",
        }

        response = requests.patch(
            f"http://{self.db_host}/api/v2/products/{product_id}",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
        )
        return response.status_code == 200
