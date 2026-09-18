"""Stats API checks using a fake Supabase client; no network requests."""

import os
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from packet_sniffer.api import app


class StatsTests(unittest.TestCase):
    def run_request(self, rows=None, failure=False):
        client = MagicMock()
        query = client.table.return_value
        query.select.return_value = query
        query.order.return_value = query
        query.range.side_effect = lambda start, end: self.page(query, rows or [], start, end)
        if failure:
            query.execute.side_effect = RuntimeError("private database error")
        with patch.dict(os.environ, {"SUPABASE_URL": "https://example.supabase.co", "SUPABASE_KEY": "test-key"}), patch("packet_sniffer.api.create_client", return_value=client):
            with TestClient(app) as api:
                self.assertEqual(api.get("/health").json(), {"status": "ok"})
                result = api.get("/api/stats")
            client.postgrest.aclose.assert_called_once()
        return result

    @staticmethod
    def page(query, rows, start, end):
        # Simulate an API row cap smaller than the requested page size.
        query.execute.return_value = SimpleNamespace(data=rows[start:min(end + 1, start + 400)], count=len(rows))
        return query

    def test_multiple_pages_and_top_five(self):
        rows = [{"source_ip": "10.0.0.1", "payload_size": 10}] * 1001
        rows += [{"source_ip": f"10.0.0.{i}", "payload_size": i} for i in range(2, 8)]
        result = self.run_request(rows)
        self.assertEqual(result.status_code, 200)
        data = result.json()
        self.assertEqual(data["total_packets"], 1007)
        self.assertEqual(data["total_payload_bytes"], 10010 + sum(range(2, 8)))
        self.assertEqual(len(data["top_source_ips"]), 5)
        self.assertEqual(data["top_source_ips"][0], {"source_ip": "10.0.0.1", "count": 1001})
        self.assertEqual(data["top_source_ips"][1]["source_ip"], "10.0.0.2")

    def test_empty_table(self):
        self.assertEqual(self.run_request().json(), {"total_packets": 0, "top_source_ips": [], "total_payload_bytes": 0})

    def test_database_failure(self):
        result = self.run_request(failure=True)
        self.assertEqual(result.status_code, 503)
        self.assertNotIn("private", result.text)

    def test_missing_configuration(self):
        with patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""}):
            with self.assertRaises(RuntimeError):
                with TestClient(app):
                    pass


if __name__ == "__main__":
    unittest.main()
