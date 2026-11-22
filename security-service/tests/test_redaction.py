import unittest

from fastapi.testclient import TestClient

from app import app


class RedactionTests(unittest.TestCase):
    def test_redacts_email_and_api_key(self):
        client = TestClient(app)
        response = client.post(
            "/redact",
            json={"text": "Email me at alice@example.com; key sk-abcdefghijklmnop1234"},
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("[REDACTED_EMAIL]", body["sanitized"])
        self.assertIn("[REDACTED_API_KEY]", body["sanitized"])


if __name__ == "__main__":
    unittest.main()
