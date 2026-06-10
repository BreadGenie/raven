import hashlib
import uuid

import frappe
from frappe.tests import IntegrationTestCase
from frappe.utils.encryption import (
    compute_blind_index,
    decrypt_document_fields,
    is_encrypted_placeholder,
    search_blind_index,
    store_encrypted_fields,
)


class TestRavenMessageEncryption(IntegrationTestCase):
    def setUp(self):
        frappe.set_user("Administrator")

        self.test_user = "test1@example.com"
        self.non_member_user = "test3@example.com"

        for user in [self.test_user, self.non_member_user]:
            u = frappe.get_doc("User", user)
            u.add_roles("Raven User")
            u.remove_roles("Raven Admin")

        self.workspace = frappe.get_doc(
            {
                "doctype": "Raven Workspace",
                "workspace_name": f"Test Encryption Workspace {uuid.uuid4().hex[:8]}",
                "type": "Public",
            }
        ).insert(ignore_permissions=True)

        for user in [self.test_user, self.non_member_user]:
            frappe.get_doc(
                {
                    "doctype": "Raven Workspace Member",
                    "workspace": self.workspace.name,
                    "user": user,
                }
            ).insert(ignore_permissions=True)

        self.channel = frappe.get_doc(
            {
                "doctype": "Raven Channel",
                "channel_name": f"test-encryption-{uuid.uuid4().hex[:8]}",
                "type": "Private",
                "workspace": self.workspace.name,
            }
        ).insert(ignore_permissions=True)

        frappe.get_doc(
            {
                "doctype": "Raven Channel Member",
                "channel_id": self.channel.name,
                "user_id": self.test_user,
            }
        ).insert(ignore_permissions=True)

    def tearDown(self):
        frappe.set_user("Administrator")
        frappe.db.rollback()

    def _create_message(self, text: str, as_user: str | None = None) -> str:
        if as_user:
            frappe.set_user(as_user)
        msg = frappe.get_doc(
            {
                "doctype": "Raven Message",
                "channel_id": self.channel.name,
                "message_type": "Text",
                "text": text,
            }
        ).insert()
        frappe.set_user("Administrator")
        return msg.name

    def test_message_text_encrypted_in_db(self):
        msg_name = self._create_message("secret message", self.test_user)
        db_value = frappe.db.get_value("Raven Message", msg_name, "text")
        self.assertTrue(is_encrypted_placeholder(db_value))

    def test_channel_member_can_decrypt(self):
        msg_name = self._create_message("hello member", self.test_user)
        frappe.set_user(self.test_user)
        doc = frappe.get_doc("Raven Message", msg_name)
        self.assertEqual(doc.text, "hello member")
        frappe.set_user("Administrator")

    def test_non_member_gets_none_for_encrypted_text(self):
        msg_name = self._create_message("secret", self.test_user)
        frappe.set_user(self.non_member_user)
        doc = frappe.get_doc("Raven Message", msg_name)
        self.assertIsNone(doc.text)
        frappe.set_user("Administrator")

    def test_get_all_shows_placeholder(self):
        msg_name = self._create_message("hidden", self.test_user)
        rows = frappe.get_all("Raven Message", filters={"name": msg_name}, fields=["text"])
        self.assertTrue(is_encrypted_placeholder(rows[0]["text"]))

    def test_decrypt_document_fields_batch(self):
        msg1 = self._create_message("first", self.test_user)
        msg2 = self._create_message("second", self.test_user)

        rows = frappe.get_all(
            "Raven Message",
            filters={"name": ["in", [msg1, msg2]]},
            fields=["name", "text"],
        )

        decrypted = decrypt_document_fields(
            rows, "Raven Message", user=self.test_user, skip_permission_check=True
        )
        texts = {d["name"]: d["text"] for d in decrypted}
        self.assertEqual(texts[msg1], "first")
        self.assertEqual(texts[msg2], "second")

    def test_decrypt_document_fields_rejects_non_member(self):
        msg_name = self._create_message("for members only", self.test_user)

        rows = frappe.get_all(
            "Raven Message",
            filters={"name": msg_name},
            fields=["name", "text"],
        )

        decrypted = decrypt_document_fields(
            rows, "Raven Message", user=self.non_member_user, skip_permission_check=False
        )
        self.assertTrue(is_encrypted_placeholder(decrypted[0]["text"]))

    def test_re_save_preserves_encryption(self):
        msg_name = self._create_message("original", self.test_user)
        frappe.set_user(self.test_user)
        doc = frappe.get_doc("Raven Message", msg_name)
        doc.text = "updated"
        doc.save()

        db_value = frappe.db.get_value("Raven Message", msg_name, "text")
        self.assertTrue(is_encrypted_placeholder(db_value))

        doc.reload()
        self.assertEqual(doc.text, "updated")

        keys = frappe.get_all(
            "Encryption Key",
            filters={"ref_doctype": "Raven Message", "ref_docname": msg_name, "fieldname": "text"},
        )
        self.assertEqual(len(keys), 1)

        frappe.set_user("Administrator")

    def test_blind_index_stored_on_message_save(self):
        msg_name = self._create_message("meeting agenda friday", self.test_user)
        key = frappe.db.get_value(
            "Encryption Key",
            {
                "ref_doctype": "Raven Message",
                "ref_docname": msg_name,
                "fieldname": "content",
            },
            "blind_index",
        )
        self.assertIsNotNone(key)
        for word in ["meeting", "agenda", "friday"]:
            h = hashlib.sha256(word.encode()).hexdigest()
            self.assertIn(h, key)

    def test_search_blind_index_finds_message(self):
        msg_name = self._create_message("confidential project plan", self.test_user)
        results = search_blind_index("Raven Message", "content", "project")
        self.assertIn(msg_name, results)

    def test_search_blind_index_multi_word(self):
        msg_name = self._create_message("launch date december", self.test_user)
        results = search_blind_index("Raven Message", "content", "launch december")
        self.assertIn(msg_name, results)

    def test_search_blind_index_no_match(self):
        msg_name = self._create_message("something else", self.test_user)
        results = search_blind_index("Raven Message", "content", "nonexistent")
        self.assertNotIn(msg_name, results)

    def test_search_blind_index_does_not_leak_to_non_member(self):
        msg_name = self._create_message("sensitive data", self.test_user)
        frappe.set_user(self.non_member_user)
        rows = frappe.get_all(
            "Raven Message",
            filters={"name": msg_name},
            fields=["name", "text", "content"],
        )
        decrypted = decrypt_document_fields(
            rows, "Raven Message", user=self.non_member_user, skip_permission_check=False
        )
        self.assertTrue(is_encrypted_placeholder(decrypted[0]["text"]))
        self.assertTrue(is_encrypted_placeholder(decrypted[0]["content"]))
        frappe.set_user("Administrator")
