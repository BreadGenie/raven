# Raven Message Encryption — App Spec

Status: **Draft — 2026-06-10**

## R1. Objective

Add at-rest encryption to Raven messages so that:
- **Raw DB access** cannot read message content (ciphertext in DB).
- **Desk admins** who are not channel members cannot decrypt message content.
- **All existing features** work: search, push notifications, AI bots, link previews.

This spec builds on top of the Frappe framework's [Encrypted Fields spec](../frappe/specs/encrypted-field-spec.md).

## R2. Threat Model

| Threat | Protected? | How |
|---|---|---|
| Raw SQL SELECT on `tabRaven Message` | ✅ | Fields are `<<encrypted>>` placeholders; real data in `tabEncryption Keys` |
| DB dump / backup read | ✅ | Ciphertext only |
| Desk: System Manager reads Raven Message list | ✅ | `has_decrypt_permission` gates decryption |
| Desk: Raven Admin reads Raven Message list | ✅ | Same gate |
| Desk: Channel member reads message | ✅ | Has channel membership → can decrypt |
| Server compromise (runtime) | ❌ | Server has KEK in memory; can decrypt for authorized users |
| Server filesystem + DB dump (offline) | ❌ | KEK is in env var or site_config, but DB alone is not enough |

## R3. Fields to Encrypt

| DocType | Field | Current Type | Encrypted? | Notes |
|---|---|---|---|---|
| Raven Message | `text` | Long Text | ✅ | Rich HTML content |
| Raven Message | `content` | Long Text | ✅ | Plain-text extract (also encrypted — derived from text) |
| Raven Message | `json` | JSON | ✅ | Structured content payload |
| Raven Message | `replied_message_details` | JSON | ❌ | Metadata, not message content |
| Raven Message | `message_reactions` | JSON | ❌ | Aggregated reaction data |
| Raven Message | `file_thumbnail` | Attach | ❌ | File metadata, not message content |
| Raven Message | `blurhash` | Small Text | ❌ | Image placeholder |
| Raven Mention | `*` | — | ❌ | Only contains channel_id, not message text |
| Raven Channel | `channel_name` | Data | ❌ | Channel names are not sensitive |

## R4. Decryption Permission

### R4.1 Override `has_decrypt_permission`

```python
# raven/permissions.py

def raven_message_has_decrypt_permission(doc, user=None):
    if not user:
        user = frappe.session.user

    if not doc.channel_id:
        return False

    channel = frappe.get_cached_doc("Raven Channel", doc.channel_id)
    return channel.is_member(user)
```

### R4.2 Registration

In `hooks.py`:
```python
doc_events = {
    "Raven Message": {
        "has_decrypt_permission": "raven.permissions.raven_message_has_decrypt_permission"
    }
}
```

### R4.3 Admins

- `System Manager` and `Raven Admin` without channel membership see `<<encrypted>>` in Desk.
- Raven can optionally add a "break-glass" override that logs the action.

## R5. Search — Blind Index

### R5.1 Problem

Messages cannot be searched via SQL WHERE on encrypted fields. Raven currently relies on the `content` field (plaintext extract) for message search/previews.

### R5.2 Solution: Trigram Blind Index

Instead of a sidecar search index, Raven uses the framework's blind index feature (§9 in Frappe spec). This stores trigram SHA-256 hashes on each `Encryption Key` row, enabling substring search without exposing plaintext.

**How it works:**

During `store_encrypted_fields()`, the framework computes:

```python
padded = f"^{plaintext.lower()}$"   # pad with ^ and $
trigrams = {padded[i:i+3] for i in range(len(padded) - 2)}
blind_index = " ".join(sorted(sha256(t) for t in trigrams))
```

Each Encryption Key row stores `blind_index` — a space-separated list of hashed trigrams.

**Search query:**

```python
def get_messages(channel_id, search_query=None, ...):
    if search_query:
        # Step 1: Use blind index to find matching message names
        message_ids = frappe.utils.encryption.search_blind_index(
            "Raven Message", "content", search_query
        )
        if not message_ids:
            return []

        # Step 2: Fetch + batch decrypt
        rows = frappe.db.get_all(
            "Raven Message",
            filters={"name": ("in", list(message_ids)), "channel_id": channel_id},
            fields=["*"],
            order_by="creation desc",
        )
        return frappe.utils.encryption.decrypt_document_fields(
            rows, "Raven Message", skip_permission_check=True
        )
```

**Advantages over sidecar index:**
- No separate DocType to maintain
- No `after_insert`/`on_update` hooks needed — blind index is computed automatically during encryption
- Always in sync with encrypted data (stored on the same row in `tabEncryption Key`)
- Substring search support via trigrams (e.g., "ello" matches "hello world")

**Limitations:**
- Minimum 3-character query (single trigram)
- False positives are theoretically possible but astronomically unlikely (SHA-256 collision)

## R6. Chat Stream API Changes

All message-loading APIs (`get_messages`, `get_older_messages`, `get_newer_messages`, `get_pinned_messages`, `get_saved_messages`, `get_mentions`, thread APIs, search, timeline) currently do raw `frappe.db.sql` or `frappe.db.get_all` — they read ciphertext directly.

### R6.1 Pattern

Switch from raw DB queries to `frappe.get_doc()` + batch decrypt:

```python
# raven/api/chat_stream.py

def get_messages(channel_id, ...):
    # Step 1: Fast DB query to get message names + ordering
    rows = frappe.db.get_all(
        "Raven Message",
        filters={"channel_id": channel_id},
        fields=["name"],
        order_by="creation desc",
        limit=20,
    )

    # Step 2: Fetch full documents with decryption
    # (option A — use get_doc for each; fine for small batches)
    messages = [frappe.get_doc("Raven Message", r.name) for r in rows]
    # get_doc handles permission check + decryption per doc

    return messages
```

For performance-sensitive paths, use the batch utility instead:

```python
def get_messages(channel_id, ...):
    rows = frappe.db.get_all(
        "Raven Message",
        filters={"channel_id": channel_id},
        fields=["*"],
        order_by="creation desc",
        limit=20,
    )
    # Batch decrypt in 3 queries total
    messages = frappe.decrypt_document_fields(
        rows, doctype="Raven Message"
    )
    return messages
```

### R6.2 Search via index

When a search query is present, query the search index first, then fetch + decrypt:

```python
def get_messages(channel_id, search_query, ...):
    message_ids = frappe.db.get_all(
        "Raven Message Search Index",
        filters={
            "channel_id": channel_id,
            "content": ("like", f"%{search_query}%"),
        },
        pluck="message_id",
    )
    rows = frappe.db.get_all(
        "Raven Message",
        filters={"name": ("in", message_ids), "channel_id": channel_id},
        fields=["*"],
        order_by="creation desc",
    )
    return frappe.decrypt_document_fields(rows, "Raven Message")
```

### R6.3 Realtime events (`message_created`, `message_edited`)

Events carry **decrypted** content in their payload. The server has plaintext in memory during `after_insert`/`on_update`, so no extra decrypt cost.

```python
# raven_message.py — in publish_real_time()

def publish_message_created(self):
    message_details = {
        "text": self.text,           # plaintext — still in memory
        "content": self.content,     # plaintext
        "json": self.json,
        # ... other fields ...
    }
    frappe.publish_realtime(
        "message_created",
        message={"channel_id": self.channel_id, **message_details},
        room=f"raven_channel:{self.channel_id}",
    )
```

**Rationale:** The Socket.IO room is gated by channel membership — the same gate used by `has_decrypt_permission`. Adding a fetch round-trip just for content provides no meaningful security gain.

### R6.4 `last_message_details` (sidebar preview)

The `last_message_details` JSON stored on `Raven Channel` contains **plaintext** `content`. It is populated during `after_insert` while plaintext is in memory:

```python
# raven_message.py — set_last_message_timestamp()

message_details = json.dumps({
    "message_id": self.name,
    "content": self.content,         # plaintext — metadata concern
    "message_type": self.message_type,
    "owner": self.owner,
    "is_bot_message": self.is_bot_message,
    "bot": self.bot,
})
```

**Rationale:** The sidebar preview shows "there was a message" + a snippet — same exposure level as the channel name and member list. The full message content is what's protected by encryption.

## R7. Push Notifications

### R7.1 Problem

Push notifications need a plaintext preview/snippet of the message. If the message is encrypted, the notification sender can't read it.

### R7.2 Solution

Extract the notification preview **before** encryption — during `after_insert` when plaintext is still in memory.

```python
def after_insert(self):
    # ... existing logic ...
    # Build notification preview before encryption context is lost
    preview = self.content or frappe.utils.strip_html(self.text)
    if preview:
        self._send_push_notification(preview)
```

The `preview` is sent to the push service (FCM / Raven Cloud) as plaintext, which is unavoidable — push services see notification content in any messaging app.

## R8. AI Bots

AI bot handlers run in `after_insert` / `on_update`, where plaintext is still available in memory (see §6 save flow — in-memory value is NOT replaced with `<<encrypted>>`). Handlers read `doc.text` / `doc.content` directly, with no code change needed.

## R9. Link Previews and Content Extraction

Raven extracts links and generates previews in `parse_html_content()` during `before_validate`. This runs **before** encryption, so it has access to plaintext. The extracted `links` field and preview data are stored as plaintext (not sensitive).

## R10. File Attachments

File attachments are stored via Frappe's `Attach` fieldtype, which stores a file path in the DB (not the file content). The files themselves are on disk or S3.

**For v1:** Files are not encrypted. Only message text is encrypted.

**For v2 (future):** Encrypt file contents at rest with a per-file DEK. File DEK wrapped with channel key.

## R11. Migration

### R11.1 Existing Messages

Run `bench encrypt-field "Raven Message" text`, `bench encrypt-field "Raven Message" content`, and `bench encrypt-field "Raven Message" json`.

This batch-encrypts all existing messages. For a large Raven database, this can be run during maintenance or on a replica.

### R11.2 New Messages

Encryption happens transparently via the framework hook — no code change needed in `send_message` API.

## R12. Special Cases

### R12.1 Forward Message

Currently, `forward_message` copies `text`, `content`, `json` from the source message dict onto a new document. After encryption, the source fields are ciphertext.

**Solution:** Load the source message via `frappe.get_doc()` (which decrypts), then use the plaintext to create the new message. The framework encrypts on save automatically.

```python
# raven/api/raven_message.py

@frappe.whitelist(methods=["POST"])
def forward_message(channel_id, message_id):
    source = frappe.get_doc("Raven Message", message_id)
    # source.text, source.content, source.json are plaintext after get_doc
    new_doc = frappe.get_doc({
        "doctype": "Raven Message",
        "channel_id": channel_id,
        "text": source.text,          # plaintext
        "content": source.content,    # plaintext
        "json": source.json,
        "is_forwarded": 1,
        "message_type": source.message_type,
    })
    new_doc.insert()
    return new_doc
```

### R12.2 Migration Patches

Raven has DB patches that read/write `text` and `content` directly via `frappe.db.sql`. After encryption, these would read ciphertext and write back ciphertext — corrupting the data.

**Solution:** Patches must use `frappe.get_doc()` to read (which decrypts) and `doc.save()` to write (which encrypts). For example, `update_all_messages_to_include_message_content.py` should iterate via `frappe.get_all("Raven Message", pluck="name")` and process each doc through `frappe.get_doc()`.

### R12.3 Outgoing Webhooks

Frappe Webhooks triggered by `raven_webhook` deliver the Raven Message document to external URLs. If the webhook data includes `text`/`content`/`json`, these will arrive as `<<encrypted>>` placeholders.

**Solution:** The Frappe webhook delivery system uses `frappe.get_doc()` to build the payload, which automatically decrypts (with System Manager bypass). No code change needed — field values arrive as plaintext to the external URL.

Webhook operators should be aware: the webhook receiver has access to decrypted message content, equivalent to System Manager.

### R12.4 Frappe Timeline

`get_timeline_message_content()` reads `message.text` via `frappe.db.get_value`. After encryption, this returns `<<encrypted>>`.

**Solution:** Use `frappe.get_doc("Raven Message", name).text` instead of the raw DB query. The document load triggers decryption (permission gated by channel membership).

## R13. Audit Log

Raven adds a structured audit log for message decryption:

| Event | Data |
|---|---|
| Message decrypted | `{user, message_id, channel_id, timestamp}` |
| Decryption denied | `{user, message_id, channel_id, timestamp, reason}` |
| Batch encrypt run | `{user, doctype, fieldname, count, timestamp}` |

Enable via Raven Settings checkbox `enable_audit_logging`.

## R14. Implementation Order

| Step | What | Depends on |
|---|---|---|
| 1 | Frappe framework: `tabEncryption Keys` table + field property | — |
| 2 | Frappe framework: encrypt on save, decrypt on load | Step 1 |
| 3 | Frappe framework: `has_decrypt_permission` hook + `decrypt_document_fields()` | Step 2 |
| 4 | Raven: permission override in `permissions.py` | Step 3 |
| 5 | Raven: field config — mark `text`, `content`, `json` as `encrypted` | Step 3 |
| 6 | Raven: update chat stream APIs to use `get_doc()` or `decrypt_document_fields()` | Step 3 |
| 7 | Raven: update timeline, mentions, threads APIs to use decryption | Step 6 |
| 8 | Raven: search index DocType + `_build_search_index()` hook | Step 5 |
| 9 | Raven: update `get_messages` search path to use search index | Step 8 |
| 10 | Raven: update `forward_message` to load source via `get_doc()` | Step 6 |
| 11 | Raven: patch migration patches to use `get_doc()` | Step 6 |
| 12 | Migration: `bench encrypt-field "Raven Message" text content json` | Step 5 |
| 13 | Audit logging | Step 4 |
