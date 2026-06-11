import frappe
from frappe import _
from frappe.utils.encryption import decrypt_document_fields, search_blind_index


@frappe.whitelist(methods=["POST"])
def create_poll(
	channel_id: str,
	question: str,
	options: list,
	is_multi_choice: bool = None,
	is_anonymous: bool = None,
	end_date: str = None,
) -> str:
	"""
	Create a new poll in the Raven Poll doctype.
	"""
	if not frappe.has_permission(doctype="Raven Channel", doc=channel_id, ptype="read"):
		frappe.throw(_("You do not have permission to access this channel"), frappe.PermissionError)

	poll = frappe.get_doc(
		{
			"doctype": "Raven Poll",
			"question": question,
			"is_multi_choice": is_multi_choice,
			"is_anonymous": is_anonymous,
			"end_date": end_date,
			"channel_id": channel_id,
		}
	)

	for option in options:
		poll.append("options", option)

	poll.insert()

	poll_message_content = f"{question}\n"

	for index, option in enumerate(options):
		poll_message_content += f"{index + 1}. {option['option']}\n"

	message = frappe.get_doc(
		{
			"doctype": "Raven Message",
			"channel_id": channel_id,
			"text": "",
			"content": poll_message_content,
			"message_type": "Poll",
			"poll_id": poll.name,
		}
	)
	message.insert()

	return poll.name


@frappe.whitelist()
def get_poll(message_id: str):
	"""
	Get the poll data including the user's current vote selections.
	Uses blind index to look up the current user's votes (user_id is encrypted).
	"""
	if not frappe.has_permission(doctype="Raven Message", doc=message_id, ptype="read"):
		frappe.throw(_("You do not have permission to access this message"), frappe.PermissionError)

	poll_id = frappe.get_cached_value("Raven Message", message_id, "poll_id")
	poll = frappe.get_cached_doc("Raven Poll", poll_id)

	# Look up current user's votes via blind index (user_id is encrypted)
	vote_names = search_blind_index("Raven Poll Vote", "user_id", frappe.session.user)
	if vote_names:
		user_votes = frappe.db.get_all(
			"Raven Poll Vote",
			filters={"name": ["in", list(vote_names)], "poll_id": poll_id},
			pluck="name",
		)
		if user_votes:
			selections = frappe.db.get_all(
				"Raven Poll Vote Selection",
				filters={"parent": ["in", user_votes]},
				fields=["name", "option"],
			)
			current_user_votes = decrypt_document_fields(
				selections, "Raven Poll Vote Selection", fields=["option"], skip_permission_check=True
			)
		else:
			current_user_votes = []
	else:
		current_user_votes = []

	return {"poll": poll, "current_user_votes": current_user_votes}


@frappe.whitelist(methods=["POST"])
def add_vote(message_id: str, option_id: str | list):
	if not frappe.has_permission(doctype="Raven Message", doc=message_id, ptype="read"):
		frappe.throw(_("You do not have permission to access this message"), frappe.PermissionError)

	poll_id = frappe.get_cached_value("Raven Message", message_id, "poll_id")
	is_poll_multi_choice = frappe.get_cached_value("Raven Poll", poll_id, "is_multi_choice")
	is_disabled = frappe.get_cached_value("Raven Poll", poll_id, "is_disabled")

	if is_disabled:
		frappe.throw(_("This poll is closed and no longer accepting votes"), frappe.PermissionError)

	options = option_id if isinstance(option_id, list) else [option_id]

	if not is_poll_multi_choice and len(options) > 1:
		frappe.throw(_("This poll only allows one selection."))

	vote = frappe.get_doc(
		{
			"doctype": "Raven Poll Vote",
			"poll_id": poll_id,
			"user_id": frappe.session.user,
			"vote_selection": [{"option": opt} for opt in options],
		}
	)
	vote.insert()

	return "Vote added successfully."


@frappe.whitelist(methods=["POST"])
def retract_vote(poll_id: str):
	user = frappe.session.user

	is_disabled = frappe.get_cached_value("Raven Poll", poll_id, "is_disabled")
	if is_disabled:
		frappe.throw(
			_("This poll is closed and you can no longer retract your vote"), frappe.PermissionError
		)

	# Blind index lookup for encrypted user_id
	vote_names = search_blind_index("Raven Poll Vote", "user_id", user)
	if vote_names:
		votes = frappe.get_all(
			"Raven Poll Vote",
			filters={"name": ["in", list(vote_names)], "poll_id": poll_id},
			fields=["name"],
		)
	else:
		votes = []

	if not votes:
		frappe.throw(_("You have not voted for any option in this poll."))
	else:
		for vote in votes:
			frappe.delete_doc("Raven Poll Vote", vote.name)


@frappe.whitelist()
def get_all_votes(poll_id: str):
	if not frappe.has_permission(doctype="Raven Poll", doc=poll_id, ptype="read"):
		frappe.throw(_("You do not have permission to access this poll"), frappe.PermissionError)

	poll_doc = frappe.get_cached_doc("Raven Poll", poll_id)

	if poll_doc.is_anonymous:
		frappe.throw(
			_("This poll is anonymous. You do not have permission to access the votes."),
			frappe.PermissionError,
		)

	# Get all votes (encrypted fields return <<encrypted>>)
	votes = frappe.db.get_all(
		"Raven Poll Vote",
		filters={"poll_id": poll_id},
		fields=["name", "user_id"],
	)

	if not votes:
		return {}

	# Batch-decrypt user_id
	decrypted_votes = decrypt_document_fields(
		votes, "Raven Poll Vote", fields=["user_id"], skip_permission_check=True
	)

	# Get selections for these votes
	vote_names = [v["name"] for v in decrypted_votes]
	selections = frappe.db.get_all(
		"Raven Poll Vote Selection",
		filters={"parent": ["in", vote_names]},
		fields=["name", "parent", "option"],
	)

	# Batch-decrypt option
	decrypted_selections = decrypt_document_fields(
		selections, "Raven Poll Vote Selection", fields=["option"], skip_permission_check=True
	)

	# Build user → option mapping
	vote_map = {v["name"]: v["user_id"] for v in decrypted_votes}

	results = {
		option.name: {"users": [], "count": option.votes} for option in poll_doc.options if option.votes
	}

	for sel in decrypted_selections:
		option = sel["option"]
		uid = vote_map.get(sel["parent"], "?")
		if option in results:
			results[option]["users"].append(uid)

	total_votes = poll_doc.total_votes or 0
	for result in results.values():
		if total_votes > 0:
			result["percentage"] = (result["count"] / total_votes) * 100
		else:
			result["percentage"] = 0

	return results


@frappe.whitelist(methods=["POST"])
def close_poll(poll_id: str):
	poll_owner = frappe.get_cached_value("Raven Poll", poll_id, "owner")
	is_poll_closed = frappe.get_cached_value("Raven Poll", poll_id, "is_disabled")

	if poll_owner != frappe.session.user:
		frappe.throw(_("Only the poll owner can close the poll"), frappe.PermissionError)

	if is_poll_closed:
		frappe.throw(_("This poll is already closed"), frappe.PermissionError)

	frappe.db.set_value("Raven Poll", poll_id, "is_disabled", 1)

	frappe.publish_realtime(
		"doc_update",
		{"doctype": "Raven Poll", "name": poll_id},
		doctype="Raven Poll",
		docname=poll_id,
		after_commit=True,
	)

	return "Poll closed successfully."
