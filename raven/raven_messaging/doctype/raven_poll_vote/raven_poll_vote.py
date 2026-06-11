# Copyright (c) 2024, The Commit Company and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils.encryption import decrypt_document_fields, search_blind_index


class RavenPollVote(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		from raven.raven_messaging.doctype.raven_poll_vote_selection.raven_poll_vote_selection import (
			RavenPollVoteSelection,
		)

		poll_id: DF.Link
		user_id: DF.Link
		vote_selection: DF.Table[RavenPollVoteSelection]
	# end: auto-generated types

	def before_insert(self):
		poll = frappe.get_cached_doc("Raven Poll", self.poll_id)
		if poll.is_disabled:
			frappe.throw(_("This poll is closed."))

		if not self.vote_selection:
			frappe.throw(_("Please select at least one option."))

		if not poll.is_multi_choice and len(self.vote_selection) > 1:
			frappe.throw(_("This poll only allows one selection."))

		selected_options = [s.option for s in self.vote_selection]
		if len(selected_options) != len(set(selected_options)):
			frappe.throw(_("Cannot select the same option multiple times."))

		# Check user hasn't already voted — blind index lookup on encrypted user_id
		existing_vote_names = search_blind_index("Raven Poll Vote", "user_id", self.user_id)
		if existing_vote_names:
			duplicate = frappe.db.exists(
				"Raven Poll Vote",
				{"name": ["in", list(existing_vote_names)], "poll_id": self.poll_id},
			)
			if duplicate:
				frappe.throw(_("You have already voted in this poll."))

	def validate(self):
		if self.user_id != frappe.session.user:
			frappe.throw(_("You can only vote for yourself."))

	def after_insert(self):
		update_poll_votes(self.poll_id)

	def after_delete(self):
		update_poll_votes(self.poll_id)

	def has_decrypt_permission(self, user=None) -> bool:
		if not user:
			user = frappe.session.user
		return self.owner == user


def update_poll_votes(poll_id):
	"""
	Update vote counts for a poll. Batch-decrypts option field and counts in Python.
	"""
	poll = frappe.get_doc("Raven Poll", poll_id, for_update=True)

	# Fetch all vote selections for this poll (option is encrypted, returns <<encrypted>>)
	vote_names = frappe.db.get_all("Raven Poll Vote", filters={"poll_id": poll_id}, pluck="name")
	if not vote_names:
		vote_map = {}
	else:
		selections = frappe.db.get_all(
			"Raven Poll Vote Selection",
			filters={"parent": ["in", vote_names]},
			fields=["name", "option"],
		)
		# Batch-decrypt the option field
		decrypted = decrypt_document_fields(
			selections, "Raven Poll Vote Selection", fields=["option"], skip_permission_check=True
		)
		vote_map = {}
		for s in decrypted:
			vote_map[s["option"]] = vote_map.get(s["option"], 0) + 1

	for option in poll.options:
		option.votes = vote_map.get(option.name, 0)
		frappe.db.set_value(
			"Raven Poll Option", option.name, "votes", option.votes, update_modified=False
		)

	total_votes = frappe.db.count("Raven Poll Vote", filters={"poll_id": poll_id})
	frappe.db.set_value("Raven Poll", poll_id, "total_votes", total_votes, update_modified=False)
	poll.total_votes = total_votes

	poll.notify_update()
