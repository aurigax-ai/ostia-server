package store

const schemaV1 = `
CREATE TABLE accounts (
	id TEXT PRIMARY KEY,
	provider TEXT NOT NULL,
	provider_id_hash TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	publish_disabled INTEGER NOT NULL DEFAULT 0,
	UNIQUE (provider, provider_id_hash)
);
CREATE TABLE devices (
	id TEXT PRIMARY KEY,
	account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	sign_pub BLOB NOT NULL,
	box_pub BLOB NOT NULL,
	created_at INTEGER NOT NULL,
	last_seen INTEGER NOT NULL,
	revoked_at INTEGER NOT NULL DEFAULT 0,
	last_signed_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX devices_account ON devices(account_id);
CREATE TABLE sessions (
	token_hash BLOB PRIMARY KEY,
	device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	expires_at INTEGER NOT NULL,
	elevated_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE approvals (
	id TEXT PRIMARY KEY,
	account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	requester_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	requester_token_hash BLOB NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	approved_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX approvals_account ON approvals(account_id);
CREATE INDEX sessions_device ON sessions(device_id);
CREATE TABLE invites (
	code_hash BLOB PRIMARY KEY,
	account_id TEXT REFERENCES accounts(id) ON DELETE CASCADE,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	used_at INTEGER NOT NULL DEFAULT 0,
	elevated INTEGER NOT NULL DEFAULT 0,
	hint TEXT NOT NULL DEFAULT '',
	created_account TEXT REFERENCES accounts(id) ON DELETE SET NULL
);
CREATE INDEX invites_created_account ON invites(created_account);
CREATE TABLE device_seen (
	viewer_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	PRIMARY KEY (viewer_device_id, device_id)
);
CREATE TABLE key_wraps (
	account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	slot TEXT NOT NULL,
	blob BLOB NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (account_id, slot)
);
CREATE TABLE sync_manifests (
	account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	version INTEGER NOT NULL,
	blob BLOB NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (account_id, version)
);
CREATE TABLE sync_blobs (
	account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	blob_id TEXT NOT NULL,
	size INTEGER NOT NULL,
	sha256 BLOB NOT NULL,
	created_at INTEGER NOT NULL,
	PRIMARY KEY (account_id, blob_id)
);
CREATE TABLE relay_labels (
	label TEXT PRIMARY KEY,
	device_id TEXT NOT NULL UNIQUE REFERENCES devices(id) ON DELETE CASCADE,
	account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	bytes_month INTEGER NOT NULL DEFAULT 0,
	month TEXT NOT NULL DEFAULT ''
);
CREATE INDEX relay_labels_account ON relay_labels(account_id);
CREATE TABLE shares (
	id TEXT PRIMARY KEY,
	account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	mode TEXT NOT NULL,
	salt BLOB,
	size INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	views INTEGER NOT NULL DEFAULT 0,
	delete_token_hash BLOB NOT NULL,
	uploaded_at INTEGER NOT NULL DEFAULT 0,
	removed_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX shares_account ON shares(account_id);
CREATE TABLE reports (
	share_id TEXT NOT NULL,
	reason_code TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX reports_share ON reports(share_id);
CREATE TABLE push_handles (
	handle TEXT PRIMARY KEY,
	account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	platform TEXT NOT NULL,
	token_sealed BLOB NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX push_handles_account ON push_handles(account_id);
CREATE TABLE push_tickets (
	hash BLOB PRIMARY KEY,
	account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	expires_at INTEGER NOT NULL
);
CREATE TABLE admin_codes (
	code_hash BLOB PRIMARY KEY,
	hint TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	used_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE admin_sessions (
	token_hash BLOB PRIMARY KEY,
	admin TEXT NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE TABLE admin_audit (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	at INTEGER NOT NULL,
	admin TEXT NOT NULL,
	action TEXT NOT NULL,
	target TEXT NOT NULL DEFAULT ''
);
`
