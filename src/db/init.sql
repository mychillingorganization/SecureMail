-- SecureMail unified PostgreSQL bootstrap schema (base)
-- Source of truth: Alembic revisions under src/db/migrations/versions
-- This script is intended for fresh-machine initialization.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'emailstatus') THEN
        CREATE TYPE emailstatus AS ENUM ('processing', 'completed', 'quarantined');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'verdicttype') THEN
        CREATE TYPE verdicttype AS ENUM ('safe', 'suspicious', 'malicious');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'entitystatus') THEN
        CREATE TYPE entitystatus AS ENUM ('benign', 'suspicious', 'malicious', 'unknown');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'chatrole') THEN
        CREATE TYPE chatrole AS ENUM ('user', 'assistant', 'tool');
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS emails (
    id SERIAL PRIMARY KEY,
    message_id VARCHAR(255),
    sender VARCHAR(255),
    receiver VARCHAR(255),
    status emailstatus NOT NULL,
    total_risk_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    final_verdict verdicttype NOT NULL DEFAULT 'safe',
    correlation_id VARCHAR(36),
    retry_count INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 0,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    agent_name VARCHAR(100) NOT NULL,
    reasoning_trace JSON NOT NULL,
    cryptographic_hash VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS domain_emails (
    domain_email VARCHAR(255) PRIMARY KEY,
    status entitystatus NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS files (
    file_hash VARCHAR(64) PRIMARY KEY,
    status entitystatus NOT NULL,
    file_path VARCHAR(1024),
    risk_level VARCHAR(20),
    first_seen TIMESTAMPTZ,
    last_analyzed TIMESTAMPTZ,
    is_whitelisted BOOLEAN NOT NULL DEFAULT FALSE,
    is_blacklisted BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS urls (
    url_hash VARCHAR(64) PRIMARY KEY,
    raw_url TEXT NOT NULL,
    status entitystatus NOT NULL,
    risk_level VARCHAR(20),
    first_seen TIMESTAMPTZ,
    phishing_target VARCHAR(255),
    last_verified TIMESTAMPTZ,
    is_whitelisted BOOLEAN NOT NULL DEFAULT FALSE,
    is_blacklisted BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS email_urls (
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    url_hash VARCHAR(64) NOT NULL REFERENCES urls(url_hash) ON DELETE CASCADE,
    PRIMARY KEY (email_id, url_hash)
);

CREATE TABLE IF NOT EXISTS email_files (
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    file_hash VARCHAR(64) NOT NULL REFERENCES files(file_hash) ON DELETE CASCADE,
    PRIMARY KEY (email_id, file_hash)
);

CREATE TABLE IF NOT EXISTS scan_history (
    id VARCHAR(36) PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scan_mode VARCHAR(50) NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    sender VARCHAR(255),
    receiver VARCHAR(255),
    final_status VARCHAR(100) NOT NULL,
    issue_count INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    termination_reason VARCHAR(500),
    ai_classify VARCHAR(100),
    ai_reason TEXT,
    ai_summary TEXT,
    ai_provider VARCHAR(100),
    ai_confidence_percent INTEGER,
    execution_logs JSON NOT NULL DEFAULT '[]'::json,
    ai_cot_steps JSON NOT NULL DEFAULT '[]'::json
);

CREATE TABLE IF NOT EXISTS chat_conversations (
    id VARCHAR(36) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_message_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id VARCHAR(36) PRIMARY KEY,
    conversation_id VARCHAR(36) NOT NULL REFERENCES chat_conversations(id) ON DELETE CASCADE,
    role chatrole NOT NULL,
    content TEXT NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'sent',
    tool_name VARCHAR(100),
    tool_payload JSON,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_emails_correlation_id ON emails(correlation_id);
CREATE INDEX IF NOT EXISTS ix_emails_sender ON emails(sender);
CREATE INDEX IF NOT EXISTS ix_emails_processed_at ON emails(processed_at);
CREATE INDEX IF NOT EXISTS ix_audit_logs_email_id ON audit_logs(email_id);
CREATE INDEX IF NOT EXISTS ix_files_is_whitelisted ON files(is_whitelisted);
CREATE INDEX IF NOT EXISTS ix_files_is_blacklisted ON files(is_blacklisted);
CREATE INDEX IF NOT EXISTS ix_urls_is_whitelisted ON urls(is_whitelisted);
CREATE INDEX IF NOT EXISTS ix_urls_is_blacklisted ON urls(is_blacklisted);
CREATE INDEX IF NOT EXISTS ix_scan_history_timestamp ON scan_history(timestamp);
CREATE INDEX IF NOT EXISTS ix_scan_history_scan_mode ON scan_history(scan_mode);
CREATE INDEX IF NOT EXISTS ix_scan_history_sender ON scan_history(sender);
CREATE INDEX IF NOT EXISTS ix_chat_conversations_last_message_at ON chat_conversations(last_message_at);
CREATE INDEX IF NOT EXISTS ix_chat_messages_conversation_id ON chat_messages(conversation_id);
CREATE INDEX IF NOT EXISTS ix_chat_messages_created_at ON chat_messages(created_at);
