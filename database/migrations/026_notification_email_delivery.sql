-- ============================================================
-- LOVEMI - NOTIFICATION EMAIL DELIVERY TRACKING
-- Migration: 026
-- ============================================================

ALTER TABLE notifications

    ADD COLUMN email_sent_at DATETIME NULL
        AFTER created_at,

    ADD COLUMN email_attempted_at DATETIME NULL
        AFTER email_sent_at,

    ADD COLUMN email_attempts INT UNSIGNED NOT NULL DEFAULT 0
        AFTER email_attempted_at,

    ADD COLUMN email_last_error VARCHAR(1000) NULL
        AFTER email_attempts;


CREATE INDEX idx_notifications_email_dispatch
    ON notifications (
        user_id,
        email_sent_at,
        email_attempted_at,
        id
    );