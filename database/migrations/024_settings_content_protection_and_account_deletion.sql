-- ============================================================
-- LOVEMI MIGRATION 024
-- SETTINGS CONTENT PROTECTION + SECURE ACCOUNT DELETION
-- ============================================================

SET FOREIGN_KEY_CHECKS = 0;

-- ============================================================
-- 1. POST PROTECTION COLUMNS
-- ============================================================

ALTER TABLE posts

    ADD COLUMN IF NOT EXISTS allow_repost
        TINYINT(1) NOT NULL DEFAULT 1
        AFTER visibility,

    ADD COLUMN IF NOT EXISTS allow_video_download
        TINYINT(1) NOT NULL DEFAULT 1
        AFTER allow_repost,

    ADD COLUMN IF NOT EXISTS media_protection_enabled
        TINYINT(1) NOT NULL DEFAULT 0
        AFTER allow_video_download,

    ADD COLUMN IF NOT EXISTS media_password_hash
        VARCHAR(255) DEFAULT NULL
        AFTER media_protection_enabled;


-- ============================================================
-- 2. USER CONTENT SECURITY DEFAULTS
-- ============================================================

CREATE TABLE IF NOT EXISTS user_content_security (

    user_id
        BIGINT UNSIGNED NOT NULL,

    default_allow_repost
        TINYINT(1) NOT NULL DEFAULT 1,

    default_allow_video_download
        TINYINT(1) NOT NULL DEFAULT 1,

    created_at
        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at
        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (user_id),

    CONSTRAINT fk_user_content_security_user

        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- ============================================================
-- 3. ACCOUNT DELETION VERIFICATION
-- ============================================================

CREATE TABLE IF NOT EXISTS account_deletion_verifications (

    id
        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    user_id
        BIGINT UNSIGNED NOT NULL,

    code_hash
        CHAR(64) NOT NULL,

    link_token_hash
        CHAR(64) NOT NULL,

    code_expires_at
        DATETIME NOT NULL,

    link_expires_at
        DATETIME NOT NULL,

    code_attempts
        INT UNSIGNED NOT NULL DEFAULT 0,

    link_attempts
        INT UNSIGNED NOT NULL DEFAULT 0,

    link_verified
        TINYINT(1) NOT NULL DEFAULT 0,

    email_verified
        TINYINT(1) NOT NULL DEFAULT 0,

    two_factor_verified
        TINYINT(1) NOT NULL DEFAULT 0,

    created_at
        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at
        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    used_at
        DATETIME DEFAULT NULL,

    PRIMARY KEY (id),

    KEY idx_account_delete_user
        (user_id),

    KEY idx_account_delete_link
        (link_token_hash),

    CONSTRAINT fk_account_delete_user

        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- ============================================================
-- 4. INITIALIZE DEFAULT SECURITY ROWS
-- ============================================================

INSERT INTO user_content_security
(
    user_id,
    default_allow_repost,
    default_allow_video_download
)

SELECT
    id,
    1,
    1

FROM users

ON DUPLICATE KEY UPDATE
    user_id = VALUES(user_id);


SET FOREIGN_KEY_CHECKS = 1;