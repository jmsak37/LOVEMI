-- ============================================================
-- LOVEMI
-- 023_create_profile_access_codes.sql
-- ============================================================

CREATE TABLE IF NOT EXISTS profile_access_codes (
    id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,

    user_id BIGINT(20) UNSIGNED NOT NULL,

    code_hash CHAR(64) NOT NULL,

    encrypted_payload TEXT NOT NULL,

    code_version TINYINT(3) UNSIGNED NOT NULL DEFAULT 1,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    expires_at DATETIME DEFAULT NULL,

    revoked_at DATETIME DEFAULT NULL,

    last_used_at DATETIME DEFAULT NULL,

    PRIMARY KEY (id),

    UNIQUE KEY uq_profile_access_codes_hash (code_hash),

    KEY idx_profile_access_codes_user_id (user_id),

    KEY idx_profile_access_codes_expires_at (expires_at),

    KEY idx_profile_access_codes_revoked_at (revoked_at),

    CONSTRAINT fk_profile_access_codes_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE

) ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;