-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Aug 27, 2026 at 02:33 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `lovemi`
--

-- --------------------------------------------------------

--
-- Table structure for table `audit_logs`
--

CREATE TABLE `audit_logs` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED DEFAULT NULL,
  `action` varchar(100) NOT NULL,
  `entity_type` varchar(80) DEFAULT NULL,
  `entity_id` bigint(20) UNSIGNED DEFAULT NULL,
  `old_values` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`old_values`)),
  `new_values` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`new_values`)),
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `audit_logs`
--

INSERT INTO `audit_logs` (`id`, `user_id`, `action`, `entity_type`, `entity_id`, `old_values`, `new_values`, `ip_address`, `user_agent`, `created_at`) VALUES
(1, NULL, 'registration', 'user', 1, NULL, '{\"role\":\"admin\",\"account_status\":\"pending\"}', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-26 19:53:43'),
(2, NULL, 'registration', 'user', 2, NULL, '{\"role\":\"admin\",\"account_status\":\"pending\"}', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 10:46:40'),
(3, 3, 'registration', 'user', 3, NULL, '{\"role\":\"admin\",\"account_status\":\"pending\"}', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 11:19:45'),
(4, 4, 'registration', 'user', 4, NULL, '{\"role\":\"member\",\"account_status\":\"pending\"}', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 12:15:41');

-- --------------------------------------------------------

--
-- Table structure for table `backup_logs`
--

CREATE TABLE `backup_logs` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `created_by` bigint(20) UNSIGNED DEFAULT NULL,
  `file_name` varchar(255) DEFAULT NULL,
  `file_path` varchar(500) DEFAULT NULL,
  `status` varchar(30) NOT NULL DEFAULT 'created',
  `file_size` bigint(20) UNSIGNED DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `blocked_users`
--

CREATE TABLE `blocked_users` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `blocked_user_id` bigint(20) UNSIGNED NOT NULL,
  `reason` varchar(255) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `connections`
--

CREATE TABLE `connections` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `connected_user_id` bigint(20) UNSIGNED NOT NULL,
  `initiated_by` bigint(20) UNSIGNED NOT NULL,
  `status` varchar(30) NOT NULL DEFAULT 'pending',
  `connected_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `user_low_id` bigint(20) UNSIGNED GENERATED ALWAYS AS (least(`user_id`,`connected_user_id`)) STORED,
  `user_high_id` bigint(20) UNSIGNED GENERATED ALWAYS AS (greatest(`user_id`,`connected_user_id`)) STORED
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Triggers `connections`
--
DELIMITER $$
CREATE TRIGGER `trg_connection_create_conversation` AFTER INSERT ON `connections` FOR EACH ROW BEGIN

    IF NEW.status = 'accepted'
       OR NEW.status = 'connected' THEN

        INSERT INTO conversations
        (
            connection_id,
            user_one_id,
            user_two_id,
            status
        )
        VALUES
        (
            NEW.id,
            NEW.user_id,
            NEW.connected_user_id,
            'active'
        )
        ON DUPLICATE KEY UPDATE
            connection_id = VALUES(connection_id),
            status = 'active';

    END IF;

END
$$
DELIMITER ;
DELIMITER $$
CREATE TRIGGER `trg_connection_notification` AFTER INSERT ON `connections` FOR EACH ROW BEGIN

    IF
        NEW.status IN ('accepted', 'connected')
    THEN

        INSERT INTO notifications
        (
            user_id,
            notification_type_id,
            sender_id,
            title,
            message
        )

        SELECT
            NEW.user_id,
            nt.id,
            NEW.connected_user_id,
            'New Connection',
            CONCAT(
                'You are now connected with another LOVEMI member.'
            )

        FROM notification_types nt

        WHERE nt.slug = 'new_connection'

        LIMIT 1;


        INSERT INTO notifications
        (
            user_id,
            notification_type_id,
            sender_id,
            title,
            message
        )

        SELECT
            NEW.connected_user_id,
            nt.id,
            NEW.user_id,
            'New Connection',
            CONCAT(
                'You are now connected with another LOVEMI member.'
            )

        FROM notification_types nt

        WHERE nt.slug = 'new_connection'

        LIMIT 1;

    END IF;

END
$$
DELIMITER ;
DELIMITER $$
CREATE TRIGGER `trg_connection_status_update` BEFORE UPDATE ON `connections` FOR EACH ROW BEGIN

    IF
        NEW.status IN ('accepted', 'connected')
        AND OLD.status NOT IN ('accepted', 'connected')
    THEN

        SET NEW.connected_at =
            COALESCE(
                NEW.connected_at,
                CURRENT_TIMESTAMP
            );

    END IF;

END
$$
DELIMITER ;
DELIMITER $$
CREATE TRIGGER `trg_prevent_self_connection` BEFORE INSERT ON `connections` FOR EACH ROW BEGIN

    IF NEW.user_id = NEW.connected_user_id THEN

        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT =
            'A user cannot connect with their own account.';

    END IF;

END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `conversations`
--

CREATE TABLE `conversations` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `connection_id` bigint(20) UNSIGNED DEFAULT NULL,
  `user_one_id` bigint(20) UNSIGNED NOT NULL,
  `user_two_id` bigint(20) UNSIGNED NOT NULL,
  `status` varchar(30) NOT NULL DEFAULT 'active',
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `user_low_id` bigint(20) UNSIGNED GENERATED ALWAYS AS (least(`user_one_id`,`user_two_id`)) STORED,
  `user_high_id` bigint(20) UNSIGNED GENERATED ALWAYS AS (greatest(`user_one_id`,`user_two_id`)) STORED
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `countries`
--

CREATE TABLE `countries` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `name` varchar(120) NOT NULL,
  `iso2` char(2) NOT NULL,
  `iso3` char(3) DEFAULT NULL,
  `phone_code` varchar(10) NOT NULL,
  `currency_id` bigint(20) UNSIGNED DEFAULT NULL,
  `flag_code` varchar(10) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `countries`
--

INSERT INTO `countries` (`id`, `name`, `iso2`, `iso3`, `phone_code`, `currency_id`, `flag_code`, `is_active`, `created_at`, `updated_at`) VALUES
(1, 'Kenya', 'KE', 'KEN', '+254', 2, 'KE', 1, '2026-08-26 17:05:54', '2026-08-26 19:43:59'),
(2, 'United States', 'US', 'USA', '+1', 1, 'US', 1, '2026-08-26 17:05:54', '2026-08-26 19:43:59'),
(3, 'United Kingdom', 'GB', 'GBR', '+44', 4, 'GB', 1, '2026-08-26 17:05:54', '2026-08-26 19:43:59'),
(4, 'Tanzania, United Republic of', 'TZ', 'TZA', '+255', 6, 'TZ', 1, '2026-08-26 17:05:54', '2026-08-26 19:43:59'),
(5, 'Uganda', 'UG', 'UGA', '+256', 5, 'UG', 1, '2026-08-26 17:05:54', '2026-08-26 19:43:59'),
(6, 'Nigeria', 'NG', 'NGA', '+234', 7, 'NG', 1, '2026-08-26 17:05:54', '2026-08-26 19:43:59'),
(7, 'South Africa', 'ZA', 'ZAF', '+27', 8, 'ZA', 1, '2026-08-26 17:05:54', '2026-08-26 19:43:59'),
(8, 'Germany', 'DE', 'DEU', '+49', 3, 'DE', 1, '2026-08-26 17:05:54', '2026-08-26 19:43:59'),
(9, 'Andorra', 'AD', 'AND', '+376', 3, 'AD', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(10, 'United Arab Emirates', 'AE', 'ARE', '+971', 9, 'AE', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(11, 'Afghanistan', 'AF', 'AFG', '+93', 10, 'AF', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(12, 'Antigua and Barbuda', 'AG', 'ATG', '+1268', 11, 'AG', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(13, 'Anguilla', 'AI', 'AIA', '+1264', 11, 'AI', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(14, 'Albania', 'AL', 'ALB', '+355', 12, 'AL', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(15, 'Armenia', 'AM', 'ARM', '+374', 13, 'AM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(16, 'Angola', 'AO', 'AGO', '+244', 14, 'AO', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(17, 'Antarctica', 'AQ', 'ATA', '+672', NULL, 'AQ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(18, 'Argentina', 'AR', 'ARG', '+54', 15, 'AR', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(19, 'American Samoa', 'AS', 'ASM', '+1684', 1, 'AS', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(20, 'Austria', 'AT', 'AUT', '+43', 3, 'AT', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(21, 'Australia', 'AU', 'AUS', '+61', 16, 'AU', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(22, 'Aruba', 'AW', 'ABW', '+297', 17, 'AW', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(23, 'Åland Islands', 'AX', 'ALA', '+358', 3, 'AX', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(24, 'Azerbaijan', 'AZ', 'AZE', '+994', 18, 'AZ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(25, 'Bosnia and Herzegovina', 'BA', 'BIH', '+387', 19, 'BA', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(26, 'Barbados', 'BB', 'BRB', '+1246', 20, 'BB', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(27, 'Bangladesh', 'BD', 'BGD', '+880', 21, 'BD', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(28, 'Belgium', 'BE', 'BEL', '+32', 3, 'BE', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(29, 'Burkina Faso', 'BF', 'BFA', '+226', 22, 'BF', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(30, 'Bulgaria', 'BG', 'BGR', '+359', 23, 'BG', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(31, 'Bahrain', 'BH', 'BHR', '+973', 24, 'BH', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(32, 'Burundi', 'BI', 'BDI', '+257', 25, 'BI', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(33, 'Benin', 'BJ', 'BEN', '+229', 22, 'BJ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(34, 'Saint Barthélemy', 'BL', 'BLM', '+590', 3, 'BL', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(35, 'Bermuda', 'BM', 'BMU', '+1441', 26, 'BM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(36, 'Brunei Darussalam', 'BN', 'BRN', '+673', 27, 'BN', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(37, 'Bolivia, Plurinational State of', 'BO', 'BOL', '+591', 28, 'BO', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(38, 'Bonaire, Sint Eustatius and Saba', 'BQ', 'BES', '+599', 1, 'BQ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(39, 'Brazil', 'BR', 'BRA', '+55', 29, 'BR', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(40, 'Bahamas', 'BS', 'BHS', '+1242', 30, 'BS', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(41, 'Bhutan', 'BT', 'BTN', '+975', 31, 'BT', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(42, 'Bouvet Island', 'BV', 'BVT', '+47', 32, 'BV', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(43, 'Botswana', 'BW', 'BWA', '+267', 33, 'BW', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(44, 'Belarus', 'BY', 'BLR', '+375', 34, 'BY', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(45, 'Belize', 'BZ', 'BLZ', '+501', 35, 'BZ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(46, 'Canada', 'CA', 'CAN', '+1', 36, 'CA', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(47, 'Cocos (Keeling) Islands', 'CC', 'CCK', '+61', 16, 'CC', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(48, 'Congo, The Democratic Republic of the', 'CD', 'COD', '+243', 37, 'CD', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(49, 'Central African Republic', 'CF', 'CAF', '+236', 38, 'CF', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(50, 'Congo', 'CG', 'COG', '+242', 38, 'CG', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(51, 'Switzerland', 'CH', 'CHE', '+41', 39, 'CH', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(52, 'Côte d\'Ivoire', 'CI', 'CIV', '+225', 22, 'CI', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(53, 'Cook Islands', 'CK', 'COK', '+682', 40, 'CK', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(54, 'Chile', 'CL', 'CHL', '+56', 41, 'CL', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(55, 'Cameroon', 'CM', 'CMR', '+237', 38, 'CM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(56, 'China', 'CN', 'CHN', '+86', 42, 'CN', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(57, 'Colombia', 'CO', 'COL', '+57', 43, 'CO', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(58, 'Costa Rica', 'CR', 'CRI', '+506', 44, 'CR', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(59, 'Cuba', 'CU', 'CUB', '+53', 45, 'CU', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(60, 'Cabo Verde', 'CV', 'CPV', '+238', 46, 'CV', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(61, 'Curaçao', 'CW', 'CUW', '+599', 47, 'CW', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(62, 'Christmas Island', 'CX', 'CXR', '+61', 16, 'CX', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(63, 'Cyprus', 'CY', 'CYP', '+357', 3, 'CY', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(64, 'Czechia', 'CZ', 'CZE', '+420', 48, 'CZ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(65, 'Djibouti', 'DJ', 'DJI', '+253', 49, 'DJ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(66, 'Denmark', 'DK', 'DNK', '+45', 50, 'DK', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(67, 'Dominica', 'DM', 'DMA', '+1767', 11, 'DM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(68, 'Dominican Republic', 'DO', 'DOM', '+1809', 51, 'DO', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(69, 'Algeria', 'DZ', 'DZA', '+213', 52, 'DZ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(70, 'Ecuador', 'EC', 'ECU', '+593', 1, 'EC', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(71, 'Estonia', 'EE', 'EST', '+372', 3, 'EE', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(72, 'Egypt', 'EG', 'EGY', '+20', 53, 'EG', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(73, 'Western Sahara', 'EH', 'ESH', '+212', 54, 'EH', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(74, 'Eritrea', 'ER', 'ERI', '+291', 55, 'ER', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(75, 'Spain', 'ES', 'ESP', '+34', 3, 'ES', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(76, 'Ethiopia', 'ET', 'ETH', '+251', 56, 'ET', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(77, 'Finland', 'FI', 'FIN', '+358', 3, 'FI', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(78, 'Fiji', 'FJ', 'FJI', '+679', 57, 'FJ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(79, 'Falkland Islands (Malvinas)', 'FK', 'FLK', '+500', 58, 'FK', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(80, 'Micronesia, Federated States of', 'FM', 'FSM', '+691', 1, 'FM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(81, 'Faroe Islands', 'FO', 'FRO', '+298', 50, 'FO', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(82, 'France', 'FR', 'FRA', '+33', 3, 'FR', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(83, 'Gabon', 'GA', 'GAB', '+241', 38, 'GA', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(84, 'Grenada', 'GD', 'GRD', '+1473', 11, 'GD', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(85, 'Georgia', 'GE', 'GEO', '+995', 59, 'GE', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(86, 'French Guiana', 'GF', 'GUF', '+594', 3, 'GF', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(87, 'Guernsey', 'GG', 'GGY', '+44', 4, 'GG', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(88, 'Ghana', 'GH', 'GHA', '+233', 60, 'GH', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(89, 'Gibraltar', 'GI', 'GIB', '+350', 61, 'GI', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(90, 'Greenland', 'GL', 'GRL', '+299', 50, 'GL', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(91, 'Gambia', 'GM', 'GMB', '+220', 62, 'GM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(92, 'Guinea', 'GN', 'GIN', '+224', 63, 'GN', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(93, 'Guadeloupe', 'GP', 'GLP', '+590', 3, 'GP', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(94, 'Equatorial Guinea', 'GQ', 'GNQ', '+240', 38, 'GQ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(95, 'Greece', 'GR', 'GRC', '+30', 3, 'GR', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(96, 'South Georgia and the South Sandwich Islands', 'GS', 'SGS', '+500', 4, 'GS', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(97, 'Guatemala', 'GT', 'GTM', '+502', 64, 'GT', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(98, 'Guam', 'GU', 'GUM', '+1671', 1, 'GU', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(99, 'Guinea-Bissau', 'GW', 'GNB', '+245', 22, 'GW', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(100, 'Guyana', 'GY', 'GUY', '+592', 65, 'GY', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(101, 'Hong Kong', 'HK', 'HKG', '+852', 66, 'HK', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(102, 'Heard Island and McDonald Islands', 'HM', 'HMD', '+672', 16, 'HM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(103, 'Honduras', 'HN', 'HND', '+504', 67, 'HN', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(104, 'Croatia', 'HR', 'HRV', '+385', 3, 'HR', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(105, 'Haiti', 'HT', 'HTI', '+509', 68, 'HT', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(106, 'Hungary', 'HU', 'HUN', '+36', 69, 'HU', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(107, 'Indonesia', 'ID', 'IDN', '+62', 70, 'ID', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(108, 'Ireland', 'IE', 'IRL', '+353', 3, 'IE', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(109, 'Israel', 'IL', 'ISR', '+972', 71, 'IL', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(110, 'Isle of Man', 'IM', 'IMN', '+44', 4, 'IM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(111, 'India', 'IN', 'IND', '+91', 31, 'IN', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(112, 'British Indian Ocean Territory', 'IO', 'IOT', '+246', 1, 'IO', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(113, 'Iraq', 'IQ', 'IRQ', '+964', 72, 'IQ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(114, 'Iran, Islamic Republic of', 'IR', 'IRN', '+98', 73, 'IR', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(115, 'Iceland', 'IS', 'ISL', '+354', 74, 'IS', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(116, 'Italy', 'IT', 'ITA', '+39', 3, 'IT', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(117, 'Jersey', 'JE', 'JEY', '+44', 4, 'JE', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(118, 'Jamaica', 'JM', 'JAM', '+1876', 75, 'JM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(119, 'Jordan', 'JO', 'JOR', '+962', 76, 'JO', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(120, 'Japan', 'JP', 'JPN', '+81', 77, 'JP', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(121, 'Kyrgyzstan', 'KG', 'KGZ', '+996', 78, 'KG', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(122, 'Cambodia', 'KH', 'KHM', '+855', 79, 'KH', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(123, 'Kiribati', 'KI', 'KIR', '+686', 16, 'KI', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(124, 'Comoros', 'KM', 'COM', '+269', 80, 'KM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(125, 'Saint Kitts and Nevis', 'KN', 'KNA', '+1869', 11, 'KN', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(126, 'Korea, Democratic People\'s Republic of', 'KP', 'PRK', '+850', 81, 'KP', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(127, 'Korea, Republic of', 'KR', 'KOR', '+82', 82, 'KR', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(128, 'Kuwait', 'KW', 'KWT', '+965', 83, 'KW', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(129, 'Cayman Islands', 'KY', 'CYM', '+1345', 84, 'KY', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(130, 'Kazakhstan', 'KZ', 'KAZ', '+7', 85, 'KZ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(131, 'Lao People\'s Democratic Republic', 'LA', 'LAO', '+856', 86, 'LA', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(132, 'Lebanon', 'LB', 'LBN', '+961', 87, 'LB', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(133, 'Saint Lucia', 'LC', 'LCA', '+1758', 11, 'LC', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(134, 'Liechtenstein', 'LI', 'LIE', '+423', 39, 'LI', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(135, 'Sri Lanka', 'LK', 'LKA', '+94', 88, 'LK', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(136, 'Liberia', 'LR', 'LBR', '+231', 89, 'LR', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(137, 'Lesotho', 'LS', 'LSO', '+266', 8, 'LS', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(138, 'Lithuania', 'LT', 'LTU', '+370', 3, 'LT', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(139, 'Luxembourg', 'LU', 'LUX', '+352', 3, 'LU', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(140, 'Latvia', 'LV', 'LVA', '+371', 3, 'LV', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(141, 'Libya', 'LY', 'LBY', '+218', 90, 'LY', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(142, 'Morocco', 'MA', 'MAR', '+212', 54, 'MA', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(143, 'Monaco', 'MC', 'MCO', '+377', 3, 'MC', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(144, 'Moldova, Republic of', 'MD', 'MDA', '+373', 91, 'MD', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(145, 'Montenegro', 'ME', 'MNE', '+382', 3, 'ME', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(146, 'Saint Martin (French part)', 'MF', 'MAF', '+590', 3, 'MF', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(147, 'Madagascar', 'MG', 'MDG', '+261', 92, 'MG', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(148, 'Marshall Islands', 'MH', 'MHL', '+692', 1, 'MH', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(149, 'North Macedonia', 'MK', 'MKD', '+389', 93, 'MK', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(150, 'Mali', 'ML', 'MLI', '+223', 22, 'ML', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(151, 'Myanmar', 'MM', 'MMR', '+95', 94, 'MM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(152, 'Mongolia', 'MN', 'MNG', '+976', 95, 'MN', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(153, 'Macao', 'MO', 'MAC', '+853', 96, 'MO', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(154, 'Northern Mariana Islands', 'MP', 'MNP', '+1670', 1, 'MP', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(155, 'Martinique', 'MQ', 'MTQ', '+596', 3, 'MQ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(156, 'Mauritania', 'MR', 'MRT', '+222', 97, 'MR', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(157, 'Montserrat', 'MS', 'MSR', '+1664', 11, 'MS', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(158, 'Malta', 'MT', 'MLT', '+356', 3, 'MT', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(159, 'Mauritius', 'MU', 'MUS', '+230', 98, 'MU', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(160, 'Maldives', 'MV', 'MDV', '+960', 99, 'MV', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(161, 'Malawi', 'MW', 'MWI', '+265', 100, 'MW', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(162, 'Mexico', 'MX', 'MEX', '+52', 101, 'MX', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(163, 'Malaysia', 'MY', 'MYS', '+60', 102, 'MY', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(164, 'Mozambique', 'MZ', 'MOZ', '+258', 103, 'MZ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(165, 'Namibia', 'NA', 'NAM', '+264', 8, 'NA', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(166, 'New Caledonia', 'NC', 'NCL', '+687', 104, 'NC', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(167, 'Niger', 'NE', 'NER', '+227', 22, 'NE', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(168, 'Norfolk Island', 'NF', 'NFK', '+672', 16, 'NF', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(169, 'Nicaragua', 'NI', 'NIC', '+505', 105, 'NI', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(170, 'Netherlands', 'NL', 'NLD', '+31', 3, 'NL', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(171, 'Norway', 'NO', 'NOR', '+47', 32, 'NO', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(172, 'Nepal', 'NP', 'NPL', '+977', 106, 'NP', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(173, 'Nauru', 'NR', 'NRU', '+674', 16, 'NR', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(174, 'Niue', 'NU', 'NIU', '+683', 40, 'NU', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(175, 'New Zealand', 'NZ', 'NZL', '+64', 40, 'NZ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(176, 'Oman', 'OM', 'OMN', '+968', 107, 'OM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(177, 'Panama', 'PA', 'PAN', '+507', 108, 'PA', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(178, 'Peru', 'PE', 'PER', '+51', 109, 'PE', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(179, 'French Polynesia', 'PF', 'PYF', '+689', 104, 'PF', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(180, 'Papua New Guinea', 'PG', 'PNG', '+675', 110, 'PG', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(181, 'Philippines', 'PH', 'PHL', '+63', 111, 'PH', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(182, 'Pakistan', 'PK', 'PAK', '+92', 112, 'PK', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(183, 'Poland', 'PL', 'POL', '+48', 113, 'PL', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(184, 'Saint Pierre and Miquelon', 'PM', 'SPM', '+508', 3, 'PM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(185, 'Pitcairn', 'PN', 'PCN', '+64', 40, 'PN', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(186, 'Puerto Rico', 'PR', 'PRI', '+1787', 1, 'PR', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(187, 'Palestine, State of', 'PS', 'PSE', '+970', 71, 'PS', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(188, 'Portugal', 'PT', 'PRT', '+351', 3, 'PT', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(189, 'Palau', 'PW', 'PLW', '+680', 1, 'PW', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(190, 'Paraguay', 'PY', 'PRY', '+595', 114, 'PY', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(191, 'Qatar', 'QA', 'QAT', '+974', 115, 'QA', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(192, 'Réunion', 'RE', 'REU', '+262', 3, 'RE', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(193, 'Romania', 'RO', 'ROU', '+40', 116, 'RO', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(194, 'Serbia', 'RS', 'SRB', '+381', 117, 'RS', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(195, 'Russian Federation', 'RU', 'RUS', '+7', 118, 'RU', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(196, 'Rwanda', 'RW', 'RWA', '+250', 119, 'RW', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(197, 'Saudi Arabia', 'SA', 'SAU', '+966', 120, 'SA', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(198, 'Solomon Islands', 'SB', 'SLB', '+677', 121, 'SB', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(199, 'Seychelles', 'SC', 'SYC', '+248', 122, 'SC', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(200, 'Sudan', 'SD', 'SDN', '+249', 123, 'SD', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(201, 'Sweden', 'SE', 'SWE', '+46', 124, 'SE', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(202, 'Singapore', 'SG', 'SGP', '+65', 125, 'SG', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(203, 'Saint Helena, Ascension and Tristan da Cunha', 'SH', 'SHN', '+290', 126, 'SH', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(204, 'Slovenia', 'SI', 'SVN', '+386', 3, 'SI', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(205, 'Svalbard and Jan Mayen', 'SJ', 'SJM', '+47', 32, 'SJ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(206, 'Slovakia', 'SK', 'SVK', '+421', 3, 'SK', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(207, 'Sierra Leone', 'SL', 'SLE', '+232', 127, 'SL', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(208, 'San Marino', 'SM', 'SMR', '+378', 3, 'SM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(209, 'Senegal', 'SN', 'SEN', '+221', 22, 'SN', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(210, 'Somalia', 'SO', 'SOM', '+252', 128, 'SO', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(211, 'Suriname', 'SR', 'SUR', '+597', 129, 'SR', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(212, 'South Sudan', 'SS', 'SSD', '+211', 130, 'SS', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(213, 'Sao Tome and Principe', 'ST', 'STP', '+239', 131, 'ST', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(214, 'El Salvador', 'SV', 'SLV', '+503', 1, 'SV', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(215, 'Sint Maarten (Dutch part)', 'SX', 'SXM', '+1721', 47, 'SX', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(216, 'Syrian Arab Republic', 'SY', 'SYR', '+963', 132, 'SY', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(217, 'Eswatini', 'SZ', 'SWZ', '+268', 133, 'SZ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(218, 'Turks and Caicos Islands', 'TC', 'TCA', '+1649', 1, 'TC', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(219, 'Chad', 'TD', 'TCD', '+235', 38, 'TD', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(220, 'French Southern Territories', 'TF', 'ATF', '+262', 3, 'TF', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(221, 'Togo', 'TG', 'TGO', '+228', 22, 'TG', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(222, 'Thailand', 'TH', 'THA', '+66', 134, 'TH', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(223, 'Tajikistan', 'TJ', 'TJK', '+992', 135, 'TJ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(224, 'Tokelau', 'TK', 'TKL', '+690', 40, 'TK', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(225, 'Timor-Leste', 'TL', 'TLS', '+670', 1, 'TL', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(226, 'Turkmenistan', 'TM', 'TKM', '+993', 136, 'TM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(227, 'Tunisia', 'TN', 'TUN', '+216', 137, 'TN', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(228, 'Tonga', 'TO', 'TON', '+676', 138, 'TO', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(229, 'Türkiye', 'TR', 'TUR', '+90', 139, 'TR', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(230, 'Trinidad and Tobago', 'TT', 'TTO', '+1868', 140, 'TT', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(231, 'Tuvalu', 'TV', 'TUV', '+688', 16, 'TV', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(232, 'Taiwan, Province of China', 'TW', 'TWN', '+886', 141, 'TW', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(233, 'Ukraine', 'UA', 'UKR', '+380', 142, 'UA', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(234, 'United States Minor Outlying Islands', 'UM', 'UMI', '+1', 1, 'UM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(235, 'Uruguay', 'UY', 'URY', '+598', 143, 'UY', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(236, 'Uzbekistan', 'UZ', 'UZB', '+998', 144, 'UZ', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(237, 'Holy See (Vatican City State)', 'VA', 'VAT', '+39', 3, 'VA', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(238, 'Saint Vincent and the Grenadines', 'VC', 'VCT', '+1784', 11, 'VC', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(239, 'Venezuela, Bolivarian Republic of', 'VE', 'VEN', '+58', 145, 'VE', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(240, 'Virgin Islands, British', 'VG', 'VGB', '+1284', 1, 'VG', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(241, 'Virgin Islands, U.S.', 'VI', 'VIR', '+1340', 1, 'VI', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(242, 'Viet Nam', 'VN', 'VNM', '+84', 146, 'VN', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(243, 'Vanuatu', 'VU', 'VUT', '+678', 147, 'VU', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(244, 'Wallis and Futuna', 'WF', 'WLF', '+681', 104, 'WF', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(245, 'Samoa', 'WS', 'WSM', '+685', 148, 'WS', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(246, 'Yemen', 'YE', 'YEM', '+967', 149, 'YE', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(247, 'Mayotte', 'YT', 'MYT', '+262', 3, 'YT', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(248, 'Zambia', 'ZM', 'ZMB', '+260', 150, 'ZM', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59'),
(249, 'Zimbabwe', 'ZW', 'ZWE', '+263', 1, 'ZW', 1, '2026-08-26 19:43:59', '2026-08-26 19:43:59');

-- --------------------------------------------------------

--
-- Table structure for table `currencies`
--

CREATE TABLE `currencies` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `code` varchar(10) NOT NULL,
  `name` varchar(100) NOT NULL,
  `symbol` varchar(20) NOT NULL DEFAULT '',
  `decimal_places` tinyint(3) UNSIGNED NOT NULL DEFAULT 2,
  `is_base` tinyint(1) NOT NULL DEFAULT 0,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `currencies`
--

INSERT INTO `currencies` (`id`, `code`, `name`, `symbol`, `decimal_places`, `is_base`, `is_active`, `created_at`, `updated_at`) VALUES
(1, 'USD', 'United States Dollar', '$', 2, 1, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(2, 'KES', 'Kenyan Shilling', 'KSh', 2, 0, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(3, 'EUR', 'Euro', '€', 2, 0, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(4, 'GBP', 'British Pound', '£', 2, 0, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(5, 'UGX', 'Ugandan Shilling', 'USh', 0, 0, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(6, 'TZS', 'Tanzanian Shilling', 'TSh', 2, 0, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(7, 'NGN', 'Nigerian Naira', '₦', 2, 0, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(8, 'ZAR', 'South African Rand', 'R', 2, 0, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(9, 'AED', 'AED', 'AED', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(10, 'AFN', 'AFN', 'AFN', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(11, 'XCD', 'XCD', 'XCD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(12, 'ALL', 'ALL', 'ALL', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(13, 'AMD', 'AMD', 'AMD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(14, 'AOA', 'AOA', 'AOA', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(15, 'ARS', 'ARS', 'ARS', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(16, 'AUD', 'AUD', 'AUD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(17, 'AWG', 'AWG', 'AWG', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(18, 'AZN', 'AZN', 'AZN', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(19, 'BAM', 'BAM', 'BAM', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(20, 'BBD', 'BBD', 'BBD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(21, 'BDT', 'BDT', 'BDT', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(22, 'XOF', 'XOF', 'XOF', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(23, 'BGN', 'BGN', 'BGN', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(24, 'BHD', 'BHD', 'BHD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(25, 'BIF', 'BIF', 'BIF', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(26, 'BMD', 'BMD', 'BMD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(27, 'BND', 'BND', 'BND', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(28, 'BOB', 'BOB', 'BOB', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(29, 'BRL', 'BRL', 'BRL', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(30, 'BSD', 'BSD', 'BSD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(31, 'INR', 'INR', 'INR', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(32, 'NOK', 'NOK', 'NOK', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(33, 'BWP', 'BWP', 'BWP', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(34, 'BYN', 'BYN', 'BYN', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(35, 'BZD', 'BZD', 'BZD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(36, 'CAD', 'CAD', 'CAD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(37, 'CDF', 'CDF', 'CDF', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(38, 'XAF', 'XAF', 'XAF', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(39, 'CHF', 'CHF', 'CHF', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(40, 'NZD', 'NZD', 'NZD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(41, 'CLP', 'CLP', 'CLP', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(42, 'CNY', 'CNY', 'CNY', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(43, 'COP', 'COP', 'COP', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(44, 'CRC', 'CRC', 'CRC', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(45, 'CUP', 'CUP', 'CUP', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(46, 'CVE', 'CVE', 'CVE', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(47, 'XCG', 'XCG', 'XCG', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(48, 'CZK', 'CZK', 'CZK', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(49, 'DJF', 'DJF', 'DJF', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(50, 'DKK', 'DKK', 'DKK', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(51, 'DOP', 'DOP', 'DOP', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(52, 'DZD', 'DZD', 'DZD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(53, 'EGP', 'EGP', 'EGP', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(54, 'MAD', 'MAD', 'MAD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(55, 'ERN', 'ERN', 'ERN', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(56, 'ETB', 'ETB', 'ETB', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(57, 'FJD', 'FJD', 'FJD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(58, 'FKP', 'FKP', 'FKP', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(59, 'GEL', 'GEL', 'GEL', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(60, 'GHS', 'GHS', 'GHS', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(61, 'GIP', 'GIP', 'GIP', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(62, 'GMD', 'GMD', 'GMD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(63, 'GNF', 'GNF', 'GNF', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(64, 'GTQ', 'GTQ', 'GTQ', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(65, 'GYD', 'GYD', 'GYD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(66, 'HKD', 'HKD', 'HKD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(67, 'HNL', 'HNL', 'HNL', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(68, 'HTG', 'HTG', 'HTG', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(69, 'HUF', 'HUF', 'HUF', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(70, 'IDR', 'IDR', 'IDR', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(71, 'ILS', 'ILS', 'ILS', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(72, 'IQD', 'IQD', 'IQD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(73, 'IRR', 'IRR', 'IRR', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(74, 'ISK', 'ISK', 'ISK', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(75, 'JMD', 'JMD', 'JMD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(76, 'JOD', 'JOD', 'JOD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(77, 'JPY', 'JPY', 'JPY', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(78, 'KGS', 'KGS', 'KGS', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(79, 'KHR', 'KHR', 'KHR', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(80, 'KMF', 'KMF', 'KMF', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(81, 'KPW', 'KPW', 'KPW', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(82, 'KRW', 'KRW', 'KRW', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(83, 'KWD', 'KWD', 'KWD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(84, 'KYD', 'KYD', 'KYD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(85, 'KZT', 'KZT', 'KZT', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(86, 'LAK', 'LAK', 'LAK', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(87, 'LBP', 'LBP', 'LBP', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(88, 'LKR', 'LKR', 'LKR', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(89, 'LRD', 'LRD', 'LRD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(90, 'LYD', 'LYD', 'LYD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(91, 'MDL', 'MDL', 'MDL', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(92, 'MGA', 'MGA', 'MGA', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(93, 'MKD', 'MKD', 'MKD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(94, 'MMK', 'MMK', 'MMK', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(95, 'MNT', 'MNT', 'MNT', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(96, 'MOP', 'MOP', 'MOP', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(97, 'MRU', 'MRU', 'MRU', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(98, 'MUR', 'MUR', 'MUR', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(99, 'MVR', 'MVR', 'MVR', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(100, 'MWK', 'MWK', 'MWK', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(101, 'MXN', 'MXN', 'MXN', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(102, 'MYR', 'MYR', 'MYR', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(103, 'MZN', 'MZN', 'MZN', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(104, 'XPF', 'XPF', 'XPF', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(105, 'NIO', 'NIO', 'NIO', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(106, 'NPR', 'NPR', 'NPR', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(107, 'OMR', 'OMR', 'OMR', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(108, 'PAB', 'PAB', 'PAB', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(109, 'PEN', 'PEN', 'PEN', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(110, 'PGK', 'PGK', 'PGK', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(111, 'PHP', 'PHP', 'PHP', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(112, 'PKR', 'PKR', 'PKR', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(113, 'PLN', 'PLN', 'PLN', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(114, 'PYG', 'PYG', 'PYG', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(115, 'QAR', 'QAR', 'QAR', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(116, 'RON', 'RON', 'RON', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(117, 'RSD', 'RSD', 'RSD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(118, 'RUB', 'RUB', 'RUB', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(119, 'RWF', 'RWF', 'RWF', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(120, 'SAR', 'SAR', 'SAR', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(121, 'SBD', 'SBD', 'SBD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(122, 'SCR', 'SCR', 'SCR', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(123, 'SDG', 'SDG', 'SDG', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(124, 'SEK', 'SEK', 'SEK', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(125, 'SGD', 'SGD', 'SGD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(126, 'SHP', 'SHP', 'SHP', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(127, 'SLE', 'SLE', 'SLE', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(128, 'SOS', 'SOS', 'SOS', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(129, 'SRD', 'SRD', 'SRD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(130, 'SSP', 'SSP', 'SSP', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(131, 'STN', 'STN', 'STN', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(132, 'SYP', 'SYP', 'SYP', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(133, 'SZL', 'SZL', 'SZL', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(134, 'THB', 'THB', 'THB', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(135, 'TJS', 'TJS', 'TJS', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(136, 'TMT', 'TMT', 'TMT', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(137, 'TND', 'TND', 'TND', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(138, 'TOP', 'TOP', 'TOP', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(139, 'TRY', 'TRY', 'TRY', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(140, 'TTD', 'TTD', 'TTD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(141, 'TWD', 'TWD', 'TWD', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(142, 'UAH', 'UAH', 'UAH', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(143, 'UYU', 'UYU', 'UYU', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(144, 'UZS', 'UZS', 'UZS', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(145, 'VES', 'VES', 'VES', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(146, 'VND', 'VND', 'VND', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(147, 'VUV', 'VUV', 'VUV', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(148, 'WST', 'WST', 'WST', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(149, 'YER', 'YER', 'YER', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58'),
(150, 'ZMW', 'ZMW', 'ZMW', 2, 0, 1, '2026-08-26 19:43:58', '2026-08-26 19:43:58');

-- --------------------------------------------------------

--
-- Table structure for table `exchange_rates`
--

CREATE TABLE `exchange_rates` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `base_currency_id` bigint(20) UNSIGNED NOT NULL,
  `target_currency_id` bigint(20) UNSIGNED NOT NULL,
  `rate` decimal(20,10) NOT NULL,
  `source` varchar(100) DEFAULT NULL,
  `effective_at` datetime NOT NULL DEFAULT current_timestamp(),
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `exchange_rates`
--

INSERT INTO `exchange_rates` (`id`, `base_currency_id`, `target_currency_id`, `rate`, `source`, `effective_at`, `is_active`, `created_at`) VALUES
(1, 1, 2, 130.0000000000, 'initial_database_seed', '2026-08-26 17:05:54', 1, '2026-08-26 17:05:54');

-- --------------------------------------------------------

--
-- Table structure for table `login_logs`
--

CREATE TABLE `login_logs` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED DEFAULT NULL,
  `identifier` varchar(190) DEFAULT NULL,
  `login_status` varchar(30) NOT NULL,
  `failure_reason` varchar(255) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `login_logs`
--

INSERT INTO `login_logs` (`id`, `user_id`, `identifier`, `login_status`, `failure_reason`, `ip_address`, `user_agent`, `created_at`) VALUES
(1, NULL, 'jmsak37@gmail.com', 'blocked', 'Account pending approval.', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-26 20:08:19'),
(2, 3, 'jmsak37', 'password_verified_2fa_pending', NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 11:59:36'),
(3, 3, 'jmsak37', 'password_verified_2fa_pending', NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 12:00:32'),
(4, 3, 'jmsak37', 'password_verified_2fa_pending', NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 12:09:28'),
(5, 3, 'jmsak37', 'password_verified_2fa_pending', NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 12:13:49'),
(6, 4, 'eduassista', 'password_verified_2fa_pending', NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 12:35:06'),
(7, 3, 'jmsak37', 'password_verified_2fa_pending', NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 12:40:00'),
(8, 3, 'jmsak37', 'password_verified_2fa_pending', NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 12:40:54'),
(9, 3, 'jmsak37', 'password_verified_2fa_pending', NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 12:48:26'),
(10, 3, 'jmsak37', 'password_verified_2fa_pending', NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 13:39:58'),
(11, 4, 'eduassista', 'password_verified_2fa_pending', NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 15:29:24');

-- --------------------------------------------------------

--
-- Table structure for table `messages`
--

CREATE TABLE `messages` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `conversation_id` bigint(20) UNSIGNED NOT NULL,
  `sender_id` bigint(20) UNSIGNED NOT NULL,
  `receiver_id` bigint(20) UNSIGNED NOT NULL,
  `message_type` varchar(30) NOT NULL DEFAULT 'text',
  `message_text` text DEFAULT NULL,
  `attachment_path` varchar(500) DEFAULT NULL,
  `attachment_name` varchar(255) DEFAULT NULL,
  `attachment_mime` varchar(100) DEFAULT NULL,
  `is_read` tinyint(1) NOT NULL DEFAULT 0,
  `read_at` datetime DEFAULT NULL,
  `deleted_by_sender` tinyint(1) NOT NULL DEFAULT 0,
  `deleted_by_receiver` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `notifications`
--

CREATE TABLE `notifications` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `notification_type_id` bigint(20) UNSIGNED DEFAULT NULL,
  `sender_id` bigint(20) UNSIGNED DEFAULT NULL,
  `title` varchar(180) NOT NULL,
  `message` text NOT NULL,
  `reference_type` varchar(50) DEFAULT NULL,
  `reference_id` bigint(20) UNSIGNED DEFAULT NULL,
  `audio_id` bigint(20) UNSIGNED DEFAULT NULL,
  `is_read` tinyint(1) NOT NULL DEFAULT 0,
  `read_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `notification_audio`
--

CREATE TABLE `notification_audio` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `notification_type_id` bigint(20) UNSIGNED DEFAULT NULL,
  `name` varchar(100) NOT NULL,
  `file_name` varchar(255) NOT NULL,
  `file_path` varchar(500) NOT NULL,
  `mime_type` varchar(100) NOT NULL DEFAULT 'audio/mpeg',
  `sort_order` int(11) NOT NULL DEFAULT 0,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `notification_audio`
--

INSERT INTO `notification_audio` (`id`, `notification_type_id`, `name`, `file_name`, `file_path`, `mime_type`, `sort_order`, `is_active`, `created_at`, `updated_at`) VALUES
(1, 1, 'Notification Sound 1', 'notification1.mp3', 'assets/audio/notification1.mp3', 'audio/mpeg', 1, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:55'),
(2, 2, 'Notification Sound 2', 'notification2.mp3', 'assets/audio/notification2.mp3', 'audio/mpeg', 2, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:55'),
(3, 3, 'Notification Sound 3', 'notification3.mp3', 'assets/audio/notification3.mp3', 'audio/mpeg', 3, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:55'),
(4, 4, 'Notification Sound 4', 'notification4.mp3', 'assets/audio/notification4.mp3', 'audio/mpeg', 4, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:55'),
(5, 5, 'Notification Sound 5', 'notification5.mp3', 'assets/audio/notification5.mp3', 'audio/mpeg', 5, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:55'),
(6, 6, 'Notification Sound 6', 'notification6.mp3', 'assets/audio/notification6.mp3', 'audio/mpeg', 6, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:55'),
(7, 7, 'Notification Sound 7', 'notification7.mp3', 'assets/audio/notification7.mp3', 'audio/mpeg', 7, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:55'),
(8, 8, 'Notification Sound 8', 'notification8.mp3', 'assets/audio/notification8.mp3', 'audio/mpeg', 8, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:55'),
(9, 11, 'Notification Sound 9', 'notification9.mp3', 'assets/audio/notification9.mp3', 'audio/mpeg', 9, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:55');

-- --------------------------------------------------------

--
-- Table structure for table `notification_preferences`
--

CREATE TABLE `notification_preferences` (
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `email_notifications` tinyint(1) NOT NULL DEFAULT 1,
  `sms_notifications` tinyint(1) NOT NULL DEFAULT 1,
  `push_notifications` tinyint(1) NOT NULL DEFAULT 1,
  `connection_notifications` tinyint(1) NOT NULL DEFAULT 1,
  `message_notifications` tinyint(1) NOT NULL DEFAULT 1,
  `premium_notifications` tinyint(1) NOT NULL DEFAULT 1,
  `system_notifications` tinyint(1) NOT NULL DEFAULT 1,
  `sound_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `notification_preferences`
--

INSERT INTO `notification_preferences` (`user_id`, `email_notifications`, `sms_notifications`, `push_notifications`, `connection_notifications`, `message_notifications`, `premium_notifications`, `system_notifications`, `sound_enabled`, `updated_at`) VALUES
(3, 1, 1, 1, 1, 1, 1, 1, 1, '2026-08-27 11:19:45'),
(4, 1, 1, 1, 1, 1, 1, 1, 1, '2026-08-27 12:15:41');

-- --------------------------------------------------------

--
-- Table structure for table `notification_types`
--

CREATE TABLE `notification_types` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `name` varchar(100) NOT NULL,
  `slug` varchar(120) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `sound_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `notification_types`
--

INSERT INTO `notification_types` (`id`, `name`, `slug`, `description`, `sound_enabled`, `created_at`) VALUES
(1, 'New Connection', 'new_connection', 'A new connection has been created.', 1, '2026-08-26 17:05:54'),
(2, 'New Message', 'new_message', 'A new chat message was received.', 1, '2026-08-26 17:05:54'),
(3, 'Premium Activated', 'premium_activated', 'Premium subscription has been activated.', 1, '2026-08-26 17:05:54'),
(4, 'Premium Expiring', 'premium_expiring', 'Premium subscription is about to expire.', 1, '2026-08-26 17:05:54'),
(5, 'Premium Expired', 'premium_expired', 'Premium subscription has expired.', 1, '2026-08-26 17:05:54'),
(6, 'Payment Successful', 'payment_successful', 'Payment was completed successfully.', 1, '2026-08-26 17:05:54'),
(7, 'Payment Failed', 'payment_failed', 'Payment failed.', 1, '2026-08-26 17:05:54'),
(8, 'Post Approved', 'post_approved', 'Your post was approved.', 1, '2026-08-26 17:05:54'),
(9, 'Photo Approved', 'photo_approved', 'Your photo was approved.', 1, '2026-08-26 17:05:54'),
(10, 'Account Approved', 'account_approved', 'Your account was approved.', 1, '2026-08-26 17:05:54'),
(11, 'System Notification', 'system', 'General system notification.', 1, '2026-08-26 17:05:54');

-- --------------------------------------------------------

--
-- Table structure for table `password_resets`
--

CREATE TABLE `password_resets` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `email` varchar(190) DEFAULT NULL,
  `phone_e164` varchar(30) DEFAULT NULL,
  `id_number_hash` char(64) DEFAULT NULL,
  `reset_token_hash` char(64) NOT NULL,
  `attempt_count` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `max_attempts` int(10) UNSIGNED NOT NULL DEFAULT 3,
  `expires_at` datetime NOT NULL,
  `used_at` datetime DEFAULT NULL,
  `blocked_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `payments`
--

CREATE TABLE `payments` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `service_id` bigint(20) UNSIGNED DEFAULT NULL,
  `subscription_id` bigint(20) UNSIGNED DEFAULT NULL,
  `payment_reference` varchar(150) NOT NULL,
  `gateway` varchar(50) NOT NULL,
  `gateway_transaction_id` varchar(180) DEFAULT NULL,
  `payment_method` varchar(50) DEFAULT NULL,
  `status` varchar(30) NOT NULL DEFAULT 'pending',
  `currency_id` bigint(20) UNSIGNED DEFAULT NULL,
  `base_amount_usd` decimal(12,2) NOT NULL DEFAULT 0.00,
  `exchange_rate` decimal(20,10) DEFAULT NULL,
  `amount_expected` decimal(18,4) NOT NULL DEFAULT 0.0000,
  `amount_paid` decimal(18,4) NOT NULL DEFAULT 0.0000,
  `gateway_fee` decimal(18,4) NOT NULL DEFAULT 0.0000,
  `phone_number` varchar(30) DEFAULT NULL,
  `checkout_reference` varchar(180) DEFAULT NULL,
  `paid_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Triggers `payments`
--
DELIMITER $$
CREATE TRIGGER `trg_payment_paid_timestamp` BEFORE UPDATE ON `payments` FOR EACH ROW BEGIN

    IF
        NEW.status = 'paid'
        AND OLD.status <> 'paid'
        AND NEW.paid_at IS NULL
    THEN

        SET NEW.paid_at =
            CURRENT_TIMESTAMP;

    END IF;

END
$$
DELIMITER ;
DELIMITER $$
CREATE TRIGGER `trg_payment_success_notification` AFTER UPDATE ON `payments` FOR EACH ROW BEGIN

    IF
        NEW.status = 'paid'
        AND OLD.status <> 'paid'
    THEN

        INSERT INTO notifications
        (
            user_id,
            notification_type_id,
            title,
            message
        )

        SELECT
            NEW.user_id,
            nt.id,
            'Payment Successful',
            CONCAT(
                'Your payment ',
                NEW.payment_reference,
                ' was completed successfully.'
            )

        FROM notification_types nt

        WHERE nt.slug = 'payment_successful'

        LIMIT 1;

    END IF;

END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `payment_receipts`
--

CREATE TABLE `payment_receipts` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `payment_id` bigint(20) UNSIGNED NOT NULL,
  `receipt_number` varchar(100) NOT NULL,
  `receipt_path` varchar(500) DEFAULT NULL,
  `issued_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `permissions`
--

CREATE TABLE `permissions` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `name` varchar(100) NOT NULL,
  `slug` varchar(120) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `permissions`
--

INSERT INTO `permissions` (`id`, `name`, `slug`, `description`, `created_at`) VALUES
(1, 'View Dashboard', 'dashboard.view', 'View dashboard', '2026-08-26 17:05:54'),
(2, 'Manage Users', 'users.manage', 'Create, edit, suspend and delete users', '2026-08-26 17:05:54'),
(3, 'View Users', 'users.view', 'View users', '2026-08-26 17:05:54'),
(4, 'Manage Profiles', 'profiles.manage', 'Edit user profiles', '2026-08-26 17:05:54'),
(5, 'Manage Photos', 'photos.manage', 'Approve, reject and delete photos', '2026-08-26 17:05:54'),
(6, 'Manage Posts', 'posts.manage', 'Approve, edit and delete posts', '2026-08-26 17:05:54'),
(7, 'Manage Connections', 'connections.manage', 'Manage user connections', '2026-08-26 17:05:54'),
(8, 'Manage Conversations', 'conversations.manage', 'View and manage conversations', '2026-08-26 17:05:54'),
(9, 'Manage Messages', 'messages.manage', 'Manage messages', '2026-08-26 17:05:54'),
(10, 'Manage Premium', 'premium.manage', 'Manage premium subscriptions', '2026-08-26 17:05:54'),
(11, 'Manage Payments', 'payments.manage', 'Manage payments', '2026-08-26 17:05:54'),
(12, 'Manage Services', 'services.manage', 'Create and edit services', '2026-08-26 17:05:54'),
(13, 'Manage Countries', 'countries.manage', 'Manage countries', '2026-08-26 17:05:54'),
(14, 'Manage Currencies', 'currencies.manage', 'Manage currencies', '2026-08-26 17:05:54'),
(15, 'Manage Exchange Rates', 'exchange_rates.manage', 'Manage exchange rates', '2026-08-26 17:05:54'),
(16, 'Manage Notifications', 'notifications.manage', 'Manage notifications', '2026-08-26 17:05:54'),
(17, 'Manage Audio', 'audio.manage', 'Manage notification audio', '2026-08-26 17:05:54'),
(18, 'Manage Reports', 'reports.manage', 'Review reports', '2026-08-26 17:05:54'),
(19, 'Manage Blocks', 'blocks.manage', 'Manage blocked accounts', '2026-08-26 17:05:54'),
(20, 'Manage Admins', 'admins.manage', 'Manage administrators', '2026-08-26 17:05:54'),
(21, 'Manage Roles', 'roles.manage', 'Manage roles', '2026-08-26 17:05:54'),
(22, 'Manage Permissions', 'permissions.manage', 'Manage permissions', '2026-08-26 17:05:54'),
(23, 'View Audit Logs', 'audit.view', 'View audit logs', '2026-08-26 17:05:54'),
(24, 'View Login Logs', 'login_logs.view', 'View login logs', '2026-08-26 17:05:54'),
(25, 'Manage Settings', 'settings.manage', 'Manage system settings', '2026-08-26 17:05:54'),
(26, 'Manage Backups', 'backups.manage', 'Create and manage backups', '2026-08-26 17:05:54');

-- --------------------------------------------------------

--
-- Table structure for table `photos`
--

CREATE TABLE `photos` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `file_name` varchar(255) NOT NULL,
  `file_path` varchar(500) NOT NULL,
  `thumbnail_path` varchar(500) DEFAULT NULL,
  `mime_type` varchar(100) DEFAULT NULL,
  `file_size` bigint(20) UNSIGNED DEFAULT NULL,
  `width` int(10) UNSIGNED DEFAULT NULL,
  `height` int(10) UNSIGNED DEFAULT NULL,
  `photo_type` varchar(30) NOT NULL DEFAULT 'profile',
  `approval_status` varchar(30) NOT NULL DEFAULT 'pending',
  `is_primary` tinyint(1) NOT NULL DEFAULT 0,
  `is_featured` tinyint(1) NOT NULL DEFAULT 0,
  `uploaded_at` datetime NOT NULL DEFAULT current_timestamp(),
  `approved_at` datetime DEFAULT NULL,
  `approved_by` bigint(20) UNSIGNED DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `posts`
--

CREATE TABLE `posts` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `content` text DEFAULT NULL,
  `visibility` varchar(30) NOT NULL DEFAULT 'public',
  `approval_status` varchar(30) NOT NULL DEFAULT 'pending',
  `is_featured` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `approved_at` datetime DEFAULT NULL,
  `approved_by` bigint(20) UNSIGNED DEFAULT NULL,
  `deleted_at` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `post_photos`
--

CREATE TABLE `post_photos` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `post_id` bigint(20) UNSIGNED NOT NULL,
  `photo_id` bigint(20) UNSIGNED NOT NULL,
  `display_order` int(10) UNSIGNED NOT NULL DEFAULT 1,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `profiles`
--

CREATE TABLE `profiles` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `display_name` varchar(180) DEFAULT NULL,
  `bio` text DEFAULT NULL,
  `occupation` varchar(150) DEFAULT NULL,
  `education` varchar(180) DEFAULT NULL,
  `city` varchar(120) DEFAULT NULL,
  `relationship_status` varchar(50) DEFAULT NULL,
  `looking_for` varchar(100) DEFAULT NULL,
  `interests` text DEFAULT NULL,
  `profile_visibility` varchar(30) NOT NULL DEFAULT 'public',
  `show_online_status` tinyint(1) NOT NULL DEFAULT 1,
  `allow_messages` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `profiles`
--

INSERT INTO `profiles` (`id`, `user_id`, `display_name`, `bio`, `occupation`, `education`, `city`, `relationship_status`, `looking_for`, `interests`, `profile_visibility`, `show_online_status`, `allow_messages`, `created_at`, `updated_at`) VALUES
(3, 3, 'Julius Samuel', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'public', 1, 1, '2026-08-27 11:19:45', '2026-08-27 11:19:45'),
(4, 4, 'Eduassista SAMUEL', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'public', 1, 1, '2026-08-27 12:15:41', '2026-08-27 12:15:41');

-- --------------------------------------------------------

--
-- Table structure for table `reports`
--

CREATE TABLE `reports` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `reporter_id` bigint(20) UNSIGNED NOT NULL,
  `reported_user_id` bigint(20) UNSIGNED DEFAULT NULL,
  `post_id` bigint(20) UNSIGNED DEFAULT NULL,
  `message_id` bigint(20) UNSIGNED DEFAULT NULL,
  `reason` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `status` varchar(30) NOT NULL DEFAULT 'pending',
  `reviewed_by` bigint(20) UNSIGNED DEFAULT NULL,
  `reviewed_at` datetime DEFAULT NULL,
  `resolution` text DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `roles`
--

CREATE TABLE `roles` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `name` varchar(80) NOT NULL,
  `slug` varchar(80) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `is_admin_role` tinyint(1) NOT NULL DEFAULT 0,
  `is_system_role` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `roles`
--

INSERT INTO `roles` (`id`, `name`, `slug`, `description`, `is_admin_role`, `is_system_role`, `created_at`, `updated_at`) VALUES
(1, 'Member', 'member', 'Normal LOVEMI member', 0, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(2, 'Administrator', 'admin', 'Full LOVEMI administrator', 1, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(3, 'Moderator', 'moderator', 'Moderates users, posts and reports', 1, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(4, 'Support', 'support', 'Handles support conversations and reports', 1, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:54');

-- --------------------------------------------------------

--
-- Table structure for table `role_permissions`
--

CREATE TABLE `role_permissions` (
  `role_id` bigint(20) UNSIGNED NOT NULL,
  `permission_id` bigint(20) UNSIGNED NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `role_permissions`
--

INSERT INTO `role_permissions` (`role_id`, `permission_id`, `created_at`) VALUES
(2, 1, '2026-08-26 17:05:54'),
(2, 2, '2026-08-26 17:05:54'),
(2, 3, '2026-08-26 17:05:54'),
(2, 4, '2026-08-26 17:05:54'),
(2, 5, '2026-08-26 17:05:54'),
(2, 6, '2026-08-26 17:05:54'),
(2, 7, '2026-08-26 17:05:54'),
(2, 8, '2026-08-26 17:05:54'),
(2, 9, '2026-08-26 17:05:54'),
(2, 10, '2026-08-26 17:05:54'),
(2, 11, '2026-08-26 17:05:54'),
(2, 12, '2026-08-26 17:05:54'),
(2, 13, '2026-08-26 17:05:54'),
(2, 14, '2026-08-26 17:05:54'),
(2, 15, '2026-08-26 17:05:54'),
(2, 16, '2026-08-26 17:05:54'),
(2, 17, '2026-08-26 17:05:54'),
(2, 18, '2026-08-26 17:05:54'),
(2, 19, '2026-08-26 17:05:54'),
(2, 20, '2026-08-26 17:05:54'),
(2, 21, '2026-08-26 17:05:54'),
(2, 22, '2026-08-26 17:05:54'),
(2, 23, '2026-08-26 17:05:54'),
(2, 24, '2026-08-26 17:05:54'),
(2, 25, '2026-08-26 17:05:54'),
(2, 26, '2026-08-26 17:05:54'),
(3, 3, '2026-08-26 17:05:54'),
(3, 4, '2026-08-26 17:05:54'),
(3, 5, '2026-08-26 17:05:54'),
(3, 6, '2026-08-26 17:05:54'),
(3, 7, '2026-08-26 17:05:54'),
(3, 18, '2026-08-26 17:05:54'),
(3, 19, '2026-08-26 17:05:54'),
(4, 3, '2026-08-26 17:05:54'),
(4, 8, '2026-08-26 17:05:54'),
(4, 9, '2026-08-26 17:05:54'),
(4, 18, '2026-08-26 17:05:54');

-- --------------------------------------------------------

--
-- Table structure for table `security_events`
--

CREATE TABLE `security_events` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED DEFAULT NULL,
  `event_type` varchar(100) NOT NULL,
  `severity` varchar(30) NOT NULL DEFAULT 'info',
  `description` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `services`
--

CREATE TABLE `services` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `name` varchar(150) NOT NULL,
  `slug` varchar(150) NOT NULL,
  `description` text DEFAULT NULL,
  `service_type` varchar(50) NOT NULL DEFAULT 'premium',
  `base_price_usd` decimal(12,2) NOT NULL DEFAULT 0.00,
  `duration_days` int(10) UNSIGNED NOT NULL DEFAULT 30,
  `max_usage` int(10) UNSIGNED DEFAULT NULL,
  `is_premium` tinyint(1) NOT NULL DEFAULT 0,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `sort_order` int(11) NOT NULL DEFAULT 0,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `services`
--

INSERT INTO `services` (`id`, `name`, `slug`, `description`, `service_type`, `base_price_usd`, `duration_days`, `max_usage`, `is_premium`, `is_active`, `sort_order`, `created_at`, `updated_at`) VALUES
(1, 'LOVEMI Premium', 'lovemi-premium', 'Premium access to LOVEMI connection and messaging services.', 'premium', 2.00, 30, NULL, 1, 1, 1, '2026-08-26 17:05:54', '2026-08-26 17:05:54');

-- --------------------------------------------------------

--
-- Table structure for table `subscriptions`
--

CREATE TABLE `subscriptions` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `service_id` bigint(20) UNSIGNED NOT NULL,
  `status` varchar(30) NOT NULL DEFAULT 'pending',
  `start_at` datetime DEFAULT NULL,
  `end_at` datetime DEFAULT NULL,
  `base_amount_usd` decimal(12,2) NOT NULL DEFAULT 0.00,
  `amount_paid` decimal(18,4) NOT NULL DEFAULT 0.0000,
  `currency_id` bigint(20) UNSIGNED DEFAULT NULL,
  `exchange_rate` decimal(20,10) DEFAULT NULL,
  `payment_id` bigint(20) UNSIGNED DEFAULT NULL,
  `usage_limit` int(10) UNSIGNED DEFAULT NULL,
  `usage_used` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Triggers `subscriptions`
--
DELIMITER $$
CREATE TRIGGER `trg_one_active_premium_before_insert` BEFORE INSERT ON `subscriptions` FOR EACH ROW BEGIN

    IF NEW.status = 'active' THEN

        IF EXISTS
        (
            SELECT 1
            FROM subscriptions
            WHERE user_id = NEW.user_id
              AND status = 'active'
              AND end_at > CURRENT_TIMESTAMP
        ) THEN

            SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT =
                'This user already has an active premium subscription.';

        END IF;

    END IF;

END
$$
DELIMITER ;
DELIMITER $$
CREATE TRIGGER `trg_one_active_premium_before_update` BEFORE UPDATE ON `subscriptions` FOR EACH ROW BEGIN

    IF NEW.status = 'active' THEN

        IF EXISTS
        (
            SELECT 1
            FROM subscriptions
            WHERE user_id = NEW.user_id
              AND status = 'active'
              AND end_at > CURRENT_TIMESTAMP
              AND id <> NEW.id
        ) THEN

            SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT =
                'This user already has another active premium subscription.';

        END IF;

    END IF;

END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `system_settings`
--

CREATE TABLE `system_settings` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `setting_key` varchar(150) NOT NULL,
  `setting_value` text DEFAULT NULL,
  `value_type` varchar(30) NOT NULL DEFAULT 'string',
  `description` varchar(255) DEFAULT NULL,
  `is_public` tinyint(1) NOT NULL DEFAULT 0,
  `updated_by` bigint(20) UNSIGNED DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `system_settings`
--

INSERT INTO `system_settings` (`id`, `setting_key`, `setting_value`, `value_type`, `description`, `is_public`, `updated_by`, `created_at`, `updated_at`) VALUES
(1, 'app_name', 'LOVEMI', 'string', 'Application name', 1, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(2, 'base_currency', 'USD', 'string', 'Base application currency', 1, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(3, 'kenya_currency', 'KES', 'string', 'Currency used for Kenyan users', 1, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(4, 'premium_price_usd', '2.00', 'decimal', 'Base LOVEMI premium price in USD', 1, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(5, 'premium_duration_days', '30', 'integer', 'Premium duration in days', 1, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(6, 'minimum_age', '18', 'integer', 'Minimum age required for LOVEMI', 1, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(7, 'public_posts_enabled', '1', 'boolean', 'Allow approved posts to appear publicly', 1, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(8, 'public_phone_numbers', '0', 'boolean', 'Never expose phone numbers on public pages', 0, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(9, 'public_whatsapp_numbers', '0', 'boolean', 'Never expose WhatsApp numbers on public pages', 0, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(10, 'require_email_verification', '1', 'boolean', 'Require email verification', 0, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(11, 'require_phone_verification', '1', 'boolean', 'Require phone verification', 0, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(12, 'require_identity_verification', '1', 'boolean', 'Require identity verification', 0, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(13, 'automatic_post_approval', '0', 'boolean', 'Automatically approve new posts', 0, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(14, 'automatic_photo_approval', '0', 'boolean', 'Automatically approve new photos', 0, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(15, 'latest_post_rotation_seconds', '120', 'integer', 'Seconds before latest image changes', 1, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(16, 'password_reset_max_attempts', '3', 'integer', 'Maximum reset verification attempts', 0, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54'),
(17, 'notification_sounds_enabled', '1', 'boolean', 'Enable notification sounds', 1, NULL, '2026-08-26 17:05:54', '2026-08-26 17:05:54');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `role_id` bigint(20) UNSIGNED NOT NULL,
  `username` varchar(50) NOT NULL,
  `full_names` varchar(180) NOT NULL,
  `gender` varchar(30) NOT NULL,
  `email` varchar(190) NOT NULL,
  `country_id` bigint(20) UNSIGNED NOT NULL,
  `phone_number` varchar(30) NOT NULL,
  `phone_e164` varchar(30) NOT NULL,
  `id_number_hash` char(64) DEFAULT NULL,
  `id_number_encrypted` text DEFAULT NULL,
  `date_of_birth` date DEFAULT NULL,
  `password_hash` varchar(255) NOT NULL,
  `two_factor_secret_encrypted` text DEFAULT NULL,
  `two_factor_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `two_factor_verified_at` datetime DEFAULT NULL,
  `account_status` varchar(30) NOT NULL DEFAULT 'pending',
  `email_verified` tinyint(1) NOT NULL DEFAULT 0,
  `phone_verified` tinyint(1) NOT NULL DEFAULT 0,
  `identity_verified` tinyint(1) NOT NULL DEFAULT 0,
  `age_verified` tinyint(1) NOT NULL DEFAULT 0,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `is_suspended` tinyint(1) NOT NULL DEFAULT 0,
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
  `last_login_at` datetime DEFAULT NULL,
  `last_seen_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `role_id`, `username`, `full_names`, `gender`, `email`, `country_id`, `phone_number`, `phone_e164`, `id_number_hash`, `id_number_encrypted`, `date_of_birth`, `password_hash`, `two_factor_secret_encrypted`, `two_factor_enabled`, `two_factor_verified_at`, `account_status`, `email_verified`, `phone_verified`, `identity_verified`, `age_verified`, `is_active`, `is_suspended`, `is_deleted`, `last_login_at`, `last_seen_at`, `created_at`, `updated_at`) VALUES
(3, 2, 'jmsak37', 'Julius Samuel', 'Male', 'jmsak37@gmail.com', 1, '0769089734', '+2540769089734', '1091b506d8020be8fa979cd09b982895b58641cacdf07c68a1abef3e8d1fa28b', NULL, '1999-05-24', '$2y$10$BcVUg77YoQs2G6MZPDGK2eJ4bY6YQdRqBv6YoTjaxvagT8ygkdTyO', 'vgMoyY7hXfCMzGsDBD3OJA==:65Cq4KGYo/ymFLNucELDNEJEZKXoiRG2tmAfTj8J8M8=', 1, '2026-08-27 12:40:44', 'approved', 1, 0, 0, 1, 1, 0, 0, NULL, '2026-08-27 15:29:11', '2026-08-27 11:19:45', '2026-08-27 15:29:11'),
(4, 1, 'eduassista', 'Eduassista SAMUEL', 'Female', 'eduassistasc@gmail.com', 1, '0791642994', '+2540791642994', 'ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f', NULL, '2002-05-27', '$2y$10$290wtiCBuq3jrpEEwZU69O5uE0ddvobCPULOnEw2igumaqCtUJn.W', 'EKAWI8r2x49lbcfrOJmA6Q==:DaZxINRCVHO8aJeSwX8Lr/byab4MMnzpRJV1d5kaj8w=', 1, '2026-08-27 12:34:57', 'approved', 1, 0, 0, 1, 1, 0, 0, NULL, '2026-08-27 15:31:06', '2026-08-27 12:15:41', '2026-08-27 15:31:06');

--
-- Triggers `users`
--
DELIMITER $$
CREATE TRIGGER `trg_user_create_profile` AFTER INSERT ON `users` FOR EACH ROW BEGIN

    INSERT INTO profiles
    (
        user_id,
        display_name
    )
    VALUES
    (
        NEW.id,
        NEW.full_names
    );

END
$$
DELIMITER ;
DELIMITER $$
CREATE TRIGGER `trg_user_notification_preferences` AFTER INSERT ON `users` FOR EACH ROW BEGIN

    INSERT INTO notification_preferences
    (
        user_id
    )
    VALUES
    (
        NEW.id
    );

    INSERT INTO user_presence
    (
        user_id,
        is_online
    )
    VALUES
    (
        NEW.id,
        FALSE
    );

END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `user_presence`
--

CREATE TABLE `user_presence` (
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `is_online` tinyint(1) NOT NULL DEFAULT 0,
  `last_seen_at` datetime DEFAULT NULL,
  `is_typing` tinyint(1) NOT NULL DEFAULT 0,
  `typing_conversation_id` bigint(20) UNSIGNED DEFAULT NULL,
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `user_presence`
--

INSERT INTO `user_presence` (`user_id`, `is_online`, `last_seen_at`, `is_typing`, `typing_conversation_id`, `updated_at`) VALUES
(3, 0, NULL, 0, NULL, '2026-08-27 11:19:45'),
(4, 0, NULL, 0, NULL, '2026-08-27 12:15:41');

-- --------------------------------------------------------

--
-- Table structure for table `user_sessions`
--

CREATE TABLE `user_sessions` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `session_token_hash` char(64) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `last_activity_at` datetime NOT NULL DEFAULT current_timestamp(),
  `two_factor_passed` tinyint(1) NOT NULL DEFAULT 0,
  `expires_at` datetime NOT NULL,
  `revoked_at` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `user_sessions`
--

INSERT INTO `user_sessions` (`id`, `user_id`, `session_token_hash`, `ip_address`, `user_agent`, `created_at`, `last_activity_at`, `two_factor_passed`, `expires_at`, `revoked_at`) VALUES
(1, 3, 'eeee270ce625efe72d6dda4855c26695fca08c422607d1adef748b8d70ef030e', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 11:59:36', '2026-08-27 11:59:36', 0, '2026-08-28 10:59:36', '2026-08-27 12:00:32'),
(2, 3, '163d58c4ee0a97a43b9b996ad65751ca5b274ae7c9dd78a3616d418691a7c884', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 12:00:32', '2026-08-27 12:00:32', 0, '2026-09-26 11:00:32', '2026-08-27 12:09:28'),
(3, 3, '925b67261cc72831ead9906fdd289f966368dbb16cd1e4c42a3b9f56e8af4ff1', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 12:09:28', '2026-08-27 12:09:28', 0, '2026-08-28 11:09:28', '2026-08-27 12:13:49'),
(4, 3, 'e0d06fc6414420443092acb9d16358eebabedeb0a2388924d33aadf3ec37eaba', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 12:13:49', '2026-08-27 12:13:49', 0, '2026-08-28 11:13:49', '2026-08-27 12:40:00'),
(5, 4, 'ea861899d937186304468e7ad8214380619aca990f2bd234fb9c7766b92ca9ee', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 12:35:06', '2026-08-27 13:30:12', 1, '2026-09-26 11:35:06', '2026-08-27 15:29:24'),
(6, 3, 'f4101f8858b081b73c0ae305aeaa5b162ad897cf70a9c94ee2fb04e2ce1d6c12', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 12:40:00', '2026-08-27 12:40:00', 0, '2026-08-28 11:40:00', '2026-08-27 12:40:54'),
(7, 3, '0c2a9ff0be75def0e230cfdb52fd843691355dd61fbe6f039d38ee45ef0a2cda', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 12:40:54', '2026-08-27 12:48:18', 1, '2026-08-28 11:40:54', '2026-08-27 12:48:26'),
(8, 3, '1aa3b06b5b1c0107b3ab2d17653b2a76b53a534cc0886c2451d33a63311f1baf', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 12:48:26', '2026-08-27 12:48:26', 0, '2026-08-28 11:48:26', '2026-08-27 13:39:58'),
(9, 3, 'e7e14e5eaf9c1bd06e9d7511156d5e4826a61f40dbe7f313d31b2171d5b39932', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 13:39:58', '2026-08-27 15:29:11', 1, '2026-09-26 12:39:58', NULL),
(10, 4, 'a42b3c40e2ea2f2ccdb4d6f0f16ff0ebf93d29ac8b943b877589360194fac07e', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36', '2026-08-27 15:29:24', '2026-08-27 15:31:06', 1, '2026-09-26 14:29:24', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `verifications`
--

CREATE TABLE `verifications` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED DEFAULT NULL,
  `email` varchar(190) DEFAULT NULL,
  `phone_e164` varchar(30) DEFAULT NULL,
  `verification_type` varchar(40) NOT NULL,
  `code_hash` char(64) DEFAULT NULL,
  `attempt_count` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `send_count` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `expires_at` datetime NOT NULL,
  `verified_at` datetime DEFAULT NULL,
  `blocked_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `verifications`
--

INSERT INTO `verifications` (`id`, `user_id`, `email`, `phone_e164`, `verification_type`, `code_hash`, `attempt_count`, `send_count`, `expires_at`, `verified_at`, `blocked_at`, `created_at`) VALUES
(11, 3, 'jmsak37@gmail.com', NULL, 'email_registration', 'f22c302aaca43c28a5bc54a57b719f8b521628ab77ba74c3d8448d2436858551', 0, 1, '2026-08-27 10:29:45', '2026-08-27 11:20:10', NULL, '2026-08-27 11:19:45'),
(12, 4, 'eduassistasc@gmail.com', NULL, 'email_registration', 'c41657fd0d16d44478a6a8ff650532ac9e0351132ca2fecb486cb267c9fbd969', 0, 1, '2026-08-27 11:25:41', '2026-08-27 12:16:30', NULL, '2026-08-27 12:15:41');

-- --------------------------------------------------------

--
-- Stand-in structure for view `v_active_premium`
-- (See below for the actual view)
--
CREATE TABLE `v_active_premium` (
`subscription_id` bigint(20) unsigned
,`user_id` bigint(20) unsigned
,`username` varchar(50)
,`full_names` varchar(180)
,`service_id` bigint(20) unsigned
,`service_name` varchar(150)
,`status` varchar(30)
,`start_at` datetime
,`end_at` datetime
,`base_amount_usd` decimal(12,2)
,`amount_paid` decimal(18,4)
,`currency_code` varchar(10)
,`exchange_rate` decimal(20,10)
,`usage_limit` int(10) unsigned
,`usage_used` int(10) unsigned
);

-- --------------------------------------------------------

--
-- Stand-in structure for view `v_latest_public_posts`
-- (See below for the actual view)
--
CREATE TABLE `v_latest_public_posts` (
`post_id` bigint(20) unsigned
,`user_id` bigint(20) unsigned
,`username` varchar(50)
,`full_name` varchar(180)
,`gender` varchar(30)
,`country_name` varchar(120)
,`iso2` char(2)
,`bio` text
,`content` text
,`posted_at` datetime
,`photo_id` bigint(20) unsigned
,`post_image` varchar(500)
,`post_thumbnail` varchar(500)
,`mime_type` varchar(100)
);

-- --------------------------------------------------------

--
-- Stand-in structure for view `v_payment_summary`
-- (See below for the actual view)
--
CREATE TABLE `v_payment_summary` (
`payment_id` bigint(20) unsigned
,`user_id` bigint(20) unsigned
,`username` varchar(50)
,`full_names` varchar(180)
,`payment_reference` varchar(150)
,`gateway` varchar(50)
,`gateway_transaction_id` varchar(180)
,`status` varchar(30)
,`currency` varchar(10)
,`base_amount_usd` decimal(12,2)
,`exchange_rate` decimal(20,10)
,`amount_expected` decimal(18,4)
,`amount_paid` decimal(18,4)
,`paid_at` datetime
,`created_at` datetime
);

-- --------------------------------------------------------

--
-- Stand-in structure for view `v_public_posts`
-- (See below for the actual view)
--
CREATE TABLE `v_public_posts` (
`post_id` bigint(20) unsigned
,`user_id` bigint(20) unsigned
,`username` varchar(50)
,`full_name` varchar(180)
,`gender` varchar(30)
,`country_name` varchar(120)
,`iso2` char(2)
,`bio` text
,`content` text
,`posted_at` datetime
,`photo_id` bigint(20) unsigned
,`post_image` varchar(500)
,`post_thumbnail` varchar(500)
,`mime_type` varchar(100)
);

-- --------------------------------------------------------

--
-- Stand-in structure for view `v_unread_notifications`
-- (See below for the actual view)
--
CREATE TABLE `v_unread_notifications` (
`id` bigint(20) unsigned
,`user_id` bigint(20) unsigned
,`title` varchar(180)
,`message` text
,`notification_type` varchar(120)
,`audio_path` varchar(500)
,`created_at` datetime
);

-- --------------------------------------------------------

--
-- Stand-in structure for view `v_user_connections`
-- (See below for the actual view)
--
CREATE TABLE `v_user_connections` (
`connection_id` bigint(20) unsigned
,`user_id` bigint(20) unsigned
,`user_username` varchar(50)
,`user_full_name` varchar(180)
,`connected_user_id` bigint(20) unsigned
,`connected_username` varchar(50)
,`connected_full_name` varchar(180)
,`initiated_by` bigint(20) unsigned
,`status` varchar(30)
,`connected_at` datetime
,`created_at` datetime
);

-- --------------------------------------------------------

--
-- Structure for view `v_active_premium`
--
DROP TABLE IF EXISTS `v_active_premium`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_active_premium`  AS SELECT `s`.`id` AS `subscription_id`, `s`.`user_id` AS `user_id`, `u`.`username` AS `username`, `u`.`full_names` AS `full_names`, `s`.`service_id` AS `service_id`, `sv`.`name` AS `service_name`, `s`.`status` AS `status`, `s`.`start_at` AS `start_at`, `s`.`end_at` AS `end_at`, `s`.`base_amount_usd` AS `base_amount_usd`, `s`.`amount_paid` AS `amount_paid`, `cu`.`code` AS `currency_code`, `s`.`exchange_rate` AS `exchange_rate`, `s`.`usage_limit` AS `usage_limit`, `s`.`usage_used` AS `usage_used` FROM (((`subscriptions` `s` join `users` `u` on(`u`.`id` = `s`.`user_id`)) join `services` `sv` on(`sv`.`id` = `s`.`service_id`)) left join `currencies` `cu` on(`cu`.`id` = `s`.`currency_id`)) WHERE `s`.`status` = 'active' AND `s`.`end_at` > current_timestamp() ;

-- --------------------------------------------------------

--
-- Structure for view `v_latest_public_posts`
--
DROP TABLE IF EXISTS `v_latest_public_posts`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_latest_public_posts`  AS SELECT `v_public_posts`.`post_id` AS `post_id`, `v_public_posts`.`user_id` AS `user_id`, `v_public_posts`.`username` AS `username`, `v_public_posts`.`full_name` AS `full_name`, `v_public_posts`.`gender` AS `gender`, `v_public_posts`.`country_name` AS `country_name`, `v_public_posts`.`iso2` AS `iso2`, `v_public_posts`.`bio` AS `bio`, `v_public_posts`.`content` AS `content`, `v_public_posts`.`posted_at` AS `posted_at`, `v_public_posts`.`photo_id` AS `photo_id`, `v_public_posts`.`post_image` AS `post_image`, `v_public_posts`.`post_thumbnail` AS `post_thumbnail`, `v_public_posts`.`mime_type` AS `mime_type` FROM `v_public_posts` ORDER BY `v_public_posts`.`posted_at` DESC ;

-- --------------------------------------------------------

--
-- Structure for view `v_payment_summary`
--
DROP TABLE IF EXISTS `v_payment_summary`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_payment_summary`  AS SELECT `p`.`id` AS `payment_id`, `p`.`user_id` AS `user_id`, `u`.`username` AS `username`, `u`.`full_names` AS `full_names`, `p`.`payment_reference` AS `payment_reference`, `p`.`gateway` AS `gateway`, `p`.`gateway_transaction_id` AS `gateway_transaction_id`, `p`.`status` AS `status`, `cu`.`code` AS `currency`, `p`.`base_amount_usd` AS `base_amount_usd`, `p`.`exchange_rate` AS `exchange_rate`, `p`.`amount_expected` AS `amount_expected`, `p`.`amount_paid` AS `amount_paid`, `p`.`paid_at` AS `paid_at`, `p`.`created_at` AS `created_at` FROM ((`payments` `p` join `users` `u` on(`u`.`id` = `p`.`user_id`)) left join `currencies` `cu` on(`cu`.`id` = `p`.`currency_id`)) ;

-- --------------------------------------------------------

--
-- Structure for view `v_public_posts`
--
DROP TABLE IF EXISTS `v_public_posts`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_public_posts`  AS SELECT `p`.`id` AS `post_id`, `u`.`id` AS `user_id`, `u`.`username` AS `username`, `u`.`full_names` AS `full_name`, `u`.`gender` AS `gender`, `c`.`name` AS `country_name`, `c`.`iso2` AS `iso2`, `pr`.`bio` AS `bio`, `p`.`content` AS `content`, `p`.`created_at` AS `posted_at`, `pp`.`photo_id` AS `photo_id`, `ph`.`file_path` AS `post_image`, `ph`.`thumbnail_path` AS `post_thumbnail`, `ph`.`mime_type` AS `mime_type` FROM (((((`posts` `p` join `users` `u` on(`u`.`id` = `p`.`user_id`)) join `countries` `c` on(`c`.`id` = `u`.`country_id`)) left join `profiles` `pr` on(`pr`.`user_id` = `u`.`id`)) left join `post_photos` `pp` on(`pp`.`post_id` = `p`.`id` and `pp`.`display_order` = 1)) left join `photos` `ph` on(`ph`.`id` = `pp`.`photo_id`)) WHERE `p`.`approval_status` = 'approved' AND `p`.`visibility` = 'public' AND `p`.`deleted_at` is null AND `u`.`is_active` = 1 AND `u`.`is_suspended` = 0 AND `u`.`is_deleted` = 0 AND `ph`.`approval_status` = 'approved' ;

-- --------------------------------------------------------

--
-- Structure for view `v_unread_notifications`
--
DROP TABLE IF EXISTS `v_unread_notifications`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_unread_notifications`  AS SELECT `n`.`id` AS `id`, `n`.`user_id` AS `user_id`, `n`.`title` AS `title`, `n`.`message` AS `message`, `nt`.`slug` AS `notification_type`, `na`.`file_path` AS `audio_path`, `n`.`created_at` AS `created_at` FROM ((`notifications` `n` left join `notification_types` `nt` on(`nt`.`id` = `n`.`notification_type_id`)) left join `notification_audio` `na` on(`na`.`id` = `n`.`audio_id`)) WHERE `n`.`is_read` = 0 ;

-- --------------------------------------------------------

--
-- Structure for view `v_user_connections`
--
DROP TABLE IF EXISTS `v_user_connections`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_user_connections`  AS SELECT `c`.`id` AS `connection_id`, `c`.`user_id` AS `user_id`, `u1`.`username` AS `user_username`, `u1`.`full_names` AS `user_full_name`, `c`.`connected_user_id` AS `connected_user_id`, `u2`.`username` AS `connected_username`, `u2`.`full_names` AS `connected_full_name`, `c`.`initiated_by` AS `initiated_by`, `c`.`status` AS `status`, `c`.`connected_at` AS `connected_at`, `c`.`created_at` AS `created_at` FROM ((`connections` `c` join `users` `u1` on(`u1`.`id` = `c`.`user_id`)) join `users` `u2` on(`u2`.`id` = `c`.`connected_user_id`)) ;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `audit_logs`
--
ALTER TABLE `audit_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_audit_user` (`user_id`),
  ADD KEY `idx_audit_action` (`action`),
  ADD KEY `idx_audit_entity` (`entity_type`,`entity_id`),
  ADD KEY `idx_audit_created` (`created_at`),
  ADD KEY `idx_audit_entity_created` (`entity_type`,`entity_id`,`created_at`);

--
-- Indexes for table `backup_logs`
--
ALTER TABLE `backup_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_backup_creator` (`created_by`);

--
-- Indexes for table `blocked_users`
--
ALTER TABLE `blocked_users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_block_pair` (`user_id`,`blocked_user_id`),
  ADD KEY `idx_block_user` (`user_id`),
  ADD KEY `idx_blocked_user` (`blocked_user_id`);

--
-- Indexes for table `connections`
--
ALTER TABLE `connections`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_connection_pair` (`user_low_id`,`user_high_id`),
  ADD KEY `idx_connection_user` (`user_id`),
  ADD KEY `idx_connection_connected_user` (`connected_user_id`),
  ADD KEY `idx_connection_status` (`status`),
  ADD KEY `idx_connection_initiator` (`initiated_by`);

--
-- Indexes for table `conversations`
--
ALTER TABLE `conversations`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_conversation_pair` (`user_low_id`,`user_high_id`),
  ADD KEY `idx_conversation_connection` (`connection_id`),
  ADD KEY `fk_conversation_user_one` (`user_one_id`),
  ADD KEY `fk_conversation_user_two` (`user_two_id`);

--
-- Indexes for table `countries`
--
ALTER TABLE `countries`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_country_iso2` (`iso2`),
  ADD UNIQUE KEY `uq_country_iso3` (`iso3`),
  ADD KEY `idx_country_currency` (`currency_id`),
  ADD KEY `idx_country_active` (`is_active`);

--
-- Indexes for table `currencies`
--
ALTER TABLE `currencies`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_currency_code` (`code`),
  ADD KEY `idx_currency_active` (`is_active`);

--
-- Indexes for table `exchange_rates`
--
ALTER TABLE `exchange_rates`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_exchange_pair_time` (`base_currency_id`,`target_currency_id`,`effective_at`),
  ADD KEY `idx_exchange_target` (`target_currency_id`),
  ADD KEY `idx_exchange_active` (`is_active`),
  ADD KEY `idx_exchange_effective` (`effective_at`);

--
-- Indexes for table `login_logs`
--
ALTER TABLE `login_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_login_user` (`user_id`),
  ADD KEY `idx_login_identifier` (`identifier`),
  ADD KEY `idx_login_status` (`login_status`),
  ADD KEY `idx_login_created` (`created_at`);

--
-- Indexes for table `messages`
--
ALTER TABLE `messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_message_conversation` (`conversation_id`),
  ADD KEY `idx_message_sender` (`sender_id`),
  ADD KEY `idx_message_receiver` (`receiver_id`),
  ADD KEY `idx_message_read` (`is_read`),
  ADD KEY `idx_message_created` (`created_at`),
  ADD KEY `idx_messages_conversation_created` (`conversation_id`,`created_at`);

--
-- Indexes for table `notifications`
--
ALTER TABLE `notifications`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_notification_user` (`user_id`),
  ADD KEY `idx_notification_read` (`is_read`),
  ADD KEY `idx_notification_type` (`notification_type_id`),
  ADD KEY `idx_notification_created` (`created_at`),
  ADD KEY `fk_notification_sender` (`sender_id`),
  ADD KEY `fk_notification_audio` (`audio_id`),
  ADD KEY `idx_notifications_user_created` (`user_id`,`created_at`);

--
-- Indexes for table `notification_audio`
--
ALTER TABLE `notification_audio`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_notification_audio_name` (`name`),
  ADD KEY `idx_audio_type` (`notification_type_id`),
  ADD KEY `idx_audio_active` (`is_active`);

--
-- Indexes for table `notification_preferences`
--
ALTER TABLE `notification_preferences`
  ADD PRIMARY KEY (`user_id`);

--
-- Indexes for table `notification_types`
--
ALTER TABLE `notification_types`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_notification_type_name` (`name`),
  ADD UNIQUE KEY `uq_notification_type_slug` (`slug`);

--
-- Indexes for table `password_resets`
--
ALTER TABLE `password_resets`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_reset_token_hash` (`reset_token_hash`),
  ADD KEY `idx_reset_user` (`user_id`),
  ADD KEY `idx_reset_expiry` (`expires_at`);

--
-- Indexes for table `payments`
--
ALTER TABLE `payments`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_payment_reference` (`payment_reference`),
  ADD KEY `idx_payment_user` (`user_id`),
  ADD KEY `idx_payment_service` (`service_id`),
  ADD KEY `idx_payment_subscription` (`subscription_id`),
  ADD KEY `idx_payment_status` (`status`),
  ADD KEY `idx_payment_gateway_transaction` (`gateway_transaction_id`),
  ADD KEY `fk_payment_currency` (`currency_id`),
  ADD KEY `idx_payments_user_created` (`user_id`,`created_at`);

--
-- Indexes for table `payment_receipts`
--
ALTER TABLE `payment_receipts`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_receipt_number` (`receipt_number`),
  ADD UNIQUE KEY `uq_receipt_payment` (`payment_id`);

--
-- Indexes for table `permissions`
--
ALTER TABLE `permissions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_permission_name` (`name`),
  ADD UNIQUE KEY `uq_permission_slug` (`slug`);

--
-- Indexes for table `photos`
--
ALTER TABLE `photos`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_photo_user` (`user_id`),
  ADD KEY `idx_photo_status` (`approval_status`),
  ADD KEY `idx_photo_primary` (`is_primary`),
  ADD KEY `idx_photo_featured` (`is_featured`),
  ADD KEY `fk_photo_approver` (`approved_by`),
  ADD KEY `idx_photos_user_approved` (`user_id`,`approval_status`);

--
-- Indexes for table `posts`
--
ALTER TABLE `posts`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_post_user` (`user_id`),
  ADD KEY `idx_post_status` (`approval_status`),
  ADD KEY `idx_post_visibility` (`visibility`),
  ADD KEY `idx_post_featured` (`is_featured`),
  ADD KEY `idx_post_created` (`created_at`),
  ADD KEY `fk_post_approver` (`approved_by`),
  ADD KEY `idx_posts_user_created` (`user_id`,`created_at`);

--
-- Indexes for table `post_photos`
--
ALTER TABLE `post_photos`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_post_photo` (`post_id`,`photo_id`),
  ADD KEY `idx_post_photo_order` (`post_id`,`display_order`),
  ADD KEY `fk_post_photo_photo` (`photo_id`);

--
-- Indexes for table `profiles`
--
ALTER TABLE `profiles`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_profile_user` (`user_id`),
  ADD KEY `idx_profile_visibility` (`profile_visibility`),
  ADD KEY `idx_profiles_city` (`city`);

--
-- Indexes for table `reports`
--
ALTER TABLE `reports`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_report_reporter` (`reporter_id`),
  ADD KEY `idx_report_user` (`reported_user_id`),
  ADD KEY `idx_report_post` (`post_id`),
  ADD KEY `idx_report_message` (`message_id`),
  ADD KEY `idx_report_status` (`status`),
  ADD KEY `fk_report_reviewer` (`reviewed_by`);

--
-- Indexes for table `roles`
--
ALTER TABLE `roles`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_role_name` (`name`),
  ADD UNIQUE KEY `uq_role_slug` (`slug`);

--
-- Indexes for table `role_permissions`
--
ALTER TABLE `role_permissions`
  ADD PRIMARY KEY (`role_id`,`permission_id`),
  ADD KEY `fk_role_permission_permission` (`permission_id`);

--
-- Indexes for table `security_events`
--
ALTER TABLE `security_events`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_security_user` (`user_id`),
  ADD KEY `idx_security_type` (`event_type`),
  ADD KEY `idx_security_severity` (`severity`);

--
-- Indexes for table `services`
--
ALTER TABLE `services`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_service_slug` (`slug`),
  ADD KEY `idx_service_active` (`is_active`),
  ADD KEY `idx_service_premium` (`is_premium`);

--
-- Indexes for table `subscriptions`
--
ALTER TABLE `subscriptions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_subscription_user` (`user_id`),
  ADD KEY `idx_subscription_service` (`service_id`),
  ADD KEY `idx_subscription_status` (`status`),
  ADD KEY `idx_subscription_end` (`end_at`),
  ADD KEY `fk_subscription_currency` (`currency_id`),
  ADD KEY `idx_subscriptions_user_end` (`user_id`,`end_at`);

--
-- Indexes for table `system_settings`
--
ALTER TABLE `system_settings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_setting_key` (`setting_key`),
  ADD KEY `idx_setting_public` (`is_public`),
  ADD KEY `fk_setting_updated_by` (`updated_by`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_user_username` (`username`),
  ADD UNIQUE KEY `uq_user_email` (`email`),
  ADD UNIQUE KEY `uq_user_phone` (`phone_e164`),
  ADD KEY `idx_user_role` (`role_id`),
  ADD KEY `idx_user_country` (`country_id`),
  ADD KEY `idx_user_status` (`account_status`),
  ADD KEY `idx_user_active` (`is_active`),
  ADD KEY `idx_user_gender` (`gender`),
  ADD KEY `idx_user_deleted` (`is_deleted`),
  ADD KEY `idx_users_created` (`created_at`),
  ADD KEY `idx_users_two_factor` (`two_factor_enabled`);

--
-- Indexes for table `user_presence`
--
ALTER TABLE `user_presence`
  ADD PRIMARY KEY (`user_id`),
  ADD KEY `fk_presence_conversation` (`typing_conversation_id`);

--
-- Indexes for table `user_sessions`
--
ALTER TABLE `user_sessions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_session_token` (`session_token_hash`),
  ADD KEY `idx_session_user` (`user_id`),
  ADD KEY `idx_session_expires` (`expires_at`),
  ADD KEY `idx_session_revoked` (`revoked_at`),
  ADD KEY `idx_sessions_two_factor` (`two_factor_passed`);

--
-- Indexes for table `verifications`
--
ALTER TABLE `verifications`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_verification_user` (`user_id`),
  ADD KEY `idx_verification_email` (`email`),
  ADD KEY `idx_verification_phone` (`phone_e164`),
  ADD KEY `idx_verification_type` (`verification_type`),
  ADD KEY `idx_verification_expiry` (`expires_at`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `audit_logs`
--
ALTER TABLE `audit_logs`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `backup_logs`
--
ALTER TABLE `backup_logs`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `blocked_users`
--
ALTER TABLE `blocked_users`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `connections`
--
ALTER TABLE `connections`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `conversations`
--
ALTER TABLE `conversations`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `countries`
--
ALTER TABLE `countries`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=250;

--
-- AUTO_INCREMENT for table `currencies`
--
ALTER TABLE `currencies`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=151;

--
-- AUTO_INCREMENT for table `exchange_rates`
--
ALTER TABLE `exchange_rates`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `login_logs`
--
ALTER TABLE `login_logs`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- AUTO_INCREMENT for table `messages`
--
ALTER TABLE `messages`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `notifications`
--
ALTER TABLE `notifications`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `notification_audio`
--
ALTER TABLE `notification_audio`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- AUTO_INCREMENT for table `notification_types`
--
ALTER TABLE `notification_types`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- AUTO_INCREMENT for table `password_resets`
--
ALTER TABLE `password_resets`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `payments`
--
ALTER TABLE `payments`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `payment_receipts`
--
ALTER TABLE `payment_receipts`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `permissions`
--
ALTER TABLE `permissions`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=27;

--
-- AUTO_INCREMENT for table `photos`
--
ALTER TABLE `photos`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `posts`
--
ALTER TABLE `posts`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `post_photos`
--
ALTER TABLE `post_photos`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `profiles`
--
ALTER TABLE `profiles`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `reports`
--
ALTER TABLE `reports`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `roles`
--
ALTER TABLE `roles`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `security_events`
--
ALTER TABLE `security_events`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `services`
--
ALTER TABLE `services`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `subscriptions`
--
ALTER TABLE `subscriptions`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `system_settings`
--
ALTER TABLE `system_settings`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=18;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `user_sessions`
--
ALTER TABLE `user_sessions`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `verifications`
--
ALTER TABLE `verifications`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `audit_logs`
--
ALTER TABLE `audit_logs`
  ADD CONSTRAINT `fk_audit_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Constraints for table `backup_logs`
--
ALTER TABLE `backup_logs`
  ADD CONSTRAINT `fk_backup_creator` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Constraints for table `blocked_users`
--
ALTER TABLE `blocked_users`
  ADD CONSTRAINT `fk_block_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_blocked_user` FOREIGN KEY (`blocked_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `connections`
--
ALTER TABLE `connections`
  ADD CONSTRAINT `fk_connection_initiator` FOREIGN KEY (`initiated_by`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_connection_target` FOREIGN KEY (`connected_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_connection_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `conversations`
--
ALTER TABLE `conversations`
  ADD CONSTRAINT `fk_conversation_connection` FOREIGN KEY (`connection_id`) REFERENCES `connections` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_conversation_user_one` FOREIGN KEY (`user_one_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_conversation_user_two` FOREIGN KEY (`user_two_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `countries`
--
ALTER TABLE `countries`
  ADD CONSTRAINT `fk_country_currency` FOREIGN KEY (`currency_id`) REFERENCES `currencies` (`id`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Constraints for table `exchange_rates`
--
ALTER TABLE `exchange_rates`
  ADD CONSTRAINT `fk_exchange_base` FOREIGN KEY (`base_currency_id`) REFERENCES `currencies` (`id`) ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_exchange_target` FOREIGN KEY (`target_currency_id`) REFERENCES `currencies` (`id`) ON UPDATE CASCADE;

--
-- Constraints for table `login_logs`
--
ALTER TABLE `login_logs`
  ADD CONSTRAINT `fk_login_log_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Constraints for table `messages`
--
ALTER TABLE `messages`
  ADD CONSTRAINT `fk_message_conversation` FOREIGN KEY (`conversation_id`) REFERENCES `conversations` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_message_receiver` FOREIGN KEY (`receiver_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_message_sender` FOREIGN KEY (`sender_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `notifications`
--
ALTER TABLE `notifications`
  ADD CONSTRAINT `fk_notification_audio` FOREIGN KEY (`audio_id`) REFERENCES `notification_audio` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_notification_sender` FOREIGN KEY (`sender_id`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_notification_type` FOREIGN KEY (`notification_type_id`) REFERENCES `notification_types` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_notification_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `notification_audio`
--
ALTER TABLE `notification_audio`
  ADD CONSTRAINT `fk_audio_type` FOREIGN KEY (`notification_type_id`) REFERENCES `notification_types` (`id`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Constraints for table `notification_preferences`
--
ALTER TABLE `notification_preferences`
  ADD CONSTRAINT `fk_notification_preferences_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `password_resets`
--
ALTER TABLE `password_resets`
  ADD CONSTRAINT `fk_password_reset_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `payments`
--
ALTER TABLE `payments`
  ADD CONSTRAINT `fk_payment_currency` FOREIGN KEY (`currency_id`) REFERENCES `currencies` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_payment_service` FOREIGN KEY (`service_id`) REFERENCES `services` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_payment_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON UPDATE CASCADE;

--
-- Constraints for table `payment_receipts`
--
ALTER TABLE `payment_receipts`
  ADD CONSTRAINT `fk_receipt_payment` FOREIGN KEY (`payment_id`) REFERENCES `payments` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `photos`
--
ALTER TABLE `photos`
  ADD CONSTRAINT `fk_photo_approver` FOREIGN KEY (`approved_by`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_photo_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `posts`
--
ALTER TABLE `posts`
  ADD CONSTRAINT `fk_post_approver` FOREIGN KEY (`approved_by`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_post_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `post_photos`
--
ALTER TABLE `post_photos`
  ADD CONSTRAINT `fk_post_photo_photo` FOREIGN KEY (`photo_id`) REFERENCES `photos` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_post_photo_post` FOREIGN KEY (`post_id`) REFERENCES `posts` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `profiles`
--
ALTER TABLE `profiles`
  ADD CONSTRAINT `fk_profile_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `reports`
--
ALTER TABLE `reports`
  ADD CONSTRAINT `fk_report_message` FOREIGN KEY (`message_id`) REFERENCES `messages` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_report_post` FOREIGN KEY (`post_id`) REFERENCES `posts` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_report_reported_user` FOREIGN KEY (`reported_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_report_reporter` FOREIGN KEY (`reporter_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_report_reviewer` FOREIGN KEY (`reviewed_by`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Constraints for table `role_permissions`
--
ALTER TABLE `role_permissions`
  ADD CONSTRAINT `fk_role_permission_permission` FOREIGN KEY (`permission_id`) REFERENCES `permissions` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_role_permission_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `security_events`
--
ALTER TABLE `security_events`
  ADD CONSTRAINT `fk_security_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Constraints for table `subscriptions`
--
ALTER TABLE `subscriptions`
  ADD CONSTRAINT `fk_subscription_currency` FOREIGN KEY (`currency_id`) REFERENCES `currencies` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_subscription_service` FOREIGN KEY (`service_id`) REFERENCES `services` (`id`) ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_subscription_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `system_settings`
--
ALTER TABLE `system_settings`
  ADD CONSTRAINT `fk_setting_updated_by` FOREIGN KEY (`updated_by`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Constraints for table `users`
--
ALTER TABLE `users`
  ADD CONSTRAINT `fk_user_country` FOREIGN KEY (`country_id`) REFERENCES `countries` (`id`) ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_user_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON UPDATE CASCADE;

--
-- Constraints for table `user_presence`
--
ALTER TABLE `user_presence`
  ADD CONSTRAINT `fk_presence_conversation` FOREIGN KEY (`typing_conversation_id`) REFERENCES `conversations` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_presence_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `user_sessions`
--
ALTER TABLE `user_sessions`
  ADD CONSTRAINT `fk_session_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `verifications`
--
ALTER TABLE `verifications`
  ADD CONSTRAINT `fk_verification_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
