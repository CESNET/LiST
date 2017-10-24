-- phpMyAdmin SQL Dump
-- version 3.4.11.1deb2+deb7u1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Dec 04, 2014 at 02:54 PM
-- Server version: 5.5.38
-- PHP Version: 5.4.4-14+deb7u14

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `warden3`
--

-- --------------------------------------------------------

--
-- Table structure for table `categories`
--

CREATE TABLE IF NOT EXISTS `categories` (
  `id` int UNSIGNED NOT NULL,
  `category` varchar(64) NOT NULL,
  `subcategory` varchar(64) DEFAULT NULL,
  `cat_subcat` varchar(129) NOT NULL,
  KEY `cat_sub` (`cat_subcat`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 DEFAULT COLLATE utf8_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `clients`
--

CREATE TABLE IF NOT EXISTS `clients` (
  `id` int UNSIGNED NOT NULL AUTO_INCREMENT,
  `registered` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `requestor` varchar(256) NOT NULL,
  `hostname` varchar(256) NOT NULL,
  `note` text NULL,
  `valid` tinyint UNSIGNED NOT NULL DEFAULT '1',
  `name` varchar(64) NOT NULL,
  `secret` varchar(16) NULL,
  `read` tinyint UNSIGNED NOT NULL DEFAULT '1',
  `debug` tinyint UNSIGNED NOT NULL DEFAULT '0',
  `write` tinyint UNSIGNED NOT NULL DEFAULT '0',
  `test` tinyint UNSIGNED NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `clients_1` (`valid`, `secret`, `hostname`),
  KEY `clients_2` (`valid`, `name`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 DEFAULT COLLATE utf8_unicode_ci AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `events`
--

CREATE TABLE IF NOT EXISTS `events` (
  `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT,
  `received` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `client_id` int UNSIGNED NOT NULL,
  `data` longtext NOT NULL,
  `valid` tinyint UNSIGNED NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  KEY `id` (`id`,`client_id`),
  KEY `received` (`received`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8  DEFAULT COLLATE utf8_unicode_ci AUTO_INCREMENT=2 ;

-- --------------------------------------------------------

--
-- Table structure for table `event_category_mapping`
--

CREATE TABLE IF NOT EXISTS `event_category_mapping` (
  `event_id` bigint UNSIGNED NOT NULL,
  `category_id` int UNSIGNED NOT NULL,
  KEY `event_id_2` (`event_id`,`category_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 DEFAULT COLLATE utf8_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `event_tag_mapping`
--

CREATE TABLE IF NOT EXISTS `event_tag_mapping` (
  `event_id` bigint UNSIGNED NOT NULL,
  `tag_id` int UNSIGNED NOT NULL,
  KEY `event_id_2` (`event_id`,`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 DEFAULT COLLATE utf8_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `last_events`
--

CREATE TABLE IF NOT EXISTS `last_events` (
  `id` int UNSIGNED NOT NULL AUTO_INCREMENT,
  `client_id` int UNSIGNED NOT NULL,
  `event_id` bigint UNSIGNED NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `client_id` (`client_id`,`event_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 DEFAULT COLLATE utf8_unicode_ci AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `tags`
--

CREATE TABLE IF NOT EXISTS `tags` (
  `id` int UNSIGNED NOT NULL,
  `tag` varchar(64) NOT NULL,
  KEY `id_tag_name` (`id`,`tag`),
  KEY `tag_name` (`tag`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 DEFAULT COLLATE utf8_unicode_ci;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
