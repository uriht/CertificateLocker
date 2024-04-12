-- phpMyAdmin SQL Dump
-- version 2.11.6
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Mar 09, 2024 at 05:52 PM
-- Server version: 5.0.51
-- PHP Version: 5.2.6

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `certificate_locker_new`
--

-- --------------------------------------------------------

--
-- Table structure for table `nt_blockchain`
--

CREATE TABLE `nt_blockchain` (
  `id` int(11) NOT NULL default '0',
  `block_id` int(11) NOT NULL,
  `pre_hash` varchar(200) NOT NULL,
  `hash_value` varchar(200) NOT NULL,
  `sdata` varchar(200) NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `nt_blockchain`
--
-- --------------------------------------------------------

--
-- Table structure for table `nt_cca`
--

CREATE TABLE `nt_cca` (
  `id` int(11) NOT NULL,
  `name` varchar(20) NOT NULL,
  `mobile` bigint(20) NOT NULL,
  `email` varchar(40) NOT NULL,
  `address` varchar(40) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `pass` varchar(20) NOT NULL,
  `state` varchar(20) NOT NULL,
  `utype` varchar(20) NOT NULL,
  `status` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `nt_cca`
--

INSERT INTO `nt_cca` (`id`, `name`, `mobile`, `email`, `address`, `uname`, `pass`, `state`, `utype`, `status`) VALUES
(1, 'Rajiv', 9034566264, 'cca_verify@gmail.com', 'Chennai', 'CCA1', '12345', '', 'CCA', 1);

-- --------------------------------------------------------

--
-- Table structure for table `nt_certificate`
--

CREATE TABLE `nt_certificate` (
  `id` int(11) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `ctype` varchar(30) NOT NULL,
  `filename` varchar(50) NOT NULL,
  `detail` varchar(100) NOT NULL,
  `rdate` varchar(20) NOT NULL,
  `status` int(11) NOT NULL,
  `canno` varchar(20) NOT NULL,
  `transfer_sii` varchar(20) NOT NULL,
  `transfer_siv` varchar(20) NOT NULL,
  `transfer_ccv` varchar(20) NOT NULL,
  `transfer_cca` varchar(20) NOT NULL,
  `ckey` varchar(20) NOT NULL,
  `c_status` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `nt_certificate`
--
-- --------------------------------------------------------

--
-- Table structure for table `nt_certificate_issued`
--

CREATE TABLE `nt_certificate_issued` (
  `id` int(11) NOT NULL,
  `kyc_code` varchar(20) NOT NULL,
  `filename` varchar(50) NOT NULL,
  `description` varchar(100) NOT NULL,
  `hash_value` varchar(100) NOT NULL,
  `face_status` int(11) NOT NULL,
  `text_value` text NOT NULL,
  `name` varchar(20) NOT NULL,
  `email` varchar(40) NOT NULL,
  `issue_date` varchar(20) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `value1` text NOT NULL,
  `value2` text NOT NULL,
  `value3` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `nt_certificate_issued`
--
-- --------------------------------------------------------

--
-- Table structure for table `nt_issuer`
--

CREATE TABLE `nt_issuer` (
  `id` int(11) NOT NULL,
  `name` varchar(20) NOT NULL,
  `mobile` bigint(20) NOT NULL,
  `email` varchar(40) NOT NULL,
  `address` varchar(40) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `pass` varchar(20) NOT NULL,
  `status` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `nt_issuer`
--

INSERT INTO `nt_issuer` (`id`, `name`, `mobile`, `email`, `address`, `uname`, `pass`, `status`) VALUES
(1, 'Gokul', 9893478595, 'gokul@gmail.com', 'Chennai', 'SS1', '123456', 1);

-- --------------------------------------------------------

--
-- Table structure for table `nt_login`
--

CREATE TABLE `nt_login` (
  `username` varchar(20) NOT NULL,
  `password` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `nt_login`
--

INSERT INTO `nt_login` (`username`, `password`) VALUES
('admin', 'admin');

-- --------------------------------------------------------

--
-- Table structure for table `nt_proof`
--

CREATE TABLE `nt_proof` (
  `id` int(11) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `cid` int(11) NOT NULL,
  `filename` varchar(50) NOT NULL,
  `detail` varchar(100) NOT NULL,
  `rdate` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `nt_proof`
--


-- --------------------------------------------------------

--
-- Table structure for table `nt_register`
--

CREATE TABLE `nt_register` (
  `id` int(11) NOT NULL,
  `name` varchar(20) NOT NULL,
  `mobile` bigint(20) NOT NULL,
  `email` varchar(40) NOT NULL,
  `address` varchar(50) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `pass` varchar(20) NOT NULL,
  `private_key` varchar(20) NOT NULL,
  `public_key` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `nt_register`
--

INSERT INTO `nt_register` (`id`, `name`, `mobile`, `email`, `address`, `uname`, `pass`, `private_key`, `public_key`) VALUES
(1, 'Rajan', 9894442716, 'rajan@gmail.com', '6/7, FG Nagar', 'U24393001', '123456', 'c5aa4c2c', '78067fa1');

-- --------------------------------------------------------

--
-- Table structure for table `nt_require`
--

CREATE TABLE `nt_require` (
  `id` int(11) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `cid` int(11) NOT NULL,
  `detail` varchar(100) NOT NULL,
  `rdate` varchar(20) NOT NULL,
  `verifier` varchar(20) NOT NULL,
  `cno` varchar(20) NOT NULL,
  `ckey` varchar(20) NOT NULL,
  `status` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;



CREATE TABLE `nt_tamper` (
  `id` int(11) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `canno` varchar(20) NOT NULL,
  `hash1` varchar(100) NOT NULL,
  `hash2` varchar(100) NOT NULL,
  `filename` varchar(50) NOT NULL,
  `face_status` int(11) NOT NULL,
  `text_value` text NOT NULL,
  `upload_file` varchar(50) NOT NULL,
  `value1` text NOT NULL,
  `value2` text NOT NULL,
  `value3` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `nt_tamper`
--
