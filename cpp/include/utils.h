#ifndef UTILS_H
#define UTILS_H

#include "common.h"
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <memory>
#include <random>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <regex>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <pcap.h>

namespace nsa {

class Utils {
public:
    // String utilities
    static std::vector<std::string> split_string(const std::string& str, char delimiter);
    static std::string join_strings(const std::vector<std::string>& strings, const std::string& separator);
    static std::string to_lowercase(const std::string& str);
    static std::string to_uppercase(const std::string& str);
    static std::string trim(const std::string& str);
    static std::string replace_all(const std::string& str, const std::string& from, const std::string& to);
    
    // IP address utilities
    static bool is_valid_ip(const std::string& ip);
    static bool is_private_ip(const std::string& ip);
    static bool is_loopback_ip(const std::string& ip);
    static std::string ip_to_binary(const std::string& ip);
    static std::string binary_to_ip(const std::string& binary);
    static uint32_t ip_to_uint32(const std::string& ip);
    static std::string uint32_to_ip(uint32_t ip);
    static std::string get_ip_class(const std::string& ip);
    static std::string get_subnet_mask(const std::string& ip);
    
    // Port utilities
    static bool is_valid_port(uint16_t port);
    static bool is_well_known_port(uint16_t port);
    static bool is_registered_port(uint16_t port);
    static bool is_dynamic_port(uint16_t port);
    static std::string get_service_name(uint16_t port);
    static std::vector<uint16_t> get_common_ports();
    
    // Protocol utilities
    static std::string get_protocol_name(uint8_t protocol);
    static uint8_t get_protocol_number(const std::string& protocol);
    static bool is_tcp_protocol(uint8_t protocol);
    static bool is_udp_protocol(uint8_t protocol);
    static bool is_icmp_protocol(uint8_t protocol);
    
    // Time utilities
    static std::string format_timestamp(const std::chrono::system_clock::time_point& time);
    static std::string format_duration(const std::chrono::milliseconds& duration);
    static std::chrono::system_clock::time_point parse_timestamp(const std::string& timestamp);
    static std::chrono::system_clock::time_point get_current_time();
    static uint64_t get_timestamp_ms();
    static uint64_t get_timestamp_us();
    
    // Hash utilities
    static std::string md5_hash(const std::string& data);
    static std::string sha1_hash(const std::string& data);
    static std::string sha256_hash(const std::string& data);
    static std::string generate_uuid();
    static uint64_t hash_string(const std::string& str);
    
    // Encoding utilities
    static std::string base64_encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64_decode(const std::string& encoded);
    static std::string hex_encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> hex_decode(const std::string& encoded);
    static std::string url_encode(const std::string& str);
    static std::string url_decode(const std::string& str);
    
    // Network utilities
    static std::string resolve_hostname(const std::string& hostname);
    static std::vector<std::string> get_dns_servers();
    static std::string get_local_ip();
    static std::string get_interface_ip(const std::string& interface);
    static std::vector<std::string> get_network_interfaces();
    static bool is_port_open(const std::string& ip, uint16_t port);
    
    // File utilities
    static bool file_exists(const std::string& filename);
    static uint64_t get_file_size(const std::string& filename);
    static std::string get_file_extension(const std::string& filename);
    static std::string get_file_name(const std::string& path);
    static std::string get_directory(const std::string& path);
    static bool create_directory(const std::string& path);
    static std::vector<std::string> list_files(const std::string& directory);
    static bool copy_file(const std::string& source, const std::string& destination);
    static bool delete_file(const std::string& filename);
    
    // Data conversion utilities
    static std::string bytes_to_hex(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);
    static std::string bytes_to_string(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> string_to_bytes(const std::string& str);
    static std::string format_bytes(uint64_t bytes);
    static std::string format_bits_per_second(uint64_t bps);
    static std::string format_packets_per_second(uint64_t pps);
    
    // Mathematical utilities
    static double calculate_percentage(double value, double total);
    static double calculate_percentage_change(double old_value, double new_value);
    static double calculate_average(const std::vector<double>& values);
    static double calculate_median(const std::vector<double>& values);
    static double calculate_standard_deviation(const std::vector<double>& values);
    static double calculate_variance(const std::vector<double>& values);
    static double calculate_percentile(const std::vector<double>& values, double percentile);
    static double calculate_correlation(const std::vector<double>& x, const std::vector<double>& y);
    
    // Validation utilities
    static bool is_numeric(const std::string& str);
    static bool is_alpha(const std::string& str);
    static bool is_alphanumeric(const std::string& str);
    static bool is_email(const std::string& email);
    static bool is_url(const std::string& url);
    static bool is_mac_address(const std::string& mac);
    static bool is_valid_filename(const std::string& filename);
    
    // Logging utilities
    static void log_info(const std::string& message);
    static void log_warning(const std::string& message);
    static void log_error(const std::string& message);
    static void log_debug(const std::string& message);
    static void set_log_level(const std::string& level);
    static void set_log_file(const std::string& filename);
    
    // Configuration utilities
    static bool load_config(const std::string& filename, std::map<std::string, std::string>& config);
    static bool save_config(const std::string& filename, const std::map<std::string, std::string>& config);
    static std::string get_config_value(const std::map<std::string, std::string>& config, 
                                       const std::string& key, const std::string& default_value = "");
    static bool set_config_value(std::map<std::string, std::string>& config, 
                                const std::string& key, const std::string& value);
    
    // Random utilities
    static uint32_t random_uint32();
    static uint64_t random_uint64();
    static std::string random_string(size_t length);
    static std::vector<uint8_t> random_bytes(size_t length);
    static void set_random_seed(uint64_t seed);
    
    // System utilities
    static std::string get_os_name();
    static std::string get_os_version();
    static std::string get_architecture();
    static uint64_t get_memory_usage();
    static double get_cpu_usage();
    static std::string get_username();
    static std::string get_hostname();
    static bool is_root_user();
    
    // Performance utilities
    static void start_timer(const std::string& name);
    static double stop_timer(const std::string& name);
    static double get_timer_value(const std::string& name);
    static void reset_timer(const std::string& name);
    static std::map<std::string, double> get_all_timers();
    
    // Error handling utilities
    static std::string get_last_error();
    static void set_last_error(const std::string& error);
    static void clear_last_error();
    static bool has_error();
    static std::string format_error(const std::string& message, const std::string& details = "");

private:
    // Static members for state
    static std::string last_error_;
    static std::string log_level_;
    static std::string log_file_;
    static std::map<std::string, std::chrono::high_resolution_clock::time_point> timers_;
    static std::mt19937 random_generator_;
    
    // Private constructor to prevent instantiation
    Utils() = delete;
};

} // namespace nsa

#endif // UTILS_H

