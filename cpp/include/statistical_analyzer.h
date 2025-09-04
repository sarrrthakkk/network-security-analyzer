#ifndef STATISTICAL_ANALYZER_H
#define STATISTICAL_ANALYZER_H

#include "common.h"
#include <vector>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <chrono>

namespace nsa {

class StatisticalAnalyzer {
public:
    StatisticalAnalyzer();
    ~StatisticalAnalyzer();

    // Initialize analyzer
    void initialize(const Config& config);
    
    // Process packet for statistics
    void process_packet(const Packet& packet);
    
    // Process flow for statistics
    void process_flow(const Flow& flow);
    
    // Get current statistics
    Statistics get_statistics() const;
    
    // Get historical statistics
    std::vector<Statistics> get_historical_statistics(size_t count = 100) const;
    
    // Get specific statistics
    std::map<std::string, uint64_t> get_ip_statistics() const;
    std::map<uint16_t, uint64_t> get_port_statistics() const;
    std::map<PacketType, uint64_t> get_protocol_statistics() const;
    
    // Get time-based statistics
    std::map<std::string, std::vector<uint64_t>> get_time_series_data(
        const std::string& metric, 
        const std::chrono::system_clock::time_point& start,
        const std::chrono::system_clock::time_point& end,
        const std::chrono::seconds& interval) const;
    
    // Get statistical summaries
    struct StatisticalSummary {
        double mean;
        double median;
        double std_dev;
        double variance;
        double min;
        double max;
        double percentile_25;
        double percentile_75;
        double percentile_95;
        double percentile_99;
    };
    
    StatisticalSummary get_packet_size_summary() const;
    StatisticalSummary get_packet_rate_summary() const;
    StatisticalSummary get_byte_rate_summary() const;
    
    // Get top talkers
    std::vector<std::pair<std::string, uint64_t>> get_top_source_ips(size_t count = 10) const;
    std::vector<std::pair<std::string, uint64_t>> get_top_dest_ips(size_t count = 10) const;
    std::vector<std::pair<uint16_t, uint64_t>> get_top_ports(size_t count = 10) const;
    
    // Get traffic patterns
    std::map<std::string, std::vector<std::chrono::system_clock::time_point>> get_traffic_patterns() const;
    std::map<std::string, std::vector<uint64_t>> get_bandwidth_usage() const;
    
    // Clear statistics
    void clear_statistics();
    
    // Export statistics
    bool export_statistics(const std::string& filename, const std::string& format = "json") const;
    
    // Set analysis parameters
    void set_history_size(size_t size);
    void set_update_interval(const std::chrono::milliseconds& interval);
    void enable_real_time_updates(bool enabled);

private:
    // Configuration
    Config config_;
    size_t history_size_;
    std::chrono::milliseconds update_interval_;
    bool real_time_updates_enabled_;
    
    // Current statistics
    mutable std::mutex stats_mutex_;
    Statistics current_stats_;
    
    // Historical statistics
    mutable std::mutex history_mutex_;
    std::deque<Statistics> historical_stats_;
    std::deque<std::chrono::system_clock::time_point> history_timestamps_;
    
    // Detailed statistics
    struct DetailedStats {
        std::map<std::string, uint64_t> ip_packet_counts;
        std::map<std::string, uint64_t> ip_byte_counts;
        std::map<uint16_t, uint64_t> port_packet_counts;
        std::map<uint16_t, uint64_t> port_byte_counts;
        std::map<PacketType, uint64_t> protocol_packet_counts;
        std::map<PacketType, uint64_t> protocol_byte_counts;
        
        std::map<std::string, std::deque<uint64_t>> ip_packet_history;
        std::map<std::string, std::deque<uint64_t>> ip_byte_history;
        std::map<uint16_t, std::deque<uint64_t>> port_packet_history;
        std::map<uint16_t, std::deque<uint64_t>> port_byte_history;
        
        std::deque<uint32_t> packet_size_history;
        std::deque<std::chrono::system_clock::time_point> packet_timestamps;
    };
    
    mutable std::mutex detailed_mutex_;
    DetailedStats detailed_stats_;
    
    // Update tracking
    std::chrono::system_clock::time_point last_update_;
    std::atomic<uint64_t> packet_counter_;
    std::atomic<uint64_t> byte_counter_;
    
    // Statistical calculations
    void update_basic_statistics(const Packet& packet);
    void update_detailed_statistics(const Packet& packet);
    void update_historical_statistics();
    
    // Time series analysis
    void update_time_series_data(const Packet& packet);
    void cleanup_old_time_series_data();
    
    // Statistical computations
    double calculate_mean(const std::vector<uint64_t>& values) const;
    double calculate_median(const std::vector<uint64_t>& values) const;
    double calculate_std_dev(const std::vector<uint64_t>& values, double mean) const;
    double calculate_variance(const std::vector<uint64_t>& values, double mean) const;
    double calculate_percentile(const std::vector<uint64_t>& values, double percentile) const;
    
    // Rate calculations
    double calculate_packets_per_second() const;
    double calculate_bytes_per_second() const;
    double calculate_avg_packet_size() const;
    
    // Top talker analysis
    std::vector<std::pair<std::string, uint64_t>> get_top_items(
        const std::map<std::string, uint64_t>& data, size_t count) const;
    std::vector<std::pair<uint16_t, uint64_t>> get_top_ports(
        const std::map<uint16_t, uint64_t>& data, size_t count) const;
    
    // Export functionality
    bool export_json(const std::string& filename) const;
    bool export_csv(const std::string& filename) const;
    bool export_xml(const std::string& filename) const;
    
    // Utility methods
    void cleanup_old_history();
    std::chrono::system_clock::time_point get_current_time() const;
    std::string format_timestamp(const std::chrono::system_clock::time_point& time) const;
};

} // namespace nsa

#endif // STATISTICAL_ANALYZER_H

