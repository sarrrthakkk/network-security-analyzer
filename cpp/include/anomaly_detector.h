#ifndef ANOMALY_DETECTOR_H
#define ANOMALY_DETECTOR_H

#include "common.h"
#include <vector>
#include <deque>
#include <map>
#include <memory>
#include <mutex>

namespace nsa {

class AnomalyDetector {
public:
    AnomalyDetector();
    ~AnomalyDetector();

    // Initialize detector with configuration
    void initialize(const Config& config);
    
    // Process new packet for anomaly detection
    void process_packet(const Packet& packet);
    
    // Process flow for anomaly detection
    void process_flow(const Flow& flow);
    
    // Get detected anomalies
    std::vector<Threat> get_anomalies() const;
    
    // Clear detected anomalies
    void clear_anomalies();
    
    // Get anomaly statistics
    std::map<AnomalyType, uint64_t> get_anomaly_statistics() const;
    
    // Set detection thresholds
    void set_volume_threshold(double threshold);
    void set_frequency_threshold(double threshold);
    void set_pattern_threshold(double threshold);
    
    // Enable/disable specific detection methods
    void enable_volume_detection(bool enabled);
    void enable_frequency_detection(bool enabled);
    void enable_pattern_detection(bool enabled);
    void enable_behavioral_detection(bool enabled);

private:
    // Configuration
    Config config_;
    
    // Detection state
    std::atomic<bool> volume_detection_enabled_;
    std::atomic<bool> frequency_detection_enabled_;
    std::atomic<bool> pattern_detection_enabled_;
    std::atomic<bool> behavioral_detection_enabled_;
    
    // Thresholds
    double volume_threshold_;
    double frequency_threshold_;
    double pattern_threshold_;
    
    // Historical data
    mutable std::mutex data_mutex_;
    std::deque<Packet> recent_packets_;
    std::deque<Flow> recent_flows_;
    std::map<std::string, std::deque<std::chrono::system_clock::time_point>> ip_timestamps_;
    std::map<uint16_t, std::deque<std::chrono::system_clock::time_point>> port_timestamps_;
    
    // Statistical models
    struct StatisticalModel {
        double mean;
        double std_dev;
        double variance;
        uint64_t count;
        std::deque<double> recent_values;
    };
    
    std::map<std::string, StatisticalModel> ip_models_;
    std::map<uint16_t, StatisticalModel> port_models_;
    std::map<PacketType, StatisticalModel> protocol_models_;
    
    // Detected anomalies
    mutable std::mutex anomalies_mutex_;
    std::vector<Threat> anomalies_;
    std::map<AnomalyType, uint64_t> anomaly_counts_;
    
    // Detection methods
    void detect_volume_anomalies(const Packet& packet);
    void detect_frequency_anomalies(const Packet& packet);
    void detect_pattern_anomalies(const Packet& packet);
    void detect_behavioral_anomalies(const Packet& packet);
    
    // Statistical calculations
    void update_statistical_model(StatisticalModel& model, double value);
    double calculate_z_score(double value, const StatisticalModel& model);
    bool is_anomalous(double z_score, double threshold);
    
    // Volume analysis
    void analyze_packet_volume(const Packet& packet);
    void analyze_byte_volume(const Packet& packet);
    void analyze_flow_volume(const Flow& flow);
    
    // Frequency analysis
    void analyze_ip_frequency(const Packet& packet);
    void analyze_port_frequency(const Packet& packet);
    void analyze_protocol_frequency(const Packet& packet);
    
    // Pattern analysis
    void analyze_packet_patterns(const Packet& packet);
    void analyze_flow_patterns(const Flow& flow);
    void analyze_temporal_patterns(const Packet& packet);
    
    // Behavioral analysis
    void analyze_user_behavior(const Packet& packet);
    void analyze_service_behavior(const Packet& packet);
    void analyze_network_behavior(const Packet& packet);
    
    // Utility methods
    void add_anomaly(AnomalyType type, const std::string& description, 
                     const std::string& source_ip, const std::string& dest_ip,
                     double confidence, const std::map<std::string, std::string>& evidence);
    void cleanup_old_data();
    std::chrono::system_clock::time_point get_current_time() const;
};

} // namespace nsa

#endif // ANOMALY_DETECTOR_H

