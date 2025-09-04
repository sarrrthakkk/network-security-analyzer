#ifndef THREAT_DETECTOR_H
#define THREAT_DETECTOR_H

#include "common.h"
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <mutex>

namespace nsa {

class ThreatDetector {
public:
    ThreatDetector();
    ~ThreatDetector();

    // Initialize threat detector
    void initialize(const Config& config);
    
    // Process packet for threat detection
    void process_packet(const Packet& packet);
    
    // Process flow for threat detection
    void process_flow(const Flow& flow);
    
    // Get detected threats
    std::vector<Threat> get_threats() const;
    
    // Clear detected threats
    void clear_threats();
    
    // Get threat statistics
    std::map<ThreatLevel, uint64_t> get_threat_statistics() const;
    
    // Set detection sensitivity
    void set_sensitivity(ThreatLevel level);
    
    // Enable/disable specific threat detection
    void enable_ddos_detection(bool enabled);
    void enable_port_scan_detection(bool enabled);
    void enable_malware_detection(bool enabled);
    void enable_data_exfiltration_detection(bool enabled);
    void enable_suspicious_payload_detection(bool enabled);

private:
    // Configuration
    Config config_;
    ThreatLevel sensitivity_level_;
    
    // Detection state
    std::atomic<bool> ddos_detection_enabled_;
    std::atomic<bool> port_scan_detection_enabled_;
    std::atomic<bool> malware_detection_enabled_;
    std::atomic<bool> data_exfiltration_detection_enabled_;
    std::atomic<bool> suspicious_payload_detection_enabled_;
    
    // Detected threats
    mutable std::mutex threats_mutex_;
    std::vector<Threat> threats_;
    std::map<ThreatLevel, uint64_t> threat_counts_;
    
    // Threat patterns and signatures
    struct ThreatPattern {
        std::string name;
        std::string description;
        AnomalyType type;
        ThreatLevel level;
        std::vector<std::string> signatures;
        std::map<std::string, std::string> conditions;
    };
    
    std::vector<ThreatPattern> threat_patterns_;
    
    // Detection state tracking
    struct DetectionState {
        std::map<std::string, std::deque<std::chrono::system_clock::time_point>> connection_attempts;
        std::map<std::string, std::set<uint16_t>> scanned_ports;
        std::map<std::string, uint64_t> packet_counts;
        std::map<std::string, uint64_t> byte_counts;
        std::map<std::string, std::chrono::system_clock::time_point> last_seen;
    };
    
    mutable std::mutex state_mutex_;
    DetectionState detection_state_;
    
    // Threat detection methods
    void detect_ddos_attack(const Packet& packet);
    void detect_port_scan(const Packet& packet);
    void detect_malware_traffic(const Packet& packet);
    void detect_data_exfiltration(const Packet& packet);
    void detect_suspicious_payload(const Packet& packet);
    
    // DDoS detection
    void analyze_connection_rate(const Packet& packet);
    void analyze_bandwidth_usage(const Packet& packet);
    void analyze_syn_flood(const Packet& packet);
    void analyze_udp_flood(const Packet& packet);
    void analyze_icmp_flood(const Packet& packet);
    
    // Port scan detection
    void analyze_port_scanning(const Packet& packet);
    void analyze_stealth_scan(const Packet& packet);
    void analyze_slow_scan(const Packet& packet);
    void analyze_distributed_scan(const Packet& packet);
    
    // Malware detection
    void analyze_malware_signatures(const Packet& packet);
    void analyze_command_control_traffic(const Packet& packet);
    void analyze_exploit_patterns(const Packet& packet);
    void analyze_botnet_behavior(const Packet& packet);
    
    // Data exfiltration detection
    void analyze_data_volume(const Packet& packet);
    void analyze_data_patterns(const Packet& packet);
    void analyze_encrypted_tunnels(const Packet& packet);
    void analyze_dns_tunneling(const Packet& packet);
    
    // Suspicious payload detection
    void analyze_payload_content(const Packet& packet);
    void analyze_encoding_patterns(const Packet& packet);
    void analyze_compression_patterns(const Packet& packet);
    void analyze_obfuscation_techniques(const Packet& packet);
    
    // Pattern matching
    bool matches_threat_pattern(const Packet& packet, const ThreatPattern& pattern);
    bool contains_signature(const std::vector<uint8_t>& data, const std::string& signature);
    bool matches_conditions(const Packet& packet, const std::map<std::string, std::string>& conditions);
    
    // Threat assessment
    ThreatLevel assess_threat_level(const Packet& packet, AnomalyType type);
    double calculate_confidence(const Packet& packet, const ThreatPattern& pattern);
    std::map<std::string, std::string> collect_evidence(const Packet& packet, const ThreatPattern& pattern);
    
    // Utility methods
    void add_threat(AnomalyType type, const std::string& description,
                    const std::string& source_ip, const std::string& dest_ip,
                    ThreatLevel level, double confidence,
                    const std::map<std::string, std::string>& evidence);
    void cleanup_old_state();
    bool is_whitelisted(const std::string& ip);
    std::chrono::system_clock::time_point get_current_time() const;
    
    // Initialize threat patterns
    void initialize_threat_patterns();
};

} // namespace nsa

#endif // THREAT_DETECTOR_H

