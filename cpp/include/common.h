#ifndef COMMON_H
#define COMMON_H

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <memory>

namespace nsa {

// Packet types
enum class PacketType {
    UNKNOWN = 0,
    TCP,
    UDP,
    ICMP,
    HTTP,
    HTTPS,
    DNS,
    FTP,
    SMTP,
    SSH
};

// Threat levels
enum class ThreatLevel {
    NONE = 0,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

// Anomaly types
enum class AnomalyType {
    NONE = 0,
    VOLUME_SPIKE,
    PROTOCOL_VIOLATION,
    PORT_SCAN,
    DDoS_ATTACK,
    MALWARE_TRAFFIC,
    DATA_EXFILTRATION,
    SUSPICIOUS_PAYLOAD
};

// Packet structure
struct Packet {
    uint64_t id;
    std::chrono::system_clock::time_point timestamp;
    std::string source_ip;
    std::string dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    PacketType type;
    uint32_t size;
    std::vector<uint8_t> payload;
    std::map<std::string, std::string> metadata;
};

// Flow structure
struct Flow {
    std::string flow_id;
    std::string source_ip;
    std::string dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    PacketType protocol;
    uint64_t packet_count;
    uint64_t byte_count;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point last_seen;
    std::vector<std::shared_ptr<Packet>> packets;
};

// Threat information
struct Threat {
    uint64_t id;
    std::chrono::system_clock::time_point timestamp;
    ThreatLevel level;
    AnomalyType type;
    std::string description;
    std::string source_ip;
    std::string dest_ip;
    std::map<std::string, std::string> evidence;
    double confidence;
};

// Statistical metrics
struct Statistics {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    std::map<std::string, uint64_t> ip_frequencies;
    std::map<uint16_t, uint64_t> port_frequencies;
    std::map<PacketType, uint64_t> protocol_frequencies;
    double avg_packet_size;
    double packets_per_second;
    double bytes_per_second;
};

// Configuration
struct Config {
    std::string interface;
    std::string filter;
    int timeout;
    bool verbose;
    bool save_packets;
    std::string output_file;
    double anomaly_threshold;
    double threat_threshold;
    uint32_t max_packets;
    uint32_t buffer_size;
};

// Constants
constexpr uint32_t DEFAULT_BUFFER_SIZE = 65536;
constexpr uint32_t MAX_PACKET_SIZE = 65535;
constexpr double DEFAULT_ANOMALY_THRESHOLD = 2.0;
constexpr double DEFAULT_THREAT_THRESHOLD = 0.8;
constexpr uint32_t DEFAULT_MAX_PACKETS = 1000000;

// Utility functions
std::string packet_type_to_string(PacketType type);
std::string threat_level_to_string(ThreatLevel level);
std::string anomaly_type_to_string(AnomalyType type);
std::string format_timestamp(const std::chrono::system_clock::time_point& time);
uint64_t generate_flow_id(const std::string& src_ip, uint16_t src_port, 
                          const std::string& dst_ip, uint16_t dst_port);

} // namespace nsa

#endif // COMMON_H

