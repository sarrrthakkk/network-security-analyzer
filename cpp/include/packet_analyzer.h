#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#include "common.h"
#include <vector>
#include <map>
#include <memory>

namespace nsa {

class PacketAnalyzer {
public:
    PacketAnalyzer();
    ~PacketAnalyzer();

    // Analyze a single packet
    void analyze_packet(const Packet& packet);
    
    // Analyze a flow of packets
    void analyze_flow(const Flow& flow);
    
    // Get analysis results
    std::map<std::string, std::string> get_packet_analysis(const Packet& packet) const;
    std::map<std::string, std::string> get_flow_analysis(const Flow& flow) const;
    
    // Protocol-specific analysis
    void analyze_tcp(const Packet& packet, std::map<std::string, std::string>& analysis);
    void analyze_udp(const Packet& packet, std::map<std::string, std::string>& analysis);
    void analyze_http(const Packet& packet, std::map<std::string, std::string>& analysis);
    void analyze_dns(const Packet& packet, std::map<std::string, std::string>& analysis);
    void analyze_icmp(const Packet& packet, std::map<std::string, std::string>& analysis);
    
    // Payload analysis
    void analyze_payload(const Packet& packet, std::map<std::string, std::string>& analysis);
    
    // Set analysis options
    void set_analyze_payloads(bool enabled);
    void set_analyze_encrypted(bool enabled);
    void set_max_payload_size(uint32_t size);

private:
    // Analysis options
    bool analyze_payloads_;
    bool analyze_encrypted_;
    uint32_t max_payload_size_;
    
    // Analysis cache
    mutable std::mutex cache_mutex_;
    std::map<uint64_t, std::map<std::string, std::string>> analysis_cache_;
    
    // Helper methods
    std::string extract_http_method(const std::vector<uint8_t>& payload);
    std::string extract_http_url(const std::vector<uint8_t>& payload);
    std::string extract_http_headers(const std::vector<uint8_t>& payload);
    std::string extract_dns_query(const std::vector<uint8_t>& payload);
    std::string extract_dns_response(const std::vector<uint8_t>& payload);
    std::string analyze_tcp_flags(uint8_t flags);
    std::string analyze_icmp_type(uint8_t type, uint8_t code);
    
    // Pattern matching
    bool contains_pattern(const std::vector<uint8_t>& data, const std::string& pattern);
    std::vector<std::string> find_patterns(const std::vector<uint8_t>& data);
    
    // Encoding detection
    std::string detect_encoding(const std::vector<uint8_t>& data);
    bool is_printable_ascii(const std::vector<uint8_t>& data);
    bool is_utf8(const std::vector<uint8_t>& data);
    
    // Cache management
    void cache_analysis(uint64_t packet_id, const std::map<std::string, std::string>& analysis);
    std::map<std::string, std::string> get_cached_analysis(uint64_t packet_id) const;
    void clear_cache();
};

} // namespace nsa

#endif // PACKET_ANALYZER_H

