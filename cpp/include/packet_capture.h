#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include "common.h"
#include <pcap.h>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>

namespace nsa {

class PacketCapture {
public:
    PacketCapture();
    ~PacketCapture();

    // Initialize packet capture
    bool initialize(const Config& config);
    
    // Start/stop capture
    bool start_capture();
    void stop_capture();
    
    // Set packet callback
    void set_packet_callback(std::function<void(const Packet&)> callback);
    
    // Get capture statistics
    Statistics get_statistics() const;
    
    // Check if capture is running
    bool is_running() const;
    
    // Get available interfaces
    static std::vector<std::string> get_available_interfaces();
    
    // Get interface description
    static std::string get_interface_description(const std::string& interface);

private:
    // Pcap handle
    pcap_t* pcap_handle_;
    
    // Configuration
    Config config_;
    
    // Capture state
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    Statistics stats_;
    
    // Callback
    std::function<void(const Packet&)> packet_callback_;
    
    // Capture thread
    std::thread capture_thread_;
    std::mutex capture_mutex_;
    std::condition_variable capture_cv_;
    
    // Internal methods
    void capture_loop();
    Packet parse_packet(const struct pcap_pkthdr* header, const u_char* data);
    PacketType determine_packet_type(const u_char* data, uint32_t size);
    std::string extract_ip_address(const u_char* data);
    uint16_t extract_port(const u_char* data);
    void update_statistics(const Packet& packet);
    
    // Error handling
    void handle_pcap_error(const char* error_msg);
    
    // Cleanup
    void cleanup();
};

} // namespace nsa

#endif // PACKET_CAPTURE_H

