#include "packet_capture.h"
#include "common.h"
#include <iostream>
#include <cstring>
#include <stdexcept>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

using namespace nsa;

PacketCapture::PacketCapture() 
    : pcap_handle_(nullptr), running_(false), initialized_(false) {
}

PacketCapture::~PacketCapture() {
    stop_capture();
}

bool PacketCapture::initialize(const Config& config) {
    try {
        // Store configuration
        config_ = config;
        
        // Initialize libpcap
        char errbuf[PCAP_ERRBUF_SIZE];
        
        // Open live capture
        pcap_handle_ = pcap_open_live(
            config.interface.c_str(),
            config.buffer_size,
            0,  // promiscuous mode disabled by default
            1000,  // timeout in milliseconds
            errbuf
        );
        
        if (pcap_handle_ == nullptr) {
            std::cerr << "Failed to open device " << config.interface 
                      << ": " << errbuf << std::endl;
            return false;
        }
        
        // Set filter if specified
        if (!config.filter.empty()) {
            struct bpf_program fp;
            if (pcap_compile(pcap_handle_, &fp, config.filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
                std::cerr << "Failed to compile filter " << config.filter 
                          << ": " << pcap_geterr(pcap_handle_) << std::endl;
                pcap_close(pcap_handle_);
                pcap_handle_ = nullptr;
                return false;
            }
            
            if (pcap_setfilter(pcap_handle_, &fp) == -1) {
                std::cerr << "Failed to set filter: " << pcap_geterr(pcap_handle_) << std::endl;
                pcap_freecode(&fp);
                pcap_close(pcap_handle_);
                pcap_handle_ = nullptr;
                return false;
            }
            
            pcap_freecode(&fp);
        }
        
        initialized_ = true;
        std::cout << "Packet capture initialized on interface: " << config.interface << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error initializing packet capture: " << e.what() << std::endl;
        return false;
    }
}

bool PacketCapture::start_capture() {
    if (pcap_handle_ == nullptr) {
        std::cerr << "Packet capture not initialized" << std::endl;
        return false;
    }
    
    if (running_) {
        std::cout << "Packet capture already running" << std::endl;
        return true;
    }
    
    try {
        running_ = true;
        
        // Reset statistics
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_ = Statistics{};
        }
        
        // Start capture thread
        capture_thread_ = std::thread(&PacketCapture::capture_loop, this);
        
        std::cout << "Packet capture started" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error starting packet capture: " << e.what() << std::endl;
        running_ = false;
        return false;
    }
}

void PacketCapture::stop_capture() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    capture_cv_.notify_all();
    
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
    
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
    
    std::cout << "Packet capture stopped" << std::endl;
}

void PacketCapture::capture_loop() {
    struct pcap_pkthdr header;
    const u_char* packet_data;
    
    while (running_) {
        packet_data = pcap_next(pcap_handle_, &header);
        if (packet_data != nullptr) {
            Packet packet = parse_packet(&header, packet_data);
            update_statistics(packet);
            
            if (packet_callback_) {
                packet_callback_(packet);
            }
        }
    }
}

Packet PacketCapture::parse_packet(const struct pcap_pkthdr* header, const u_char* data) {
    Packet packet;
    packet.timestamp = std::chrono::system_clock::from_time_t(header->ts.tv_sec);
    packet.size = header->len;
    
    // Parse packet headers (basic implementation)
    if (header->len >= 14) {  // Minimum Ethernet frame size
        // Parse Ethernet header
        const struct ether_header* eth_header = reinterpret_cast<const struct ether_header*>(data);
        
        // Parse IP header if present
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP && header->len >= 34) {
            const struct ip* ip_header = reinterpret_cast<const struct ip*>(data + 14);
            
            packet.source_ip = inet_ntoa(ip_header->ip_src);
            packet.dest_ip = inet_ntoa(ip_header->ip_dst);
            packet.type = static_cast<PacketType>(ip_header->ip_p);
            
            // Parse TCP/UDP headers
            if (ip_header->ip_p == IPPROTO_TCP && header->len >= 54) {
                const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(data + 14 + (ip_header->ip_hl * 4));
                packet.source_port = ntohs(tcp_header->th_sport);
                packet.dest_port = ntohs(tcp_header->th_dport);
            } else if (ip_header->ip_p == IPPROTO_UDP && header->len >= 42) {
                const struct udphdr* udp_header = reinterpret_cast<const struct udphdr*>(data + 14 + (ip_header->ip_hl * 4));
                packet.source_port = ntohs(udp_header->uh_sport);
                packet.dest_port = ntohs(udp_header->uh_dport);
            }
        }
    }
    
    return packet;
}

PacketType PacketCapture::determine_packet_type(const u_char* data, uint32_t size) {
    if (size < 14) return PacketType::UNKNOWN;
    
    const struct ether_header* eth_header = reinterpret_cast<const struct ether_header*>(data);
    uint16_t ether_type = ntohs(eth_header->ether_type);
    
    if (ether_type == ETHERTYPE_IP) {
        if (size < 34) return PacketType::UNKNOWN;
        const struct ip* ip_header = reinterpret_cast<const struct ip*>(data + 14);
        return static_cast<PacketType>(ip_header->ip_p);
    }
    
    return PacketType::UNKNOWN;
}

std::string PacketCapture::extract_ip_address(const u_char* data) {
    if (data == nullptr) return "";
    
    char ip_str[INET_ADDRSTRLEN];
    const struct ip* ip_header = reinterpret_cast<const struct ip*>(data);
    inet_ntop(AF_INET, &ip_header->ip_src, ip_str, INET_ADDRSTRLEN);
    return std::string(ip_str);
}

uint16_t PacketCapture::extract_port(const u_char* data) {
    if (data == nullptr) return 0;
    
    const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(data);
    return ntohs(tcp_header->th_sport);
}

void PacketCapture::update_statistics(const Packet& packet) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.total_packets++;
    stats_.total_bytes += packet.size;
    
    // Update protocol statistics
    stats_.protocol_frequencies[packet.type]++;
}

bool PacketCapture::is_running() const {
    return running_;
}

Statistics PacketCapture::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

std::vector<std::string> PacketCapture::get_available_interfaces() {
    std::vector<std::string> interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return interfaces;
    }
    
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        if (dev->name != nullptr) {
            interfaces.push_back(dev->name);
        }
    }
    
    pcap_freealldevs(alldevs);
    return interfaces;
}

std::string PacketCapture::get_interface_description(const std::string& interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return "";
    }
    
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        if (dev->name && interface == dev->name) {
            std::string description = dev->description ? dev->description : "";
            pcap_freealldevs(alldevs);
            return description;
        }
    }
    
    pcap_freealldevs(alldevs);
    return "";
}

void PacketCapture::set_packet_callback(std::function<void(const Packet&)> callback) {
    packet_callback_ = callback;
}

void PacketCapture::handle_pcap_error(const char* error_msg) {
    std::cerr << "Pcap error: " << error_msg << std::endl;
}

void PacketCapture::cleanup() {
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
}


