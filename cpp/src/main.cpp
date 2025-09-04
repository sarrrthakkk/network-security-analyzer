#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <thread>
#include <signal.h>
#include <getopt.h>
#include <atomic>

#include "packet_capture.h"
#include "packet_analyzer.h"
#include "anomaly_detector.h"
#include "threat_detector.h"
#include "statistical_analyzer.h"
#include "report_generator.h"
#include "utils.h"

using namespace nsa;

// Global variables for signal handling
std::atomic<bool> running(true);
std::unique_ptr<PacketCapture> packet_capture;
std::unique_ptr<PacketAnalyzer> packet_analyzer;
std::unique_ptr<AnomalyDetector> anomaly_detector;
std::unique_ptr<ThreatDetector> threat_detector;
std::unique_ptr<StatisticalAnalyzer> statistical_analyzer;
std::unique_ptr<ReportGenerator> report_generator;
Config global_config;  // Global config variable

// Signal handler
void signal_handler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down gracefully..." << std::endl;
    running = false;
    
    if (packet_capture) {
        packet_capture->stop_capture();
    }
}

// Print usage information
void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "Network Security Analyzer - Spring 2024 Security Software Development\n\n"
              << "Options:\n"
              << "  -i, --interface <interface>    Network interface to capture (default: auto-detect)\n"
              << "  -f, --filter <filter>          BPF filter expression\n"
              << "  -t, --timeout <seconds>        Capture timeout in seconds (0 = infinite)\n"
              << "  -o, --output <file>            Output file for reports\n"
              << "  -v, --verbose                  Enable verbose output\n"
              << "  -q, --quiet                    Suppress normal output\n"
              << "  -s, --save-packets             Save captured packets to file\n"
              << "  -r, --report-format <format>   Report format (html, json, xml, txt)\n"
              << "  -a, --anomaly-threshold <val>  Anomaly detection threshold (default: 2.0)\n"
              << "  --threat-threshold <val>       Threat detection threshold (default: 0.8)\n"
              << "  --max-packets <count>          Maximum packets to capture (default: unlimited)\n"
              << "  --buffer-size <bytes>          Capture buffer size (default: 65536)\n"
              << "  --list-interfaces             List available network interfaces\n"
              << "  --help                        Display this help message\n\n"
              << "Examples:\n"
              << "  " << program_name << " -i eth0 -t 60 -v\n"
              << "  " << program_name << " -i wlan0 -f \"port 80 or port 443\" -o report.html\n"
              << "  " << program_name << " --list-interfaces\n"
              << std::endl;
}

// List available network interfaces
void list_interfaces() {
    std::cout << "Available network interfaces:\n" << std::endl;
    
    try {
        auto interfaces = PacketCapture::get_available_interfaces();
        if (interfaces.empty()) {
            std::cout << "No network interfaces found." << std::endl;
            return;
        }
        
        for (const auto& interface : interfaces) {
            std::string description = PacketCapture::get_interface_description(interface);
            std::cout << "  " << interface;
            if (!description.empty()) {
                std::cout << " (" << description << ")";
            }
            std::cout << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error listing interfaces: " << e.what() << std::endl;
    }
}

// Initialize components
bool initialize_components(const Config& config) {
    try {
        // Initialize packet capture
        packet_capture = std::make_unique<PacketCapture>();
        if (!packet_capture->initialize(config)) {
            std::cerr << "Failed to initialize packet capture" << std::endl;
            return false;
        }
        
        // Initialize packet analyzer
        packet_analyzer = std::make_unique<PacketAnalyzer>();
        packet_analyzer->set_analyze_payloads(true);
        packet_analyzer->set_analyze_encrypted(false);
        packet_analyzer->set_max_payload_size(1024);
        
        // Initialize anomaly detector
        anomaly_detector = std::make_unique<AnomalyDetector>();
        anomaly_detector->initialize(config);
        anomaly_detector->enable_volume_detection(true);
        anomaly_detector->enable_frequency_detection(true);
        anomaly_detector->enable_pattern_detection(true);
        anomaly_detector->enable_behavioral_detection(true);
        
        // Initialize threat detector
        threat_detector = std::make_unique<ThreatDetector>();
        threat_detector->initialize(config);
        threat_detector->enable_ddos_detection(true);
        threat_detector->enable_port_scan_detection(true);
        threat_detector->enable_malware_detection(true);
        threat_detector->enable_data_exfiltration_detection(true);
        threat_detector->enable_suspicious_payload_detection(true);
        
        // Initialize statistical analyzer
        statistical_analyzer = std::make_unique<StatisticalAnalyzer>();
        statistical_analyzer->initialize(config);
        statistical_analyzer->set_history_size(1000);
        statistical_analyzer->set_update_interval(std::chrono::milliseconds(1000));
        statistical_analyzer->enable_real_time_updates(true);
        
        // Initialize report generator
        report_generator = std::make_unique<ReportGenerator>();
        report_generator->initialize(config);
        report_generator->set_format("html");
        report_generator->enable_executive_summary(true);
        report_generator->enable_detailed_analysis(true);
        report_generator->enable_recommendations(true);
        report_generator->enable_appendix(true);
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error initializing components: " << e.what() << std::endl;
        return false;
    }
}

// Packet processing callback
void process_packet(const Packet& packet) {
    try {
        // Process packet through all analyzers
        packet_analyzer->analyze_packet(packet);
        anomaly_detector->process_packet(packet);
        threat_detector->process_packet(packet);
        statistical_analyzer->process_packet(packet);
        
        // Print packet information if verbose
        if (global_config.verbose) {
            std::cout << "Packet: " << packet.source_ip << ":" << packet.source_port
                      << " -> " << packet.dest_ip << ":" << packet.dest_port
                      << " (" << packet_type_to_string(packet.type) << ") "
                      << packet.size << " bytes" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error processing packet: " << e.what() << std::endl;
    }
}

// Generate and display summary
void display_summary() {
    try {
        std::cout << "\n=== Network Security Analysis Summary ===" << std::endl;
        
        // Get statistics
        auto stats = statistical_analyzer->get_statistics();
        auto anomalies = anomaly_detector->get_anomalies();
        auto threats = threat_detector->get_threats();
        
        // Display basic statistics
        std::cout << "Total packets captured: " << stats.total_packets << std::endl;
        std::cout << "Total bytes processed: " << Utils::format_bytes(stats.total_bytes) << std::endl;
        std::cout << "Average packet size: " << Utils::format_bytes(static_cast<uint64_t>(stats.avg_packet_size)) << std::endl;
        std::cout << "Packets per second: " << stats.packets_per_second << std::endl;
        std::cout << "Bytes per second: " << Utils::format_bits_per_second(static_cast<uint64_t>(stats.bytes_per_second * 8)) << std::endl;
        
        // Display protocol breakdown
        std::cout << "\nProtocol breakdown:" << std::endl;
        for (const auto& [protocol, count] : stats.protocol_frequencies) {
            if (count > 0) {
                double percentage = Utils::calculate_percentage(count, stats.total_packets);
                std::cout << "  " << packet_type_to_string(protocol) << ": " 
                          << count << " (" << std::fixed << std::setprecision(1) << percentage << "%)" << std::endl;
            }
        }
        
        // Display top talkers
        auto top_sources = statistical_analyzer->get_top_source_ips(5);
        if (!top_sources.empty()) {
            std::cout << "\nTop source IPs:" << std::endl;
            for (const auto& [ip, count] : top_sources) {
                std::cout << "  " << ip << ": " << count << " packets" << std::endl;
            }
        }
        
        // Display anomalies and threats
        if (!anomalies.empty()) {
            std::cout << "\nAnomalies detected: " << anomalies.size() << std::endl;
            for (const auto& anomaly : anomalies) {
                std::cout << "  " << anomaly_type_to_string(anomaly.type) << " from " 
                          << anomaly.source_ip << " (confidence: " 
                          << std::fixed << std::setprecision(1) << anomaly.confidence * 100 << "%)" << std::endl;
            }
        }
        
        if (!threats.empty()) {
            std::cout << "\nThreats detected: " << threats.size() << std::endl;
            for (const auto& threat : threats) {
                std::cout << "  " << threat_level_to_string(threat.level) << " " 
                          << anomaly_type_to_string(threat.type) << " from " 
                          << threat.source_ip << " (confidence: " 
                          << std::fixed << std::setprecision(1) << threat.confidence * 100 << "%)" << std::endl;
            }
        }
        
        std::cout << "\n=== End Summary ===" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error displaying summary: " << e.what() << std::endl;
    }
}

// Generate report
void generate_report(const Config& config) {
    try {
        if (config.output_file.empty()) {
            return;
        }
        
        std::cout << "Generating security report..." << std::endl;
        
        auto stats = statistical_analyzer->get_statistics();
        auto anomalies = anomaly_detector->get_anomalies();
        auto threats = threat_detector->get_threats();
        
        if (report_generator->generate_security_report(config.output_file, stats, threats, anomalies)) {
            std::cout << "Security report generated: " << config.output_file << std::endl;
        } else {
            std::cerr << "Failed to generate security report" << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error generating report: " << e.what() << std::endl;
    }
}

// Main function
int main(int argc, char* argv[]) {
    // Set up signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Parse command line arguments
    global_config.interface = "";
    global_config.filter = "";
    global_config.timeout = 0;
    global_config.verbose = false;
    global_config.save_packets = false;
    global_config.output_file = "";
    global_config.anomaly_threshold = DEFAULT_ANOMALY_THRESHOLD;
    global_config.threat_threshold = DEFAULT_THREAT_THRESHOLD;
    global_config.max_packets = DEFAULT_MAX_PACKETS;
    global_config.buffer_size = DEFAULT_BUFFER_SIZE;
    
    int opt;
    const char* short_options = "i:f:t:o:vqsr:a:h";
    struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"filter", required_argument, 0, 'f'},
        {"timeout", required_argument, 0, 't'},
        {"output", required_argument, 0, 'o'},
        {"verbose", no_argument, 0, 'v'},
        {"quiet", no_argument, 0, 'q'},
        {"save-packets", no_argument, 0, 's'},
        {"report-format", required_argument, 0, 'r'},
        {"anomaly-threshold", required_argument, 0, 'a'},
        {"threat-threshold", required_argument, 0, 0},
        {"max-packets", required_argument, 0, 0},
        {"buffer-size", required_argument, 0, 0},
        {"list-interfaces", no_argument, 0, 0},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, short_options, long_options, nullptr)) != -1) {
        switch (opt) {
            case 'i':
                global_config.interface = optarg;
                break;
            case 'f':
                global_config.filter = optarg;
                break;
            case 't':
                global_config.timeout = std::stoi(optarg);
                break;
            case 'o':
                global_config.output_file = optarg;
                break;
            case 'v':
                global_config.verbose = true;
                break;
            case 'q':
                global_config.verbose = false;
                break;
            case 's':
                global_config.save_packets = true;
                break;
            case 'r':
                if (report_generator) {
                    report_generator->set_format(optarg);
                }
                break;
            case 'a':
                global_config.anomaly_threshold = std::stod(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 0:
                // Handle long options
                if (strcmp(long_options[optind].name, "threat-threshold") == 0) {
                    global_config.threat_threshold = std::stod(optarg);
                } else if (strcmp(long_options[optind].name, "max-packets") == 0) {
                    global_config.max_packets = std::stoul(optarg);
                } else if (strcmp(long_options[optind].name, "buffer-size") == 0) {
                    global_config.buffer_size = std::stoul(optarg);
                } else if (strcmp(long_options[optind].name, "list-interfaces") == 0) {
                    list_interfaces();
                    return 0;
                }
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Auto-detect interface if not specified
    if (global_config.interface.empty()) {
        auto interfaces = PacketCapture::get_available_interfaces();
        if (!interfaces.empty()) {
            global_config.interface = interfaces[0];
            if (global_config.verbose) {
                std::cout << "Auto-selected interface: " << global_config.interface << std::endl;
            }
        } else {
            std::cerr << "No network interfaces available" << std::endl;
            return 1;
        }
    }
    
    // Display startup information
    std::cout << "Network Security Analyzer - Spring 2024 Security Software Development" << std::endl;
    std::cout << "Interface: " << global_config.interface << std::endl;
    if (!global_config.filter.empty()) {
        std::cout << "Filter: " << global_config.filter << std::endl;
    }
    std::cout << "Timeout: " << (global_config.timeout > 0 ? std::to_string(global_config.timeout) + "s" : "infinite") << std::endl;
    std::cout << "Anomaly threshold: " << global_config.anomaly_threshold << std::endl;
    std::cout << "Threat threshold: " << global_config.threat_threshold << std::endl;
    std::cout << std::endl;
    
    try {
        // Initialize components
        if (!initialize_components(global_config)) {
            std::cerr << "Failed to initialize components" << std::endl;
            return 1;
        }
        
        // Set packet callback
        packet_capture->set_packet_callback(process_packet);
        
        // Start packet capture
        std::cout << "Starting packet capture..." << std::endl;
        if (!packet_capture->start_capture()) {
            std::cerr << "Failed to start packet capture" << std::endl;
            return 1;
        }
        
        // Main capture loop
        auto start_time = std::chrono::system_clock::now();
        std::cout << "Capture started at " << Utils::format_timestamp(start_time) << std::endl;
        std::cout << "Press Ctrl+C to stop capture" << std::endl;
        
        while (running && packet_capture->is_running()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            // Check timeout
            if (global_config.timeout > 0) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now() - start_time).count();
                if (elapsed >= global_config.timeout) {
                    std::cout << "Capture timeout reached" << std::endl;
                    break;
                }
            }
            
            // Display periodic updates
            static auto last_update = std::chrono::system_clock::now();
            auto now = std::chrono::system_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_update).count() >= 10) {
                auto stats = statistical_analyzer->get_statistics();
                std::cout << "Captured " << stats.total_packets << " packets, "
                          << Utils::format_bytes(stats.total_bytes) << " total" << std::endl;
                last_update = now;
            }
        }
        
        // Stop capture
        std::cout << "Stopping packet capture..." << std::endl;
        packet_capture->stop_capture();
        
        // Display final summary
        display_summary();
        
        // Generate report
        generate_report(global_config);
        
        std::cout << "Analysis complete" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error during execution: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

