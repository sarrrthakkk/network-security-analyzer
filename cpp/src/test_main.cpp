#include <iostream>
#include "packet_capture.h"
#include "common.h"

using namespace nsa;

int main() {
    std::cout << "Network Security Analyzer - Basic Test" << std::endl;
    std::cout << "======================================" << std::endl;
    
    try {
        // Test PacketCapture
        PacketCapture capture;
        std::cout << "✓ PacketCapture created successfully" << std::endl;
        
        // Test interface listing
        auto interfaces = PacketCapture::get_available_interfaces();
        std::cout << "✓ Found " << interfaces.size() << " network interfaces" << std::endl;
        
        for (const auto& interface : interfaces) {
            std::cout << "  - " << interface << std::endl;
        }
        
        std::cout << "\nBasic test completed successfully!" << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
