cmake_minimum_required(VERSION 3.16)
project(NetworkSecurityAnalyzer VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set CMAKE_PREFIX_PATH for Homebrew packages
set(CMAKE_PREFIX_PATH "/opt/homebrew")

# Find required packages
find_package(PkgConfig REQUIRED)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(include)
include_directories(/opt/homebrew/include)
include_directories(/opt/homebrew/opt/openssl@3/include)

# Source files (basic version for now)
set(SOURCES
    src/packet_capture.cpp
    src/test_main.cpp
)

# Header files
file(GLOB_RECURSE HEADERS "include/*.h")

# Create executable
add_executable(network_analyzer ${SOURCES} ${HEADERS})

# Link libraries (using direct paths)
target_link_libraries(network_analyzer 
    OpenSSL::SSL 
    OpenSSL::Crypto
    pcap
)

# Set library search paths
target_link_directories(network_analyzer PRIVATE
    /opt/homebrew/lib
    /opt/homebrew/opt/openssl@3/lib
)

# Compiler flags
target_compile_options(network_analyzer PRIVATE 
    -Wall 
    -Wextra 
    -O2 
    -std=c++17
)

# Enable testing
enable_testing()

# Install target
install(TARGETS network_analyzer DESTINATION bin)

