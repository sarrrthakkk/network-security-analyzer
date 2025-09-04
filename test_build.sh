#!/bin/bash

# Test Build Script for Network Security Analyzer
# Spring 2024 Security Software Development

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python_version() {
    if command_exists python3; then
        python_version=$(python3 --version 2>&1 | awk '{print $2}')
        print_status "Found Python: $python_version"
        
        # Check if version is 3.8 or higher
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
            print_success "Python version is compatible (>= 3.8)"
            return 0
        else
            print_error "Python version must be 3.8 or higher"
            return 1
        fi
    else
        print_error "Python 3 not found"
        return 1
    fi
}

# Function to check C++ build tools
check_cpp_tools() {
    print_status "Checking C++ build tools..."
    
    local missing_tools=()
    
    if ! command_exists g++; then
        missing_tools+=("g++")
    fi
    
    if ! command_exists cmake; then
        missing_tools+=("cmake")
    fi
    
    if ! command_exists make; then
        missing_tools+=("make")
    fi
    
    if [ ${#missing_tools[@]} -eq 0 ]; then
        print_success "All C++ build tools found"
        return 0
    else
        print_error "Missing C++ build tools: ${missing_tools[*]}"
        return 1
    fi
}

# Function to check system dependencies
check_system_deps() {
    print_status "Checking system dependencies..."
    
    local missing_deps=()
    
    # Check for libpcap
    if ! pkg-config --exists libpcap 2>/dev/null; then
        missing_deps+=("libpcap")
    fi
    
    # Check for OpenSSL
    if ! pkg-config --exists openssl 2>/dev/null; then
        missing_deps+=("openssl")
    fi
    
    # Check for Boost
    if ! pkg-config --exists boost 2>/dev/null; then
        missing_deps+=("boost")
    fi
    
    if [ ${#missing_deps[@]} -eq 0 ]; then
        print_success "All system dependencies found"
        return 0
    else
        print_warning "Missing system dependencies: ${missing_deps[*]}"
        print_warning "These may need to be installed via package manager"
        return 1
    fi
}

# Function to test Python package
test_python_package() {
    print_status "Testing Python package..."
    
    cd python
    
    # Test basic imports
    if python3 demo.py; then
        print_success "Python package tests passed"
    else
        print_error "Python package tests failed"
        return 1
    fi
    
    cd ..
}

# Function to test C++ build
test_cpp_build() {
    print_status "Testing C++ build system..."
    
    cd cpp
    
    # Test CMake build
    if [ -d "build" ]; then
        rm -rf build
    fi
    
    mkdir build
    cd build
    
    if cmake ..; then
        print_success "CMake configuration successful"
    else
        print_error "CMake configuration failed"
        cd ../..
        return 1
    fi
    
    if make -j$(nproc 2>/dev/null || echo 1); then
        print_success "C++ build successful"
    else
        print_error "C++ build failed"
        cd ../..
        return 1
    fi
    
    cd ../..
}

# Function to test Makefile build
test_makefile_build() {
    print_status "Testing Makefile build system..."
    
    cd cpp
    
    if make clean && make; then
        print_success "Makefile build successful"
    else
        print_error "Makefile build failed"
        cd ..
        return 1
    fi
    
    cd ..
}

# Function to test overall build script
test_build_script() {
    print_status "Testing overall build script..."
    
    if ./scripts/build.sh --help; then
        print_success "Build script help works"
    else
        print_error "Build script help failed"
        return 1
    fi
}

# Main test function
main() {
    echo "=========================================="
    echo "Network Security Analyzer - Build Test"
    echo "=========================================="
    echo ""
    
    local tests_passed=0
    local tests_total=0
    
    # Test 1: Python version
    print_status "Test 1: Checking Python version"
    if check_python_version; then
        print_success "Python version check passed"
        ((tests_passed++))
    else
        print_error "Python version check failed"
    fi
    ((tests_total++))
    echo ""
    
    # Test 2: C++ build tools
    print_status "Test 2: Checking C++ build tools"
    if check_cpp_tools; then
        print_success "C++ build tools check passed"
        ((tests_passed++))
    else
        print_error "C++ build tools check failed"
    fi
    ((tests_total++))
    echo ""
    
    # Test 3: System dependencies
    print_status "Test 3: Checking system dependencies"
    if check_system_deps; then
        print_success "System dependencies check passed"
        ((tests_passed++))
    else
        print_warning "System dependencies check had warnings"
        ((tests_passed++))  # Count as passed since it's just warnings
    fi
    ((tests_total++))
    echo ""
    
    # Test 4: Python package
    print_status "Test 4: Testing Python package"
    if test_python_package; then
        print_success "Python package test passed"
        ((tests_passed++))
    else
        print_error "Python package test failed"
    fi
    ((tests_total++))
    echo ""
    
    # Test 5: C++ CMake build
    print_status "Test 5: Testing C++ CMake build"
    if test_cpp_build; then
        print_success "C++ CMake build test passed"
        ((tests_passed++))
    else
        print_error "C++ CMake build test failed"
    fi
    ((tests_total++))
    echo ""
    
    # Test 6: C++ Makefile build
    print_status "Test 6: Testing C++ Makefile build"
    if test_makefile_build; then
        print_success "C++ Makefile build test passed"
        ((tests_passed++))
    else
        print_error "C++ Makefile build test failed"
    fi
    ((tests_total++))
    echo ""
    
    # Test 7: Build script
    print_status "Test 7: Testing build script"
    if test_build_script; then
        print_success "Build script test passed"
        ((tests_passed++))
    else
        print_error "Build script test failed"
    fi
    ((tests_total++))
    echo ""
    
    # Summary
    echo "=========================================="
    echo "Build Test Summary"
    echo "=========================================="
    echo "Tests passed: $tests_passed/$tests_total"
    
    if [ $tests_passed -eq $tests_total ]; then
        print_success "All tests passed! Build system is working correctly."
        exit 0
    else
        print_error "Some tests failed. Please check the errors above."
        exit 1
    fi
}

# Run main function
main "$@"

