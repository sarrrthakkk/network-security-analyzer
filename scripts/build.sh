#!/bin/bash
# Network Security Analyzer - Build Script
# Spring 2024 Security Software Development

set -e

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

# Function to check system requirements
check_requirements() {
    print_status "Checking system requirements..."
    
    # Check for required commands
    local missing_commands=()
    
    if ! command_exists cmake; then
        missing_commands+=("cmake")
    fi
    
    if ! command_exists make; then
        missing_commands+=("make")
    fi
    
    if ! command_exists gcc; then
        if ! command_exists clang; then
            missing_commands+=("gcc or clang")
        fi
    fi
    
    if ! command_exists pkg-config; then
        missing_commands+=("pkg-config")
    fi
    
    # Check for required libraries
    if ! pkg-config --exists libpcap; then
        missing_commands+=("libpcap-dev")
    fi
    
    if ! pkg-config --exists openssl; then
        missing_commands+=("libssl-dev")
    fi
    
    if ! pkg-config --exists libboost_system; then
        missing_commands+=("libboost-system-dev")
    fi
    
    if ! pkg-config --exists libboost_thread; then
        missing_commands+=("libboost-thread-dev")
    fi
    
    if [ ${#missing_commands[@]} -ne 0 ]; then
        print_error "Missing required dependencies:"
        for cmd in "${missing_commands[@]}"; do
            echo "  - $cmd"
        done
        echo ""
        echo "Please install the missing dependencies:"
        echo ""
        
        if command_exists apt-get; then
            echo "Ubuntu/Debian:"
            echo "  sudo apt-get update"
            echo "  sudo apt-get install build-essential cmake pkg-config libpcap-dev libssl-dev libboost-system-dev libboost-thread-dev"
        elif command_exists yum; then
            echo "CentOS/RHEL:"
            echo "  sudo yum groupinstall 'Development Tools'"
            echo "  sudo yum install cmake pkg-config libpcap-devel openssl-devel boost-devel"
        elif command_exists brew; then
            echo "macOS (Homebrew):"
            echo "  brew install cmake pkg-config libpcap openssl boost"
        else
            echo "Please install the required dependencies for your system."
        fi
        
        exit 1
    fi
    
    print_success "System requirements satisfied"
}

# Function to build C++ version
build_cpp() {
    print_status "Building C++ version..."
    
    cd cpp
    
    # Create build directory
    if [ -d "build" ]; then
        print_status "Cleaning existing build directory..."
        rm -rf build
    fi
    
    mkdir build
    cd build
    
    # Configure with CMake
    print_status "Configuring with CMake..."
    cmake .. -DCMAKE_BUILD_TYPE=Release
    
    # Build
    print_status "Building..."
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    
    # Install (optional)
    if [ "$1" = "--install" ]; then
        print_status "Installing..."
        sudo make install
        print_success "C++ version installed successfully"
    else
        print_success "C++ version built successfully"
        print_status "Binary location: cpp/build/network_analyzer"
    fi
    
    cd ../..
}

# Function to setup Python environment
setup_python() {
    print_status "Setting up Python environment..."
    
    if ! command_exists python3; then
        print_error "Python 3 is not installed"
        exit 1
    fi
    
    cd python
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        print_status "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    print_status "Activating virtual environment..."
    source venv/bin/activate
    
    # Install dependencies
    print_status "Installing Python dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
    
    print_success "Python environment setup complete"
    print_status "To activate: source python/venv/bin/activate"
    
    cd ..
}

# Function to run tests
run_tests() {
    print_status "Running tests..."
    
    # C++ tests
    if [ -f "cpp/build/network_analyzer" ]; then
        cd cpp/build
        if [ -f "Makefile" ]; then
            print_status "Running C++ tests..."
            make test
        fi
        cd ../..
    fi
    
    # Python tests
    if [ -d "python/venv" ]; then
        cd python
        source venv/bin/activate
        if [ -d "tests" ]; then
            print_status "Running Python tests..."
            python -m pytest tests/ -v
        fi
        cd ..
    fi
    
    print_success "Tests completed"
}

# Function to clean build artifacts
clean_build() {
    print_status "Cleaning build artifacts..."
    
    if [ -d "cpp/build" ]; then
        rm -rf cpp/build
        print_success "C++ build artifacts cleaned"
    fi
    
    if [ -d "python/venv" ]; then
        rm -rf python/venv
        print_success "Python virtual environment cleaned"
    fi
    
    if [ -d "__pycache__" ]; then
        find . -type d -name "__pycache__" -exec rm -rf {} +
        print_success "Python cache cleaned"
    fi
    
    print_success "Cleanup complete"
}

# Function to show help
show_help() {
    echo "Network Security Analyzer - Build Script"
    echo "Spring 2024 Security Software Development"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --cpp           Build C++ version only"
    echo "  --python        Setup Python environment only"
    echo "  --install       Install C++ version after building"
    echo "  --test          Run tests after building"
    echo "  --clean         Clean build artifacts"
    echo "  --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Build everything"
    echo "  $0 --cpp --install   # Build and install C++ version"
    echo "  $0 --python          # Setup Python environment only"
    echo "  $0 --clean           # Clean all build artifacts"
}

# Main build process
main() {
    print_status "Starting Network Security Analyzer build process..."
    
    # Parse command line arguments
    local build_cpp_flag=false
    local build_python_flag=false
    local install_flag=false
    local test_flag=false
    local clean_flag=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --cpp)
                build_cpp_flag=true
                shift
                ;;
            --python)
                build_python_flag=true
                shift
                ;;
            --install)
                install_flag=true
                shift
                ;;
            --test)
                test_flag=true
                shift
                ;;
            --clean)
                clean_flag=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # If no specific flags, build everything
    if [ "$build_cpp_flag" = false ] && [ "$build_python_flag" = false ] && [ "$clean_flag" = false ]; then
        build_cpp_flag=true
        build_python_flag=true
    fi
    
    # Clean if requested
    if [ "$clean_flag" = true ]; then
        clean_build
        if [ "$build_cpp_flag" = false ] && [ "$build_python_flag" = false ]; then
            exit 0
        fi
    fi
    
    # Check requirements
    check_requirements
    
    # Build C++ version
    if [ "$build_cpp_flag" = true ]; then
        build_cpp $([ "$install_flag" = true ] && echo "--install")
    fi
    
    # Setup Python environment
    if [ "$build_python_flag" = true ]; then
        setup_python
    fi
    
    # Run tests if requested
    if [ "$test_flag" = true ]; then
        run_tests
    fi
    
    print_success "Build process completed successfully!"
    echo ""
    echo "Next steps:"
    echo "  1. C++ version: ./cpp/build/network_analyzer --help"
    echo "  2. Python version: source python/venv/bin/activate && python python/src/network_analyzer.py --help"
    echo "  3. Examples: python examples/basic_usage.py"
}

# Run main function with all arguments
main "$@"

