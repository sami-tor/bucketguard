#!/bin/bash

echo "Setting up BucketGuard..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go first."
    echo "Visit https://golang.org/doc/install for installation instructions."
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
MIN_VERSION="1.20"
if [[ "$GO_VERSION" < "$MIN_VERSION" ]]; then
    echo "Error: Go version $MIN_VERSION or higher is required. Current version: $GO_VERSION"
    exit 1
fi

# Create required directories
mkdir -p wordlists output

# Initialize Go module if not already initialized
if [ ! -f "go.mod" ]; then
    go mod init github.com/BucketGuard
fi

# Install dependencies
echo "Installing dependencies..."
go mod tidy

# Build the project
echo "Building BucketGuard..."
go build -o bucketguard

# Check if build was successful
if [ $? -eq 0 ]; then
    echo "Build successful! The binary 'bucketguard' has been created."
    echo ""
    echo "Usage examples:"
    echo "  ./bucketguard -domain example.com -auto-discover -output results.json"
    echo "  ./bucketguard -wordlist wordlists/basic.txt -output results.json"
    echo ""
    echo "For more options, run: ./bucketguard -h"
else
    echo "Build failed. Please check the error messages above."
    exit 1
fi
