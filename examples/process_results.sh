#!/bin/bash

# Check if file is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 results.json"
    exit 1
fi

RESULTS_FILE="$1"

# Check if file exists
if [ ! -f "$RESULTS_FILE" ]; then
    echo "Error: File $RESULTS_FILE not found"
    exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed."
    echo "Install with: sudo apt install jq (Ubuntu/Debian)"
    echo "          or: brew install jq (macOS)"
    exit 1
fi

echo "Processing results from $RESULTS_FILE..."
echo

# Get summary statistics
echo "=== Summary Statistics ==="
jq '.stats' "$RESULTS_FILE"
echo

# List all public buckets
echo "=== Publicly Accessible Buckets ==="
jq -r '.results[] | select(.findings[] | contains("Publicly accessible")) | .bucket_name' "$RESULTS_FILE"
echo

# List buckets without encryption
echo "=== Buckets Without Encryption ==="
jq -r '.results[] | select(.findings[] | contains("No default encryption")) | .bucket_name' "$RESULTS_FILE"
echo

# List buckets with public write access
echo "=== Buckets with Public Write Access ==="
jq -r '.results[] | select(.findings[] | contains("Public WRITE")) | .bucket_name' "$RESULTS_FILE"
echo

# Generate markdown report
echo "=== Generating Markdown Report ==="
{
    echo "# BucketGuard Scan Results"
    echo
    echo "## Summary"
    echo
    jq -r '"* Total Buckets: \(.stats.total_buckets)\n* Vulnerable Buckets: \(.stats.vulnerable_buckets)"' "$RESULTS_FILE"
    echo
    echo "## Findings"
    echo
    jq -r '.results[] | select((.findings | length) > 0) | "### \(.bucket_name)\n\n* URL: \(.url)\n* Findings:\n\(.findings[] | "  * " + .)\n"' "$RESULTS_FILE"
} > "report_$(date +%Y%m%d_%H%M%S).md"

echo "Report generated: report_$(date +%Y%m%d_%H%M%S).md"
