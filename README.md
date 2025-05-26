# BucketGuard

A fast and efficient AWS S3 bucket scanner that discovers and checks for misconfigurations.

## Features

- Automatic bucket discovery based on domain name
- Advanced name permutations with common patterns
- Regex-based extraction from Google dorks
- Concurrent scanning with rate limiting
- AWS integration for deeper checks (when credentials available)
- JSON output format
- Cross-platform (Windows, Linux, macOS)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/BucketGuard
cd BucketGuard
```

2. Run the setup script:
```bash
# On Linux/macOS
./setup.sh

# On Windows
go mod tidy
go build -o bucketguard.exe
```

## Usage

### Basic Examples

1. Auto-discover buckets for a domain:
```bash
./bucketguard -domain example.com -auto-discover -output results.json
```

2. Scan using a wordlist:
```bash
./bucketguard -wordlist wordlists/basic.txt -output results.json
```

3. With AWS credentials:
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1
./bucketguard -domain example.com -auto-discover -output results.json
```

See [examples/README.md](examples/README.md) for more usage examples.

## Directory Structure

```
BucketGuard/
├── examples/           # Example usage and helper scripts
├── output/            # Scan results directory
├── wordlists/         # Bucket name wordlists
├── go.mod            # Go module file
├── main.go           # Core scanner code
├── setup.sh          # Setup script
└── README.md         # This file
```

## Output Format

Results are saved in JSON format:

```json
{
    "results": [
        {
            "bucket_name": "example-bucket",
            "findings": [
                "Bucket exists",
                "Publicly accessible",
                "No default encryption"
            ],
            "url": "https://example-bucket.s3.amazonaws.com"
        }
    ],
    "stats": {
        "total_buckets": 100,
        "vulnerable_buckets": 5
    }
}
```

## Processing Results

Use the included script to process and format results:

```bash
./examples/process_results.sh results.json
```

This will generate a formatted report and show key statistics.

## Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -am 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for security research and testing only. Always obtain proper authorization before scanning any systems you don't own.

## Contributer
@MalikHamza7
