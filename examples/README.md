# BucketGuard Examples

This directory contains example commands and use cases for BucketGuard.

## Basic Usage

1. Auto-discover mode:
```bash
./bucketguard -domain example.com -auto-discover -output results.json
```

2. Wordlist mode:
```bash
./bucketguard -wordlist wordlists/basic.txt -output results.json
```

3. High concurrency scan:
```bash
./bucketguard -domain example.com -auto-discover -concurrent 50 -output results.json
```

## Advanced Usage

1. Scan multiple domains from file:
```bash
while read domain; do
    ./bucketguard -domain "$domain" -auto-discover -output "output/${domain}_results.json"
done < domains.txt
```

2. Scan with AWS credentials:
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1
./bucketguard -domain example.com -auto-discover -output results.json
```

3. Combine multiple wordlists:
```bash
cat wordlists/*.txt > combined_wordlist.txt
./bucketguard -wordlist combined_wordlist.txt -output results.json
```

## Tips

1. For large scans, increase the concurrency but be mindful of rate limits:
```bash
./bucketguard -domain example.com -auto-discover -concurrent 100 -output results.json
```

2. Redirect Google dorks to a file:
```bash
./bucketguard -domain example.com -auto-discover 2> dorks.txt
```

3. Parse results with jq:
```bash
jq '.results[] | select(.findings[] | contains("Publicly accessible"))' results.json
