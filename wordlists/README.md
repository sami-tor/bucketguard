# Wordlists Directory

Place your bucket name wordlists in this directory. Example formats:

- One bucket name per line
- Lines starting with # are treated as comments
- Empty lines are ignored

Example content:
```
# AWS S3 bucket wordlist
example-bucket
test-bucket
staging-bucket
prod-bucket
dev-bucket
```

## Recommended Structure

```
wordlists/
├── basic.txt       # Basic bucket names
├── common.txt      # Common patterns and variations
├── industries.txt  # Industry-specific patterns
└── regions.txt     # Region-specific patterns
```

## Format Rules

1. All bucket names should be lowercase
2. Only use alphanumeric characters, hyphens, and dots
3. Length between 3-63 characters
4. Must not be formatted as an IP address
