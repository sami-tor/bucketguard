# Output Directory

This directory contains scan results from BucketGuard.

## File Format

Results are saved in JSON format with the following structure:

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

## Fields Description

- `bucket_name`: Name of the S3 bucket
- `findings`: List of security issues found
- `url`: Direct URL to the bucket
- `stats`: Overall scan statistics
  - `total_buckets`: Total number of buckets checked
  - `vulnerable_buckets`: Number of buckets with security issues

## Possible Findings

- "Bucket exists"
- "Publicly accessible"
- "Public READ permission"
- "Public WRITE permission"
- "Public READ_ACP permission"
- "Public WRITE_ACP permission"
- "Public FULL_CONTROL permission"
- "No default encryption"
