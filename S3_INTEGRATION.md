# AWS S3 Integration for LogForge Forensic Analyzer

This document describes the AWS S3 integration features added to the LogForge Forensic AI Log Analyzer.

## Overview

The S3 integration provides an optional storage backend for log files, allowing you to:
- Upload log files to S3 for persistent storage
- Download files from S3 for analysis
- Browse and select files stored in your S3 bucket
- Maintain a hybrid local/S3 workflow

## Configuration

### Environment Variables

Add the following environment variables to your `.env` file:

```bash
# AWS S3 Configuration
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
AWS_DEFAULT_REGION=us-east-1
AWS_S3_BUCKET=your_s3_bucket_name_here
```

### Dependencies

Install the required dependency:

```bash
pip install boto3>=1.34.0
```

Or update your `requirements.txt`:

```
# AWS S3 integration
boto3>=1.34.0
```

## Features

### 1. S3 File Browser
- Browse files stored in your S3 bucket
- Select files for download and analysis
- View file metadata (size, last modified, etc.)

### 2. Automatic S3 Upload
- Option to upload processed files to S3
- Organized folder structure with timestamps
- Support for both individual files and ZIP archives

### 3. Seamless Integration
- Works alongside existing local file processing
- Graceful fallback when S3 is not configured
- No breaking changes to existing functionality

## Usage

### In the Dashboard

1. **S3 Status**: The dashboard shows whether S3 is configured and available
2. **File Selection**: Use the S3 file browser to select files for analysis
3. **Upload Options**: Choose to upload processed files to S3 during analysis
4. **Hybrid Workflow**: Mix local and S3 files in the same analysis session

### File Organization

Files uploaded to S3 are organized as follows:

```
your-bucket/
├── uploads/
│   └── 20250101_120000_filename.log
├── zip_extracts/
│   └── 20250101_120000/
│       ├── file1.log
│       └── file2.csv
└── test/
    └── logforge_test.txt
```

## Testing

Run the S3 integration test to verify your configuration:

```bash
python test_s3_integration.py
```

This will test:
- S3 connectivity
- File upload/download
- File listing and metadata
- File deletion
- Content verification

## Error Handling

The integration includes comprehensive error handling:

- **Missing Credentials**: Graceful fallback to local-only mode
- **Network Issues**: Detailed error messages and logging
- **Permission Errors**: Clear feedback on access issues
- **File Not Found**: Proper handling of missing files

## Security Considerations

1. **IAM Permissions**: Use least-privilege access for S3 operations
2. **Bucket Policies**: Configure appropriate bucket policies
3. **Encryption**: Consider enabling S3 server-side encryption
4. **Access Logging**: Enable S3 access logging for audit trails

### Recommended IAM Policy

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::your-bucket-name",
                "arn:aws:s3:::your-bucket-name/*"
            ]
        }
    ]
}
```

## Troubleshooting

### Common Issues

1. **"S3 not configured"**
   - Check environment variables are set correctly
   - Verify AWS credentials are valid
   - Ensure bucket name is correct

2. **"Access denied"**
   - Check IAM permissions
   - Verify bucket policies
   - Ensure bucket exists in the specified region

3. **"Connection timeout"**
   - Check network connectivity
   - Verify region configuration
   - Check AWS service status

### Debug Mode

Enable debug logging by setting:

```bash
LOG_LEVEL=DEBUG
```

## Migration from Local-Only

The S3 integration is designed to be non-breaking:

1. **Existing functionality**: All local file processing remains unchanged
2. **Optional feature**: S3 is only used when configured
3. **Hybrid support**: Mix local and S3 files in the same session
4. **Backward compatibility**: No changes required to existing workflows

## Future Enhancements

Potential future improvements:

- S3 event notifications for file changes
- Automatic backup of analysis results to S3
- Cross-region replication support
- Integration with AWS CloudTrail for audit logs
- Support for S3 Glacier for long-term storage
