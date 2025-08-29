"""
AWS S3 Utilities for the Forensic AI Log Analyzer.
Provides helper functions for S3 operations with graceful fallback to local storage.
"""
import os
import tempfile
from typing import List, Optional
from pathlib import Path
from loguru import logger

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    logger.warning("boto3 not available. S3 functionality will be disabled.")

from config import Config


class S3Utils:
    """AWS S3 utility class for file operations."""
    
    def __init__(self):
        """Initialize S3 client with environment variables."""
        self.s3_client = None
        self.bucket_name = os.getenv("AWS_S3_BUCKET", "")
        self.is_configured = False
        
        if not BOTO3_AVAILABLE:
            logger.warning("boto3 not installed. Install with: pip install boto3")
            return
            
        try:
            # Check if AWS credentials are available
            aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
            aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
            aws_region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
            
            if not aws_access_key or not aws_secret_key:
                logger.warning("AWS credentials not found in environment variables")
                return
                
            if not self.bucket_name:
                logger.warning("AWS_S3_BUCKET environment variable not set")
                return
            
            # Initialize S3 client
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=aws_region
            )
            
            # Test connection by listing buckets
            self.s3_client.list_buckets()
            self.is_configured = True
            logger.info(f"S3 client initialized successfully for bucket: {self.bucket_name}")
            
        except NoCredentialsError:
            logger.warning("AWS credentials not found or invalid")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchBucket':
                logger.error(f"S3 bucket '{self.bucket_name}' does not exist")
            elif error_code == 'AccessDenied':
                logger.error(f"Access denied to S3 bucket '{self.bucket_name}'")
            else:
                logger.error(f"S3 client error: {error_code}")
        except EndpointConnectionError:
            logger.error("Failed to connect to AWS S3 endpoint")
        except Exception as e:
            logger.error(f"Failed to initialize S3 client: {e}")
    
    def upload_file(self, local_path: str, bucket: Optional[str] = None, key: Optional[str] = None) -> bool:
        """
        Upload a file to S3.
        
        Args:
            local_path: Path to the local file
            bucket: S3 bucket name (uses default if not provided)
            key: S3 object key (uses filename if not provided)
            
        Returns:
            bool: True if upload successful, False otherwise
        """
        if not self.is_configured or not self.s3_client:
            logger.warning("S3 not configured, skipping upload")
            return False
            
        try:
            bucket = bucket or self.bucket_name
            if not key:
                key = Path(local_path).name
            
            # Ensure the file exists
            if not os.path.exists(local_path):
                logger.error(f"Local file does not exist: {local_path}")
                return False
            
            logger.info(f"Uploading {local_path} to s3://{bucket}/{key}")
            self.s3_client.upload_file(local_path, bucket, key)
            logger.success(f"Successfully uploaded {local_path} to s3://{bucket}/{key}")
            return True
            
        except ClientError as e:
            logger.error(f"S3 upload error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during S3 upload: {e}")
            return False
    
    def download_file(self, bucket: Optional[str] = None, key: str = "", local_path: Optional[str] = None) -> Optional[str]:
        """
        Download a file from S3.
        
        Args:
            bucket: S3 bucket name (uses default if not provided)
            key: S3 object key
            local_path: Local path to save the file (creates temp file if not provided)
            
        Returns:
            str: Path to the downloaded file, or None if download failed
        """
        if not self.is_configured or not self.s3_client:
            logger.warning("S3 not configured, cannot download file")
            return None
            
        try:
            bucket = bucket or self.bucket_name
            
            if not local_path:
                # Create temporary file
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{Path(key).name}")
                local_path = temp_file.name
                temp_file.close()
            
            logger.info(f"Downloading s3://{bucket}/{key} to {local_path}")
            self.s3_client.download_file(bucket, key, local_path)
            logger.success(f"Successfully downloaded s3://{bucket}/{key} to {local_path}")
            return local_path
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchKey':
                logger.error(f"S3 object does not exist: s3://{bucket}/{key}")
            elif error_code == 'NoSuchBucket':
                logger.error(f"S3 bucket does not exist: {bucket}")
            else:
                logger.error(f"S3 download error: {error_code}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during S3 download: {e}")
            return None
    
    def list_files(self, bucket: Optional[str] = None, prefix: str = "") -> List[str]:
        """
        List files in an S3 bucket with optional prefix.
        
        Args:
            bucket: S3 bucket name (uses default if not provided)
            prefix: Prefix to filter files
            
        Returns:
            List[str]: List of file keys
        """
        if not self.is_configured or not self.s3_client:
            logger.warning("S3 not configured, cannot list files")
            return []
            
        try:
            bucket = bucket or self.bucket_name
            
            logger.info(f"Listing files in s3://{bucket} with prefix: {prefix}")
            response = self.s3_client.list_objects_v2(
                Bucket=bucket,
                Prefix=prefix
            )
            
            if 'Contents' in response:
                files = [obj['Key'] for obj in response['Contents']]
                logger.info(f"Found {len(files)} files in s3://{bucket}")
                return files
            else:
                logger.info(f"No files found in s3://{bucket} with prefix: {prefix}")
                return []
                
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchBucket':
                logger.error(f"S3 bucket does not exist: {bucket}")
            else:
                logger.error(f"S3 list error: {error_code}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing S3 files: {e}")
            return []
    
    def delete_file(self, bucket: Optional[str] = None, key: str = "") -> bool:
        """
        Delete a file from S3.
        
        Args:
            bucket: S3 bucket name (uses default if not provided)
            key: S3 object key
            
        Returns:
            bool: True if deletion successful, False otherwise
        """
        if not self.is_configured or not self.s3_client:
            logger.warning("S3 not configured, cannot delete file")
            return False
            
        try:
            bucket = bucket or self.bucket_name
            
            logger.info(f"Deleting s3://{bucket}/{key}")
            self.s3_client.delete_object(Bucket=bucket, Key=key)
            logger.success(f"Successfully deleted s3://{bucket}/{key}")
            return True
            
        except ClientError as e:
            logger.error(f"S3 delete error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during S3 delete: {e}")
            return False
    
    def get_file_info(self, bucket: Optional[str] = None, key: str = "") -> Optional[dict]:
        """
        Get metadata for an S3 file.
        
        Args:
            bucket: S3 bucket name (uses default if not provided)
            key: S3 object key
            
        Returns:
            dict: File metadata or None if not found
        """
        if not self.is_configured or not self.s3_client:
            logger.warning("S3 not configured, cannot get file info")
            return None
            
        try:
            bucket = bucket or self.bucket_name
            
            response = self.s3_client.head_object(Bucket=bucket, Key=key)
            return {
                'size': response.get('ContentLength', 0),
                'last_modified': response.get('LastModified'),
                'content_type': response.get('ContentType'),
                'etag': response.get('ETag', '').strip('"')
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NotFound':
                logger.warning(f"S3 object not found: s3://{bucket}/{key}")
            else:
                logger.error(f"S3 head object error: {error_code}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting S3 file info: {e}")
            return None


# Global S3 utils instance
_s3_utils = None

def get_s3_utils() -> S3Utils:
    """Get the global S3 utils instance."""
    global _s3_utils
    if _s3_utils is None:
        _s3_utils = S3Utils()
    return _s3_utils

def is_s3_available() -> bool:
    """Check if S3 is available and configured."""
    s3_utils = get_s3_utils()
    return s3_utils.is_configured
