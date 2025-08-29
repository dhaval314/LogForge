#!/usr/bin/env python3
"""
Test script for AWS S3 integration.
Run this to verify S3 connectivity and functionality.
"""
import os
import tempfile
from pathlib import Path
from loguru import logger

# Add the current directory to Python path
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from aws_s3_utils import get_s3_utils, is_s3_available
from config import Config


def test_s3_integration():
    """Test S3 integration functionality."""
    print("🔍 Testing AWS S3 Integration...")
    print("=" * 50)
    
    # Check if S3 is available
    if not is_s3_available():
        print("❌ S3 is not available. Please check your configuration:")
        print(f"   AWS_ACCESS_KEY_ID: {'✅ Set' if Config.AWS_ACCESS_KEY_ID else '❌ Not set'}")
        print(f"   AWS_SECRET_ACCESS_KEY: {'✅ Set' if Config.AWS_SECRET_ACCESS_KEY else '❌ Not set'}")
        print(f"   AWS_S3_BUCKET: {'✅ Set' if Config.AWS_S3_BUCKET else '❌ Not set'}")
        print(f"   AWS_DEFAULT_REGION: {Config.AWS_DEFAULT_REGION}")
        return False
    
    print("✅ S3 is configured and available")
    
    # Get S3 utils instance
    s3_utils = get_s3_utils()
    
    # Test file operations
    test_content = "This is a test file for S3 integration\nCreated by LogForge Forensic Analyzer"
    test_key = "test/logforge_test.txt"
    
    try:
        # Create a temporary test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_file:
            tmp_file.write(test_content)
            tmp_path = tmp_file.name
        
        print(f"📝 Created test file: {tmp_path}")
        
        # Test upload
        print(f"📤 Uploading to s3://{s3_utils.bucket_name}/{test_key}...")
        if s3_utils.upload_file(tmp_path, key=test_key):
            print("✅ Upload successful")
        else:
            print("❌ Upload failed")
            return False
        
        # Test list files
        print(f"📋 Listing files in bucket...")
        files = s3_utils.list_files()
        if test_key in files:
            print(f"✅ Found uploaded file in bucket ({len(files)} total files)")
        else:
            print(f"❌ Uploaded file not found in bucket")
            return False
        
        # Test get file info
        print(f"📊 Getting file info...")
        file_info = s3_utils.get_file_info(key=test_key)
        if file_info:
            print(f"✅ File info retrieved: {file_info['size']} bytes")
        else:
            print("❌ Could not get file info")
            return False
        
        # Test download
        print(f"📥 Downloading file...")
        downloaded_path = s3_utils.download_file(key=test_key)
        if downloaded_path and os.path.exists(downloaded_path):
            print(f"✅ Download successful: {downloaded_path}")
            
            # Verify content
            with open(downloaded_path, 'r') as f:
                downloaded_content = f.read()
            if downloaded_content == test_content:
                print("✅ Content verification successful")
            else:
                print("❌ Content verification failed")
                return False
        else:
            print("❌ Download failed")
            return False
        
        # Test delete
        print(f"🗑️ Deleting test file...")
        if s3_utils.delete_file(key=test_key):
            print("✅ Delete successful")
        else:
            print("❌ Delete failed")
            return False
        
        # Verify deletion
        files_after_delete = s3_utils.list_files()
        if test_key not in files_after_delete:
            print("✅ File deletion verified")
        else:
            print("❌ File still exists after deletion")
            return False
        
        # Cleanup local files
        try:
            os.unlink(tmp_path)
            os.unlink(downloaded_path)
            print("✅ Local files cleaned up")
        except Exception as e:
            print(f"⚠️ Warning: Could not clean up local files: {e}")
        
        print("\n🎉 All S3 integration tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        logger.exception("S3 integration test error")
        return False


if __name__ == "__main__":
    success = test_s3_integration()
    sys.exit(0 if success else 1)
