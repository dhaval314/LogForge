#!/usr/bin/env python3
"""
Test script for LLM Provider System
"""
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from llm_providers import get_available_providers, get_provider_info, provider_manager
from data_models import LogEntry
from datetime import datetime

def test_provider_availability():
    """Test which providers are available."""
    print("=== Testing LLM Provider Availability ===")
    
    available_providers = get_available_providers()
    print(f"Available providers: {len(available_providers)}")
    
    for provider_id, provider_info in available_providers.items():
        print(f"  ✓ {provider_info['name']}: {provider_info['description']}")
    
    print()
    
    # Test individual provider info
    for provider_id in ["ibm_granite"]:
        info = get_provider_info(provider_id)
        if info:
            status = "Available" if info["available"] else "Not Available"
            print(f"  {provider_id}: {status}")
        else:
            print(f"  {provider_id}: Not Found")
    
    print()

def test_provider_analysis():
    """Test analysis with available providers."""
    print("=== Testing LLM Provider Analysis ===")
    
    # Create sample log entries
    sample_logs = [
        LogEntry(
            timestamp=datetime.now(),
            source="firewall",
            event_type="connection",
            message="Connection attempt from 192.168.1.100 to 10.0.0.1:22",
            severity="INFO"
        ),
        LogEntry(
            timestamp=datetime.now(),
            source="system",
            event_type="login",
            message="Failed login attempt for user admin from 192.168.1.100",
            severity="WARNING"
        ),
        LogEntry(
            timestamp=datetime.now(),
            source="antivirus",
            event_type="threat",
            message="Malware detected: trojan.exe (hash: abc123)",
            severity="HIGH"
        )
    ]
    
    available_providers = get_available_providers()
    
    for provider_id in available_providers.keys():
        print(f"\nTesting {provider_id}...")
        try:
            analysis = provider_manager.analyze_logs(sample_logs, provider_id)
            print(f"  ✓ Analysis completed")
            print(f"  Summary: {analysis.summary[:100]}...")
            print(f"  IOCs found: {len(analysis.iocs)}")
            print(f"  MITRE mappings: {len(analysis.mitre_mappings)}")
            print(f"  Severity: {analysis.severity}")
            print(f"  Confidence: {analysis.confidence:.2f}")
        except Exception as e:
            print(f"  ✗ Analysis failed: {e}")

def main():
    """Main test function."""
    print("LLM Provider System Test")
    print("=" * 50)
    
    # Test provider availability
    test_provider_availability()
    
    # Test analysis (only if providers are configured)
    test_provider_analysis()
    
    print("\n" + "=" * 50)
    print("Test completed!")

if __name__ == "__main__":
    main()
