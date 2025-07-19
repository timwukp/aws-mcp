#!/usr/bin/env python3
"""Test script to verify the list_secrets fix."""

import boto3
import json

def test_list_secrets_fix():
    """Test the fixed list_secrets functionality."""
    try:
        # Create client directly
        client = boto3.client('secretsmanager', region_name='us-east-1')
        
        # Test with the old problematic filter (should fail)
        print("Testing old problematic filter...")
        try:
            response_old = client.list_secrets(
                MaxResults=5,
                Filters=[{
                    'Key': 'primary-region',
                    'Values': ['us-east-1']
                }]
            )
            print(f"Old filter returned {len(response_old['SecretList'])} secrets")
        except Exception as e:
            print(f"Old filter failed (expected): {e}")
        
        # Test with the correct approach (should work)
        print("\nTesting correct approach...")
        response_new = client.list_secrets(
            MaxResults=5,
            IncludePlannedDeletion=False
        )
        print(f"New approach returned {len(response_new['SecretList'])} secrets")
        
        # Show first few secrets
        for i, secret in enumerate(response_new['SecretList'][:3]):
            print(f"{i+1}. {secret['Name']}")
            
        return len(response_new['SecretList']) > 0
        
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    success = test_list_secrets_fix()
    print(f"\nTest {'PASSED' if success else 'FAILED'}")
