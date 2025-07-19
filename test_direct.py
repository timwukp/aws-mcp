#!/usr/bin/env python3
"""Direct test of the fixed list_secrets functionality."""

import asyncio
import sys
import os
sys.path.insert(0, '/Users/tmwu/aws-secrets-manager-mcp-server')

from awslabs.aws_secrets_manager_mcp_server.server import get_secrets_client
from awslabs.aws_secrets_manager_mcp_server.models import ListSecretsResponse, SecretListItem, Tag

async def test_fixed_list_secrets():
    """Test the fixed list_secrets functionality directly."""
    try:
        print("Testing fixed list_secrets function...")
        
        # Get the client
        client = get_secrets_client('us-east-1')
        
        # Test the fixed parameters
        params = {
            'MaxResults': 50,
            'IncludePlannedDeletion': False
        }
        
        print(f"Calling list_secrets with params: {params}")
        response = client.list_secrets(**params)
        
        print(f"Raw AWS response received {len(response['SecretList'])} secrets")
        
        # Process the response like the MCP server does
        secrets = []
        for secret_data in response['SecretList']:
            tags = [
                Tag(key=tag['Key'], value=tag['Value']) 
                for tag in secret_data.get('Tags', [])
            ]
            
            secret = SecretListItem(
                name=secret_data['Name'],
                arn=secret_data['ARN'],
                description=secret_data.get('Description'),
                created_date=secret_data.get('CreatedDate'),
                last_changed_date=secret_data.get('LastChangedDate'),
                last_accessed_date=secret_data.get('LastAccessedDate'),
                rotation_enabled=secret_data.get('RotationEnabled', False),
                tags=tags
            )
            secrets.append(secret)
        
        # Create the response
        result = ListSecretsResponse(
            secrets=secrets,
            next_token=response.get('NextToken'),
            total_count=len(secrets)
        )
        
        print(f"✅ SUCCESS: Found {result.total_count} secrets")
        print("\nFirst 5 secrets:")
        for i, secret in enumerate(result.secrets[:5]):
            print(f"{i+1}. {secret.name}")
            if secret.description:
                print(f"   Description: {secret.description}")
        
        return result.total_count > 0
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_fixed_list_secrets())
    print(f"\n{'✅ TEST PASSED' if success else '❌ TEST FAILED'}")
