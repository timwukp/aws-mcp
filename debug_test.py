#!/usr/bin/env python3
"""Debug script to test AWS Secrets Manager MCP server functionality."""

import asyncio
import sys
import os
import boto3
from botocore.exceptions import ClientError

# Add the source directory to Python path
sys.path.insert(0, '/Users/tmwu/aws-secrets-manager-mcp-server/src/aws-secrets-manager-mcp-server')

from awslabs.aws_secrets_manager_mcp_server.server import list_secrets, get_secrets_client
from mcp.server.fastmcp import Context


class MockContext:
    """Mock context for testing."""
    
    async def error(self, message: str):
        print(f"ERROR: {message}")


async def test_list_secrets():
    """Test the list_secrets function."""
    print("Testing list_secrets function...")
    
    # Test with mock context
    ctx = MockContext()
    
    try:
        # Test direct AWS client first
        print("\n1. Testing direct AWS client...")
        client = boto3.client('secretsmanager', region_name='us-east-1')
        response = client.list_secrets()
        print(f"Direct AWS client found {len(response['SecretList'])} secrets")
        
        # Test our get_secrets_client function
        print("\n2. Testing get_secrets_client function...")
        our_client = get_secrets_client('us-east-1')
        our_response = our_client.list_secrets()
        print(f"Our client found {len(our_response['SecretList'])} secrets")
        
        # Test the MCP tool function
        print("\n3. Testing MCP list_secrets function...")
        result = await list_secrets(ctx, region='us-east-1')
        print(f"MCP function result: {result}")
        
        # Test with different parameters
        print("\n4. Testing with max_results=100...")
        result2 = await list_secrets(ctx, max_results=100, region='us-east-1')
        print(f"MCP function result with max_results=100: {result2}")
        
    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_list_secrets())
