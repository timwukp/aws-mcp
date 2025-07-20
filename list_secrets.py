#!/usr/bin/env python3
"""
Script to list AWS Secrets Manager secrets in us-east-1 region.
"""

import asyncio
import sys
import os

# Add the source directory to Python path
sys.path.insert(0, '/Users/tmwu/aws-secrets-manager-mcp-server/src/aws-secrets-manager-mcp-server')

from awslabs.aws_secrets_manager_mcp_server.server import list_secrets

class MockContext:
    """Mock context for MCP function calls."""
    
    async def error(self, message: str):
        print(f"ERROR: {message}")

async def main():
    """List secrets in AWS Secrets Manager."""
    print("Listing AWS Secrets Manager secrets in us-east-1 region...\n")
    
    # Create mock context
    ctx = MockContext()
    
    try:
        # Call the list_secrets function with region us-east-1
        result = await list_secrets(ctx, region='us-east-1')
        
        if result.secrets:
            print(f"Found {result.total_count} secrets:")
            for i, secret in enumerate(result.secrets, 1):
                print(f"\n{i}. Secret: {secret.name}")
                print(f"   ARN: {secret.arn}")
                if secret.description:
                    print(f"   Description: {secret.description}")
                print(f"   Created: {secret.created_date}")
                if secret.tags:
                    print(f"   Tags: {len(secret.tags)}")
                    for tag in secret.tags:
                        print(f"     - {tag.key}: {tag.value}")
        else:
            print("No secrets found in your AWS account in us-east-1 region.")
            
    except Exception as e:
        print(f"Error listing secrets: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())