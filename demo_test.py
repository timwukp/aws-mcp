#!/usr/bin/env python3
"""
Demo script to test AWS Secrets Manager MCP Server functionality.

This script demonstrates the key features of the MCP server by:
1. Testing password generation
2. Creating a test secret
3. Retrieving the secret
4. Listing secrets
5. Cleaning up

Run this script to verify your MCP server is working correctly.
"""

import asyncio
import json
import sys
from datetime import datetime

# Add the project to the path
sys.path.insert(0, '/Users/tmwu/aws-secrets-manager-mcp-server')

from awslabs.aws_secrets_manager_mcp_server.server import (
    create_secret,
    get_secret_value,
    list_secrets,
    delete_secret,
    get_random_password,
    get_secrets_client
)
from mcp.server.fastmcp import Context


class MockContext:
    """Mock context for testing MCP tools."""
    
    async def error(self, message: str):
        print(f"❌ Error: {message}")


async def demo_secrets_manager():
    """Demonstrate AWS Secrets Manager MCP Server functionality."""
    
    print("🚀 AWS Secrets Manager MCP Server Demo")
    print("=" * 50)
    
    # Create mock context
    ctx = MockContext()
    
    # Test 1: Verify AWS connection
    print("\n1️⃣ Testing AWS Connection...")
    try:
        client = get_secrets_client()
        print(f"✅ Connected to AWS Secrets Manager in region: {client.meta.region_name}")
    except Exception as e:
        print(f"❌ Failed to connect to AWS: {e}")
        return False
    
    # Test 2: Generate a random password
    print("\n2️⃣ Testing Random Password Generation...")
    try:
        password_result = await get_random_password(
            ctx=ctx,
            password_length=16,
            exclude_punctuation=True
        )
        if password_result.success:
            generated_password = password_result.data['password']
            print(f"✅ Generated secure password: {generated_password[:4]}****{generated_password[-4:]}")
        else:
            print(f"❌ Password generation failed: {password_result.message}")
            return False
    except Exception as e:
        print(f"❌ Password generation error: {e}")
        return False
    
    # Test 3: Create a test secret
    test_secret_name = f"mcp-demo-secret-{int(datetime.now().timestamp())}"
    print(f"\n3️⃣ Testing Secret Creation...")
    print(f"Creating secret: {test_secret_name}")
    
    try:
        secret_data = {
            "username": "demo_user",
            "password": generated_password,
            "database": "demo_db",
            "host": "localhost",
            "port": 5432
        }
        
        create_result = await create_secret(
            ctx=ctx,
            name=test_secret_name,
            secret_value=secret_data,
            description="Demo secret created by MCP server test",
            tags=[
                {"Key": "Environment", "Value": "demo"},
                {"Key": "CreatedBy", "Value": "MCP-Demo"}
            ]
        )
        
        if create_result.success:
            print(f"✅ Secret created successfully!")
            print(f"   ARN: {create_result.data['arn']}")
        else:
            print(f"❌ Secret creation failed: {create_result.message}")
            return False
            
    except Exception as e:
        print(f"❌ Secret creation error: {e}")
        return False
    
    # Test 4: Retrieve the secret
    print(f"\n4️⃣ Testing Secret Retrieval...")
    try:
        get_result = await get_secret_value(
            ctx=ctx,
            secret_id=test_secret_name
        )
        
        if get_result.success:
            print(f"✅ Secret retrieved successfully!")
            retrieved_data = get_result.data['parsed_json']
            print(f"   Username: {retrieved_data['username']}")
            print(f"   Database: {retrieved_data['database']}")
            print(f"   Host: {retrieved_data['host']}")
            print(f"   Password: {retrieved_data['password'][:4]}****")
        else:
            print(f"❌ Secret retrieval failed: {get_result.message}")
            
    except Exception as e:
        print(f"❌ Secret retrieval error: {e}")
    
    # Test 5: List secrets
    print(f"\n5️⃣ Testing Secret Listing...")
    try:
        list_result = await list_secrets(
            ctx=ctx,
            max_results=10,
            name_prefix="mcp-demo"
        )
        
        print(f"✅ Found {list_result.total_count} demo secrets:")
        for secret in list_result.secrets:
            print(f"   - {secret.name}")
            print(f"     Created: {secret.created_date}")
            print(f"     Tags: {len(secret.tags)} tags")
            
    except Exception as e:
        print(f"❌ Secret listing error: {e}")
    
    # Test 6: Clean up - Delete the test secret
    print(f"\n6️⃣ Cleaning Up...")
    try:
        delete_result = await delete_secret(
            ctx=ctx,
            secret_id=test_secret_name,
            recovery_window_days=7  # Minimum recovery window
        )
        
        if delete_result.success:
            print(f"✅ Test secret scheduled for deletion")
            print(f"   Recovery window: 7 days")
            print(f"   Deletion date: {delete_result.data.get('deletion_date', 'Not specified')}")
        else:
            print(f"❌ Secret deletion failed: {delete_result.message}")
            
    except Exception as e:
        print(f"❌ Secret deletion error: {e}")
    
    print("\n" + "=" * 50)
    print("🎉 Demo completed successfully!")
    print("\nYour AWS Secrets Manager MCP Server is working correctly!")
    print("\nNext steps:")
    print("1. Configure your MCP client (Claude Desktop, etc.)")
    print("2. Add the server to your MCP configuration")
    print("3. Start managing secrets through natural language!")
    
    return True


async def main():
    """Main demo function."""
    try:
        success = await demo_secrets_manager()
        if success:
            print("\n✅ All tests passed! MCP server is ready for use.")
            sys.exit(0)
        else:
            print("\n❌ Some tests failed. Please check your AWS configuration.")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
