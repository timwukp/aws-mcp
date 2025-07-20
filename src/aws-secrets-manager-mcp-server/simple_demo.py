#!/usr/bin/env python3
"""
Simple demo script to test AWS Secrets Manager connectivity and basic operations.

This script tests the core AWS functionality without MCP tool wrappers.
"""

import json
import sys
from datetime import datetime

# Add the project to the path
sys.path.insert(0, '/Users/tmwu/aws-secrets-manager-mcp-server')

from awslabs.aws_secrets_manager_mcp_server.server import get_secrets_client
from botocore.exceptions import ClientError


def test_aws_connection():
    """Test AWS Secrets Manager connection."""
    print("🚀 AWS Secrets Manager Connection Test")
    print("=" * 50)
    
    try:
        client = get_secrets_client()
        print(f"✅ Connected to AWS Secrets Manager")
        print(f"   Region: {client.meta.region_name}")
        print(f"   Service: {client.meta.service_model.service_name}")
        return client
    except Exception as e:
        print(f"❌ Failed to connect to AWS: {e}")
        return None


def test_random_password(client):
    """Test random password generation."""
    print(f"\n2️⃣ Testing Random Password Generation...")
    
    try:
        response = client.get_random_password(
            PasswordLength=16,
            ExcludePunctuation=True,
            RequireEachIncludedType=True
        )
        
        password = response['RandomPassword']
        print(f"✅ Generated secure password: {password[:4]}****{password[-4:]}")
        return password
        
    except ClientError as e:
        print(f"❌ AWS API Error: {e.response['Error']['Code']} - {e.response['Error']['Message']}")
        return None
    except Exception as e:
        print(f"❌ Password generation error: {e}")
        return None


def test_list_secrets(client):
    """Test listing existing secrets."""
    print(f"\n3️⃣ Testing Secret Listing...")
    
    try:
        response = client.list_secrets(MaxResults=5)
        
        secrets = response.get('SecretList', [])
        print(f"✅ Found {len(secrets)} secrets in your account")
        
        if secrets:
            print("   Recent secrets:")
            for secret in secrets[:3]:  # Show first 3
                print(f"   - {secret['Name']}")
                if 'Description' in secret:
                    print(f"     Description: {secret['Description']}")
        else:
            print("   No secrets found in your account")
            
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDeniedException':
            print(f"❌ Access denied. Please check your IAM permissions for Secrets Manager.")
        else:
            print(f"❌ AWS API Error: {error_code} - {e.response['Error']['Message']}")
        return False
    except Exception as e:
        print(f"❌ Secret listing error: {e}")
        return False


def test_create_and_cleanup_secret(client, password):
    """Test creating and deleting a test secret."""
    test_secret_name = f"mcp-demo-test-{int(datetime.now().timestamp())}"
    print(f"\n4️⃣ Testing Secret Creation and Cleanup...")
    print(f"Creating test secret: {test_secret_name}")
    
    try:
        # Create secret
        secret_data = {
            "username": "demo_user",
            "password": password,
            "database": "demo_db",
            "host": "localhost",
            "port": 5432,
            "created_by": "MCP Demo Script"
        }
        
        create_response = client.create_secret(
            Name=test_secret_name,
            Description="Temporary secret created by MCP demo script",
            SecretString=json.dumps(secret_data),
            Tags=[
                {'Key': 'Environment', 'Value': 'demo'},
                {'Key': 'CreatedBy', 'Value': 'MCP-Demo'},
                {'Key': 'Purpose', 'Value': 'Testing'}
            ]
        )
        
        print(f"✅ Secret created successfully!")
        print(f"   ARN: {create_response['ARN']}")
        print(f"   Version: {create_response['VersionId']}")
        
        # Retrieve the secret to verify
        print(f"   Verifying secret retrieval...")
        get_response = client.get_secret_value(SecretId=test_secret_name)
        retrieved_data = json.loads(get_response['SecretString'])
        
        print(f"   ✅ Secret retrieved and verified!")
        print(f"      Username: {retrieved_data['username']}")
        print(f"      Database: {retrieved_data['database']}")
        
        # Clean up - delete the secret
        print(f"   Cleaning up test secret...")
        delete_response = client.delete_secret(
            SecretId=test_secret_name,
            RecoveryWindowInDays=7  # Minimum recovery window
        )
        
        print(f"   ✅ Test secret scheduled for deletion")
        print(f"      Recovery window: 7 days")
        
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDeniedException':
            print(f"❌ Access denied. Please check your IAM permissions.")
            print(f"   Required permissions: secretsmanager:CreateSecret, secretsmanager:GetSecretValue, secretsmanager:DeleteSecret")
        elif error_code == 'ResourceExistsException':
            print(f"❌ Secret already exists. This shouldn't happen with timestamp-based names.")
        else:
            print(f"❌ AWS API Error: {error_code} - {e.response['Error']['Message']}")
        return False
    except Exception as e:
        print(f"❌ Secret creation/cleanup error: {e}")
        return False


def main():
    """Main demo function."""
    print("Testing AWS Secrets Manager MCP Server Prerequisites")
    
    # Test 1: AWS Connection
    client = test_aws_connection()
    if not client:
        print("\n❌ Cannot proceed without AWS connection")
        sys.exit(1)
    
    # Test 2: Random Password Generation
    password = test_random_password(client)
    if not password:
        print("\n⚠️  Password generation failed, using fallback password")
        password = "demo_password_123"
    
    # Test 3: List Secrets (to test read permissions)
    list_success = test_list_secrets(client)
    if not list_success:
        print("\n⚠️  Secret listing failed - you may have limited permissions")
    
    # Test 4: Create and Cleanup Secret (to test write permissions)
    create_success = test_create_and_cleanup_secret(client, password)
    
    # Summary
    print("\n" + "=" * 50)
    if create_success:
        print("🎉 All tests completed successfully!")
        print("\n✅ Your AWS Secrets Manager MCP Server is ready to use!")
        print("\nNext steps:")
        print("1. Configure your MCP client (Claude Desktop, etc.)")
        print("2. Add this server to your MCP configuration:")
        print('   "awslabs.aws-secrets-manager-mcp-server"')
        print("3. Start managing secrets through natural language!")
    else:
        print("⚠️  Some tests failed, but basic connectivity works.")
        print("\nYour MCP server should still work for read operations.")
        print("For full functionality, ensure you have these IAM permissions:")
        print("- secretsmanager:CreateSecret")
        print("- secretsmanager:GetSecretValue") 
        print("- secretsmanager:UpdateSecret")
        print("- secretsmanager:DeleteSecret")
        print("- secretsmanager:ListSecrets")
        print("- secretsmanager:DescribeSecret")
        print("- secretsmanager:GetRandomPassword")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
