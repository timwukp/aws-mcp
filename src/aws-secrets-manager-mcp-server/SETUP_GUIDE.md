# AWS Secrets Manager MCP Server - Setup Guide

## 🎉 Installation Complete!

Your AWS Secrets Manager MCP Server has been successfully installed and tested. This guide will help you configure it with your MCP clients.

## ✅ What's Working

- ✅ **AWS Connection**: Connected to AWS Secrets Manager in `us-east-1`
- ✅ **Credentials**: AWS credentials validated successfully
- ✅ **MCP Server**: Server starts and responds correctly
- ✅ **Core Functionality**: Secret creation, retrieval, and deletion tested
- ✅ **15 MCP Tools**: All secret management tools available

## 🔧 Configuration for MCP Clients

### Claude Desktop Configuration

1. **Open Claude Desktop Settings**
   - Click the gear icon in Claude Desktop
   - Navigate to the "Developer" or "MCP" section

2. **Add Server Configuration**
   Add this configuration to your `claude_desktop_config.json`:

   ```json
   {
     "mcpServers": {
       "aws-secrets-manager": {
         "command": "awslabs.aws-secrets-manager-mcp-server",
         "env": {
           "AWS_REGION": "us-east-1",
           "FASTMCP_LOG_LEVEL": "INFO"
         }
       }
     }
   }
   ```

3. **Restart Claude Desktop**
   - Close and reopen Claude Desktop
   - The MCP server will be automatically loaded

### Other MCP Clients

For other MCP clients, use the same configuration format with:
- **Command**: `awslabs.aws-secrets-manager-mcp-server`
- **Environment Variables**:
  - `AWS_REGION`: Your preferred AWS region (default: us-east-1)
  - `FASTMCP_LOG_LEVEL`: Logging level (INFO, DEBUG, WARNING, ERROR)

## 🛠️ Available Tools

Once configured, you'll have access to these 15 MCP tools:

### Core Secret Management
- `create-secret` - Create new secrets
- `get-secret-value` - Retrieve secret values
- `update-secret` - Update existing secrets
- `delete-secret` - Schedule secrets for deletion
- `restore-secret` - Restore deleted secrets
- `list-secrets` - List and filter secrets
- `describe-secret` - Get secret metadata

### Advanced Features
- `enable-rotation` - Configure automatic rotation
- `disable-rotation` - Disable rotation
- `rotate-secret` - Manual rotation
- `get-random-password` - Generate secure passwords
- `tag-resource` - Add/update tags
- `untag-resource` - Remove tags
- `get-resource-policy` - Get access policies
- `put-resource-policy` - Set access policies
- `delete-resource-policy` - Remove access policies

## 💬 Example Usage

Once configured, you can manage secrets using natural language:

### Creating Secrets
```
"Create a new secret called 'prod/database/mysql' with username 'admin' and password 'secure123', and tag it with Environment=production"
```

### Retrieving Secrets
```
"Get the value of the secret 'prod/database/mysql'"
```

### Managing Rotation
```
"Enable automatic rotation for 'prod/database/mysql' every 30 days using the Lambda function 'mysql-rotation-function'"
```

### Generating Passwords
```
"Generate a 16-character password without punctuation"
```

## 🔐 Security Best Practices

### IAM Permissions
Ensure your AWS credentials have these permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:CreateSecret",
                "secretsmanager:GetSecretValue",
                "secretsmanager:UpdateSecret",
                "secretsmanager:DeleteSecret",
                "secretsmanager:RestoreSecret",
                "secretsmanager:ListSecrets",
                "secretsmanager:DescribeSecret",
                "secretsmanager:RotateSecret",
                "secretsmanager:GetRandomPassword",
                "secretsmanager:TagResource",
                "secretsmanager:UntagResource",
                "secretsmanager:GetResourcePolicy",
                "secretsmanager:PutResourcePolicy",
                "secretsmanager:DeleteResourcePolicy"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:Encrypt",
                "kms:GenerateDataKey"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "kms:ViaService": "secretsmanager.*.amazonaws.com"
                }
            }
        }
    ]
}
```

### Secret Naming
- Use hierarchical naming: `environment/service/component`
- Examples: `prod/database/mysql`, `staging/api/stripe`
- Keep names descriptive but not revealing

### Secret Structure
Use JSON for structured secrets:
```json
{
    "username": "admin",
    "password": "secure_password",
    "host": "database.example.com",
    "port": 5432,
    "database": "production"
}
```

## 🔍 Troubleshooting

### Common Issues

1. **"Command not found" error**
   - Run: `which awslabs.aws-secrets-manager-mcp-server`
   - If not found, reinstall: `pip install -e .`

2. **AWS credentials error**
   - Check: `aws sts get-caller-identity`
   - Configure: `aws configure`

3. **Permission denied errors**
   - Verify IAM permissions above
   - Check CloudTrail logs for specific denied actions

4. **MCP server not loading**
   - Check Claude Desktop logs
   - Verify JSON configuration syntax
   - Restart Claude Desktop

### Debug Mode
Enable debug logging by setting:
```json
"env": {
  "FASTMCP_LOG_LEVEL": "DEBUG"
}
```

## 📊 Testing Your Setup

Run these test scripts to verify everything works:

```bash
# Test AWS connectivity
python simple_demo.py

# Test MCP server startup
python test_mcp_server.py

# Run unit tests
pytest tests/ -v
```

## 🚀 Next Steps

1. **Configure your MCP client** with the provided configuration
2. **Test basic operations** like creating and retrieving secrets
3. **Set up rotation** for database credentials and API keys
4. **Implement tagging strategy** for organization and cost allocation
5. **Configure resource policies** for cross-account access if needed

## 📚 Additional Resources

- [AWS Secrets Manager Documentation](https://docs.aws.amazon.com/secretsmanager/)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [Project README](README.md) - Complete feature documentation
- [API Examples](README.md#examples) - Detailed usage examples

## 🆘 Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review the project README for detailed documentation
3. Check AWS CloudTrail logs for permission issues
4. Verify your MCP client configuration

---

**🎉 Congratulations! Your AWS Secrets Manager MCP Server is ready to use!**

Start managing your secrets securely through natural language interactions with your AI assistant.
