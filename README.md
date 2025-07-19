# AWS Secrets Manager MCP Server

A comprehensive Model Context Protocol (MCP) server for AWS Secrets Manager that provides secure secret lifecycle management through natural language interactions.

## Overview

This MCP server enables AI assistants to securely manage AWS Secrets Manager operations, including creating, retrieving, updating, and rotating secrets. It provides a complete interface for secret lifecycle management while maintaining security best practices.

## Key Features

### 🔐 Complete Secret Lifecycle Management
- **Create secrets** with structured or simple values
- **Retrieve secret values** with version control
- **Update secrets** with automatic versioning
- **Delete and restore** secrets with recovery windows
- **List and search** secrets with filtering capabilities

### 🔄 Automatic Rotation Support
- **Enable/disable rotation** with Lambda functions
- **Manual rotation triggers** for immediate updates
- **Rotation monitoring** and status tracking
- **Configurable rotation intervals** (1-365 days)

### 🏷️ Organization and Access Control
- **Tag management** for cost allocation and organization
- **Resource-based policies** for fine-grained access control
- **Cross-account access** configuration
- **Compliance and audit** support

### 🛡️ Security Best Practices
- **Encryption at rest** with AWS KMS integration
- **Encryption in transit** with TLS
- **Audit logging** through AWS CloudTrail
- **Access validation** and error handling
- **Secure password generation** with customizable requirements

## Installation

### Prerequisites

- Python 3.10 or higher
- AWS credentials configured (via AWS CLI, environment variables, or IAM roles)
- Appropriate IAM permissions for Secrets Manager operations

### Install from PyPI

```bash
pip install awslabs.aws-secrets-manager-mcp-server
```

### Install from Source

```bash
git clone <repository-url>
cd aws-secrets-manager-mcp-server
pip install -e .
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_REGION` | AWS region for Secrets Manager operations | `us-east-1` |
| `AWS_PROFILE` | AWS profile to use for authentication | None |
| `FASTMCP_LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | `WARNING` |

### AWS Credentials

The server supports all standard AWS credential methods:

1. **AWS CLI Configuration**
   ```bash
   aws configure
   ```

2. **Environment Variables**
   ```bash
   export AWS_ACCESS_KEY_ID=your-access-key
   export AWS_SECRET_ACCESS_KEY=your-secret-key
   export AWS_REGION=us-east-1
   ```

3. **IAM Roles** (for EC2/Lambda/ECS deployments)

4. **AWS Profiles**
   ```bash
   export AWS_PROFILE=your-profile-name
   ```

### Required IAM Permissions

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

## Usage

### Running the Server

```bash
# Run directly
awslabs.aws-secrets-manager-mcp-server

# Or with Python module
python -m awslabs.aws_secrets_manager_mcp_server.server
```

### Integration with MCP Clients

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "aws-secrets-manager": {
      "command": "awslabs.aws-secrets-manager-mcp-server",
      "env": {
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

## Available Tools

### Secret Management

#### `createsecret`
Create a new secret with optional configuration.

**Parameters:**
- `name` (required): Secret name (supports hierarchical naming like `prod/database/mysql`)
- `secret_value` (required): Secret value as string or JSON object
- `description` (optional): Human-readable description
- `kms_key_id` (optional): Custom KMS key for encryption
- `tags` (optional): List of tags for organization
- `region` (optional): AWS region override

**Examples:**
```python
# Simple API key
create_secret(
    name="prod/api-keys/stripe",
    secret_value="sk_live_abc123...",
    description="Stripe production API key"
)

# Database credentials
create_secret(
    name="prod/database/mysql",
    secret_value={
        "username": "admin",
        "password": "secure_password_123",
        "host": "db.example.com",
        "port": 3306,
        "dbname": "production"
    },
    tags=[
        {"Key": "Environment", "Value": "production"},
        {"Key": "Service", "Value": "database"}
    ]
)
```

#### `getsecretvalue`
Retrieve the current or specific version of a secret.

**Parameters:**
- `secret_id` (required): Secret name or ARN
- `version_id` (optional): Specific version to retrieve
- `version_stage` (optional): Version stage (AWSCURRENT, AWSPENDING, AWSPREVIOUS)
- `region` (optional): AWS region override

**Example:**
```python
# Get current version
get_secret_value(secret_id="prod/database/mysql")

# Get specific version
get_secret_value(
    secret_id="prod/database/mysql",
    version_id="12345678-1234-1234-1234-123456789012"
)
```

#### `updatesecret`
Update an existing secret's value, description, or encryption key.

**Parameters:**
- `secret_id` (required): Secret name or ARN
- `secret_value` (optional): New secret value
- `description` (optional): New description
- `kms_key_id` (optional): New KMS key for encryption
- `region` (optional): AWS region override

#### `deletesecret`
Schedule a secret for deletion with recovery window.

**Parameters:**
- `secret_id` (required): Secret name or ARN
- `recovery_window_days` (optional): Recovery window (7-30 days, default: 30)
- `force_delete_without_recovery` (optional): Immediate deletion (DANGEROUS)
- `region` (optional): AWS region override

#### `restoresecret`
Restore a secret that was scheduled for deletion.

**Parameters:**
- `secret_id` (required): Secret name or ARN
- `region` (optional): AWS region override

#### `listsecrets`
List secrets with optional filtering.

**Parameters:**
- `max_results` (optional): Maximum results to return (1-100, default: 50)
- `name_prefix` (optional): Filter by name prefix
- `tag_filters` (optional): Filter by tags
- `include_planned_deletion` (optional): Include secrets scheduled for deletion
- `region` (optional): AWS region override

#### `describesecret`
Get detailed metadata about a secret without retrieving its value.

**Parameters:**
- `secret_id` (required): Secret name or ARN
- `region` (optional): AWS region override

### Rotation Management

#### `enablerotation`
Enable automatic rotation for a secret.

**Parameters:**
- `secret_id` (required): Secret name or ARN
- `lambda_function_arn` (required): Lambda function for rotation
- `rotation_interval_days` (optional): Days between rotations (1-365, default: 30)
- `rotate_immediately` (optional): Rotate immediately after enabling
- `region` (optional): AWS region override

#### `disablerotation`
Disable automatic rotation for a secret.

#### `rotatesecret`
Manually trigger rotation for a secret.

**Parameters:**
- `secret_id` (required): Secret name or ARN
- `force_rotate_immediately` (optional): Force immediate rotation (default: true)
- `region` (optional): AWS region override

### Utility Tools

#### `getrandompassword`
Generate a cryptographically secure random password.

**Parameters:**
- `password_length` (optional): Password length (4-4096, default: 32)
- `exclude_characters` (optional): Characters to exclude
- `exclude_numbers` (optional): Exclude numbers (default: false)
- `exclude_punctuation` (optional): Exclude punctuation (default: false)
- `exclude_uppercase` (optional): Exclude uppercase letters (default: false)
- `exclude_lowercase` (optional): Exclude lowercase letters (default: false)
- `include_space` (optional): Include space character (default: false)
- `require_each_included_type` (optional): Require each character type (default: true)
- `region` (optional): AWS region override

### Tag Management

#### `tagresource`
Add or update tags on a secret.

**Parameters:**
- `secret_id` (required): Secret name or ARN
- `tags` (required): List of tag objects with "Key" and "Value"
- `region` (optional): AWS region override

#### `untagresource`
Remove tags from a secret.

**Parameters:**
- `secret_id` (required): Secret name or ARN
- `tag_keys` (required): List of tag keys to remove
- `region` (optional): AWS region override

### Policy Management

#### `getresourcepolicy`
Retrieve the resource-based policy for a secret.

#### `putresourcepolicy`
Set or update the resource-based policy for a secret.

**Parameters:**
- `secret_id` (required): Secret name or ARN
- `policy` (required): JSON policy document
- `block_public_policy` (optional): Block public access (default: true)
- `region` (optional): AWS region override

#### `deleteresourcepolicy`
Remove the resource-based policy from a secret.

## Best Practices

### Secret Naming
- Use hierarchical naming with forward slashes: `environment/service/component`
- Examples: `prod/database/mysql`, `staging/api/stripe`, `dev/cache/redis`
- Keep names descriptive but not revealing sensitive information

### Secret Structure
- Use JSON format for structured secrets (database credentials, API configurations)
- Include all necessary connection parameters
- Use consistent key naming across similar secrets

```json
{
    "username": "admin",
    "password": "secure_password",
    "host": "database.example.com",
    "port": 5432,
    "database": "production",
    "ssl_mode": "require"
}
```

### Rotation Strategy
- Enable automatic rotation for database credentials and long-lived API keys
- Use appropriate rotation intervals based on security requirements
- Test rotation functions thoroughly before enabling in production
- Monitor rotation status and failures

### Access Control
- Use IAM policies for primary access control
- Implement resource-based policies for cross-account access
- Apply principle of least privilege
- Use tags for organizing and controlling access

### Security Considerations
- Never log or expose secret values in application logs
- Use customer-managed KMS keys for additional control
- Implement proper error handling to avoid information disclosure
- Regularly audit secret access patterns

## Common Use Cases

### Database Credentials Management
```python
# Create database secret
create_secret(
    name="prod/rds/mysql-primary",
    secret_value={
        "username": "admin",
        "password": "generated_secure_password",
        "engine": "mysql",
        "host": "prod-mysql.cluster-xyz.us-east-1.rds.amazonaws.com",
        "port": 3306,
        "dbname": "production"
    },
    description="Production MySQL primary database credentials"
)

# Enable automatic rotation
enable_rotation(
    secret_id="prod/rds/mysql-primary",
    lambda_function_arn="arn:aws:lambda:us-east-1:123456789012:function:mysql-rotation",
    rotation_interval_days=30
)
```

### API Key Management
```python
# Store third-party API key
create_secret(
    name="prod/integrations/stripe-api",
    secret_value={
        "api_key": "sk_live_...",
        "webhook_secret": "whsec_...",
        "endpoint": "https://api.stripe.com"
    },
    tags=[
        {"Key": "Service", "Value": "payment"},
        {"Key": "Environment", "Value": "production"}
    ]
)
```

### Certificate Management
```python
# Store SSL certificate
create_secret(
    name="prod/certificates/api-example-com",
    secret_value={
        "certificate": "<CERTIFICATE_CONTENT>",
        "private_key": "<PRIVATE_KEY_CONTENT>",
        "certificate_chain": "<CERTIFICATE_CHAIN_CONTENT>"
    },
    description="SSL certificate for api.example.com"
)
```

## Error Handling

The server provides comprehensive error handling with user-friendly messages:

- **ResourceNotFoundException**: Secret not found
- **AccessDeniedException**: Insufficient permissions
- **InvalidParameterException**: Invalid input parameters
- **EncryptionFailure**: KMS encryption/decryption issues
- **LimitExceededException**: AWS service limits exceeded

All errors include context and suggestions for resolution.

## Development

### Setting up Development Environment

```bash
# Clone repository
git clone <repository-url>
cd aws-secrets-manager-mcp-server

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=awslabs.aws_secrets_manager_mcp_server

# Run specific test categories
pytest -m "not live"  # Skip live AWS API tests
```

### Code Quality

```bash
# Format code
ruff format

# Lint code
ruff check

# Type checking
pyright
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

Please follow the existing code style and include appropriate tests and documentation.

## Security

This MCP server handles sensitive data. Please:

- Report security vulnerabilities privately
- Follow AWS security best practices
- Use appropriate IAM permissions
- Enable CloudTrail logging for audit trails
- Regularly rotate secrets and access keys

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## Support

For issues and questions:

1. Check the [documentation](https://awslabs.github.io/mcp/servers/aws-secrets-manager-mcp-server/)
2. Search existing [GitHub issues](https://github.com/awslabs/mcp/issues)
3. Create a new issue with detailed information

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.
