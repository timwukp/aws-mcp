# Changelog

All notable changes to the AWS Secrets Manager MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-01-19

### Added
- Initial release of AWS Secrets Manager MCP Server
- Complete secret lifecycle management tools:
  - `create-secret`: Create new secrets with structured or simple values
  - `get-secret-value`: Retrieve secret values with version control
  - `update-secret`: Update existing secrets with automatic versioning
  - `delete-secret`: Schedule secrets for deletion with recovery windows
  - `restore-secret`: Restore secrets scheduled for deletion
  - `list-secrets`: List and filter secrets by name prefix and tags
  - `describe-secret`: Get detailed secret metadata without values
- Automatic rotation support:
  - `enable-rotation`: Configure automatic rotation with Lambda functions
  - `disable-rotation`: Disable automatic rotation
  - `rotate-secret`: Manually trigger secret rotation
- Tag management:
  - `tag-resource`: Add or update tags on secrets
  - `untag-resource`: Remove tags from secrets
- Resource policy management:
  - `get-resource-policy`: Retrieve resource-based policies
  - `put-resource-policy`: Set or update resource-based policies
  - `delete-resource-policy`: Remove resource-based policies
- Utility tools:
  - `get-random-password`: Generate cryptographically secure passwords
- Comprehensive error handling with user-friendly messages
- Support for all AWS credential methods (CLI, environment variables, IAM roles, profiles)
- Configurable logging with structured output
- Pydantic models for request/response validation
- Security best practices implementation
- Comprehensive documentation and examples

### Security
- All secret values encrypted at rest using AWS KMS
- Secure transmission using TLS
- Proper error handling to prevent information disclosure
- Support for customer-managed KMS keys
- Resource-based policy validation

### Documentation
- Complete README with usage examples
- API documentation for all tools
- Best practices guide
- Security considerations
- Development setup instructions
