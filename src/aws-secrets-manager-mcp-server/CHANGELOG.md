# Changelog

All notable changes to the AWS Secrets Manager MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Updated tool names to follow MCP naming conventions (removed hyphens)
  - `create-secret` → `createsecret`
  - `get-secret-value` → `getsecretvalue`
  - `update-secret` → `updatesecret`
  - `delete-secret` → `deletesecret`
  - `restore-secret` → `restoresecret`
  - `list-secrets` → `listsecrets`
  - `describe-secret` → `describesecret`
  - `get-random-password` → `getrandompassword`
  - `enable-rotation` → `enablerotation`
  - `disable-rotation` → `disablerotation`
  - `rotate-secret` → `rotatesecret`
  - `tag-resource` → `tagresource`
  - `untag-resource` → `untagresource`
  - `get-resource-policy` → `getresourcepolicy`
  - `put-resource-policy` → `putresourcepolicy`
  - `delete-resource-policy` → `deleteresourcepolicy`

## [0.1.0] - 2025-01-19

### Added
- Initial release of AWS Secrets Manager MCP Server
- Complete secret lifecycle management tools:
  - `createsecret`: Create new secrets with structured or simple values
  - `getsecretvalue`: Retrieve secret values with version control
  - `updatesecret`: Update existing secrets with automatic versioning
  - `deletesecret`: Schedule secrets for deletion with recovery windows
  - `restoresecret`: Restore secrets scheduled for deletion
  - `listsecrets`: List and filter secrets by name prefix and tags
  - `describesecret`: Get detailed secret metadata without values
- Automatic rotation support:
  - `enablerotation`: Configure automatic rotation with Lambda functions
  - `disablerotation`: Disable automatic rotation
  - `rotatesecret`: Manually trigger secret rotation
- Tag management:
  - `tagresource`: Add or update tags on secrets
  - `untagresource`: Remove tags from secrets
- Resource policy management:
  - `getresourcepolicy`: Retrieve resource-based policies
  - `putresourcepolicy`: Set or update resource-based policies
  - `deleteresourcepolicy`: Remove resource-based policies
- Utility tools:
  - `getrandompassword`: Generate cryptographically secure passwords
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
