# Changelog

## [0.1.0] - 2025-01-20

### Added
- Initial implementation of AWS Secrets Manager MCP Server
- 16 comprehensive tools for secrets management:
  - `create-secret` - Create new secrets
  - `get-secret-value` - Retrieve secret values
  - `update-secret` - Update existing secrets
  - `delete-secret` - Schedule secrets for deletion
  - `restore-secret` - Restore deleted secrets
  - `list-secrets` - List all secrets with filtering
  - `describe-secret` - Get secret metadata
  - `get-random-password` - Generate secure passwords
  - `enable-rotation` - Enable automatic rotation
  - `disable-rotation` - Disable automatic rotation
  - `rotate-secret` - Manually trigger rotation
  - `tag-resource` - Add tags to secrets
  - `untag-resource` - Remove tags from secrets
  - `get-resource-policy` - Retrieve resource policies
  - `put-resource-policy` - Set resource policies
  - `delete-resource-policy` - Remove resource policies

### Fixed
- Parameter handling issue where FastMCP framework passed FieldInfo objects instead of actual values
- Tool naming consistency to use hyphenated format throughout
- Proper error handling and AWS credential validation

### Technical Details
- Uses boto3 for AWS API integration
- Comprehensive error handling with user-friendly messages
- Pydantic models for request/response validation
- Support for all AWS regions
- Proper logging with configurable levels