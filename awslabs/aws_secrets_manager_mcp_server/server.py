# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""AWS Secrets Manager MCP Server implementation."""

import json
import sys
from typing import Any, Dict, List, Optional, Union

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from loguru import logger
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

from .consts import (
    AWS_PROFILE,
    DEFAULT_MAX_RESULTS,
    DEFAULT_REGION,
    ERROR_MESSAGES,
    FASTMCP_LOG_LEVEL,
    SECRETS_MANAGER_INSTRUCTIONS,
    SUCCESS_MESSAGES,
)
from .models import (
    CreateSecretRequest,
    ListSecretsResponse,
    RandomPasswordConfig,
    ResourcePolicy,
    RotationConfiguration,
    SecretListItem,
    SecretMetadata,
    SecretValue,
    SecretsManagerResponse,
    Tag,
    UpdateSecretRequest,
)


# Configure logging
logger.remove()
logger.add(sys.stderr, level=FASTMCP_LOG_LEVEL)

# Initialize MCP server
mcp = FastMCP(
    'AWS-Secrets-Manager-MCP',
    instructions=SECRETS_MANAGER_INSTRUCTIONS,
    dependencies=[
        'pydantic',
        'boto3',
        'botocore',
        'loguru',
    ],
)

# Global AWS clients
_secrets_client: Optional[Any] = None


def get_secrets_client(region: Optional[str] = None) -> Any:
    """Get or create AWS Secrets Manager client."""
    global _secrets_client
    
    if _secrets_client is None or (region and region != DEFAULT_REGION):
        try:
            session = boto3.Session(profile_name=AWS_PROFILE) if AWS_PROFILE else boto3.Session()
            _secrets_client = session.client('secretsmanager', region_name=region or DEFAULT_REGION)
            logger.info(f'Created Secrets Manager client for region: {region or DEFAULT_REGION}')
        except NoCredentialsError:
            logger.error('No AWS credentials found')
            raise
        except Exception as e:
            logger.error(f'Error creating Secrets Manager client: {str(e)}')
            raise
    
    return _secrets_client


def handle_aws_error(error: ClientError, operation: str) -> SecretsManagerResponse:
    """Handle AWS client errors and return appropriate response."""
    error_code = error.response['Error']['Code']
    error_message = error.response['Error']['Message']
    
    logger.error(f'AWS error in {operation}: {error_code} - {error_message}')
    
    # Map common AWS errors to user-friendly messages
    if error_code == 'ResourceNotFoundException':
        message = f'Secret not found during {operation}'
    elif error_code == 'InvalidParameterException':
        message = f'Invalid parameter provided for {operation}: {error_message}'
    elif error_code == 'AccessDeniedException':
        message = f'Access denied for {operation}. Check IAM permissions.'
    elif error_code == 'EncryptionFailure':
        message = f'Encryption/decryption failed for {operation}. Check KMS permissions.'
    elif error_code == 'InvalidRequestException':
        message = f'Invalid request for {operation}: {error_message}'
    elif error_code == 'LimitExceededException':
        message = f'AWS service limit exceeded for {operation}'
    elif error_code == 'ResourceExistsException':
        message = f'Resource already exists for {operation}'
    else:
        message = f'AWS error in {operation}: {error_code} - {error_message}'
    
    return SecretsManagerResponse(
        success=False,
        message=message,
        data={'error_code': error_code, 'aws_message': error_message}
    )


@mcp.tool(name='create-secret')
async def create_secret(
    ctx: Context,
    name: str = Field(..., description='Name of the secret to create'),
    secret_value: Union[str, Dict[str, Any]] = Field(
        ..., 
        description='Secret value as string or JSON object'
    ),
    description: Optional[str] = Field(
        None, 
        description='Description of the secret'
    ),
    kms_key_id: Optional[str] = Field(
        None, 
        description='KMS key ID for encryption (optional)'
    ),
    tags: Optional[List[Dict[str, str]]] = Field(
        None, 
        description='Tags to associate with the secret as list of {"Key": "key", "Value": "value"} objects'
    ),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> SecretsManagerResponse:
    """Create a new secret in AWS Secrets Manager.
    
    This tool creates a new secret with the specified name and value. The secret value
    can be a simple string or a JSON object for structured data like database credentials.
    
    Examples:
    - Simple API key: create_secret(name="prod/api-key", secret_value="abc123")
    - Database credentials: create_secret(name="prod/db/mysql", secret_value={"username": "admin", "password": "secret123"})
    """
    try:
        # Validate and prepare request
        if isinstance(secret_value, dict):
            secret_string = json.dumps(secret_value)
        else:
            secret_string = str(secret_value)
        
        request = CreateSecretRequest(
            name=name,
            secret_value=secret_value,
            description=description,
            kms_key_id=kms_key_id,
            tags=[Tag(key=tag['Key'], value=tag['Value']) for tag in (tags or [])]
        )
        
        client = get_secrets_client(region)
        
        # Prepare API call parameters
        params = {
            'Name': request.name,
            'SecretString': secret_string,
        }
        
        if request.description:
            params['Description'] = request.description
        
        if request.kms_key_id:
            params['KmsKeyId'] = request.kms_key_id
        
        if request.tags:
            params['Tags'] = [{'Key': tag.key, 'Value': tag.value} for tag in request.tags]
        
        # Create the secret
        response = client.create_secret(**params)
        
        logger.info(f'Successfully created secret: {name}')
        
        return SecretsManagerResponse(
            success=True,
            message=SUCCESS_MESSAGES['secret_created'].format(name),
            data={
                'arn': response['ARN'],
                'name': response['Name'],
                'version_id': response['VersionId']
            }
        )
        
    except ClientError as e:
        return handle_aws_error(e, 'create_secret')
    except Exception as e:
        error_message = f'Error creating secret: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return SecretsManagerResponse(success=False, message=error_message)


@mcp.tool(name='get-secret-value')
async def get_secret_value(
    ctx: Context,
    secret_id: str = Field(..., description='Name or ARN of the secret'),
    version_id: Optional[str] = Field(
        None, 
        description='Specific version ID to retrieve (optional)'
    ),
    version_stage: Optional[str] = Field(
        None, 
        description='Version stage to retrieve (AWSCURRENT, AWSPENDING, AWSPREVIOUS)'
    ),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> SecretsManagerResponse:
    """Retrieve the value of a secret from AWS Secrets Manager.
    
    This tool retrieves the current or specified version of a secret's value.
    For JSON secrets, the response will include both the raw JSON string and
    parsed JSON object for easy access.
    
    IMPORTANT: This tool returns sensitive data. Use with caution and ensure
    proper access controls are in place.
    """
    try:
        client = get_secrets_client(region)
        
        # Prepare API call parameters
        params = {'SecretId': secret_id}
        
        if version_id:
            params['VersionId'] = version_id
        elif version_stage:
            params['VersionStage'] = version_stage
        
        # Get the secret value
        response = client.get_secret_value(**params)
        
        secret_value = SecretValue(
            secret_string=response.get('SecretString'),
            secret_binary=response.get('SecretBinary'),
            version_id=response['VersionId'],
            version_stages=response['VersionStages'],
            created_date=response['CreatedDate']
        )
        
        # Try to parse JSON if it's a string
        parsed_value = None
        if secret_value.secret_string:
            try:
                parsed_value = json.loads(secret_value.secret_string)
            except json.JSONDecodeError:
                # Not JSON, keep as string
                pass
        
        logger.info(f'Successfully retrieved secret value: {secret_id}')
        
        return SecretsManagerResponse(
            success=True,
            message=f'Successfully retrieved secret: {secret_id}',
            data={
                'name': response['Name'],
                'arn': response['ARN'],
                'secret_string': secret_value.secret_string,
                'secret_binary': secret_value.secret_binary.hex() if secret_value.secret_binary else None,
                'parsed_json': parsed_value,
                'version_id': secret_value.version_id,
                'version_stages': secret_value.version_stages,
                'created_date': secret_value.created_date.isoformat() if secret_value.created_date else None
            }
        )
        
    except ClientError as e:
        return handle_aws_error(e, 'get_secret_value')
    except Exception as e:
        error_message = f'Error retrieving secret value: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return SecretsManagerResponse(success=False, message=error_message)


@mcp.tool(name='update-secret')
async def update_secret(
    ctx: Context,
    secret_id: str = Field(..., description='Name or ARN of the secret to update'),
    secret_value: Optional[Union[str, Dict[str, Any]]] = Field(
        None, 
        description='New secret value (optional)'
    ),
    description: Optional[str] = Field(
        None, 
        description='New description for the secret (optional)'
    ),
    kms_key_id: Optional[str] = Field(
        None, 
        description='New KMS key ID for encryption (optional)'
    ),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> SecretsManagerResponse:
    """Update an existing secret in AWS Secrets Manager.
    
    This tool can update the secret value, description, or KMS key used for encryption.
    At least one parameter (secret_value, description, or kms_key_id) must be provided.
    """
    try:
        if not any([secret_value is not None, description is not None, kms_key_id is not None]):
            raise ValueError('At least one of secret_value, description, or kms_key_id must be provided')
        
        client = get_secrets_client(region)
        
        # Update secret value if provided
        if secret_value is not None:
            if isinstance(secret_value, dict):
                secret_string = json.dumps(secret_value)
            else:
                secret_string = str(secret_value)
            
            params = {
                'SecretId': secret_id,
                'SecretString': secret_string,
            }
            
            if kms_key_id:
                params['KmsKeyId'] = kms_key_id
            
            response = client.update_secret(**params)
            version_id = response['VersionId']
        else:
            version_id = None
        
        # Update description if provided
        if description is not None:
            client.update_secret(SecretId=secret_id, Description=description)
        
        logger.info(f'Successfully updated secret: {secret_id}')
        
        return SecretsManagerResponse(
            success=True,
            message=SUCCESS_MESSAGES['secret_updated'].format(secret_id),
            data={
                'secret_id': secret_id,
                'version_id': version_id
            }
        )
        
    except ClientError as e:
        return handle_aws_error(e, 'update_secret')
    except Exception as e:
        error_message = f'Error updating secret: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return SecretsManagerResponse(success=False, message=error_message)


@mcp.tool(name='delete-secret')
async def delete_secret(
    ctx: Context,
    secret_id: str = Field(..., description='Name or ARN of the secret to delete'),
    recovery_window_days: int = Field(
        30, 
        ge=7, 
        le=30, 
        description='Number of days before permanent deletion (7-30 days)'
    ),
    force_delete_without_recovery: bool = Field(
        False, 
        description='Whether to delete immediately without recovery window (DANGEROUS)'
    ),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> SecretsManagerResponse:
    """Schedule a secret for deletion in AWS Secrets Manager.
    
    By default, secrets are scheduled for deletion with a recovery window.
    During this period, the secret can be restored. Use force_delete_without_recovery
    only when absolutely necessary as this action is irreversible.
    
    IMPORTANT: This is a destructive operation. Deleted secrets cannot be recovered
    after the recovery window expires or if force deletion is used.
    """
    try:
        client = get_secrets_client(region)
        
        params = {'SecretId': secret_id}
        
        if force_delete_without_recovery:
            params['ForceDeleteWithoutRecovery'] = True
        else:
            params['RecoveryWindowInDays'] = recovery_window_days
        
        response = client.delete_secret(**params)
        
        logger.info(f'Successfully scheduled secret for deletion: {secret_id}')
        
        return SecretsManagerResponse(
            success=True,
            message=SUCCESS_MESSAGES['secret_deleted'].format(secret_id),
            data={
                'name': response['Name'],
                'arn': response['ARN'],
                'deletion_date': response['DeletionDate'].isoformat() if response.get('DeletionDate') else None
            }
        )
        
    except ClientError as e:
        return handle_aws_error(e, 'delete_secret')
    except Exception as e:
        error_message = f'Error deleting secret: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return SecretsManagerResponse(success=False, message=error_message)


@mcp.tool(name='restore-secret')
async def restore_secret(
    ctx: Context,
    secret_id: str = Field(..., description='Name or ARN of the secret to restore'),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> SecretsManagerResponse:
    """Restore a secret that was scheduled for deletion.
    
    This tool can restore a secret that is currently scheduled for deletion,
    as long as it's still within the recovery window.
    """
    try:
        client = get_secrets_client(region)
        
        response = client.restore_secret(SecretId=secret_id)
        
        logger.info(f'Successfully restored secret: {secret_id}')
        
        return SecretsManagerResponse(
            success=True,
            message=SUCCESS_MESSAGES['secret_restored'].format(secret_id),
            data={
                'name': response['Name'],
                'arn': response['ARN']
            }
        )
        
    except ClientError as e:
        return handle_aws_error(e, 'restore_secret')
    except Exception as e:
        error_message = f'Error restoring secret: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return SecretsManagerResponse(success=False, message=error_message)


@mcp.tool(name='list-secrets')
async def list_secrets(
    ctx: Context,
    max_results: int = Field(
        DEFAULT_MAX_RESULTS, 
        ge=1, 
        le=100, 
        description='Maximum number of secrets to return'
    ),
    name_prefix: Optional[str] = Field(
        None, 
        description='Filter secrets by name prefix'
    ),
    tag_filters: Optional[List[Dict[str, str]]] = Field(
        None, 
        description='Filter by tags as list of {"Key": "key", "Values": ["value1", "value2"]} objects'
    ),
    include_planned_deletion: bool = Field(
        False, 
        description='Whether to include secrets scheduled for deletion'
    ),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> ListSecretsResponse:
    """List secrets in AWS Secrets Manager with optional filtering.
    
    This tool returns a list of secrets with their metadata. Use filters to narrow
    down the results based on name prefix or tags.
    """
    try:
        client = get_secrets_client(region)
        
        params = {'MaxResults': max_results}
        
        # Add filters
        filters = []
        
        if name_prefix:
            filters.append({
                'Key': 'name',
                'Values': [name_prefix]
            })
        
        if not include_planned_deletion:
            filters.append({
                'Key': 'primary-region',
                'Values': [region or DEFAULT_REGION]
            })
        
        if tag_filters:
            for tag_filter in tag_filters:
                filters.append({
                    'Key': f'tag-key:{tag_filter["Key"]}',
                    'Values': tag_filter.get('Values', [])
                })
        
        if filters:
            params['Filters'] = filters
        
        response = client.list_secrets(**params)
        
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
        
        logger.info(f'Successfully listed {len(secrets)} secrets')
        
        return ListSecretsResponse(
            secrets=secrets,
            next_token=response.get('NextToken'),
            total_count=len(secrets)
        )
        
    except ClientError as e:
        error_response = handle_aws_error(e, 'list_secrets')
        await ctx.error(error_response.message)
        return ListSecretsResponse(secrets=[], next_token=None, total_count=0)
    except Exception as e:
        error_message = f'Error listing secrets: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return ListSecretsResponse(secrets=[], next_token=None, total_count=0)


@mcp.tool(name='describe-secret')
async def describe_secret(
    ctx: Context,
    secret_id: str = Field(..., description='Name or ARN of the secret'),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> SecretsManagerResponse:
    """Get detailed metadata about a secret without retrieving its value.
    
    This tool returns comprehensive information about a secret including
    rotation configuration, version information, and tags.
    """
    try:
        client = get_secrets_client(region)
        
        response = client.describe_secret(SecretId=secret_id)
        
        tags = [
            Tag(key=tag['Key'], value=tag['Value']) 
            for tag in response.get('Tags', [])
        ]
        
        metadata = SecretMetadata(
            name=response['Name'],
            arn=response['ARN'],
            description=response.get('Description'),
            kms_key_id=response.get('KmsKeyId'),
            rotation_enabled=response.get('RotationEnabled', False),
            rotation_lambda_arn=response.get('RotationLambdaARN'),
            rotation_interval_days=response.get('RotationRules', {}).get('AutomaticallyAfterDays'),
            last_rotated_date=response.get('LastRotatedDate'),
            last_changed_date=response.get('LastChangedDate'),
            last_accessed_date=response.get('LastAccessedDate'),
            deleted_date=response.get('DeletedDate'),
            tags=tags,
            version_ids_to_stages=response.get('VersionIdsToStages', {}),
            created_date=response.get('CreatedDate'),
            primary_region=response.get('PrimaryRegion'),
            replication_status=response.get('ReplicationStatus', [])
        )
        
        logger.info(f'Successfully described secret: {secret_id}')
        
        return SecretsManagerResponse(
            success=True,
            message=f'Successfully retrieved metadata for secret: {secret_id}',
            data=metadata.model_dump(mode='json')
        )
        
    except ClientError as e:
        return handle_aws_error(e, 'describe_secret')
    except Exception as e:
        error_message = f'Error describing secret: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return SecretsManagerResponse(success=False, message=error_message)


@mcp.tool(name='get-random-password')
async def get_random_password(
    ctx: Context,
    password_length: int = Field(
        32, 
        ge=4, 
        le=4096, 
        description='Length of the password to generate'
    ),
    exclude_characters: Optional[str] = Field(
        None, 
        description='Characters to exclude from the password'
    ),
    exclude_numbers: bool = Field(
        False, 
        description='Whether to exclude numbers (0-9)'
    ),
    exclude_punctuation: bool = Field(
        False, 
        description='Whether to exclude punctuation characters'
    ),
    exclude_uppercase: bool = Field(
        False, 
        description='Whether to exclude uppercase letters (A-Z)'
    ),
    exclude_lowercase: bool = Field(
        False, 
        description='Whether to exclude lowercase letters (a-z)'
    ),
    include_space: bool = Field(
        False, 
        description='Whether to include space character'
    ),
    require_each_included_type: bool = Field(
        True, 
        description='Whether to require at least one character from each included type'
    ),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> SecretsManagerResponse:
    """Generate a cryptographically secure random password.
    
    This tool uses AWS Secrets Manager's random password generation capability
    to create secure passwords with customizable character sets and requirements.
    """
    try:
        config = RandomPasswordConfig(
            password_length=password_length,
            exclude_characters=exclude_characters,
            exclude_numbers=exclude_numbers,
            exclude_punctuation=exclude_punctuation,
            exclude_uppercase=exclude_uppercase,
            exclude_lowercase=exclude_lowercase,
            include_space=include_space,
            require_each_included_type=require_each_included_type
        )
        
        client = get_secrets_client(region)
        
        params = {
            'PasswordLength': config.password_length,
            'ExcludeNumbers': config.exclude_numbers,
            'ExcludePunctuation': config.exclude_punctuation,
            'ExcludeUppercase': config.exclude_uppercase,
            'ExcludeLowercase': config.exclude_lowercase,
            'IncludeSpace': config.include_space,
            'RequireEachIncludedType': config.require_each_included_type
        }
        
        if config.exclude_characters:
            params['ExcludeCharacters'] = config.exclude_characters
        
        response = client.get_random_password(**params)
        
        logger.info(f'Successfully generated random password of length {password_length}')
        
        return SecretsManagerResponse(
            success=True,
            message=f'Successfully generated random password of length {password_length}',
            data={
                'password': response['RandomPassword']
            }
        )
        
    except ClientError as e:
        return handle_aws_error(e, 'get_random_password')
    except Exception as e:
        error_message = f'Error generating random password: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return SecretsManagerResponse(success=False, message=error_message)


@mcp.tool(name='enable-rotation')
async def enable_rotation(
    ctx: Context,
    secret_id: str = Field(..., description='Name or ARN of the secret'),
    lambda_function_arn: str = Field(
        ..., 
        description='ARN of the Lambda function to handle rotation'
    ),
    rotation_interval_days: int = Field(
        30, 
        ge=1, 
        le=365, 
        description='Number of days between automatic rotations'
    ),
    rotate_immediately: bool = Field(
        False, 
        description='Whether to rotate the secret immediately after enabling'
    ),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> SecretsManagerResponse:
    """Enable automatic rotation for a secret.
    
    This tool configures automatic rotation for a secret using a Lambda function.
    The Lambda function must be properly configured to handle the rotation process
    for the specific type of secret (database, API key, etc.).
    """
    try:
        client = get_secrets_client(region)
        
        params = {
            'SecretId': secret_id,
            'RotationLambdaARN': lambda_function_arn,
            'RotationRules': {
                'AutomaticallyAfterDays': rotation_interval_days
            }
        }
        
        if rotate_immediately:
            params['ForceRotateSecretImmediately'] = True
        
        response = client.rotate_secret(**params)
        
        logger.info(f'Successfully enabled rotation for secret: {secret_id}')
        
        return SecretsManagerResponse(
            success=True,
            message=SUCCESS_MESSAGES['rotation_enabled'].format(secret_id),
            data={
                'name': response['Name'],
                'arn': response['ARN'],
                'version_id': response['VersionId']
            }
        )
        
    except ClientError as e:
        return handle_aws_error(e, 'enable_rotation')
    except Exception as e:
        error_message = f'Error enabling rotation: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return SecretsManagerResponse(success=False, message=error_message)


@mcp.tool(name='disable-rotation')
async def disable_rotation(
    ctx: Context,
    secret_id: str = Field(..., description='Name or ARN of the secret'),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> SecretsManagerResponse:
    """Disable automatic rotation for a secret.
    
    This tool disables automatic rotation for a secret. Manual rotation
    can still be triggered using the rotate-secret tool.
    """
    try:
        client = get_secrets_client(region)
        
        response = client.update_secret(
            SecretId=secret_id,
            RotationLambdaARN='',  # Empty string disables rotation
        )
        
        logger.info(f'Successfully disabled rotation for secret: {secret_id}')
        
        return SecretsManagerResponse(
            success=True,
            message=SUCCESS_MESSAGES['rotation_disabled'].format(secret_id),
            data={
                'name': response['Name'],
                'arn': response['ARN']
            }
        )
        
    except ClientError as e:
        return handle_aws_error(e, 'disable_rotation')
    except Exception as e:
        error_message = f'Error disabling rotation: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return SecretsManagerResponse(success=False, message=error_message)


@mcp.tool(name='rotate-secret')
async def rotate_secret(
    ctx: Context,
    secret_id: str = Field(..., description='Name or ARN of the secret'),
    force_rotate_immediately: bool = Field(
        True, 
        description='Whether to force immediate rotation'
    ),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> SecretsManagerResponse:
    """Manually trigger rotation for a secret.
    
    This tool manually triggers the rotation process for a secret that has
    automatic rotation configured. The secret must have a Lambda function
    configured for rotation.
    """
    try:
        client = get_secrets_client(region)
        
        params = {
            'SecretId': secret_id,
            'ForceRotateSecretImmediately': force_rotate_immediately
        }
        
        response = client.rotate_secret(**params)
        
        logger.info(f'Successfully triggered rotation for secret: {secret_id}')
        
        return SecretsManagerResponse(
            success=True,
            message=SUCCESS_MESSAGES['rotation_triggered'].format(secret_id),
            data={
                'name': response['Name'],
                'arn': response['ARN'],
                'version_id': response['VersionId']
            }
        )
        
    except ClientError as e:
        return handle_aws_error(e, 'rotate_secret')
    except Exception as e:
        error_message = f'Error rotating secret: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return SecretsManagerResponse(success=False, message=error_message)


@mcp.tool(name='tag-resource')
async def tag_resource(
    ctx: Context,
    secret_id: str = Field(..., description='Name or ARN of the secret'),
    tags: List[Dict[str, str]] = Field(
        ..., 
        description='Tags to add as list of {"Key": "key", "Value": "value"} objects'
    ),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> SecretsManagerResponse:
    """Add or update tags on a secret.
    
    This tool adds tags to a secret for organization, cost allocation,
    and access control purposes. Existing tags with the same key will be updated.
    """
    try:
        client = get_secrets_client(region)
        
        # Validate and convert tags
        tag_objects = [Tag(key=tag['Key'], value=tag['Value']) for tag in tags]
        
        params = {
            'SecretId': secret_id,
            'Tags': [{'Key': tag.key, 'Value': tag.value} for tag in tag_objects]
        }
        
        client.tag_resource(**params)
        
        logger.info(f'Successfully tagged secret: {secret_id}')
        
        return SecretsManagerResponse(
            success=True,
            message=f'Successfully added {len(tags)} tags to secret: {secret_id}',
            data={
                'secret_id': secret_id,
                'tags_added': len(tags)
            }
        )
        
    except ClientError as e:
        return handle_aws_error(e, 'tag_resource')
    except Exception as e:
        error_message = f'Error tagging resource: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return SecretsManagerResponse(success=False, message=error_message)


@mcp.tool(name='untag-resource')
async def untag_resource(
    ctx: Context,
    secret_id: str = Field(..., description='Name or ARN of the secret'),
    tag_keys: List[str] = Field(
        ..., 
        description='List of tag keys to remove'
    ),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> SecretsManagerResponse:
    """Remove tags from a secret.
    
    This tool removes specified tags from a secret by their keys.
    """
    try:
        client = get_secrets_client(region)
        
        params = {
            'SecretId': secret_id,
            'TagKeys': tag_keys
        }
        
        client.untag_resource(**params)
        
        logger.info(f'Successfully removed tags from secret: {secret_id}')
        
        return SecretsManagerResponse(
            success=True,
            message=f'Successfully removed {len(tag_keys)} tags from secret: {secret_id}',
            data={
                'secret_id': secret_id,
                'tags_removed': len(tag_keys)
            }
        )
        
    except ClientError as e:
        return handle_aws_error(e, 'untag_resource')
    except Exception as e:
        error_message = f'Error untagging resource: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return SecretsManagerResponse(success=False, message=error_message)


@mcp.tool(name='get-resource-policy')
async def get_resource_policy(
    ctx: Context,
    secret_id: str = Field(..., description='Name or ARN of the secret'),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> SecretsManagerResponse:
    """Retrieve the resource-based policy for a secret.
    
    This tool returns the JSON policy document that controls access to the secret.
    Resource policies can be used to grant cross-account access or implement
    fine-grained access controls.
    """
    try:
        client = get_secrets_client(region)
        
        response = client.get_resource_policy(SecretId=secret_id)
        
        policy = ResourcePolicy(
            policy=response['ResourcePolicy'],
            policy_id=response.get('PolicyId'),
            policy_checksum=response.get('PolicyChecksum')
        )
        
        logger.info(f'Successfully retrieved resource policy for secret: {secret_id}')
        
        return SecretsManagerResponse(
            success=True,
            message=f'Successfully retrieved resource policy for secret: {secret_id}',
            data=policy.model_dump()
        )
        
    except ClientError as e:
        return handle_aws_error(e, 'get_resource_policy')
    except Exception as e:
        error_message = f'Error getting resource policy: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return SecretsManagerResponse(success=False, message=error_message)


@mcp.tool(name='put-resource-policy')
async def put_resource_policy(
    ctx: Context,
    secret_id: str = Field(..., description='Name or ARN of the secret'),
    policy: Union[str, Dict[str, Any]] = Field(
        ..., 
        description='JSON policy document as string or object'
    ),
    block_public_policy: bool = Field(
        True, 
        description='Whether to block public access to the secret'
    ),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> SecretsManagerResponse:
    """Set or update the resource-based policy for a secret.
    
    This tool sets a resource-based policy that controls access to the secret.
    The policy must be a valid JSON policy document.
    
    IMPORTANT: Be careful with resource policies as they can grant broad access.
    Always follow the principle of least privilege.
    """
    try:
        client = get_secrets_client(region)
        
        # Convert policy to string if it's a dict
        if isinstance(policy, dict):
            policy_string = json.dumps(policy)
        else:
            policy_string = str(policy)
        
        # Validate JSON
        try:
            json.loads(policy_string)
        except json.JSONDecodeError as e:
            raise ValueError(f'Invalid JSON policy: {str(e)}')
        
        params = {
            'SecretId': secret_id,
            'ResourcePolicy': policy_string,
            'BlockPublicPolicy': block_public_policy
        }
        
        response = client.put_resource_policy(**params)
        
        logger.info(f'Successfully set resource policy for secret: {secret_id}')
        
        return SecretsManagerResponse(
            success=True,
            message=f'Successfully set resource policy for secret: {secret_id}',
            data={
                'name': response['Name'],
                'arn': response['ARN']
            }
        )
        
    except ClientError as e:
        return handle_aws_error(e, 'put_resource_policy')
    except Exception as e:
        error_message = f'Error setting resource policy: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return SecretsManagerResponse(success=False, message=error_message)


@mcp.tool(name='delete-resource-policy')
async def delete_resource_policy(
    ctx: Context,
    secret_id: str = Field(..., description='Name or ARN of the secret'),
    region: Optional[str] = Field(
        None, 
        description='AWS region (defaults to configured region)'
    ),
) -> SecretsManagerResponse:
    """Remove the resource-based policy from a secret.
    
    This tool removes the resource-based policy from a secret, reverting
    access control to IAM policies only.
    """
    try:
        client = get_secrets_client(region)
        
        response = client.delete_resource_policy(SecretId=secret_id)
        
        logger.info(f'Successfully deleted resource policy for secret: {secret_id}')
        
        return SecretsManagerResponse(
            success=True,
            message=f'Successfully deleted resource policy for secret: {secret_id}',
            data={
                'name': response['Name'],
                'arn': response['ARN']
            }
        )
        
    except ClientError as e:
        return handle_aws_error(e, 'delete_resource_policy')
    except Exception as e:
        error_message = f'Error deleting resource policy: {str(e)}'
        logger.error(error_message)
        await ctx.error(error_message)
        return SecretsManagerResponse(success=False, message=error_message)


def main():
    """Main entry point for the AWS Secrets Manager MCP server."""
    logger.info('Starting AWS Secrets Manager MCP server')
    
    # Validate AWS credentials
    try:
        get_secrets_client()
        logger.info('AWS credentials validated successfully')
    except NoCredentialsError:
        error_message = ERROR_MESSAGES['no_credentials']
        logger.error(error_message)
        raise ValueError(error_message)
    except Exception as e:
        error_message = f'Error validating AWS credentials: {str(e)}'
        logger.error(error_message)
        raise RuntimeError(error_message)
    
    mcp.run(transport='stdio')


if __name__ == '__main__':
    main()
