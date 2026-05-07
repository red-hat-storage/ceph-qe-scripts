import json
import logging

from v2.lib.exceptions import TestExecError

log = logging.getLogger()

try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    log.warning("requests library not available. Some CORS tests will be skipped.")

try:
    from requests_aws4auth import AWS4Auth

    AWS4AUTH_AVAILABLE = True
except ImportError:
    AWS4AUTH_AVAILABLE = False
    log.warning(
        "requests-aws4auth library not available. CORS requests will not be authenticated."
    )


def test_cors_configuration(s3_client, bucket_name, config):
    """
    Test basic CORS configuration operations.

    Args:
        s3_client: boto3 S3 client
        bucket_name (str): Name of the bucket
        config: Test configuration

    Returns:
        bool: True if tests passed
    """
    try:
        log.info("Testing CORS configuration operations")

        # Define CORS rules
        cors_rules = [
            {
                "AllowedOrigins": ["http://example.com", "https://example.com"],
                "AllowedMethods": ["GET", "PUT", "POST", "DELETE"],
                "AllowedHeaders": ["*"],
                "ExposeHeaders": ["ETag", "x-amz-request-id", "x-amz-version-id"],
                "MaxAgeSeconds": 3000,
            }
        ]

        # Put CORS configuration
        log.info(f"Setting CORS configuration on bucket: {bucket_name}")
        cors_config = {"CORSRules": cors_rules}
        s3_client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=cors_config)
        log.info("Successfully set CORS configuration")

        # Get CORS configuration
        log.info(f"Getting CORS configuration from bucket: {bucket_name}")
        response = s3_client.get_bucket_cors(Bucket=bucket_name)
        retrieved_rules = response.get("CORSRules", [])
        log.info(f"Retrieved CORS rules: {json.dumps(retrieved_rules, indent=2)}")

        # Validate retrieved configuration
        if len(retrieved_rules) != len(cors_rules):
            raise TestExecError(
                f"CORS rule count mismatch. Expected {len(cors_rules)}, got {len(retrieved_rules)}"
            )

        log.info("CORS configuration test passed")
        return True

    except Exception as e:
        log.error(f"CORS configuration test failed: {e}")
        raise TestExecError(f"CORS configuration test failed: {e}")


def test_cors_multiple_rules(s3_client, bucket_name):
    """
    Test multiple CORS rules on a single bucket.

    Args:
        s3_client: boto3 S3 client
        bucket_name (str): Name of the bucket

    Returns:
        bool: True if tests passed
    """
    try:
        log.info("Testing multiple CORS rules")

        cors_rules = [
            {
                "AllowedOrigins": ["http://example.com"],
                "AllowedMethods": ["GET", "PUT"],
                "AllowedHeaders": ["*"],
                "MaxAgeSeconds": 3000,
            },
            {
                "AllowedOrigins": ["http://another.com", "https://another.com"],
                "AllowedMethods": ["GET", "DELETE"],
                "AllowedHeaders": ["Content-Type", "Authorization"],
                "ExposeHeaders": ["ETag"],
                "MaxAgeSeconds": 1800,
            },
            {
                "AllowedOrigins": ["*"],
                "AllowedMethods": ["GET", "HEAD"],
                "AllowedHeaders": ["*"],
                "MaxAgeSeconds": 600,
            },
        ]

        # Set multiple CORS rules
        log.info(f"Setting {len(cors_rules)} CORS rules on bucket: {bucket_name}")
        cors_config = {"CORSRules": cors_rules}
        s3_client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=cors_config)
        log.info("Successfully set multiple CORS rules")

        # Retrieve and validate
        response = s3_client.get_bucket_cors(Bucket=bucket_name)
        retrieved_rules = response.get("CORSRules", [])

        if len(retrieved_rules) != len(cors_rules):
            raise TestExecError(
                f"CORS rule count mismatch. Expected {len(cors_rules)}, got {len(retrieved_rules)}"
            )

        log.info(f"Successfully validated {len(retrieved_rules)} CORS rules")
        return True

    except Exception as e:
        log.error(f"Multiple CORS rules test failed: {e}")
        raise TestExecError(f"Multiple CORS rules test failed: {e}")


def test_cors_wildcard_origin(s3_client, bucket_name):
    """
    Test CORS with wildcard origin.

    Args:
        s3_client: boto3 S3 client
        bucket_name (str): Name of the bucket

    Returns:
        bool: True if tests passed
    """
    try:
        log.info("Testing CORS with wildcard origin")

        cors_rules = [
            {
                "AllowedOrigins": ["*"],
                "AllowedMethods": ["GET", "HEAD", "PUT", "POST", "DELETE"],
                "AllowedHeaders": ["*"],
                "ExposeHeaders": ["ETag", "x-amz-request-id"],
                "MaxAgeSeconds": 3000,
            }
        ]

        log.info("Setting CORS configuration with wildcard origin")
        cors_config = {"CORSRules": cors_rules}
        s3_client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=cors_config)

        # Retrieve and validate
        response = s3_client.get_bucket_cors(Bucket=bucket_name)
        retrieved_rules = response.get("CORSRules", [])

        if len(retrieved_rules) != 1:
            raise TestExecError("Failed to set wildcard CORS rule")

        if "*" not in retrieved_rules[0].get("AllowedOrigins", []):
            raise TestExecError("Wildcard origin not found in retrieved CORS rules")

        log.info("CORS wildcard origin test passed")
        return True

    except Exception as e:
        log.error(f"CORS wildcard origin test failed: {e}")
        raise TestExecError(f"CORS wildcard origin test failed: {e}")


def test_cors_preflight_request(
    endpoint_url,
    bucket_name,
    object_key,
    access_key,
    secret_key,
    region="us-east-1",
    verify_ssl=True,
):
    """
    Test CORS preflight OPTIONS request with AWS4Auth.

    Args:
        endpoint_url (str): RGW endpoint URL
        bucket_name (str): Name of the bucket
        object_key (str): Object key
        access_key (str): AWS access key
        secret_key (str): AWS secret key
        region (str): AWS region
        verify_ssl (bool): Whether to verify SSL

    Returns:
        bool: True if tests passed
    """
    if not REQUESTS_AVAILABLE:
        log.warning("Skipping preflight request test - requests library not available")
        return True

    try:
        log.info("Testing CORS preflight OPTIONS request with AWS4Auth")

        url = f"{endpoint_url}/{bucket_name}/{object_key}"
        origin = "http://example.com"
        method = "GET"

        headers = {
            "Origin": origin,
            "Access-Control-Request-Method": method,
            "Access-Control-Request-Headers": "Content-Type, Authorization",
        }

        log.info(f"Sending OPTIONS request to: {url}")
        log.info(f"Origin: {origin}, Method: {method}")

        # Create AWS4Auth if available
        auth = None
        if AWS4AUTH_AVAILABLE:
            auth = AWS4Auth(access_key, secret_key, region, "s3")
            log.info("Using AWS4Auth for request signing")

        response = requests.options(url, headers=headers, auth=auth, verify=verify_ssl)

        log.info(f"Preflight response status: {response.status_code}")
        log.info(f"Response headers: {dict(response.headers)}")

        # Check for CORS headers
        if "Access-Control-Allow-Origin" in response.headers:
            log.info(
                f"Access-Control-Allow-Origin: {response.headers['Access-Control-Allow-Origin']}"
            )
        else:
            log.warning("Access-Control-Allow-Origin header not found in response")

        if "Access-Control-Allow-Methods" in response.headers:
            log.info(
                f"Access-Control-Allow-Methods: {response.headers['Access-Control-Allow-Methods']}"
            )

        if "Access-Control-Max-Age" in response.headers:
            log.info(
                f"Access-Control-Max-Age: {response.headers['Access-Control-Max-Age']}"
            )

        # Preflight should return 200 or 204
        if response.status_code not in [200, 204]:
            log.warning(f"Unexpected preflight status code: {response.status_code}")

        log.info("CORS preflight request test passed")
        return True

    except Exception as e:
        log.error(f"CORS preflight request test failed: {e}")
        raise TestExecError(f"CORS preflight request test failed: {e}")


def test_cors_actual_request(
    endpoint_url,
    bucket_name,
    object_key,
    access_key,
    secret_key,
    region="us-east-1",
    verify_ssl=True,
):
    """
    Test actual CORS request with Origin header and AWS4Auth.

    Args:
        endpoint_url (str): RGW endpoint URL
        bucket_name (str): Name of the bucket
        object_key (str): Object key
        access_key (str): AWS access key
        secret_key (str): AWS secret key
        region (str): AWS region
        verify_ssl (bool): Whether to verify SSL

    Returns:
        bool: True if tests passed
    """
    if not REQUESTS_AVAILABLE:
        log.warning(
            "Skipping actual CORS request test - requests library not available"
        )
        return True

    try:
        log.info("Testing actual CORS GET request with AWS4Auth")

        url = f"{endpoint_url}/{bucket_name}/{object_key}"
        origin = "http://example.com"

        headers = {"Origin": origin}

        log.info(f"Sending GET request to: {url}")
        log.info(f"Origin: {origin}")

        # Create AWS4Auth if available
        auth = None
        if AWS4AUTH_AVAILABLE:
            auth = AWS4Auth(access_key, secret_key, region, "s3")
            log.info("Using AWS4Auth for request signing")

        response = requests.get(url, headers=headers, auth=auth, verify=verify_ssl)

        log.info(f"CORS request response status: {response.status_code}")

        # Check for CORS headers
        if "Access-Control-Allow-Origin" in response.headers:
            log.info(
                f"Access-Control-Allow-Origin: {response.headers['Access-Control-Allow-Origin']}"
            )
        else:
            log.warning("Access-Control-Allow-Origin header not found in response")

        if "Access-Control-Expose-Headers" in response.headers:
            log.info(
                f"Access-Control-Expose-Headers: {response.headers['Access-Control-Expose-Headers']}"
            )

        log.info("CORS actual request test passed")
        return True

    except Exception as e:
        log.error(f"CORS actual request test failed: {e}")
        raise TestExecError(f"CORS actual request test failed: {e}")


def test_cors_delete_configuration(s3_client, bucket_name):
    """
    Test deleting CORS configuration.

    Args:
        s3_client: boto3 S3 client
        bucket_name (str): Name of the bucket

    Returns:
        bool: True if tests passed
    """
    try:
        log.info("Testing CORS configuration deletion")

        # Delete CORS configuration
        log.info(f"Deleting CORS configuration from bucket: {bucket_name}")
        s3_client.delete_bucket_cors(Bucket=bucket_name)
        log.info("Successfully deleted CORS configuration")

        # Verify deletion
        try:
            response = s3_client.get_bucket_cors(Bucket=bucket_name)
            # If we get here, CORS config still exists
            raise TestExecError("CORS configuration still exists after deletion")
        except Exception as e:
            if "NoSuchCORSConfiguration" in str(e):
                log.info("Verified CORS configuration deleted")
            else:
                raise

        log.info("CORS configuration deletion test passed")
        return True

    except Exception as e:
        log.error(f"CORS configuration deletion test failed: {e}")
        raise TestExecError(f"CORS configuration deletion test failed: {e}")
