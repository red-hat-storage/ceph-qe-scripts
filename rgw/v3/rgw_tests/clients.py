"""Create clients once before sharing them with worker threads."""

import boto3
from botocore.config import Config as BotoConfig


def make_client(cfg, credentials, service="s3", endpoint=None):
    # Explicit credentials prevent accidental fallback to machine IAM credentials.
    return boto3.session.Session().client(
        service,
        endpoint_url=endpoint or cfg.endpoint,
        region_name=cfg.region,
        verify=cfg.verify_tls,
        aws_access_key_id=credentials.access_key,
        aws_secret_access_key=credentials.secret_key,
        aws_session_token=credentials.token,
        config=BotoConfig(
            signature_version="s3v4" if service == "s3" else "v4",
            s3={"addressing_style": "path"},
            retries={"mode": "standard", "max_attempts": 3},
            connect_timeout=cfg.request_timeout,
            read_timeout=cfg.request_timeout,
            max_pool_connections=max(10, cfg.workers),
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )
