"""Optional CRUD tools with environment credentials and bounded subprocesses."""

import json
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory


class ToolError(RuntimeError):
    pass


class Tool:
    def __init__(self, cfg, credentials):
        self.cfg = cfg
        self.env = dict(os.environ)
        # Remove inherited identity selectors; all tools use the test's identity.
        for key in (
            "AWS_PROFILE",
            "AWS_DEFAULT_PROFILE",
            "AWS_SESSION_TOKEN",
            "AWS_SECURITY_TOKEN",
            "AWS_ROLE_ARN",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_ENDPOINT_URL",
            "AWS_ENDPOINT_URL_S3",
        ):
            self.env.pop(key, None)
        self.env.update(
            AWS_ACCESS_KEY_ID=credentials.access_key,
            AWS_SECRET_ACCESS_KEY=credentials.secret_key,
            AWS_REGION=cfg.region,
            AWS_DEFAULT_REGION=cfg.region,
            AWS_EC2_METADATA_DISABLED="true",
            AWS_PAGER="",
            AWS_REQUEST_CHECKSUM_CALCULATION="when_required",
            AWS_RESPONSE_CHECKSUM_VALIDATION="when_required",
        )
        if credentials.token:
            self.env["AWS_SESSION_TOKEN"] = credentials.token

    def run(self, argv):
        try:
            result = subprocess.run(
                argv,
                env=self.env,
                capture_output=True,
                timeout=self.cfg.timeout,
                text=True,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise ToolError(f"{argv[0]} could not complete") from None
        if result.returncode:
            raise ToolError(f"{argv[0]} exited {result.returncode}")
        return result.stdout


class AWSCLI(Tool):
    def call(self, operation, **options):
        argv = [
            "aws",
            "--endpoint-url",
            self.cfg.endpoint,
            "--region",
            self.cfg.region,
            "--output",
            "json",
            "--cli-connect-timeout",
            str(self.cfg.request_timeout),
            "--cli-read-timeout",
            str(self.cfg.request_timeout),
        ]
        if self.cfg.verify_tls is False:
            argv.append("--no-verify-ssl")
        elif isinstance(self.cfg.verify_tls, str):
            argv.extend(["--ca-bundle", self.cfg.verify_tls])
        argv.extend(["s3api", operation])
        output = options.pop("output_file", None)
        for key, value in options.items():
            argv.extend(["--" + key.replace("_", "-"), str(value)])
        if output is not None:
            argv.append(str(output))
        result = self.run(argv)
        return json.loads(result) if result.strip() else {}

    def exercise(self, bucket, body):
        with TemporaryDirectory(prefix="rgwv3-aws-") as directory:
            source, downloaded = (
                Path(directory) / "source",
                Path(directory) / "downloaded",
            )
            source.write_bytes(body)
            self.call("put-object", bucket=bucket, key="aws-source", body=source)
            self.call(
                "copy-object",
                bucket=bucket,
                key="aws-copy",
                copy_source=f"{bucket}/aws-source",
            )
            self.call(
                "get-object", bucket=bucket, key="aws-copy", output_file=downloaded
            )
            if downloaded.read_bytes() != body:
                raise ToolError("AWS CLI copy/download content mismatch")
            result = self.call("list-objects-v2", bucket=bucket, prefix="aws-")
            keys = {item["Key"] for item in result.get("Contents", [])}
            if keys != {"aws-source", "aws-copy"}:
                raise ToolError("AWS CLI listing mismatch")
            for key in keys:
                self.call("delete-object", bucket=bucket, key=key)


class Elbencho(Tool):
    def phase(self, operation, bucket):
        if operation not in ("write", "read", "delete"):
            raise ValueError("Elbencho is restricted to CRUD")
        # Let the AWS C++ SDK use its default HTTPS validation. Custom TLS
        # overrides are deliberately unsupported by this adapter.
        if self.cfg.verify_tls is not True:
            raise ValueError("Elbencho adapter requires default TLS verification")
        flag = {"write": "-w", "read": "-r", "delete": "-F"}[operation]
        return self.run(
            [
                "elbencho",
                "--s3endpoints",
                self.cfg.endpoint,
                "--s3region",
                self.cfg.region,
                flag,
                "-t",
                "1",
                "-n",
                "0",
                "-N",
                str(self.cfg.objects),
                "-s",
                str(self.cfg.object_size),
                "-b",
                str(max(self.cfg.object_size, 5242880)),
                "--verify",
                "1",
                f"s3://{bucket}",
            ]
        )
