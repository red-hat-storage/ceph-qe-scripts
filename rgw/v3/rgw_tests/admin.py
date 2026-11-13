"""Local or remote admin argv prefix, without a shell or response logging."""

import json
import subprocess


class AdminError(RuntimeError):
    pass


class Admin:
    def __init__(self, command=("radosgw-admin",), timeout=300):
        self.command = list(command)
        self.timeout = timeout

    def run(self, *args, json_output=True, **options):
        argv = self.command + list(args)
        for key, value in options.items():
            option = "--" + key.replace("_", "-")
            if value is True:
                argv.append(option)
            elif value is not None and value is not False:
                argv.extend([option, str(value)])
        try:
            result = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AdminError(
                f"Admin operation {' '.join(args)} could not complete"
            ) from exc
        if result.returncode:
            # Admin output can contain generated access/secret keys.
            raise AdminError(
                f"Admin operation {' '.join(args)} exited {result.returncode}"
            )
        if not json_output:
            return None
        try:
            return json.loads(result.stdout) if result.stdout.strip() else None
        except json.JSONDecodeError:
            raise AdminError(
                f"Admin operation {' '.join(args)} returned invalid JSON"
            ) from None
