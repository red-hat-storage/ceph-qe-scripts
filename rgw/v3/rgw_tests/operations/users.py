"""Identity provisioning with immediate registration of owned resources."""

import json

from rgw_tests.clients import make_client
from rgw_tests.config import Credentials
from rgw_tests.resources import unique_name


class Users:
    def __init__(self, cfg, admin, resources):
        self.cfg, self.admin, self.resources = cfg, admin, resources

    def create(self, kind):
        if kind in self.cfg.identities:
            return Credentials.from_env(self.cfg.identities[kind])
        if kind in ("ldap", "sts"):
            raise ValueError(
                f"{kind} requires a pre-provisioned credentials environment prefix"
            )
        account_id = None
        if kind in ("account-root", "account-user"):
            account = self.admin.run(
                "account", "create", account_name=unique_name("account")
            )
            account_id = account["id"]
            self.resources.defer(
                f"account {account_id}",
                self.admin.run,
                "account",
                "rm",
                account_id=account_id,
                json_output=False,
            )
        uid = unique_name("user")
        tenant = unique_name("tenant") if kind == "tenanted" else None
        info = self.admin.run(
            "user",
            "create",
            uid=uid,
            display_name=uid,
            tenant=tenant,
            account_id=account_id,
            account_root=bool(account_id),
            gen_access_key=True,
            gen_secret=True,
        )
        self.resources.defer(
            f"user {uid}",
            self.admin.run,
            "user",
            "rm",
            uid=uid,
            tenant=tenant,
            json_output=False,
        )
        key = info["keys"][0]
        credentials = Credentials(key["access_key"], key["secret_key"], tenant=tenant)
        if kind != "account-user":
            return credentials
        iam = make_client(self.cfg, credentials, "iam")
        self.resources.defer("IAM client", iam.close)
        name = unique_name("iam")
        iam.create_user(UserName=name)
        self.resources.defer(f"IAM user {name}", iam.delete_user, UserName=name)
        policy_name = "rgwv3-s3"
        iam.put_user_policy(
            UserName=name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
                    ],
                }
            ),
        )
        self.resources.defer(
            f"IAM policy {name}",
            iam.delete_user_policy,
            UserName=name,
            PolicyName=policy_name,
        )
        access = iam.create_access_key(UserName=name)["AccessKey"]
        self.resources.defer(
            f"IAM access key for {name}",
            iam.delete_access_key,
            UserName=name,
            AccessKeyId=access["AccessKeyId"],
        )
        return Credentials(access["AccessKeyId"], access["SecretAccessKey"])
