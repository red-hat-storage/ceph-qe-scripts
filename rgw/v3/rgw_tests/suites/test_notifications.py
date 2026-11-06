"""Verify notifications delivered from RGW to the test runner over HTTP."""

from urllib.parse import unquote_plus

import pytest
from rgw_tests.clients import make_client
from rgw_tests.operations.notifications import Notifications
from rgw_tests.polling import wait_for
from rgw_tests.resources import unique_name


@pytest.mark.notifications
@pytest.mark.slow
class TestNotifications:
    def test_create_and_remove_events(self, feature_context, cfg, resources):
        context = feature_context
        receiver = Notifications(**cfg.notification)
        resources.defer("HTTP notification receiver", receiver.close)
        sns = make_client(cfg, context.credentials, "sns")
        resources.defer("SNS client", sns.close)
        topic = sns.create_topic(
            Name=unique_name("topic"),
            Attributes={"push-endpoint": receiver.url, "persistent": "true"},
        )["TopicArn"]
        resources.defer("notification topic", sns.delete_topic, TopicArn=topic)
        context.client.put_bucket_notification_configuration(
            Bucket=context.bucket,
            NotificationConfiguration={
                "TopicConfigurations": [
                    {
                        "Id": "rgwv3",
                        "TopicArn": topic,
                        "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
                    }
                ]
            },
        )
        resources.defer(
            "bucket notification",
            context.client.put_bucket_notification_configuration,
            Bucket=context.bucket,
            NotificationConfiguration={},
        )
        key = "event/object with spaces"
        context.crud.put(key, b"notification")
        context.crud.delete(key)

        def delivered():
            events = {
                record["eventName"]
                for record in receiver.events(context.bucket)
                if unquote_plus(record["s3"]["object"]["key"]) == key
            }
            return any("ObjectCreated:" in e for e in events) and any(
                "ObjectRemoved:" in e for e in events
            )

        wait_for(
            delivered,
            timeout=cfg.timeout,
            interval=cfg.poll_interval,
            description=f"create and remove events for {context.bucket}/{key}",
        )
