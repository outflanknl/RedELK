#!/usr/bin/python3
"""
Part of RedELK

This connector sends RedELK alerts via Slack

Authors:
- Matthijs Vos (@matthijsy)
"""
import logging
from slack_sdk.webhook import WebhookClient
from modules.helpers import get_value, pprint
import config

info = {
    "version": 0.1,
    "name": "slack connector",
    "description": "This connector sends RedELK alerts via Slack",
    "type": "redelk_connector",
    "submodule": "slack",
}


class Module:  # pylint: disable=too-few-public-methods
    """slack connector module"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def send_alarm(self, alarm):
        """Send the alarm notification"""
        description = alarm["info"]["description"]
        if len(alarm["groupby"]) > 0:
            description += f'\n _Please note that the items below have been grouped by: {alarm["groupby"]}_'

        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f'*Alarm from {alarm["info"]["name"]} [{alarm["hits"]["total"]} hits]*\n{description}',
                },
            },
            {"type": "divider"},
        ]

        try:
            for hit in alarm["hits"]["hits"]:
                i = 0
                title = hit["_id"]
                while i < len(alarm["groupby"]):
                    val = get_value(f'_source.{alarm["groupby"][i]}', hit)
                    if i == 0:
                        title = val
                    else:
                        title = f"{title} / {val}"
                    i += 1

                text = f"*Alarm on item: {title.strip()}*\n\t"
                for field in alarm["fields"]:
                    val = get_value(f"_source.{field}", hit)

                    # Add a tab to every line of values, this makes it easier to read
                    pretty_val = "".join(
                        [f"{line}\n\t" for line in pprint(val).split("\n")]
                    )
                    text += f"*{field}*: {pretty_val}"

                blocks.append(
                    {"type": "section", "text": {"type": "mrkdwn", "text": text}}
                )
                blocks.append({"type": "divider"})
            # pylint: disable=broad-except
        except Exception as error:
            self.logger.exception(error)

        webhook = WebhookClient(config.notifications["slack"]["webhook_url"])
        res = webhook.send(text="", blocks=blocks)

        if not 200 <= res.status_code <= 299:
            self.logger.error(
                "Informing slack failed: %s %s", res.status_code, res.body
            )
            self.logger.error(alarm)
