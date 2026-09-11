#!/usr/bin/env python3
"""Alertmanager -> Microsoft Teams Adaptive Card relay.

Alertmanager's webhook_configs always POSTs its own fixed JSON envelope
(https://prometheus.io/docs/alerting/latest/configuration/#webhook_config)
— never an Adaptive Card. A Power Automate "When a Teams webhook request
is received" flow trigger requires the raw POST body to already be a
valid Adaptive Card (top-level "type": "AdaptiveCard"), so pointing
webhook_configs directly at such a flow fails with
AdaptiveCards.AdaptiveSerializationException: Property 'type' must be
'AdaptiveCard'. This relay sits between the two and does the transform.

Endpoints:
  POST /webhook  Alertmanager's real target: transform + forward to
                 TEAMS_WEBHOOK_URL, relay its status code back so
                 Alertmanager's retry/failure metrics stay meaningful.
  POST /render   Same transform, no forward — returns the Adaptive Card
                 JSON directly. Used by the verification spec's
                 self-test row so `pilot verify` can exercise the
                 transform without spamming the real Teams channel.
  GET  /healthz  Liveness probe.
"""
import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8095"))
MAX_ALERTS_IN_CARD = 10
MAX_LABEL_FACTS = 8
MAX_TEXT_LENGTH = 1200


def as_text(value, default="(not set)"):
    """Return a bounded string that is safe to place in a card field."""
    if value is None or str(value).strip() == "":
        return default
    text = str(value).strip()
    if len(text) > MAX_TEXT_LENGTH:
        return text[: MAX_TEXT_LENGTH - 1] + "…"
    return text


def first_annotation(alert_annotations, common_annotations, *names):
    """Prefer alert-specific annotations, then Alertmanager common annotations."""
    for name in names:
        value = alert_annotations.get(name) or common_annotations.get(name)
        if value:
            return as_text(value, "")
    return ""


def card_color(status, severity):
    if status == "resolved":
        return "good"
    if str(severity).lower() in ("critical", "page", "emergency"):
        return "attention"
    if str(severity).lower() in ("warning", "warn"):
        return "warning"
    return "accent"


def alert_facts(alert, common_labels):
    """Select readable, useful fields without dumping every noisy label."""
    labels = alert.get("labels") or {}
    merged = dict(common_labels)
    merged.update(labels)
    subject = (
        merged.get("instance")
        or merged.get("pilot_subject")
        or merged.get("pilot_host")
        or merged.get("pilot_target")
    )
    facts = [
        {"title": "Status", "value": as_text(alert.get("status"), "unknown")},
        {"title": "Severity", "value": as_text(merged.get("severity"))},
        {"title": "Subject", "value": as_text(subject)},
    ]
    # Detection-engine alerts often carry their explanation in labels such as
    # metric, signal, source, device or value. Keep those visible first, then
    # include a small, deterministic remainder for other integrations.
    emitted = {"alertname", "severity", "instance"}
    for key in ("job", "metric", "signal", "source", "device", "host", "value"):
        if key in merged and key not in emitted:
            facts.append({"title": key, "value": as_text(merged[key])})
            emitted.add(key)
    for key in sorted(merged):
        if key not in emitted and len(facts) < MAX_LABEL_FACTS:
            facts.append({"title": key, "value": as_text(merged[key])})
            emitted.add(key)
    return facts[:MAX_LABEL_FACTS]


def anomaly_details(alert_annotations, common_annotations):
    """Render detection-engine evidence as concise human-readable card fields."""
    annotations = dict(common_annotations)
    annotations.update(alert_annotations)
    facts = []
    for key, title in (
        ("category_hint", "Category"),
        ("score", "Anomaly score"),
        ("confidence", "Confidence"),
        ("dominant_feature", "Primary signal"),
        ("detector_source", "Detector"),
        ("profile", "Profile"),
    ):
        if annotations.get(key):
            facts.append({"title": title, "value": as_text(annotations[key])})

    text = []
    raw_contributors = annotations.get("top_contributors")
    if raw_contributors:
        try:
            contributors = json.loads(raw_contributors)
            if isinstance(contributors, list) and contributors:
                text.append("Top contributors: {}".format(", ".join(as_text(item, "") for item in contributors[:5])))
        except (TypeError, ValueError):
            text.append("Top contributors: {}".format(as_text(raw_contributors)))

    raw_values = annotations.get("feature_values")
    if raw_values:
        try:
            values = json.loads(raw_values)
            if isinstance(values, dict) and values:
                rendered = []
                for key in sorted(values)[:5]:
                    rendered.append("{}={}".format(key, as_text(values[key])))
                text.append("Observed values: {}".format(", ".join(rendered)))
        except (TypeError, ValueError):
            # A malformed annotation must never make an alert notification
            # fail; preserve a bounded representation for investigation.
            text.append("Observed values: {}".format(as_text(raw_values)))
    return facts, text


def build_adaptive_card(payload):
    status = payload.get("status", "unknown")
    group_labels = payload.get("groupLabels") or {}
    common_labels = payload.get("commonLabels") or {}
    common_annotations = payload.get("commonAnnotations") or {}
    alerts = payload.get("alerts") or []
    alertname = group_labels.get("alertname") or common_labels.get("alertname")
    if not alertname and alerts:
        alertname = (alerts[0].get("labels") or {}).get("alertname")
    alertname = alertname or "unknown"
    severity = group_labels.get("severity") or common_labels.get("severity")
    if not severity and alerts:
        severity = (alerts[0].get("labels") or {}).get("severity")
    severity = severity or "unknown"
    status_text = str(status).upper()
    fallback_parts = ["[{}] {}".format(status_text, alertname), "severity={}".format(severity)]

    body = [
        {
            "type": "TextBlock",
            "text": "[{}] {}".format(status_text, alertname),
            "weight": "bolder",
            "size": "medium",
            "color": card_color(status, severity),
            "wrap": True,
        },
        {
            "type": "TextBlock",
            "text": "Alertmanager · {} alert{} · severity {}".format(
                len(alerts), "" if len(alerts) == 1 else "s", severity
            ),
            "isSubtle": True,
            "spacing": "None",
            "wrap": True,
        },
    ]
    for alert in alerts[:MAX_ALERTS_IN_CARD]:
        labels = alert.get("labels") or {}
        annotations = alert.get("annotations") or {}
        subject = (
            labels.get("instance")
            or labels.get("pilot_subject")
            or labels.get("pilot_host")
            or labels.get("pilot_target")
            or common_labels.get("instance")
            or common_labels.get("pilot_subject")
            or common_labels.get("pilot_host")
            or common_labels.get("pilot_target")
        )
        summary = first_annotation(
            annotations, common_annotations, "summary", "title", "message", "msg", "description"
        )
        description = first_annotation(annotations, common_annotations, "description", "message", "msg")
        detail_facts, detail_text = anomaly_details(annotations, common_annotations)
        fallback_parts.append("subject={}".format(as_text(subject)))
        if summary:
            fallback_parts.append(summary)
        fallback_parts.extend(detail_text)
        body.append(
            {
                "type": "TextBlock",
                "text": "{}{}".format(
                    "Subject: ", as_text(subject, "not supplied")
                ),
                "weight": "bolder",
                "spacing": "medium",
                "wrap": True,
            }
        )
        body.append({"type": "FactSet", "facts": alert_facts(alert, common_labels)})
        if detail_facts:
            body.append({"type": "FactSet", "facts": detail_facts})
        if summary:
            body.append({"type": "TextBlock", "text": str(summary), "wrap": True})
        if description and description != summary:
            body.append(
                {
                    "type": "TextBlock",
                    "text": description,
                    "wrap": True,
                    "isSubtle": True,
                }
            )
        for line in detail_text:
            body.append({"type": "TextBlock", "text": line, "wrap": True, "isSubtle": True})

    if len(alerts) > MAX_ALERTS_IN_CARD:
        body.append(
            {
                "type": "TextBlock",
                "text": "Only the first {} alerts are shown.".format(MAX_ALERTS_IN_CARD),
                "isSubtle": True,
                "wrap": True,
            }
        )

    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        # 1.2 remains compatible with both Teams desktop/mobile and the
        # Power Automate "Post card in a chat or channel" action.
        "version": "1.2",
        # Teams uses this in activity feeds, notifications, search and clients
        # that cannot render a card. Without it, those views show the opaque
        # "Card - access it on .../cards.unsupported" placeholder.
        "fallbackText": " · ".join(fallback_parts),
        "body": body,
    }


class Handler(BaseHTTPRequestHandler):
    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        return json.loads(raw or b"{}")

    def _reply(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self._reply(200, b'{"status":"ok"}')
            return
        self._reply(404)

    def do_POST(self):
        try:
            payload = self._read_json()
        except ValueError:
            self._reply(400, b'{"error":"invalid json"}')
            return

        card_bytes = json.dumps(build_adaptive_card(payload)).encode()

        if self.path == "/render":
            self._reply(200, card_bytes)
            return

        if self.path == "/webhook":
            if not TEAMS_WEBHOOK_URL:
                self._reply(500, b'{"error":"TEAMS_WEBHOOK_URL not configured"}')
                return
            req = urllib.request.Request(
                TEAMS_WEBHOOK_URL,
                data=card_bytes,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    self._reply(resp.status)
            except urllib.error.HTTPError as e:
                self._reply(e.code)
            except urllib.error.URLError:
                self._reply(502)
            return

        self._reply(404)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
