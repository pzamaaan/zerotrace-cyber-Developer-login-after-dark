"""
Data Models for ZeroTrace - Login After Dark
Authentication Monitoring & Log Analysis
"""

from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AuthLog(db.Model):
    """
    Individual authentication event log record.
    """
    __tablename__ = "auth_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, default=utc_now, index=True)
    user = db.Column(db.String(120), nullable=False, index=True)
    ip = db.Column(db.String(64), nullable=False, index=True)
    status = db.Column(db.String(16), nullable=False)  # 'SUCCESS' or 'FAILURE'
    country = db.Column(db.String(64), default="Unknown")
    country_code = db.Column(db.String(8), default="XX")
    user_agent = db.Column(db.String(256), default="Standard Browser")
    failure_reason = db.Column(db.String(128), nullable=True)  # e.g., 'invalid_credentials', 'mfa_timeout'
    risk_score = db.Column(db.Float, default=0.0)  # 0.0 to 100.0
    classification = db.Column(db.String(20), default="NORMAL")  # 'NORMAL', 'SUSPICIOUS', 'CRITICAL'
    triggered_patterns = db.Column(db.Text, default="")  # Comma-separated list of detected patterns

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "",
            "time_short": self.timestamp.strftime("%H:%M:%S") if self.timestamp else "",
            "user": self.user,
            "ip": self.ip,
            "status": self.status,
            "country": self.country,
            "country_code": self.country_code,
            "user_agent": self.user_agent,
            "failure_reason": self.failure_reason,
            "risk_score": round(self.risk_score, 1),
            "classification": self.classification,
            "triggered_patterns": [p.strip() for p in self.triggered_patterns.split(",") if p.strip()] if self.triggered_patterns else []
        }


class Alert(db.Model):
    """
    Security alert produced when anomalous authentication activity is detected.
    """
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, default=utc_now, index=True)
    user = db.Column(db.String(120), nullable=False, index=True)
    ip = db.Column(db.String(64), nullable=False, index=True)
    level = db.Column(db.String(20), nullable=False)  # 'critical', 'suspicious', 'normal'
    pattern_type = db.Column(db.String(64), nullable=False)  # e.g. 'burst', 'brute_force', 'unusual_time'
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(32), default="Investigating")  # 'Investigating', 'Blocked', 'Flagged', 'Resolved'

    def to_dict(self):
        return {
            "id": self.id,
            "time": self.timestamp.strftime("%H:%M:%S") if self.timestamp else "",
            "timestamp_iso": self.timestamp.isoformat() if self.timestamp else "",
            "user": self.user,
            "ip": self.ip,
            "level": self.level.lower(),
            "pattern_type": self.pattern_type,
            "reason": self.reason,
            "status": self.status
        }


class WatchlistIP(db.Model):
    """
    IP addresses identified as potential threats or sources of repeated anomalous behavior.
    """
    __tablename__ = "watchlist_ips"

    ip = db.Column(db.String(64), primary_key=True)
    country = db.Column(db.String(64), default="Unknown")
    country_code = db.Column(db.String(8), default="XX")
    attempts = db.Column(db.Integer, default=1)
    reason = db.Column(db.String(256), default="Repeated anomalous authentication attempts")
    risk = db.Column(db.String(16), default="Medium")  # 'High', 'Medium', 'Low'
    is_blocked = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=utc_now)

    def to_dict(self):
        return {
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "attempts": self.attempts,
            "reason": self.reason,
            "risk": self.risk,
            "is_blocked": self.is_blocked,
            "last_seen": self.last_seen.strftime("%Y-%m-%d %H:%M:%S") if self.last_seen else ""
        }

