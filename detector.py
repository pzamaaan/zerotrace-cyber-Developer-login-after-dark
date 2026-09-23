"""
ZeroTrace - Login After Dark
Core Threat Detection & Authentication Log Analysis Engine
"""

from datetime import datetime, timezone, timedelta
from models import db, AuthLog, Alert, WatchlistIP

# Known high-risk and Tor exit node IP ranges/signatures for threat intelligence correlation
KNOWN_THREAT_IPS = {
    "185.220.101.4": {"type": "Tor Exit Node", "country": "Tor Network", "code": "TOR", "risk": "High"},
    "45.155.204.12": {"type": "Automated Brute-Force Botnet", "country": "Romania", "code": "RO", "risk": "High"},
    "103.98.63.221": {"type": "Hosting / Bulletproof Proxy", "country": "Vietnam", "code": "VN", "risk": "Medium"},
    "91.240.118.82": {"type": "Commercial VPN Endpoint", "country": "Netherlands", "code": "NL", "risk": "Medium"},
    "194.26.29.11":  {"type": "Anonymous Proxy Relay", "country": "Seychelles", "code": "SC", "risk": "High"},
}

# Privileged accounts that receive elevated threat scoring upon failure
HIGH_VALUE_ACCOUNTS = {"admin", "root", "administrator", "sysadmin", "service", "j.romero"}

# Nocturnal "Login After Dark" hours (UTC): 00:00 to 05:00
AFTER_DARK_HOURS = set(range(0, 5))

# Lockout threshold configuration
ACCOUNT_LOCKOUT_THRESHOLD = 10


def to_utc_naive(dt):
    """Normalize any datetime or string into a timezone-naive UTC datetime for SQLite compatibility."""
    if dt is None:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    if isinstance(dt, str):
        try:
            clean_ts = dt.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
        except Exception:
            return datetime.now(timezone.utc).replace(tzinfo=None)
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


class ThreatDetector:
    """
    Evaluates authentication events against security rules:
    - Multiple failed logins
    - Login bursts
    - Repeated failures
    - Unusual login times (Login After Dark)
    - Suspicious IP addresses
    - Potential brute-force behavior
    - Abnormal authentication patterns (credential stuffing & impossible travel)
    """

    def __init__(self, lockout_threshold=ACCOUNT_LOCKOUT_THRESHOLD):
        self.lockout_threshold = lockout_threshold

    def analyze_event(self, event_data):
        """
        Main entry point: Analyzes an authentication event, calculates risk,
        classifies the threat level, and creates alerts if necessary.

        :param event_data: dict with keys:
            user (str), ip (str), status (str: 'SUCCESS'|'FAILURE'),
            timestamp (datetime or str, optional), country (str, optional),
            user_agent (str, optional), failure_reason (str, optional)
        :return: dict with risk_score, classification, triggered_patterns, alert
        """
        user = (event_data.get("user") or "unknown").strip().lower()
        ip = (event_data.get("ip") or "127.0.0.1").strip()
        status = (event_data.get("status") or "FAILURE").strip().upper()
        country = event_data.get("country") or "Unknown"
        user_agent = event_data.get("user_agent") or "Standard Browser"
        failure_reason = event_data.get("failure_reason") or ("None" if status == "SUCCESS" else "invalid_credentials")

        ts = to_utc_naive(event_data.get("timestamp"))

        triggered_patterns = []
        score_penalties = 0

        # Baseline score: Successful logins start low (5), Failed logins start with baseline penalty (20)
        base_score = 5.0 if status == "SUCCESS" else 20.0

        # -------------------------------------------------------------
        # Rule 1: Unusual Login Times ("Login After Dark" Nocturnal Window)
        # -------------------------------------------------------------
        is_after_dark = ts.hour in AFTER_DARK_HOURS
        if is_after_dark:
            if status == "FAILURE":
                triggered_patterns.append("Unusual login time (off-hours nocturnal window: %02d:00 UTC)" % ts.hour)
                score_penalties += 32
            else:
                # Successful login during off hours is mildly notable
                triggered_patterns.append("Off-hours successful authentication (%02d:00 UTC)" % ts.hour)
                score_penalties += 12

        # -------------------------------------------------------------
        # Rule 2: Suspicious IP Address & Threat Intelligence Check
        # -------------------------------------------------------------
        ip_threat = self._check_suspicious_ip(ip)
        if ip_threat:
            threat_desc = ip_threat.get("type", "Suspicious Host")
            triggered_patterns.append(f"Suspicious IP address: {threat_desc} [{ip}]")
            score_penalties += 35

        # -------------------------------------------------------------
        # Rule 3: Login Bursts (Velocity in 60-second window)
        # -------------------------------------------------------------
        burst_count = self._count_recent_attempts(ip=ip, user=user, current_time=ts, window_seconds=60)
        if burst_count >= 5:
            triggered_patterns.append(f"Login burst: {burst_count + 1} rapid attempts in under 60 seconds")
            score_penalties += 28

        # -------------------------------------------------------------
        # Rule 4: Multiple Failed Attempts & Repeated Failures
        # -------------------------------------------------------------
        recent_ip_failures = self._count_recent_failures(ip=ip, user=None, current_time=ts, window_minutes=15)
        recent_user_failures = self._count_recent_failures(ip=None, user=user, current_time=ts, window_minutes=15)

        if status == "FAILURE":
            recent_ip_failures += 1
            recent_user_failures += 1

        if recent_ip_failures >= 5:
            triggered_patterns.append(f"Repeated failures from IP: {recent_ip_failures} failed attempts in 15m")
            score_penalties += 25
        elif recent_ip_failures >= 3:
            triggered_patterns.append(f"Multiple failed attempts: {recent_ip_failures} failures in window")
            score_penalties += 15

        # -------------------------------------------------------------
        # Rule 5: Potential Brute-Force Behavior (Approaching Lockout)
        # -------------------------------------------------------------
        is_target_privileged = user in HIGH_VALUE_ACCOUNTS
        if recent_user_failures >= 7:
            imminent_str = " (LOCKOUT IMMINENT)" if recent_user_failures >= (self.lockout_threshold - 2) else ""
            triggered_patterns.append(
                f"Potential brute-force attack: {recent_user_failures}/{self.lockout_threshold} failures on '{user}'{imminent_str}"
            )
            score_penalties += 40 if is_target_privileged else 30
        elif is_target_privileged and status == "FAILURE":
            score_penalties += 15  # Elevated penalty for failed attempts against root/admin

        # -------------------------------------------------------------
        # Rule 6: Abnormal Pattern A — Distributed Credential Stuffing
        # -------------------------------------------------------------
        distinct_users = self._count_distinct_users_targeted(ip=ip, current_time=ts, window_minutes=15)
        if distinct_users >= 3:
            triggered_patterns.append(
                f"Credential stuffing pattern: single IP targeting {distinct_users} distinct user accounts"
            )
            score_penalties += 35

        # -------------------------------------------------------------
        # Rule 7: Abnormal Pattern B — Impossible Travel Velocity
        # -------------------------------------------------------------
        impossible_travel = self._check_impossible_travel(user=user, current_country=country, current_ip=ip, current_time=ts)
        if impossible_travel:
            triggered_patterns.append(
                f"Impossible travel anomaly: user signed in from {impossible_travel['prior_country']} then {country} within {impossible_travel['delta_minutes']}m"
            )
            score_penalties += 40

        # Calculate final composite risk score (0 to 100)
        total_risk = min(100.0, max(0.0, base_score + score_penalties))

        # Classification mapping
        if total_risk >= 70.0:
            classification = "CRITICAL"
        elif total_risk >= 35.0:
            classification = "SUSPICIOUS"
        else:
            classification = "NORMAL"

        # Record log in database
        log_entry = AuthLog(
            timestamp=ts,
            user=user,
            ip=ip,
            status=status,
            country=country,
            country_code=event_data.get("country_code", "XX"),
            user_agent=user_agent,
            failure_reason=failure_reason if status == "FAILURE" else None,
            risk_score=total_risk,
            classification=classification,
            triggered_patterns=", ".join(triggered_patterns)
        )
        db.session.add(log_entry)

        # Generate Alert record if classified as SUSPICIOUS or CRITICAL
        created_alert = None
        if classification in ("SUSPICIOUS", "CRITICAL"):
            alert_level = "critical" if classification == "CRITICAL" else "suspicious"
            alert_reason = "; ".join(triggered_patterns) if triggered_patterns else "Anomalous authentication threshold exceeded"
            
            # Determine primary pattern category
            if any("burst" in p.lower() for p in triggered_patterns):
                pattern_type = "burst"
            elif any("brute-force" in p.lower() for p in triggered_patterns):
                pattern_type = "brute_force"
            elif any("credential stuffing" in p.lower() for p in triggered_patterns):
                pattern_type = "credential_stuffing"
            elif any("impossible travel" in p.lower() for p in triggered_patterns):
                pattern_type = "impossible_travel"
            elif any("nocturnal" in p.lower() or "unusual login time" in p.lower() for p in triggered_patterns):
                pattern_type = "unusual_time"
            elif any("suspicious ip" in p.lower() for p in triggered_patterns):
                pattern_type = "suspicious_ip"
            else:
                pattern_type = "repeated_failure"

            status_label = "Blocked" if total_risk >= 85.0 else ("Investigating" if total_risk >= 65.0 else "Flagged")

            created_alert = Alert(
                timestamp=ts,
                user=user,
                ip=ip,
                level=alert_level,
                pattern_type=pattern_type,
                reason=alert_reason,
                status=status_label
            )
            db.session.add(created_alert)

        # Update IP Watchlist
        self._update_watchlist(ip=ip, country=country, classification=classification, triggered_patterns=triggered_patterns, ts=ts)

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise

        return {
            "log_id": log_entry.id,
            "user": user,
            "ip": ip,
            "status": status,
            "risk_score": round(total_risk, 1),
            "classification": classification,
            "triggered_patterns": triggered_patterns,
            "alert": created_alert.to_dict() if created_alert else None
        }

    def _check_suspicious_ip(self, ip):
        """Check if IP exists in threat intelligence database or matches threat signatures."""
        if ip in KNOWN_THREAT_IPS:
            return KNOWN_THREAT_IPS[ip]
        if ip.startswith("185.220.101."):
            return {"type": "Tor Exit Subnet", "country": "Tor Network", "code": "TOR", "risk": "High"}
        if ip.startswith("45.155.204."):
            return {"type": "Known Brute-Force Botnet Subnet", "country": "Romania", "code": "RO", "risk": "High"}
        return None

    def _count_recent_attempts(self, ip, user, current_time, window_seconds=60):
        """Count attempts from same IP or targeting user in the last window_seconds."""
        cutoff = current_time - timedelta(seconds=window_seconds)
        count = AuthLog.query.filter(
            AuthLog.timestamp >= cutoff,
            AuthLog.timestamp <= current_time,
            (AuthLog.ip == ip) | (AuthLog.user == user)
        ).count()
        return count

    def _count_recent_failures(self, ip, user, current_time, window_minutes=15):
        """Count failed authentication attempts within a sliding time window."""
        cutoff = current_time - timedelta(minutes=window_minutes)
        query = AuthLog.query.filter(
            AuthLog.timestamp >= cutoff,
            AuthLog.timestamp <= current_time,
            AuthLog.status == "FAILURE"
        )
        if ip:
            query = query.filter(AuthLog.ip == ip)
        if user:
            query = query.filter(AuthLog.user == user)
        return query.count()

    def _count_distinct_users_targeted(self, ip, current_time, window_minutes=15):
        """Count how many different user accounts this IP has attempted to access recently."""
        cutoff = current_time - timedelta(minutes=window_minutes)
        distinct_count = db.session.query(db.func.count(db.distinct(AuthLog.user))).filter(
            AuthLog.ip == ip,
            AuthLog.timestamp >= cutoff,
            AuthLog.timestamp <= current_time
        ).scalar()
        return distinct_count or 0

    def _check_impossible_travel(self, user, current_country, current_ip, current_time):
        """Check if the user authenticated from a distant country within an impossible timeframe (< 2h)."""
        if not current_country or current_country in ("Unknown", "Tor Network"):
            return None

        two_hours_ago = current_time - timedelta(hours=2)
        prior_login = AuthLog.query.filter(
            AuthLog.user == user,
            AuthLog.status == "SUCCESS",
            AuthLog.timestamp >= two_hours_ago,
            AuthLog.timestamp < current_time,
            AuthLog.country != "Unknown",
            AuthLog.country != current_country
        ).order_by(AuthLog.timestamp.desc()).first()

        if prior_login:
            prior_ts = to_utc_naive(prior_login.timestamp)
            curr_ts = to_utc_naive(current_time)
            delta_mins = max(1, int((curr_ts - prior_ts).total_seconds() / 60))
            return {
                "prior_country": prior_login.country,
                "delta_minutes": delta_mins
            }
        return None

    def _update_watchlist(self, ip, country, classification, triggered_patterns, ts):
        """Add or update IP in WatchlistIP table if suspicious or repeatedly failing."""
        if classification not in ("SUSPICIOUS", "CRITICAL") and not any(p for p in triggered_patterns if "ip" in p.lower()):
            return

        item = db.session.get(WatchlistIP, ip)
        if not item:
            reason = triggered_patterns[0] if triggered_patterns else "Anomalous authentication signature"
            risk = "High" if classification == "CRITICAL" else "Medium"
            item = WatchlistIP(
                ip=ip,
                country=country,
                country_code=country[:2].upper() if country else "XX",
                attempts=1,
                reason=reason,
                risk=risk,
                is_blocked=(classification == "CRITICAL"),
                last_seen=ts
            )
            db.session.add(item)
        else:
            item.attempts += 1
            item.last_seen = ts
            if classification == "CRITICAL":
                item.risk = "High"
                item.is_blocked = True
            if triggered_patterns:
                item.reason = triggered_patterns[0]

