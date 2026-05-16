#!/usr/bin/env python3
"""
Fitbit Morning Briefing CLI

Generates a "how did you do" briefing. By convention every metric is
*yesterday's* (the last full day of activity data) except HRV, which is
measured overnight and so belongs to the briefing date itself — this morning's
reading reflects last night's sleep.

Usage:
    python fitbit_briefing.py                    # Briefing for today
    python fitbit_briefing.py --date 2026-01-20  # As if running on that morning
    python fitbit_briefing.py --format json      # Structured output
    python fitbit_briefing.py --format brief     # 3-line summary
"""

import argparse
import json
import logging
import sys
import traceback
from datetime import datetime, timedelta
from pathlib import Path

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
sys.path.insert(0, str(Path(__file__).parent))

from fitbit_api import FitbitClient


WEEKLY_AZM_GOAL = 150
STEPS_GOAL = 10000


def _activity_level(steps, active_minutes):
    if steps >= STEPS_GOAL and active_minutes >= 30:
        return "Active"
    if steps >= 7500 and active_minutes >= 20:
        return "Moderate"
    if steps >= 5000:
        return "Light"
    return "Sedentary"


def _trend_arrow(pct):
    if pct > 0:
        return f"↑ +{pct:.0f}%"
    if pct < 0:
        return f"↓ {pct:.0f}%"
    return "→ flat"


def _safe_float(value, ndigits=1):
    """Coerce a value to a rounded float; return None if not numeric."""
    try:
        return round(float(value), ndigits)
    except (TypeError, ValueError):
        return None


def _fmt_hrv(value):
    return f"{value:.0f} ms" if isinstance(value, (int, float)) else "N/A"


# --- Extractors ----------------------------------------------------------------

def _extract_first_int(payload, key):
    items = (payload or {}).get(key) or []
    if not items:
        return 0
    try:
        return int(items[0].get("value", 0))
    except (TypeError, ValueError):
        return 0


def _extract_activity_summary(payload):
    summary = (payload or {}).get("summary", {}) or {}
    return {
        "distance": summary.get("distance", 0) or 0,
        "floors": summary.get("floors", 0) or 0,
        "active_minutes": (summary.get("veryActiveMinutes", 0) or 0)
                          + (summary.get("fairlyActiveMinutes", 0) or 0),
    }


def _extract_heart_rate(payload):
    out = {"resting": None, "avg": None, "zones": {}}
    items = (payload or {}).get("activities-heart") or []
    if not items:
        return out
    value = items[0].get("value") if isinstance(items[0], dict) else None
    if not isinstance(value, dict):
        return out

    out["resting"] = value.get("restingHeartRate")

    name_map = {"Fat Burn": "fat_burn", "Cardio": "cardio", "Peak": "peak"}
    weighted_sum, total_minutes = 0, 0
    for zone in value.get("heartRateZones", []) or []:
        minutes = zone.get("minutes", 0) or 0
        key = next((v for k, v in name_map.items() if k in zone.get("name", "")), None)
        if key is None:
            continue  # Skip "Out of Range" — mostly resting
        out["zones"][key] = minutes
        midpoint = ((zone.get("min", 0) or 0) + (zone.get("max", 0) or 0)) / 2
        weighted_sum += midpoint * minutes
        total_minutes += minutes

    out["avg"] = round(weighted_sum / total_minutes) if total_minutes else out["resting"]
    return out


def _extract_sleep(payload):
    """Pick the main overnight sleep record, falling back to the longest entry.

    Fitbit dates sleep records by the day they ended, so a query needs to use
    the morning-after date — not the night-before date — to find the main
    overnight sleep. Naps and main sleep can both appear in one day's payload;
    we prefer ``isMainSleep`` and fall back to the longest entry.
    """
    items = (payload or {}).get("sleep") or []
    if not items:
        return {"hours": None, "efficiency": None, "awake_minutes": None}
    main = next((s for s in items if s.get("isMainSleep")), None)
    s = main or max(items, key=lambda x: x.get("duration", 0) or 0)
    duration_ms = s.get("duration", 0) or 0
    return {
        "hours": round(duration_ms / 3600000, 1) if duration_ms else None,
        "efficiency": s.get("efficiency"),
        "awake_minutes": s.get("minutesAwake"),
    }


def _extract_hrv(payload):
    """Pull dailyRmssd + deepRmssd from the HRV payload. Both may be missing."""
    items = (payload or {}).get("hrv") if isinstance(payload, dict) else None
    if not items:
        return {"daily": None, "deep": None}
    value = items[0].get("value") if isinstance(items[0], dict) else None
    if not isinstance(value, dict):
        return {"daily": None, "deep": None}
    return {
        "daily": _safe_float(value.get("dailyRmssd")),
        "deep": _safe_float(value.get("deepRmssd")),
    }


def _extract_azm(client, date):
    try:
        payload = client.get_active_zone_minutes(date, date)
    except Exception as exc:
        logging.warning("Failed to fetch Active Zone Minutes for %s: %s", date, exc)
        return {}
    items = (payload or {}).get("activities-active-zone-minutes") or []
    return items[0].get("value", {}) if items else {}


def _extract_exercises(client, date):
    payload = client._request(f"1/user/-/activities/date/{date}.json") or {}
    return payload.get("activities", []) or []


def _calculate_trends(client, yesterday, yesterday_steps, yesterday_calories):
    """7-day average of the days *before* yesterday, plus % delta vs yesterday."""
    week_start = (datetime.strptime(yesterday, "%Y-%m-%d") - timedelta(days=7)).strftime("%Y-%m-%d")
    steps_entries = (client.get_steps(week_start, yesterday) or {}).get("activities-steps", []) or []
    calorie_entries = (client.get_calories(week_start, yesterday) or {}).get("activities-calories", []) or []

    sum_steps, sum_calories, days = 0, 0, 0
    for entry in steps_entries:
        if entry.get("dateTime") == yesterday:
            continue
        sum_steps += int(entry.get("value", 0) or 0)
        days += 1
    for entry in calorie_entries:
        if entry.get("dateTime") == yesterday:
            continue
        sum_calories += int(entry.get("value", 0) or 0)

    if not days:
        return {"steps": 0, "calories": 0, "avg_steps": 0, "avg_calories": 0}

    avg_steps = sum_steps // days
    avg_calories = sum_calories // days
    return {
        "steps": round((yesterday_steps - avg_steps) / avg_steps * 100, 1) if avg_steps else 0,
        "calories": round((yesterday_calories - avg_calories) / avg_calories * 100, 1) if avg_calories else 0,
        "avg_steps": avg_steps,
        "avg_calories": avg_calories,
    }


# --- Build briefing data dict --------------------------------------------------

def _build_briefing(client, briefing_date):
    """Fetch all data and assemble the briefing data dict.

    Convention:
      - "yesterday" = the last full day of activity data → steps, sleep, HR,
        AZM, logged exercises, calories, distance, floors, active minutes.
      - HRV is measured overnight, so it belongs to ``briefing_date`` (today's
        morning briefing reflects last night's HRV reading).
    """
    yesterday = (datetime.strptime(briefing_date, "%Y-%m-%d") - timedelta(days=1)).strftime("%Y-%m-%d")

    # Yesterday's full-day data
    steps = _extract_first_int(client.get_steps(yesterday, yesterday), "activities-steps")
    calories = _extract_first_int(client.get_calories(yesterday, yesterday), "activities-calories")
    activity = _extract_activity_summary(client.get_activity_summary(yesterday, yesterday))
    hr = _extract_heart_rate(client.get_heartrate(yesterday, yesterday))
    # Sleep, like HRV, is an overnight measurement: Fitbit dates it to the day
    # the user woke up, so we query the briefing date (this morning) — not
    # yesterday — to find the main sleep period that just ended.
    sleep = _extract_sleep(client.get_sleep(briefing_date, briefing_date))
    azm = _extract_azm(client, yesterday)
    exercises = _extract_exercises(client, yesterday)

    # Last night's HRV (date = briefing_date because the measurement is overnight)
    hrv = _extract_hrv(client.get_hrv(briefing_date))

    # Trends — yesterday vs prior 7 days (excluding yesterday)
    trends = _calculate_trends(client, yesterday, steps, calories)

    data = {
        # Field names retain the legacy "_today" suffix for schema stability;
        # they actually hold *yesterday's* numbers. See `date` vs `date_label`.
        "date": yesterday,                   # activity data date
        "date_label": briefing_date,         # briefing/HRV date
        "steps_today": steps,
        "calories_today": calories,
        "distance_today": activity["distance"],
        "floors_today": activity["floors"],
        "active_minutes": activity["active_minutes"],
        "activity_level": _activity_level(steps, activity["active_minutes"]),
        "resting_hr": hr["resting"],
        "avg_hr": hr["avg"],
        "hr_zones": hr["zones"],
        "hrv_rmssd": hrv["daily"] if hrv["daily"] is not None else hrv["deep"],
        "hrv_daily_rmssd": hrv["daily"],
        "hrv_deep_rmssd": hrv["deep"],
        "sleep_hours": sleep["hours"],
        "sleep_efficiency": sleep["efficiency"],
        "awake_minutes": sleep["awake_minutes"],
        "steps_trend": trends["steps"],
        "calories_trend": trends["calories"],
        "avg_steps_7d": trends["avg_steps"],
        "avg_calories_7d": trends["avg_calories"],
    }
    return data, exercises, azm


# --- Formatters ----------------------------------------------------------------

def _format_brief(data):
    steps = data.get("steps_today") or 0
    calories = data.get("calories_today") or 0
    resting_hr = data.get("resting_hr") or "N/A"
    sleep_hours = data.get("sleep_hours")
    sleep_str = f"{sleep_hours}h" if sleep_hours else "N/A"
    hrv = _fmt_hrv(data.get("hrv_rmssd"))
    trend = _trend_arrow(data.get("steps_trend", 0))
    activity_level = data.get("activity_level", "Unknown")

    return "\n".join([
        f"📊 {steps:,} steps • {calories:,} cal",
        f"❤️  Resting HR: {resting_hr} • 💓 HRV: {hrv} • 💤 {sleep_str} sleep",
        f"🏃 {activity_level} • {trend} vs avg",
    ])


def _format_text(data, exercises=None, azm=None):
    lines = []
    activity_date = data.get("date", "?")
    briefing_date = data.get("date_label", activity_date)

    lines.append(f"📅 *Fitbit Morning Briefing — {briefing_date}*")
    lines.append(f"   Yesterday's activity ({activity_date}) + last night's sleep & HRV")
    lines.append("")

    if exercises:
        lines.append("*Yesterday's Activity*")
        for ex in exercises:
            name = ex.get("name", "Unknown")
            duration_min = round((ex.get("duration", 0) or 0) / 60000, 1)
            cals = ex.get("calories", 0) or 0
            lines.append(f"  • {name}: {duration_min} min • {cals} cal")
        lines.append("")

    if azm and azm.get("activeZoneMinutes"):
        lines.append("*Yesterday's Active Zone Minutes*")
        daily_goal = round(WEEKLY_AZM_GOAL / 7, 1)
        lines.append(f"  • Total AZM: {azm['activeZoneMinutes']} min "
                     f"(need {daily_goal}/day for {WEEKLY_AZM_GOAL}/week)")
        for label, key, credit in [
            ("Fat Burn", "fatBurnActiveZoneMinutes", "1×"),
            ("Cardio",   "cardioActiveZoneMinutes", "2×"),
            ("Peak",     "peakActiveZoneMinutes",   "2×"),
        ]:
            if azm.get(key):
                lines.append(f"  • {label} zone: {azm[key]} min ({credit} credit)")
        lines.append("")

    lines.append("*Activity*")
    lines.append(f"  • Steps: {data.get('steps_today', 0):,} / {STEPS_GOAL:,} goal")
    lines.append(f"  • Calories: {data.get('calories_today', 0):,} burned")
    lines.append(f"  • Distance: {data.get('distance_today', 0):.2f} km")
    lines.append(f"  • Floors: {data.get('floors_today', 0)}")
    lines.append(f"  • Active minutes: {data.get('active_minutes', 0)}")
    lines.append(f"  • Activity level: {data.get('activity_level', 'Unknown')}")
    lines.append("")

    lines.append("*Heart Rate*")
    lines.append(f"  • Average HR: {data.get('avg_hr') or 'N/A'} bpm")
    lines.append(f"  • Resting HR: {data.get('resting_hr') or 'N/A'} bpm")
    zones = data.get("hr_zones") or {}
    if zones:
        cardio = zones.get("cardio", 0)
        peak = zones.get("peak", 0)
        lines.append(f"  • Fat Burn: {zones.get('fat_burn', 0)} min")
        lines.append(f"  • Cardio: {cardio} min")
        lines.append(f"  • Peak: {peak} min")
        lines.append(f"  • Active Zone: {cardio + peak} min")
    lines.append("")

    # HRV — overnight reading, dated to the briefing day not yesterday
    lines.append(f"*Heart Rate Variability — last night ({briefing_date})*")
    daily = data.get("hrv_daily_rmssd")
    deep = data.get("hrv_deep_rmssd")
    if daily is None and deep is None:
        lines.append("  • No data")
    else:
        if daily is not None:
            lines.append(f"  • Daily RMSSD: {daily:.0f} ms (24h trailing)")
        if deep is not None:
            lines.append(f"  • Deep-sleep RMSSD: {deep:.0f} ms")
    lines.append("")

    lines.append(f"*Sleep — last night ({briefing_date})*")
    sleep_hours = data.get("sleep_hours")
    lines.append(f"  • Duration: {sleep_hours} hours" if sleep_hours else "  • Duration: No data")
    sleep_eff = data.get("sleep_efficiency")
    if sleep_eff is not None:
        lines.append(f"  • Efficiency: {sleep_eff}%")
    awake = data.get("awake_minutes")
    lines.append(f"  • Time awake: {awake} min" if awake is not None else "  • Time awake: N/A")
    lines.append("")

    lines.append("*Trends (vs 7-day avg)*")
    lines.append(f"  • Steps: {_trend_arrow(data.get('steps_trend', 0))}")
    lines.append(f"  • Calories: {_trend_arrow(data.get('calories_trend', 0))}")

    return "\n".join(lines)


# --- Entry point ---------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Fitbit Morning Briefing")
    parser.add_argument(
        "--date",
        help="Briefing date (YYYY-MM-DD, default: today). "
             "Activity metrics are for the prior day; HRV is for this date (overnight).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "brief", "json"],
        default="text",
        help="Output format (text=full briefing, brief=3 lines, json=structured)",
    )
    args = parser.parse_args()

    briefing_date = args.date or datetime.now().strftime("%Y-%m-%d")

    try:
        client = FitbitClient()
        data, exercises, azm = _build_briefing(client, briefing_date)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

    if args.format == "json":
        print(json.dumps(data, indent=2))
    elif args.format == "brief":
        print(_format_brief(data))
    else:
        print(_format_text(data, exercises=exercises, azm=azm))


if __name__ == "__main__":
    main()
