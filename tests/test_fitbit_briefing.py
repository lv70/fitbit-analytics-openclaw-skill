import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import fitbit_briefing


class FakeClient:
    def get_steps(self, start_date, end_date):
        return {
            "activities-steps": [
                {"dateTime": "2026-03-13", "value": "7000"},
                {"dateTime": "2026-03-14", "value": "8000"},
            ]
        }

    def get_calories(self, start_date, end_date):
        return {
            "activities-calories": [
                {"dateTime": "2026-03-13", "value": "2000"},
                {"dateTime": "2026-03-14", "value": "2200"},
            ]
        }

    def get_activity_summary(self, start_date, end_date):
        return {
            "summary": {
                "distance": 5.5,
                "floors": 10,
                "veryActiveMinutes": 15,
                "fairlyActiveMinutes": 20,
            }
        }

    def get_heartrate(self, start_date, end_date):
        return {"activities-heart": [{"value": {"restingHeartRate": 58, "heartRateZones": []}}]}

    def get_sleep(self, start_date, end_date):
        return {"sleep": [{"duration": 7 * 3600000, "efficiency": 90, "minutesAwake": 10}]}

    def get_hrv(self, start_date, end_date=None):
        return {"hrv": [{"value": {"dailyRmssd": 42.0, "deepRmssd": 38.1}, "dateTime": "2026-03-14"}]}

    def _request(self, endpoint):
        return {}


class FitbitBriefingTests(unittest.TestCase):
    def test_format_brief_includes_hrv_with_units(self):
        output = fitbit_briefing._format_brief_briefing(
            {"steps_today": 8000, "calories_today": 2200, "resting_hr": 58, "hrv_rmssd": 42, "sleep_hours": 7.0}
        )
        self.assertIn("❤️ Resting HR: 58 • 💓 HRV: 42.0 ms • 💤 7.0h sleep", output)

    def test_format_brief_uses_na_when_hrv_missing(self):
        output = fitbit_briefing._format_brief_briefing(
            {"steps_today": 8000, "calories_today": 2200, "resting_hr": 58, "sleep_hours": 7.0}
        )
        self.assertIn("❤️ Resting HR: 58 • 💓 HRV: N/A • 💤 7.0h sleep", output)

    def test_main_json_output_includes_hrv_rmssd(self):
        stdout = io.StringIO()
        with mock.patch.object(fitbit_briefing, "FitbitClient", return_value=FakeClient()):
            with mock.patch.object(sys, "argv", ["fitbit_briefing.py", "--format", "json", "--date", "2026-03-14"]):
                with redirect_stdout(stdout):
                    fitbit_briefing.main()

        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["hrv_rmssd"], 42.0)
        self.assertEqual(payload["hrv_daily_rmssd"], 42.0)
        self.assertEqual(payload["hrv_deep_rmssd"], 38.1)

    def test_main_json_output_falls_back_to_deep_rmssd_when_daily_missing(self):
        class DeepOnlyHrvClient(FakeClient):
            def get_hrv(self, start_date, end_date=None):
                return {"hrv": [{"value": {"deepRmssd": 38.1}, "dateTime": "2026-03-14"}]}

        stdout = io.StringIO()
        with mock.patch.object(fitbit_briefing, "FitbitClient", return_value=DeepOnlyHrvClient()):
            with mock.patch.object(sys, "argv", ["fitbit_briefing.py", "--format", "json", "--date", "2026-03-14"]):
                with redirect_stdout(stdout):
                    fitbit_briefing.main()

        payload = json.loads(stdout.getvalue())
        self.assertIsNone(payload["hrv_daily_rmssd"])
        self.assertEqual(payload["hrv_deep_rmssd"], 38.1)
        self.assertEqual(payload["hrv_rmssd"], 38.1)

    def test_main_json_output_handles_empty_hrv_list_and_brief_shows_na(self):
        class EmptyHrvClient(FakeClient):
            def get_hrv(self, start_date, end_date=None):
                return {"hrv": []}

        stdout = io.StringIO()
        with mock.patch.object(fitbit_briefing, "FitbitClient", return_value=EmptyHrvClient()):
            with mock.patch.object(sys, "argv", ["fitbit_briefing.py", "--format", "json", "--date", "2026-03-14"]):
                with redirect_stdout(stdout):
                    fitbit_briefing.main()

        payload = json.loads(stdout.getvalue())
        self.assertIsNone(payload["hrv_rmssd"])
        brief_output = fitbit_briefing._format_brief_briefing(payload)
        self.assertIn("💓 HRV: N/A", brief_output)


if __name__ == "__main__":
    unittest.main()
