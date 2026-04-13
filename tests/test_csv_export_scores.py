import sys
import types
import unittest

sys.modules.setdefault("yaml", types.SimpleNamespace(safe_load=lambda *_args, **_kwargs: {}))

import main


class CsvExportScoresTests(unittest.TestCase):
    def test_headers2_matches_new_import_format(self):
        self.assertEqual(
            main.headers2,
            [
                "score::cvss3",
                "score::cvss",
                "score::YourLabel",
                "cves",
                "cwes",
                "score::cvss3.1",
                "score::cvss4",
                "score::likelihood_impact",
            ],
        )

    def test_build_score_fields_includes_new_columns(self):
        writeup = {
            "risk_score": {
                "CVSS3_1": {
                    "overall": 3.7,
                    "vector": "AV:A/AC:H/PR:H/UI:R/S:C/C:N/I:L/A:L",
                },
                "CVSS4": {
                    "overall": 8.9,
                    "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
                },
                "likelihood_impact": {
                    "score": 25,
                    "impact": 5,
                    "likelihood": 5,
                },
            },
            "fields": {
                "scores": {
                    "cvss3": {
                        "value": "9.8",
                        "calculation": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                    "cvss": {
                        "value": "9.5",
                        "calculation": "AV:L/AC:M/Au:N/C:C/I:N/A:P",
                    },
                    "general": {
                        "type": "general",
                        "label": "YourLabel",
                        "value": "1000",
                        "calculation": "a+b+c+d",
                    },
                }
            },
        }

        self.assertEqual(
            main.build_score_fields(writeup),
            [
                "9.8::AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "9.5::AV:L/AC:M/Au:N/C:C/I:N/A:P",
                "1000::a+b+c+d",
                "3.7::AV:A/AC:H/PR:H/UI:R/S:C/C:N/I:L/A:L",
                "8.9::CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
                "5::5",
            ],
        )


if __name__ == "__main__":
    unittest.main()
