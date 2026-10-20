"""Retired audit entry points must never touch data, models or publication."""
import contextlib
import io
import unittest
from unittest.mock import patch

import jp_incidents as app


class RetiredAuditTests(unittest.TestCase):
    def test_cli_rejects_every_legacy_flag_combination_without_side_effects(self):
        for flags in ([], ["--apply"], ["--publish"], ["--apply", "--publish"]):
            with self.subTest(flags=flags), contextlib.ExitStack() as stack:
                guards = [
                    stack.enter_context(patch.object(app, name))
                    for name in ("db", "fetch_body", "classify", "publish_public_json")
                ]
                stack.enter_context(patch("sys.argv", ["jp_incidents.py", "audit-current", *flags]))
                output = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                with self.assertRaises(SystemExit) as error:
                    app.main()
                self.assertEqual(error.exception.code, 2)
                self.assertIn("audit-current is retired", output.getvalue())
                for guard in guards:
                    guard.assert_not_called()

    def test_imported_entry_point_also_fails_closed(self):
        for apply in (False, True):
            with self.subTest(apply=apply), patch.object(app, "db") as database:
                with patch.object(app, "classify") as classify:
                    with self.assertRaisesRegex(RuntimeError, "audit-current is retired"):
                        app.audit_current(apply=apply)
                    database.assert_not_called()
                    classify.assert_not_called()
