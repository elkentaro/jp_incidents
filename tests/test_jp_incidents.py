import json
import io
import os
import sqlite3
import tempfile
import unittest
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import jp_incidents as app


class StaticPublishingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = app.DB_PATH
        app.DB_PATH = os.path.join(self.temp.name, "test.db")
        published = app.now_iso()
        self.published_day = datetime.fromisoformat(published).astimezone(app.JST).date().isoformat()
        connection = app.db()
        connection.execute(
            "INSERT INTO incidents(id,source,title,url,summary,published,first_seen,org,kind,records,score,confidence) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "incident-1", "東京都 / Tokyo Metropolitan Government", "個人情報の漏えいについて",
                "https://www.metro.tokyo.lg.jp/example", "", published,
                published, "Example Organization", "data leak", 1200, 60, "high",
            ),
        )
        connection.execute(
            "INSERT INTO refs(incident_id,url,source,title) VALUES(?,?,?,?)",
            (
                "incident-1", "https://www.metro.tokyo.lg.jp/example",
                "東京都 / Tokyo Metropolitan Government", "個人情報の漏えいについて",
            ),
        )
        connection.commit()
        connection.close()

    def test_network_wait_retries_without_touching_collection(self):
        checks = iter((False, False, True))
        delays = []
        self.assertTrue(app.wait_for_network(
            timeout=10, interval=2, probe_fn=lambda: next(checks), sleep_fn=delays.append
        ))
        self.assertEqual(delays, [2, 2])

    def test_network_wait_fails_for_systemd_to_retry(self):
        with patch.object(app.time, "monotonic", side_effect=(0, 0, 1)):
            with self.assertRaisesRegex(RuntimeError, "Network unavailable"):
                app.wait_for_network(
                    timeout=1, interval=1, probe_fn=lambda: False, sleep_fn=lambda _: None
                )

    def test_private_alert_is_rate_limited_and_redacts_secrets(self):
        state_path = os.path.join(self.temp.name, "alert-state.json")
        sent = []
        moment = datetime.fromisoformat("2026-10-19T12:00:00+00:00")
        environment = {
            "JPI_ALERT_WEBHOOK_URL": "https://discord.com/api/webhooks/example/token",
            "ANTHROPIC_API_KEY": "sk-ant-secret-value",
        }
        with patch.dict(os.environ, environment, clear=False):
            self.assertTrue(app.send_local_alert(
                "ai-billing", "AI billing", "key sk-ant-secret-value has low credits",
                now=moment, post_fn=lambda message: sent.append(message) or True,
                state_path=state_path,
            ))
            self.assertFalse(app.send_local_alert(
                "ai-billing", "AI billing", "duplicate",
                now=moment, post_fn=lambda message: sent.append(message) or True,
                state_path=state_path,
            ))
        self.assertEqual(len(sent), 1)
        self.assertNotIn("sk-ant-secret-value", sent[0])
        self.assertIn("[redacted]", sent[0])
        self.assertEqual(os.stat(state_path).st_mode & 0o777, 0o600)

    def test_discord_webhook_uses_content_payload(self):
        requests = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        def opener(request, timeout):
            requests.append((request, timeout))
            return Response()

        self.assertTrue(app.post_webhook(
            "private test", url="https://discord.com/api/webhooks/example/token", opener=opener
        ))
        self.assertEqual(json.loads(requests[0][0].data), {"content": "private test"})

    def test_ai_billing_error_sends_critical_alert(self):
        body = io.BytesIO(json.dumps({
            "type": "error",
            "error": {"type": "billing_error", "message": "credit balance is too low"},
        }).encode())
        error = urllib.error.HTTPError("https://api.anthropic.com", 402, "Payment Required", {}, body)
        with patch.object(app, "send_local_alert") as alert:
            app.report_ai_error(error, "test extraction")
        self.assertEqual(alert.call_args.args[:2], ("ai-billing", "AI credit or billing problem"))
        self.assertEqual(alert.call_args.kwargs["severity"], "critical")

    def test_cost_report_triggers_low_budget_alert(self):
        document = {"data": [{"results": [
            {"amount": "875", "currency": "USD"},
            {"amount": "1.00", "currency": "EUR"},
        ]}]}

        class Response:
            def __enter__(self):
                return io.BytesIO(json.dumps(document).encode())

            def __exit__(self, *_):
                return False

        environment = {
            "ANTHROPIC_ADMIN_API_KEY": "admin-secret",
            "JPI_AI_MONTHLY_BUDGET_USD": "10",
            "JPI_AI_LOW_CREDIT_USD": "2",
        }
        with patch.dict(os.environ, environment, clear=False), \
                patch.object(app, "send_local_alert") as alert:
            result = app.check_ai_budget(opener=lambda *_args, **_kwargs: Response())
        self.assertEqual(result["remaining"], app.Decimal("1.25"))
        self.assertEqual(alert.call_args.args[:2],
                         ("ai-low-credit", "AI monthly budget is running low"))

    def test_cost_report_fractional_cents_do_not_trigger_false_warning(self):
        document = {"data": [{"results": [{"amount": "123.78912", "currency": "USD"}]}]}
        environment = {
            "ANTHROPIC_ADMIN_API_KEY": "admin-secret",
            "JPI_AI_MONTHLY_BUDGET_USD": "10",
            "JPI_AI_LOW_CREDIT_USD": "2",
        }
        with patch.dict(os.environ, environment), patch.object(app, "send_local_alert") as alert:
            result = app.check_ai_budget(
                opener=lambda *_args, **_kwargs: io.BytesIO(json.dumps(document).encode())
            )
        self.assertEqual(result["spent"], app.Decimal("1.2378912"))
        self.assertEqual(result["remaining"], app.Decimal("8.7621088"))
        alert.assert_not_called()

    def test_budget_rejects_nonfinite_and_negative_configuration(self):
        for budget, low in [("NaN", "2"), ("Infinity", "2"), ("0", "2"),
                            ("-1", "2"), ("10", "-2"), ("10", "NaN")]:
            with self.subTest(budget=budget, low=low), patch.dict(os.environ, {
                "ANTHROPIC_ADMIN_API_KEY": "admin-secret",
                "JPI_AI_MONTHLY_BUDGET_USD": budget,
                "JPI_AI_LOW_CREDIT_USD": low,
            }), patch.object(app, "send_local_alert") as alert:
                self.assertIsNone(app.check_ai_budget(
                    opener=lambda *_args, **_kwargs: self.fail("invalid config must not call API")
                ))
                self.assertEqual(alert.call_args.args[0], "ai-budget-config")

    def test_ai_access_rate_limit_and_provider_errors_alert(self):
        for status, key in [(401, "ai-access"), (403, "ai-access"),
                            (429, "ai-rate-limit"), (503, "ai-service")]:
            with self.subTest(status=status), patch.object(app, "send_local_alert") as alert:
                error = urllib.error.HTTPError("https://api.anthropic.com", status,
                                               "test error", {}, io.BytesIO(b"{}"))
                app.report_ai_error(error, "test extraction")
                self.assertEqual(alert.call_args.args[0], key)

    def tearDown(self):
        app.DB_PATH = self.old_db
        self.temp.cleanup()

    def test_json_and_rss_are_complete_and_stable(self):
        json_path = os.path.join(self.temp.name, "data", "incidents.json")
        rss_path = os.path.join(self.temp.name, "feed.xml")

        self.assertTrue(app.write_public_json(json_path))
        self.assertTrue(app.write_public_rss(rss_path))
        self.assertFalse(app.write_public_json(json_path))
        self.assertFalse(app.write_public_rss(rss_path))

        with open(json_path, encoding="utf-8") as source:
            document = json.load(source)
        self.assertEqual(document["schema_version"], 2)
        self.assertEqual(document["total"], 1)
        self.assertEqual(document["incidents"][0]["potential_records"], 1200)
        self.assertEqual(len(document["incidents"][0]["sources"]), 1)
        self.assertEqual(len(document["daily_counts_90d"]), 90)
        self.assertEqual(sum(day["count"] for day in document["daily_counts_90d"]), 1)
        self.assertEqual(document["date_range"], {"start": self.published_day, "end": self.published_day})

        items = ET.parse(rss_path).findall("./channel/item")
        self.assertEqual(len(items), 1)
        self.assertIn("Example Organization", items[0].findtext("title"))

    def test_ai_review_is_private_until_next_cycle_promotion(self):
        connection = app.db()
        candidate = {
            "title": "Exampleへの不正アクセスについて",
            "url": "https://news.example.jp/incident",
            "summary": "個人情報が漏えいした可能性があります。",
            "published": "2026-10-18T00:00:00+00:00",
        }
        app.queue_for_review(connection, "Example News", "queued-1", candidate)
        connection.commit()
        connection.close()
        extracted = [{
            "org": "Queued Example", "kind": "data leak", "records": 42,
            "incident_date": app.calendar_date_iso(2026, 10, 18), "date_basis": "incident",
            "is_followup": False,
        }]
        evidence = [{"url": "https://other.example.jp/report", "source": "Other News", "title": "Example breach"}]
        with patch.object(app, "llm_extract_many", return_value=extracted):
            result = app.review_pending(fetch_body_fn=lambda _: "", corroborate_fn=lambda *_: evidence)
        self.assertEqual(result, {"total": 1, "confirmed": 1, "rejected": 0, "deferred": 0})
        connection = app.db()
        self.assertIsNone(connection.execute(
            "SELECT id FROM incidents WHERE org='Queued Example'"
        ).fetchone())
        promoted = app.promote_reviewed(connection)
        self.assertEqual(len(promoted), 1)
        self.assertIsNotNone(connection.execute(
            "SELECT id FROM incidents WHERE org='Queued Example'"
        ).fetchone())
        connection.close()

    def test_secondary_review_can_publish_multiple_incidents_from_one_article(self):
        connection = app.db()
        candidate = {
            "title": "複数組織への不正アクセスが判明",
            "url": "https://news.example.jp/multiple",
            "summary": "AlphaとBetaが被害を公表しました。",
            "published": "2026-10-18T00:00:00+00:00",
        }
        app.queue_for_review(connection, "Example News", "queued-multiple", candidate)
        connection.commit()
        connection.close()
        findings = [
            {"org": "Alpha", "kind": "data leak", "records": 10,
             "incident_date": app.calendar_date_iso(2026, 10, 17), "date_basis": "incident",
             "is_followup": False},
            {"org": "Beta", "kind": "unauthorized access", "records": None,
             "incident_date": app.calendar_date_iso(2026, 10, 18), "date_basis": "incident",
             "is_followup": True},  # follow-up newly identifies Beta as another victim
        ]
        evidence = [{"url": "https://other.example.jp/report", "source": "Other News", "title": "Report"}]
        with patch.object(app, "llm_extract_many", return_value=findings):
            result = app.review_pending(
                fetch_body_fn=lambda _: "article body", corroborate_fn=lambda *_: evidence
            )
        self.assertEqual(result, {"total": 1, "confirmed": 1, "rejected": 0, "deferred": 0})
        connection = app.db()
        promoted = app.promote_reviewed(connection)
        self.assertEqual(len(promoted), 2)
        self.assertEqual(
            {row[0] for row in connection.execute("SELECT org FROM incidents WHERE org IN ('Alpha','Beta')")},
            {"Alpha", "Beta"},
        )
        connection.close()

    def test_uncorroborated_secondary_finding_stays_unpublished(self):
        connection = app.db()
        candidate = {
            "title": "Exampleへの不正アクセス", "url": "https://news.example.jp/uncorroborated",
            "summary": "", "published": "2026-10-18T00:00:00+00:00",
        }
        app.queue_for_review(connection, "Example News", "queued-uncorroborated", candidate)
        connection.commit()
        connection.close()
        findings = [{
            "org": "Only One Source", "kind": "unauthorized access", "records": None,
            "incident_date": app.calendar_date_iso(2026, 10, 18), "date_basis": "incident",
            "is_followup": False,
        }]
        with patch.object(app, "llm_extract_many", return_value=findings):
            result = app.review_pending(
                fetch_body_fn=lambda _: "article body", corroborate_fn=lambda *_: []
            )
        self.assertEqual(result, {"total": 1, "confirmed": 0, "rejected": 0, "deferred": 1})

    def test_unmatched_followup_is_not_inserted_as_new_incident(self):
        connection = app.db()
        record = {
            "title": "既報インシデントの対応方針", "url": "https://example.jp/followup",
            "summary": "", "published": app.calendar_date_iso(2026, 10, 18),
        }
        classification = {
            "org": "Unlisted Example", "kind": "data leak", "records": 10,
            "incident_date": record["published"], "date_basis": "incident", "is_followup": True,
        }
        self.assertFalse(app.store(connection, "News", record, classification))
        self.assertIsNone(connection.execute(
            "SELECT id FROM incidents WHERE org='Unlisted Example'"
        ).fetchone())
        connection.close()

    def test_ai_validated_followup_can_add_newly_identified_victim(self):
        connection = app.db()
        record = {
            "title": "複数被害組織に関する調査結果（第2報）",
            "url": "https://example.jp/followup-new-victim", "summary": "",
            "published": app.calendar_date_iso(2026, 10, 18),
        }
        classification = {
            "org": "Newly Identified Victim", "kind": "data leak", "records": 10,
            "incident_date": record["published"], "date_basis": "incident",
            "is_followup": True, "secondary_validated": True,
        }
        self.assertTrue(app.store(connection, "News", record, classification))
        self.assertIsNotNone(connection.execute(
            "SELECT id FROM incidents WHERE org='Newly Identified Victim'"
        ).fetchone())
        connection.close()

    def test_followup_for_same_victim_and_incident_only_adds_reference(self):
        connection = app.db()
        incident_date = app.calendar_date_iso(2026, 10, 18)
        original = {
            "title": "Followup Exampleへの不正アクセス", "url": "https://example.jp/first",
            "summary": "", "published": incident_date,
        }
        classification = {
            "org": "Followup Example", "kind": "unauthorized access", "records": None,
            "incident_date": incident_date, "date_basis": "incident", "is_followup": False,
        }
        self.assertTrue(app.store(connection, "News", original, classification))
        followup = {
            "title": "Followup Example調査結果（第2報）", "url": "https://example.jp/second",
            "summary": "", "published": incident_date,
        }
        followup_classification = {
            **classification, "kind": "data leak", "records": 25, "is_followup": True,
            "secondary_validated": True,
        }
        self.assertFalse(app.store(connection, "News", followup, followup_classification))
        rows = list(connection.execute(
            "SELECT id,kind,records FROM incidents WHERE org='Followup Example'"
        ))
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["kind"], rows[0]["records"]), ("data leak", 25))
        self.assertEqual(connection.execute(
            "SELECT COUNT(*) FROM refs WHERE incident_id=?", (rows[0]["id"],)
        ).fetchone()[0], 2)
        connection.close()


class MunicipalSourceTests(unittest.TestCase):
    def test_discovers_feed_and_same_site_homepage_items(self):
        homepage = (
            '<html><head><link rel="alternate" type="application/rss+xml" href="/news.xml"></head>'
            '<body><a href="/notice">情報漏えいのお知らせ</a>'
            '<a href="https://outside.example/ignored">不正アクセス</a></body></html>'
        ).encode()
        feed = (
            "<rss><channel><item><title>不正アクセスについて</title>"
            "<link>https://example.jp/feed-item</link></item></channel></rss>"
        ).encode()

        def fetcher(url):
            return homepage if url == "https://example.jp/" else feed

        items = app.load_items(
            {"name": "Example city", "type": "municipal", "url": "https://example.jp/"}, fetcher
        )
        self.assertEqual({item["url"] for item in items}, {
            "https://example.jp/feed-item", "https://example.jp/notice"
        })

    def test_health_and_environment_titles_are_noise(self):
        source = {"name": "Official", "type": "municipal", "url": "https://example.jp/"}
        for title in (
            "インフルエンザウイルス感染症", "ワクチン予防接種", "アスベストの漏えい",
            "船舶からの重油流出", "スポンサー契約のお知らせ",
        ):
            record = {"title": title, "summary": "", "url": "https://example.jp/a"}
            self.assertFalse(app.gate(record, source), title)

    def test_image_and_gallery_pages_are_not_incident_sources(self):
        source = {"name": "News"}
        for url in (
            "https://news.yahoo.co.jp/articles/example/images/000",
            "https://example.jp/news/gallery/incident",
        ):
            record = {"title": "不正アクセスで情報漏えい", "summary": "", "url": url}
            self.assertFalse(app.gate(record, source))

    def test_verified_municipal_domains_are_government_tier(self):
        self.assertEqual(app.ref_tier("https://www.city.kumamoto.jp/example"), "gov")
        self.assertEqual(app.ref_tier("https://www.city.shibuya.tokyo.jp/example"), "gov")
        self.assertEqual(len(app.MUNICIPAL_SOURCES), 44)

    def test_transport_registry_is_official_and_covers_every_mode(self):
        sectors = {source["sector"] for source in app.TRANSPORT_SOURCES}
        self.assertTrue({"rail", "air", "airport", "bus", "ferry", "taxi", "parent"} <= sectors)
        self.assertGreaterEqual(len(app.TRANSPORT_SOURCES), 90)
        self.assertEqual(app.ref_tier("https://www.jreast.co.jp/example"), "official")

    def test_prefectural_national_and_disclosure_registries(self):
        self.assertEqual(len(app.PREFECTURAL_SOURCES), 46)
        self.assertEqual(len(app.NATIONAL_SOURCES), 10)
        self.assertEqual(len(app.DISCLOSURE_SOURCES), 1)
        self.assertEqual(app.ref_tier("https://www.pref.aichi.jp/example"), "gov")
        self.assertEqual(app.ref_tier("https://www.release.tdnet.info/example.pdf"), "official")

    def test_tdnet_reads_incident_disclosures_and_ignores_financial_filings(self):
        main = b'<option value="I_list_001_20261019.html">2026/10/19</option>'
        daily = (
            '<div id="kaiji-date-1">2026年10月19日</div><table>'
            '<tr><td class="kjTime">17:05</td><td class="kjName">Ｇ－Example</td>'
            '<td class="kjTitle"><a href="incident.pdf">不正アクセスに関するご報告</a></td></tr>'
            '<tr><td class="kjTime">16:00</td><td class="kjName">Finance</td>'
            '<td class="kjTitle"><a href="results.pdf">決算短信</a></td></tr></table>'
        ).encode()

        def fetcher(url):
            return main if url.endswith("I_main_00.html") else daily

        items = app.load_items(app.DISCLOSURE_SOURCES[0], fetcher)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["title"], "Example：不正アクセスに関するご報告")
        self.assertTrue(items[0]["url"].endswith("incident.pdf"))

    def test_public_source_directory_matches_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "sources.json")
            self.assertTrue(app.write_public_sources(path))
            self.assertFalse(app.write_public_sources(path))
            with open(path, encoding="utf-8") as source:
                document = json.load(source)
        self.assertEqual(document["total"], len(app.SOURCES))
        self.assertEqual(document["groups"]["prefecture"], 46)
        self.assertEqual(document["groups"]["transport"], len(app.TRANSPORT_SOURCES))

    def test_readme_lists_every_public_source(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        sources = app.public_sources()
        self.assertIn(f"**{len(sources)} configured sources**", readme)
        for source in sources:
            self.assertIn(f"[{source['name']}]({source['url']})", readme)

    def test_incident_date_not_page_update_date_controls_collection_window(self):
        body = (
            "更新日 2025年12月25日 株式会社TOKAIのサービスが不正なアクセスを受け、"
            "情報が漏えいした可能性があることが12月19日に公表されました。"
        )
        page_date = app.source_page_date(body)
        self.assertEqual(page_date, app.calendar_date_iso(2025, 12, 25))
        self.assertEqual(
            app.heuristic_incident_date(body, page_date),
            app.calendar_date_iso(2025, 12, 19),
        )
        self.assertFalse(app.within_collection_window(
            app.calendar_date_iso(2025, 12, 19), "2026-10-19T09:52:02+00:00"
        ))

    def test_classification_uses_ai_incident_date_and_rejects_stale_item(self):
        record = {
            "title": "不正アクセスによる情報漏えいについて",
            "summary": "個人情報が漏えいした可能性があります。",
            "url": "https://example.jp/incident",
            "published": "2026-10-19T00:00:00+00:00",
        }
        extracted = {
            "is_incident": True, "org": "Example", "kind": "data leak", "records": None,
            "incident_date": app.calendar_date_iso(2025, 12, 19),
        }
        with patch.object(app, "llm_extract", return_value=extracted):
            result = app.classify(
                record, {"name": "Official"}, fetch_body_fn=lambda _: "",
                observed_at="2026-10-19T09:52:02+00:00",
            )
        self.assertIsNone(result)

    def test_classification_persists_current_incident_date(self):
        record = {
            "title": "不正アクセスによる情報漏えいについて",
            "summary": "個人情報が漏えいした可能性があります。",
            "url": "https://example.jp/incident",
            "published": "2026-10-19T00:00:00+00:00",
        }
        incident_date = app.calendar_date_iso(2026, 10, 15)
        extracted = {
            "is_incident": True, "org": "Example", "kind": "data leak", "records": 10,
            "incident_date": incident_date,
        }
        with patch.object(app, "llm_extract", return_value=extracted):
            result = app.classify(
                record, {"name": "Official"}, fetch_body_fn=lambda _: "",
                observed_at="2026-10-19T09:52:02+00:00",
            )
        self.assertEqual(result["incident_date"], incident_date)
        self.assertEqual(record["published"], incident_date)

    def test_strict_ai_review_bypasses_keyword_gate(self):
        record = {
            "title": "Official announcement: Example",
            "summary": "",
            "url": "https://example.jp/notice",
            "published": "2026-10-18T00:00:00+00:00",
        }
        extracted = {
            "is_incident": True, "org": "Example", "kind": "unauthorized access", "records": None,
            "incident_date": app.calendar_date_iso(2026, 10, 17),
        }
        self.assertFalse(app.gate(record, {"name": "Official"}))
        with patch.object(app, "llm_extract", return_value=extracted):
            result = app.classify(
                record, {"name": "Official"}, fetch_body_fn=lambda _: "",
                observed_at="2026-10-19T09:52:02+00:00", require_ai=True,
            )
        self.assertEqual(result["org"], "Example")

    def test_strict_ai_review_rejects_undecided(self):
        record = {
            "title": "不正アクセスによる情報漏えいについて",
            "summary": "",
            "url": "https://example.jp/notice",
            "published": "2026-10-18T00:00:00+00:00",
        }
        with patch.object(app, "llm_extract", return_value=None):
            result = app.classify(
                record, {"name": "Official"}, fetch_body_fn=lambda _: "",
                observed_at="2026-10-19T09:52:02+00:00", require_ai=True,
            )
        self.assertIsNone(result)

    def test_strict_ai_review_rejects_bodyless_followup(self):
        record = {
            "title": "個人情報流出で怒りの声、免許証再交付の特例措置",
            "summary": "",
            "url": "https://news.example.jp/followup",
            "published": "2026-10-18T00:00:00+00:00",
        }
        extracted = {
            "is_incident": True, "org": "Example", "kind": "data leak", "records": 10,
            "incident_date": app.calendar_date_iso(2026, 10, 18),
        }
        with patch.object(app, "llm_extract", return_value=extracted) as llm:
            result = app.classify(
                record, {"name": "News"}, fetch_body_fn=lambda _: "",
                observed_at="2026-10-19T09:52:02+00:00", require_ai=True,
            )
        self.assertIsNone(result)
        llm.assert_not_called()

    def test_headline_phrase_is_not_a_plausible_organization(self):
        self.assertFalse(app.plausible_org("お客様情報の外部流出に関するお詫びとお知らせ（第2報）"))
        self.assertFalse(app.plausible_org("Studio株式会社で発生した不正アクセス"))
        self.assertFalse(app.plausible_org("産婦人科など利用のシステム"))
        self.assertTrue(app.plausible_org("IMADEYA"))


class SourceRecoveryAlertTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = {"name": "Known blocked source", "url": "https://blocked.example/news"}
        self.other = {"name": "Other source", "url": "https://other.example/news"}
        patches = [
            patch.object(app, "DB_PATH", os.path.join(self.temp.name, "test.db")),
            patch.dict(os.environ, {"JPI_EXPECTED_403_SOURCES": self.source["url"]}),
            patch.object(app, "promote_reviewed", return_value=[]),
            patch.object(app, "gate", return_value=False),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def error(self, code=403):
        return urllib.error.HTTPError(self.source["url"], code, "test error", {}, None)

    def run_poll(self, results, sources=None):
        with patch.object(app, "load_sources", return_value=sources or [self.source]), \
                patch.object(app, "load_items", side_effect=results):
            app.poll()

    def test_known_403_is_logged_but_not_alerted(self):
        with patch.object(app, "send_local_alert") as alert:
            self.run_poll([self.error()])
        alert.assert_not_called()
        with sqlite3.connect(app.DB_PATH) as connection:
            self.assertIn("403", connection.execute("SELECT error FROM runs").fetchone()[0])
            self.assertEqual(connection.execute("SELECT blocked FROM source_alert_state").fetchone()[0], 1)

    def test_other_errors_and_unconfigured_403_still_alert(self):
        with patch.object(app, "send_local_alert") as alert:
            self.run_poll([self.error(), self.error()], [self.source, self.other])
            self.assertEqual(alert.call_args.args[0], "source-errors")
            self.assertIn("Other source", alert.call_args.args[2])
            self.assertNotIn("Known blocked source", alert.call_args.args[2])
            alert.reset_mock()
            self.run_poll([self.error(500)])
            self.assertIn("Known blocked source", alert.call_args.args[2])
            self.assertIn("500", alert.call_args.args[2])

    def test_recovery_persists_and_rearms_after_new_block(self):
        items = [{"url": "https://blocked.example/article", "title": "不正アクセスに関するお知らせ", "summary": ""}]
        with patch.object(app, "send_local_alert", return_value=True) as alert:
            self.run_poll([self.error()])
            self.run_poll([items])
            self.run_poll([items])  # separate connection/process-equivalent poll
            self.assertEqual(alert.call_count, 1)
            self.assertEqual(alert.call_args.args[1], "Source access restored")
            self.assertEqual(alert.call_args.kwargs["severity"], "info")
            self.run_poll([self.error()])
            self.run_poll([items])
            self.assertEqual(alert.call_count, 2)

    def test_initial_recovery_retries_failed_delivery(self):
        items = [{"url": "https://blocked.example/article", "title": "不正アクセスに関するお知らせ", "summary": ""}]
        with patch.object(app, "send_local_alert", side_effect=[False, True]) as alert:
            self.run_poll([items])  # configuration already declares the known block
            self.run_poll([items])
            self.run_poll([items])
            self.assertEqual(alert.call_count, 2)

    def test_empty_or_failed_poll_does_not_claim_recovery(self):
        with patch.object(app, "send_local_alert", return_value=True) as alert:
            self.run_poll([self.error()])
            self.run_poll([[]])
            alert.assert_not_called()
            self.run_poll([TimeoutError("source unavailable")])
            self.assertEqual(alert.call_count, 1)
            self.assertEqual(alert.call_args.args[0], "source-errors")


class OrganizationSourceTests(unittest.TestCase):
    def test_html_redirect_resolves_articles_against_new_index(self):
        source = {"name": "Example", "type": "official", "url": "https://example.jp/news/"}
        for redirect in (
            b'<meta content="0;URL=2027/" http-equiv="refresh">',
            b'<script>window.location.href = "2027/";</script>',
        ):
            pages = {source["url"]: redirect,
                     source["url"] + "2027/": '<a href="notice.html">不正アクセスについて</a>'.encode()}
            items = app.load_items(source, pages.__getitem__)
            self.assertEqual(items[0]["url"], source["url"] + "2027/notice.html")
            self.assertEqual(source["url"], "https://example.jp/news/")

    def test_html_redirect_refuses_offsite_and_stops_loops(self):
        source = {"name": "Example", "type": "official", "url": "https://example.jp/news/"}
        for target in (source["url"], "https://other.example/news/"):
            calls = []

            def fetcher(url):
                calls.append(url)
                return f'<meta http-equiv="refresh" content="0;URL={target}">'.encode()

            self.assertEqual(app.load_items(source, fetcher), [])
            self.assertEqual(calls, [source["url"]])

    def test_json_news_reads_both_years_and_filters_invalid_links(self):
        source = {"name": "Example", "type": "json_news", "url": "https://example.jp/news/",
                  "feed_url": "https://example.jp/data/{year}.json"}
        calls = []

        def fetcher(url):
            calls.append(url)
            return json.dumps([
                {"title": "不正アクセス", "date": "2026-12-30", "url": "/notice.html", "subtitle": None},
                {"title": "Invalid", "url": "javascript:alert(1)"}, {"title": "Missing URL"}, None,
            ]).encode()

        with patch.object(app, "datetime", wraps=datetime) as clock:
            clock.now.return_value = datetime(2027, 1, 3)
            items = app.load_items(source, fetcher)
        self.assertEqual(calls, ["https://example.jp/data/2027.json", "https://example.jp/data/2026.json"])
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["url"], "https://example.jp/notice.html")
        self.assertEqual(app._incident_day(items[0]["published"]), "2026-12-30")
        self.assertEqual(items[0]["summary"], "")

    def test_json_news_new_year_404_falls_back_but_other_errors_surface(self):
        source = {"name": "Example", "type": "json_news", "url": "https://example.jp/",
                  "feed_url": "https://example.jp/{year}.json"}
        def fetcher(url):
            if "2027" in url:
                raise urllib.error.HTTPError(url, 404, "Not found", {}, None)
            return b'[]'
        with patch.object(app, "datetime", wraps=datetime) as clock:
            clock.now.return_value = datetime(2027, 1, 3)
            self.assertEqual(app.load_items(source, fetcher), [])
            clock.now.return_value = datetime(2027, 6, 3)
            with self.assertRaises(urllib.error.HTTPError):
                app.load_items(source, fetcher)

    def test_monthly_json_news_flattens_and_normalizes_dates(self):
        source = {"name": "Carrier", "type": "json_news", "url": "https://example.jp/news/",
                  "feed_url": "https://example.jp/{year}.json", "json_layout": "monthly"}
        raw = json.dumps({"data": [{"list": [
            {"title": "Notice", "url": "/notice/", "date": "20261019"}
        ]}]}).encode()
        with patch.object(app, "datetime", wraps=datetime) as clock:
            clock.now.return_value = datetime(2026, 10, 19)
            items = app.load_items(source, lambda _: raw)
        self.assertEqual(len(items), 1)
        self.assertEqual(app._incident_day(items[0]["published"]), "2026-10-19")
        self.assertEqual(items[0]["url"], "https://example.jp/notice/")

    def test_added_domains_are_official_without_trusting_lookalikes(self):
        for host in ("www.iij.ad.jp", "www.nri.com", "notices.jcom.co.jp", "www.jcho.go.jp"):
            self.assertEqual(app.ref_tier(f"https://{host}/example"), "official")
        self.assertEqual(app.ref_tier("https://www.iij.ad.jp.attacker.example/example"), "other")
        urls = [s["url"] for s in app.SOURCES]
        self.assertEqual(len(urls), len(set(urls)))


if __name__ == "__main__":
    unittest.main()
