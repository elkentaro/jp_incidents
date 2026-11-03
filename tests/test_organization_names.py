import unittest

import jp_incidents as app


class OrganizationNameTests(unittest.TestCase):
    def test_news_can_be_part_of_an_organization_name(self):
        for name in (
            "スマートニュース",
            "スマートニュース　",
            "スマートニュース株式会社（SmartNews, Inc.）",
            "SmartNews, Inc.",
            "株式会社ニューステクノロジー",
            "ニュースキンジャパン株式会社",
        ):
            with self.subTest(name=name):
                self.assertTrue(app.plausible_org(name))

    def test_generic_news_labels_and_incident_headlines_remain_invalid(self):
        for name in (
            "ニュース", "最新ニュース", "ニュース速報", "ニュース記事",
            "大手スーパー", "産婦人科など利用のシステム", "　",
            "スマートニュースにまた不正アクセス、10日で2度目",
            "スマートニュース株式会社のお知らせ",
            "お客様情報の外部流出に関するお詫びとお知らせ（第2報）",
        ):
            with self.subTest(name=name):
                self.assertFalse(app.plausible_org(name))


if __name__ == '__main__':
    unittest.main()
