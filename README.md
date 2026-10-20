# JP Incident Monitor

A Python collector and static, bilingual dashboard for publicly reported cybersecurity incidents affecting organizations in Japan.

The collector stores normalized incidents in SQLite, polls its sources hourly on the host machine, and writes the complete public dataset to `data/incidents.json` and `feed.xml`. The GitHub Pages site reads the JSON in the browser and paginates it at 100 records per page; feed readers can subscribe to the full-history RSS feed.

## Coverage and confidence

The collector keeps any relevant Japanese incident it finds, regardless of organization size. Its source mix includes broad Japanese/English news searches, security publications, incident aggregators, JPCERT/CC, global outlets filtered for Japan, and direct official-site layers.

The government layer covers:

- Tokyo Metropolitan Government
- All 23 Tokyo special wards
- All 20 ordinance-designated cities
- All 47 prefectural governments
- National privacy, cyber, financial, communications, industry, health, education, digital, police, and research authorities

The transport layer polls 92 major official operator and group sites across rail, subway, airlines, airports, buses, ferries, taxis, and their distinct parent companies. Broad news monitoring supplies additional coverage for public companies and named subsidiaries; subsidiary incidents remain listed under the organization reported by the source.

Listed-company coverage includes the Japan Exchange Group's public TDnet viewer, checked across its latest 14 days of disclosures. A targeted PR TIMES search adds company-issued releases that may not yet have received editorial coverage. The published [source directory](https://elkentaro.github.io/jp_incidents/sources.html) is generated from the same registry used by the hourly poller.

Direct organization coverage also includes banks, insurers, securities and payment providers, universities, individual hospitals and hospital networks, energy and water utilities, manufacturers, pharmaceutical companies, and wholesale suppliers. These are selected sources rather than an exhaustive organization census.

For official sites, the collector discovers advertised RSS/Atom feeds and scans current same-site links. Health and environmental uses of terms such as “virus infection” and “leak” are excluded before analysis.

Confidence is based on source authority and independent corroboration: direct official/government disclosures score highly, while single aggregators and social sources score lower. It is a guide to the reliability of the collected record, not incident severity. The dashboard can sort every column—including confidence—across the complete dataset before applying its 100-row pagination.

The displayed date is the incident's occurrence, discovery, or first-disclosure date—not a webpage's later update date. New candidates must fall within the collector's 14-day intake window when first discovered. An older incident may enter when AI review supplies a recent first-disclosure date backed by an exact, dated quote in the source. Its original incident date is retained, and the separate disclosure date is shown underneath it. If a report states no incident date, its source publication date is used as a fallback. Once a valid incident is collected it remains in the all-history dataset as it ages.

One database row represents one affected organization and underlying incident, not one article. Follow-up reports, second notices, reactions, remediation, recovery, and impact stories add sources or facts when that organization/incident is already listed. A follow-up may also reveal a previously unidentified victim organization; after secondary AI evaluation confirms the victim, original incident date, relevance, and source corroboration, that organization can receive its own row. A follow-up remains unpublished when its original incident date is unknown, and an underlying incident must meet the incident-date or verified first-disclosure intake rule. A recent follow-up or recovery announcement alone does not qualify.

## Related incident records

Each affected organization has its own incident record. For a supplier breach,
affected municipalities or customers can be linked to the directly breached
provider without implying that their own infrastructure was compromised.
Separate incidents affecting the same organization remain separate records.

The directory displays **Related 1**, **Related 2**, and so on (関連 1, 関連 2
in Japanese). These links open the specific record, including across pages or
active filters. Hover or focus a link to see the relationship description.
Numbers are local to each row; stable incident IDs identify the destinations.

The JSON includes an additive `related` array on each record. Each entry has
`incident_id`, `relationship`, and `evidence_url`. `affected_by` points to the
provider incident; its reciprocal is `affects`. `same_organization` connects
verified separate incidents at one organization. Names are not relationship
keys, and matching names alone do not create links. Withdrawn records and their
links are omitted from public output.

After verifying the public evidence, link existing records with:

```bash
python3 jp_incidents.py link AFFECTED_ID PROVIDER_ID --relationship affected_by --evidence-url https://example.org/notice
python3 jp_incidents.py link INCIDENT_ID EARLIER_INCIDENT_ID --relationship same_organization --evidence-url https://example.org/notice
python3 jp_incidents.py link AFFECTED_ID PROVIDER_ID --relationship affected_by --remove
```

Changes appear on the next publication. Relationship source URLs are public;
keep private review notes out of them.

<!-- source-registry:begin -->
## Complete source registry

The collector currently polls **365 configured sources**. This list is generated from [`data/sources.json`](data/sources.json); run `python3 scripts/update_readme_sources.py` after changing the registry.

<details>
<summary><strong>News, search, and specialist publications (20)</strong></summary>

- [GNews 不正アクセス](https://news.google.com/rss/search?q=%E4%B8%8D%E6%AD%A3%E3%82%A2%E3%82%AF%E3%82%BB%E3%82%B9%20when%3A7d&hl=ja&gl=JP&ceid=JP:ja)
- [GNews 情報漏えい](https://news.google.com/rss/search?q=%E6%83%85%E5%A0%B1%E6%BC%8F%E3%81%88%E3%81%84%20OR%20%E6%83%85%E5%A0%B1%E6%BC%8F%E6%B4%A9%20when%3A7d&hl=ja&gl=JP&ceid=JP:ja)
- [GNews 個人情報 流出](https://news.google.com/rss/search?q=%E5%80%8B%E4%BA%BA%E6%83%85%E5%A0%B1%20%E6%B5%81%E5%87%BA%20when%3A7d&hl=ja&gl=JP&ceid=JP:ja)
- [GNews ランサムウェア](https://news.google.com/rss/search?q=%E3%83%A9%E3%83%B3%E3%82%B5%E3%83%A0%E3%82%A6%E3%82%A7%E3%82%A2%20%E8%A2%AB%E5%AE%B3%20when%3A7d&hl=ja&gl=JP&ceid=JP:ja)
- [GNews サイバー攻撃](https://news.google.com/rss/search?q=%E3%82%B5%E3%82%A4%E3%83%90%E3%83%BC%E6%94%BB%E6%92%83%20%E8%A2%AB%E5%AE%B3%20when%3A7d&hl=ja&gl=JP&ceid=JP:ja)
- [GNews お詫び 漏えい](https://news.google.com/rss/search?q=%E3%81%8A%E8%A9%AB%E3%81%B3%20%E6%BC%8F%E3%81%88%E3%81%84%20OR%20%E3%81%8A%E7%9F%A5%E3%82%89%E3%81%9B%20%E4%B8%8D%E6%AD%A3%E3%82%A2%E3%82%AF%E3%82%BB%E3%82%B9%20when%3A7d&hl=ja&gl=JP&ceid=JP:ja)
- [GNews Japan breach](https://news.google.com/rss/search?q=Japan%20data%20breach%20OR%20Japan%20ransomware%20when%3A7d&hl=ja&gl=JP&ceid=JP:ja)
- [GNews PR TIMES disclosures](https://news.google.com/rss/search?q=site%3Aprtimes.jp%20%28%E4%B8%8D%E6%AD%A3%E3%82%A2%E3%82%AF%E3%82%BB%E3%82%B9%20OR%20%E6%83%85%E5%A0%B1%E6%BC%8F%E3%81%88%E3%81%84%20OR%20%E6%83%85%E5%A0%B1%E6%BC%8F%E6%B4%A9%20OR%20%E3%83%A9%E3%83%B3%E3%82%B5%E3%83%A0%E3%82%A6%E3%82%A7%E3%82%A2%20OR%20%E3%82%B5%E3%82%A4%E3%83%90%E3%83%BC%E6%94%BB%E6%92%83%29%20when%3A14d&hl=ja&gl=JP&ceid=JP:ja)
- [Bing 不正アクセス](https://www.bing.com/news/search?q=%E4%B8%8D%E6%AD%A3%E3%82%A2%E3%82%AF%E3%82%BB%E3%82%B9&format=rss&setlang=ja&cc=jp)
- [Bing 情報漏えい](https://www.bing.com/news/search?q=%E6%83%85%E5%A0%B1%E6%BC%8F%E3%81%88%E3%81%84&format=rss&setlang=ja&cc=jp)
- [Security NEXT](https://www.security-next.com/feed)
- [ScanNetSecurity](https://scan.netsecurity.ne.jp/rss/index.rdf)
- [Cybersecurity.jp](https://cybersecurity-jp.com/feed)
- [piyolog](https://piyolog.hatenadiary.jp/rss)
- [JPCERT/CC](https://www.jpcert.or.jp/rss/jpcert.rdf)
- [Westeria list](https://westeria.jp/security-incidents/2026/)
- [legalagent list](https://legalagent.co.jp/en/legal-lab/security-incidents/)
- [satimo list](https://satimo.org/2026/10/data-breach-list-2026/)
- [BleepingComputer](https://www.bleepingcomputer.com/feed/)
- [The Record](https://therecord.media/feed)

</details>

<details>
<summary><strong>Listed-company disclosures (1)</strong></summary>

- [日本取引所グループ TDnet / JPX TDnet](https://www.release.tdnet.info/inbs/I_main_00.html)

</details>

<details>
<summary><strong>National authorities (10)</strong></summary>

- [個人情報保護委員会 / PPC](https://www.ppc.go.jp/news/press/)
- [国家サイバー統括室 / NCO](https://www.cyber.go.jp/news/)
- [金融庁 / Financial Services Agency](https://www.fsa.go.jp/news/)
- [総務省 / Ministry of Internal Affairs and Communications](https://www.soumu.go.jp/menu_news/s-news/)
- [経済産業省 / Ministry of Economy, Trade and Industry](https://www.meti.go.jp/press/)
- [厚生労働省 / Ministry of Health, Labour and Welfare](https://www.mhlw.go.jp/stf/houdou/index.html)
- [文部科学省 / Ministry of Education, Culture, Sports, Science and Technology](https://www.mext.go.jp/b_menu/houdou/index.htm)
- [デジタル庁 / Digital Agency](https://www.digital.go.jp/news)
- [警察庁サイバー警察局 / National Police Agency Cyber Bureau](https://www.npa.go.jp/bureau/cyber/)
- [情報通信研究機構 / NICT](https://www.nict.go.jp/press/)

</details>

<details>
<summary><strong>Prefectural governments (46)</strong></summary>

- [北海道 / Hokkaido](https://www.pref.hokkaido.lg.jp/)
- [青森県 / Aomori](https://www.pref.aomori.lg.jp/)
- [岩手県 / Iwate](https://www.pref.iwate.jp/)
- [宮城県 / Miyagi](https://www.pref.miyagi.jp/)
- [秋田県 / Akita](https://www.pref.akita.lg.jp/)
- [山形県 / Yamagata](https://www.pref.yamagata.jp/)
- [福島県 / Fukushima](https://www.pref.fukushima.lg.jp/)
- [茨城県 / Ibaraki](https://www.pref.ibaraki.jp/)
- [栃木県 / Tochigi](https://www.pref.tochigi.lg.jp/)
- [群馬県 / Gunma](https://www.pref.gunma.jp/)
- [埼玉県 / Saitama](https://www.pref.saitama.lg.jp/)
- [千葉県 / Chiba](https://www.pref.chiba.lg.jp/)
- [神奈川県 / Kanagawa](https://www.pref.kanagawa.jp/)
- [新潟県 / Niigata](https://www.pref.niigata.lg.jp/)
- [富山県 / Toyama](https://www.pref.toyama.jp/)
- [石川県 / Ishikawa](https://www.pref.ishikawa.lg.jp/)
- [福井県 / Fukui](https://www.pref.fukui.lg.jp/)
- [山梨県 / Yamanashi](https://www.pref.yamanashi.jp/)
- [長野県 / Nagano](https://www.pref.nagano.lg.jp/)
- [岐阜県 / Gifu](https://www.pref.gifu.lg.jp/)
- [静岡県 / Shizuoka](https://www.pref.shizuoka.jp/)
- [愛知県 / Aichi](https://www.pref.aichi.jp/rss/10/list7.xml)
- [三重県 / Mie](https://www.pref.mie.lg.jp/)
- [滋賀県 / Shiga](https://www.pref.shiga.lg.jp/)
- [京都府 / Kyoto](https://www.pref.kyoto.jp/)
- [大阪府 / Osaka](https://www.pref.osaka.lg.jp/)
- [兵庫県 / Hyogo](https://web.pref.hyogo.lg.jp/)
- [奈良県 / Nara](https://www.pref.nara.lg.jp/)
- [和歌山県 / Wakayama](https://www.pref.wakayama.lg.jp/)
- [鳥取県 / Tottori](https://www.pref.tottori.lg.jp/)
- [島根県 / Shimane](https://www.pref.shimane.lg.jp/)
- [岡山県 / Okayama](https://www.pref.okayama.jp/)
- [広島県 / Hiroshima](https://www.pref.hiroshima.lg.jp/)
- [山口県 / Yamaguchi](https://www.pref.yamaguchi.lg.jp/)
- [徳島県 / Tokushima](https://www.pref.tokushima.lg.jp/)
- [香川県 / Kagawa](https://www.pref.kagawa.lg.jp/)
- [愛媛県 / Ehime](https://www.pref.ehime.jp/)
- [高知県 / Kochi](https://www.pref.kochi.lg.jp/)
- [福岡県 / Fukuoka](https://www.pref.fukuoka.lg.jp/)
- [佐賀県 / Saga](https://www.pref.saga.lg.jp/)
- [長崎県 / Nagasaki](https://www.pref.nagasaki.jp/)
- [熊本県 / Kumamoto](https://www.pref.kumamoto.jp/)
- [大分県 / Oita](https://www.pref.oita.jp/)
- [宮崎県 / Miyazaki](https://www.pref.miyazaki.lg.jp/)
- [鹿児島県 / Kagoshima](https://www.pref.kagoshima.jp/)
- [沖縄県 / Okinawa](https://www.pref.okinawa.jp/)

</details>

<details>
<summary><strong>Tokyo, special wards, and ordinance-designated cities (44)</strong></summary>

- [東京都 / Tokyo Metropolitan Government](https://www.metro.tokyo.lg.jp/)
- [千代田区 / Chiyoda](https://www.city.chiyoda.lg.jp/)
- [中央区 / Chuo](https://www.city.chuo.lg.jp/)
- [港区 / Minato](https://www.city.minato.tokyo.jp/)
- [新宿区 / Shinjuku](https://www.city.shinjuku.lg.jp/)
- [文京区 / Bunkyo](https://www.city.bunkyo.lg.jp/)
- [台東区 / Taito](https://www.city.taito.lg.jp/)
- [墨田区 / Sumida](https://www.city.sumida.lg.jp/)
- [江東区 / Koto](https://www.city.koto.lg.jp/)
- [品川区 / Shinagawa](https://www.city.shinagawa.tokyo.jp/)
- [目黒区 / Meguro](https://www.city.meguro.tokyo.jp/)
- [大田区 / Ota](https://www.city.ota.tokyo.jp/)
- [世田谷区 / Setagaya](https://www.city.setagaya.lg.jp/)
- [渋谷区 / Shibuya](https://www.city.shibuya.tokyo.jp/)
- [中野区 / Nakano](https://www.city.tokyo-nakano.lg.jp/)
- [杉並区 / Suginami](https://www.city.suginami.tokyo.jp/)
- [豊島区 / Toshima](https://www.city.toshima.lg.jp/)
- [北区 / Kita](https://www.city.kita.lg.jp/)
- [荒川区 / Arakawa](https://www.city.arakawa.tokyo.jp/)
- [板橋区 / Itabashi](https://www.city.itabashi.tokyo.jp/)
- [練馬区 / Nerima](https://www.city.nerima.tokyo.jp/)
- [足立区 / Adachi](https://www.city.adachi.tokyo.jp/)
- [葛飾区 / Katsushika](https://www.city.katsushika.lg.jp/)
- [江戸川区 / Edogawa](https://www.city.edogawa.tokyo.jp/)
- [札幌市 / Sapporo](https://www.city.sapporo.jp/)
- [仙台市 / Sendai](https://www.city.sendai.jp/)
- [さいたま市 / Saitama](https://www.city.saitama.lg.jp/)
- [千葉市 / Chiba](https://www.city.chiba.jp/)
- [横浜市 / Yokohama](https://www.city.yokohama.lg.jp/)
- [川崎市 / Kawasaki](https://www.city.kawasaki.jp/)
- [相模原市 / Sagamihara](https://www.city.sagamihara.kanagawa.jp/)
- [新潟市 / Niigata](https://www.city.niigata.lg.jp/)
- [静岡市 / Shizuoka](https://www.city.shizuoka.lg.jp/)
- [浜松市 / Hamamatsu](https://www.city.hamamatsu.shizuoka.jp/)
- [名古屋市 / Nagoya](https://www.city.nagoya.jp/)
- [京都市 / Kyoto](https://www.city.kyoto.lg.jp/)
- [大阪市 / Osaka](https://www.city.osaka.lg.jp/)
- [堺市 / Sakai](https://www.city.sakai.lg.jp/)
- [神戸市 / Kobe](https://www.city.kobe.lg.jp/)
- [岡山市 / Okayama](https://www.city.okayama.jp/)
- [広島市 / Hiroshima](https://www.city.hiroshima.lg.jp/)
- [北九州市 / Kitakyushu](https://www.city.kitakyushu.lg.jp/)
- [福岡市 / Fukuoka](https://www.city.fukuoka.lg.jp/)
- [熊本市 / Kumamoto](https://www.city.kumamoto.jp/)

</details>

<details>
<summary><strong>Transport operators and parent companies (92)</strong></summary>

#### Rail and subway (35)

- [JR北海道 / JR Hokkaido](https://www.jrhokkaido.co.jp/)
- [JR東日本 / JR East](https://www.jreast.co.jp/)
- [JR東海 / JR Central](https://jr-central.co.jp/)
- [JR西日本 / JR West](https://www.westjr.co.jp/)
- [JR四国 / JR Shikoku](https://www.jr-shikoku.co.jp/)
- [JR九州 / JR Kyushu](https://www.jrkyushu.co.jp/)
- [JR貨物 / JR Freight](https://www.jrfreight.co.jp/)
- [東武鉄道 / Tobu Railway](https://www.tobu.co.jp/)
- [西武鉄道 / Seibu Railway](https://www.seiburailway.jp/)
- [京成電鉄 / Keisei Electric Railway](https://www.keisei.co.jp/)
- [京王電鉄 / Keio Corporation](https://www.keio.co.jp/)
- [小田急電鉄 / Odakyu Electric Railway](https://www.odakyu.jp/)
- [東急 / Tokyu](https://www.tokyu.co.jp/)
- [京浜急行電鉄 / Keikyu](https://www.keikyu.co.jp/)
- [東京メトロ / Tokyo Metro](https://www.tokyometro.jp/)
- [相鉄グループ / Sotetsu Group](https://www.sotetsu.co.jp/)
- [名古屋鉄道 / Meitetsu](https://www.meitetsu.co.jp/)
- [近畿日本鉄道 / Kintetsu Railway](https://www.kintetsu.co.jp/)
- [南海電気鉄道 / Nankai Electric Railway](https://www.nankai.co.jp/)
- [京阪ホールディングス / Keihan Holdings](https://www.keihan.co.jp/)
- [阪急電鉄 / Hankyu Railway](https://www.hankyu.co.jp/)
- [阪神電気鉄道 / Hanshin Electric Railway](https://www.hanshin.co.jp/)
- [西日本鉄道 / Nishitetsu](https://www.nishitetsu.co.jp/)
- [東京都交通局 / Toei Transportation](https://www.kotsu.metro.tokyo.jp/)
- [Osaka Metro](https://www.osakametro.co.jp/)
- [名古屋市交通局 / Nagoya Transportation Bureau](https://www.kotsu.city.nagoya.jp/)
- [横浜市交通局 / Yokohama Transportation Bureau](https://www.city.yokohama.lg.jp/kotsu/)
- [京都市交通局 / Kyoto Transportation Bureau](https://www.city.kyoto.lg.jp/kotsu/)
- [札幌市交通局 / Sapporo Transportation](https://www.city.sapporo.jp/st/)
- [仙台市交通局 / Sendai Transportation Bureau](https://www.kotsu.city.sendai.jp/)
- [福岡市地下鉄 / Fukuoka City Subway](https://subway.city.fukuoka.lg.jp/)
- [つくばエクスプレス / Tsukuba Express](https://www.mir.co.jp/)
- [東京臨海高速鉄道 / Tokyo Waterfront Area Rapid Transit](https://www.twr.co.jp/)
- [ゆりかもめ / Yurikamome](https://www.yurikamome.co.jp/)
- [東京モノレール / Tokyo Monorail](https://www.tokyo-monorail.co.jp/)

#### Airlines (12)

- [ANAグループ / ANA Group](https://www.ana.co.jp/group/)
- [日本航空 / Japan Airlines](https://www.jal.com/ja/)
- [スカイマーク / Skymark](https://www.skymark.co.jp/)
- [Peach Aviation](https://www.flypeach.com/)
- [ジェットスター・ジャパン / Jetstar Japan](https://www.jetstar.com/jp/ja/home)
- [AIRDO](https://www.airdo.jp/)
- [ソラシドエア / Solaseed Air](https://www.solaseedair.jp/)
- [スターフライヤー / StarFlyer](https://www.starflyer.jp/)
- [フジドリームエアラインズ / Fuji Dream Airlines](https://www.fujidream.co.jp/)
- [ZIPAIR](https://www.corporate.zipair.net/)
- [SPRING JAPAN](https://jp.ch.com/Help/News/1.html)
- [トキエア / Toki Air](https://tokiair.com/)

#### Airports (6)

- [成田国際空港株式会社 / Narita International Airport Corporation](https://www.naa.jp/)
- [日本空港ビルデング / Japan Airport Terminal](https://www.tokyo-airport-bldg.co.jp/)
- [関西エアポート / Kansai Airports](https://www.kansai-airports.co.jp/)
- [中部国際空港 / Central Japan International Airport](https://www.centrair.jp/corporate/newsroom/)
- [北海道エアポート / Hokkaido Airports](https://www.hokkaido-airports.co.jp/)
- [福岡国際空港 / Fukuoka International Airport](https://www.fukuoka-airport.jp/)

#### Bus operators (10)

- [ジェイ・アール北海道バス / JR Hokkaido Bus](https://www.jrhokkaidobus.com/)
- [ジェイアールバス東北 / JR Bus Tohoku](https://www.jrbustohoku.co.jp/)
- [ジェイアールバス関東 / JR Bus Kanto](https://www.jrbuskanto.co.jp/)
- [ジェイアール東海バス / JR Tokai Bus](https://www.jrtbinm.co.jp/)
- [西日本ジェイアールバス / West JR Bus](https://www.nishinihonjrbus.co.jp/)
- [ジェイアール四国バス / JR Shikoku Bus](https://www.jr-shikokubus.co.jp/)
- [JR九州バス / JR Kyushu Bus](https://www.jrkbus.co.jp/)
- [WILLER](https://www.willer.co.jp/)
- [神奈川中央交通 / Kanagawa Chuo Kotsu](https://www.kanachu.co.jp/)
- [国際興業 / Kokusai Kogyo](https://www.kokusaikogyo.co.jp/)

#### Ferry and maritime (13)

- [商船三井さんふらわあ / MOL Sunflower](https://www.sunflower.co.jp/)
- [新日本海フェリー / Shin Nihonkai Ferry](https://www.snf.jp/)
- [阪九フェリー / Hankyu Ferry](https://www.han9f.co.jp/)
- [東京九州フェリー / Tokyo Kyusyu Ferry](https://tqf.co.jp/)
- [名門大洋フェリー / Meimon Taiyo Ferry](https://www.cityline.co.jp/)
- [太平洋フェリー / Taiheiyo Ferry](https://www.taiheiyo-ferry.co.jp/)
- [南海フェリー / Nankai Ferry](https://nankai-ferry.co.jp/)
- [オレンジフェリー / Orange Ferry](https://www.orange-ferry.co.jp/)
- [東海汽船 / Tokai Kisen](https://www.tokaikisen.co.jp/)
- [佐渡汽船 / Sado Kisen](https://www.sadokisen.co.jp/)
- [津軽海峡フェリー / Tsugaru Kaikyo Ferry](https://www.tsugarukaikyo.co.jp/)
- [小笠原海運 / Ogasawara Kaiun](https://www.ogasawarakaiun.co.jp/)
- [オーシャントランス / Ocean Trans](https://www.otf.jp/)

#### Taxi and dispatch (10)

- [日本交通 / Nihon Kotsu](https://www.nihon-kotsu.co.jp/)
- [第一交通産業 / Daiichi Kotsu Sangyo](https://www.daiichi-koutsu.co.jp/)
- [国際自動車 / Kokusai Motorcars](https://www.km-group.co.jp/)
- [MKグループ / MK Group](https://www.mk-group.co.jp/)
- [日の丸交通 / Hinomaru Kotsu](https://hinomaru.tokyo/)
- [東京無線 / Tokyo Musen](https://www.tokyomusen.or.jp/)
- [チェッカーキャブ / Checker Cab](https://www.checker-cab.co.jp/)
- [GO株式会社 / GO Inc.](https://goinc.jp/)
- [S.RIDE](https://www.sride.jp/)
- [つばめタクシーグループ / Tsubame Taxi Group](https://www.tsubame-taxi.or.jp/)

#### Parent and holding companies (6)

- [西武ホールディングス / Seibu Holdings](https://www.seibuholdings.co.jp/)
- [近鉄グループホールディングス / Kintetsu Group Holdings](https://www.kintetsu-g-hd.co.jp/)
- [阪急阪神ホールディングス / Hankyu Hanshin Holdings](https://www.hankyu-hanshin.co.jp/)
- [みちのりホールディングス / Michinori Holdings](https://www.michinori.co.jp/)
- [アルピコグループ / Alpico Group](https://www.alpico.co.jp/)
- [商船三井 / Mitsui O.S.K. Lines](https://www.mol.co.jp/)

</details>

<details>
<summary><strong>IT solution providers and cloud services (17)</strong></summary>

- [NEC](https://jpn.nec.com/press/)
- [日立製作所 / Hitachi](https://www.hitachi.com/ja-jp/press/)
- [日立システムズ / Hitachi Systems](https://www.hitachi-systems.com/news/)
- [日立ソリューションズ / Hitachi Solutions](https://www.hitachi-solutions.co.jp/company/press/)
- [NTTデータ / NTT DATA](https://www.nttdata.com/global/ja/news/)
- [野村総合研究所 / NRI](https://www.nri.com/jp/news/index.html)
- [SCSK](https://www.scsk.jp/news/index.html)
- [TIS](https://www.tis.co.jp/news/)
- [BIPROGY](https://www.biprogy.com/news/)
- [伊藤忠テクノソリューションズ / CTC](https://www.ctc-g.co.jp/company/release/)
- [日鉄ソリューションズ / NSSOL](https://www.nssol.nipponsteel.com/press/atom.xml)
- [大塚商会 / Otsuka Corporation](https://www.otsuka-shokai.co.jp/corporate/release/)
- [オービック / OBIC](https://www.obic.co.jp/pressrelease/)
- [日本IBM / IBM Japan](https://jp.newsroom.ibm.com/)
- [さくらインターネット / Sakura Internet](https://www.sakura.ad.jp/corporate/information/)
- [IDCフロンティア / IDC Frontier](https://www.idcf.jp/news/feed)
- [GMOインターネット / GMO Internet](https://internet.gmo/news/)

</details>

<details>
<summary><strong>Retailers (14)</strong></summary>

- [イオン / AEON](https://www.aeon.info/news/)
- [セブン＆アイ・ホールディングス / Seven & i Holdings](https://www.7andi.com/company/news.html)
- [ローソン / Lawson](https://www.lawson.co.jp/company/news/)
- [ファミリーマート / FamilyMart](https://www.family.co.jp/company/news_releases.html)
- [パン・パシフィック・インターナショナルホールディングス / PPIH](https://ppih.co.jp/news/)
- [ヤマダホールディングス / Yamada Holdings](https://www.yamada-holdings.jp/ir/press.html)
- [ビックカメラ / Bic Camera](https://www.biccamera.co.jp/news/)
- [エディオン / EDION](https://www.edion.co.jp/news-release)
- [ファーストリテイリング / Fast Retailing](https://www.fastretailing.com/jp/ir/news/)
- [高島屋 / Takashimaya](https://www.takashimaya.co.jp/)
- [J.フロント リテイリング / J. Front Retailing](https://www.j-front-retailing.com/news/news_1.html)
- [マツキヨココカラ＆カンパニー / MatsukiyoCocokara](https://www.matsukiyococokara.com/news/)
- [ツルハホールディングス / Tsuruha Holdings](https://www.tsuruha-hd.co.jp/)
- [楽天グループ / Rakuten Group](https://corp.rakuten.co.jp/news/press/)

</details>

<details>
<summary><strong>Distribution and logistics (7)</strong></summary>

- [ヤマトホールディングス / Yamato Holdings](https://www.yamato-hd.co.jp/)
- [NIPPON EXPRESSホールディングス / NX Group](https://www.nipponexpress-holdings.com/ja/news/press/)
- [西濃運輸 / Seino Transportation](https://www.seino.co.jp/)
- [福山通運 / Fukuyama Transporting](https://corp.fukutsu.co.jp/news/)
- [日本郵便 / Japan Post](https://www.post.japanpost.jp/notification/)
- [センコーグループホールディングス / SENKO Group Holdings](https://www.senkogrouphd.co.jp/about/news/)
- [三菱倉庫 / Mitsubishi Logistics](https://www.mitsubishi-logistics.co.jp/news/)

</details>

<details>
<summary><strong>Healthcare organizations (24)</strong></summary>

- [国立病院機構 / National Hospital Organization](https://nho.hosp.go.jp/)
- [地域医療機能推進機構 / JCHO](https://www.jcho.go.jp/)
- [労働者健康安全機構 / JOHAS](https://www.johas.go.jp/)
- [日本赤十字社 / Japanese Red Cross Society](https://www.jrc.or.jp/press/)
- [徳洲会 / Tokushukai](https://www.tokushukai.or.jp/)
- [IMSグループ / IMS Group](https://www.ims.gr.jp/group/)
- [戸田中央メディカルケアグループ / Toda Medicalcare Group](https://www.tmg.or.jp/)
- [聖隷福祉事業団 / Seirei](https://www.seirei.or.jp/hq/)
- [済生会 / Saiseikai](https://www.saiseikai.or.jp/)
- [国立がん研究センター / National Cancer Center](https://www.ncc.go.jp/jp/information/pr_release/index.html)
- [国立循環器病研究センター / National Cerebral and Cardiovascular Center](https://www.ncvc.go.jp/pr/)
- [国立健康危機管理研究機構 / JIHS](https://www.jihs.go.jp/)
- [がん研究会有明病院 / Cancer Institute Hospital](https://www.jfcr.or.jp/hospital/information/general/)
- [北海道大学病院 / Hokkaido University Hospital](https://www.huhp.hokudai.ac.jp/news/)
- [名古屋大学医学部附属病院 / Nagoya University Hospital](https://www.med.nagoya-u.ac.jp/hospital/news/)
- [埼玉県立病院機構 / Saitama Prefectural Hospital Organization](https://www.saitama-pho.jp/)
- [大阪大学医学部附属病院 / Osaka University Hospital](https://www.hosp.med.osaka-u.ac.jp/)
- [大阪急性期・総合医療センター / Osaka General Medical Center](https://www.gh.opho.jp/news/)
- [慶應義塾大学病院 / Keio University Hospital](https://www.hosp.keio.ac.jp/oshirase/)
- [東京大学医学部附属病院 / University of Tokyo Hospital](https://www.h.u-tokyo.ac.jp/)
- [東京都立病院機構 / Tokyo Metropolitan Hospitals](https://www.tmhp.jp/)
- [東北大学病院 / Tohoku University Hospital](https://www.hosp.tohoku.ac.jp/release/news/)
- [筑波大学附属病院 / University of Tsukuba Hospital](https://www.hosp.tsukuba.ac.jp/)
- [長野県立病院機構 / Nagano Prefectural Hospital Organization](https://www.pref-nagano-hosp.jp/honbu/news/)

</details>

<details>
<summary><strong>Telecom carriers and Internet service providers (16)</strong></summary>

- [ソフトバンク / SoftBank](https://www.softbank.jp/corp/news/press/sbkk/)
- [NTTドコモビジネス / NTT DOCOMO BUSINESS](https://www.ntt.com/about-us/press-releases.html)
- [インターネットイニシアティブ / IIJ](https://www.iij.ad.jp/news/pressrelease/)
- [NTTグループ / NTT Group](https://group.ntt/jp/newsrelease/)
- [NTTドコモ / NTT DOCOMO](https://www.docomo.ne.jp/info/rss/news_release.rdf)
- [KDDI](https://newsroom.kddi.com/news/newsrelease.xml)
- [楽天モバイル / Rakuten Mobile](https://corp.mobile.rakuten.co.jp/news/)
- [NTT東日本 / NTT EAST](https://www.ntt-east.co.jp/release/)
- [NTT西日本 / NTT WEST](https://www.ntt-west.co.jp/news/)
- [JCOM](https://notices.jcom.co.jp/)
- [オプテージ / OPTAGE](https://optage.co.jp/press/)
- [ビッグローブ / BIGLOBE](https://www.biglobe.co.jp/pressroom/)
- [ニフティ / NIFTY](https://www.nifty.co.jp/newsrelease/)
- [NTTドコモ お知らせ / NTT DOCOMO notices](https://www.docomo.ne.jp/info/rss/notice.rdf)
- [KDDI 重要なお知らせ / KDDI important notices](https://news.kddi.com/important/news/rss/kddi_important_ex.xml)
- [TOKAIコミュニケーションズ / TOKAI Communications](https://www.tokai-com.co.jp/news/)

</details>

<details>
<summary><strong>Banks, insurance, securities, and payments (17)</strong></summary>

- [GMOペイメントゲートウェイ / GMO Payment Gateway](https://www.gmo-pg.com/)
- [MS&AD](https://www.ms-ad-hd.com/ja/news.html)
- [PayPay](https://about.paypay.ne.jp/pr/)
- [SOMPOホールディングス / SOMPO](https://www.sompo-hd.com/news/)
- [みずほ銀行 / Mizuho Bank](https://www.mizuhobank.co.jp/release/index.html)
- [ゆうちょ銀行 / Japan Post Bank](https://www.jp-bank.japanpost.jp/news/news_index.html)
- [りそなホールディングス / Resona](https://www.resona-gr.co.jp/holdings/news/)
- [アフラック / Aflac](https://www.aflac.co.jp/)
- [三井住友銀行 / SMBC](https://www.smbc.co.jp/news/)
- [三菱UFJ銀行 / MUFG Bank](https://www.bk.mufg.jp/news/index.html)
- [住信SBIネット銀行 / SBI Sumishin Net Bank](https://www.netbk.co.jp/contents/company/press/)
- [千葉銀行 / Chiba Bank](https://www.chibabank.co.jp/)
- [大和証券グループ / Daiwa Securities](https://www.daiwa-grp.jp/update/update.rss)
- [楽天銀行 / Rakuten Bank](https://www.rakuten-bank.co.jp/press/)
- [福岡銀行 / Bank of Fukuoka](https://www.fukuokabank.co.jp/)
- [第一生命 / Dai-ichi Life](https://www.dai-ichi-life.co.jp/)
- [野村ホールディングス / Nomura](https://www.nomuraholdings.com/jp/news/)

</details>

<details>
<summary><strong>Universities and education (17)</strong></summary>

- [九州大学 / Kyushu University](https://www.kyushu-u.ac.jp/ja/notices/)
- [京都大学 / Kyoto University](https://www.kyoto-u.ac.jp/ja)
- [北海道大学 / Hokkaido University](https://www.hokudai.ac.jp/news/)
- [千葉大学 / Chiba University](https://www.chiba-u.ac.jp/)
- [同志社大学 / Doshisha University](https://www.doshisha.ac.jp/news/)
- [広島大学 / Hiroshima University](https://www.hiroshima-u.ac.jp/)
- [慶應義塾 / Keio University](https://www.keio.ac.jp/ja/news/)
- [早稲田大学 / Waseda University](https://www.waseda.jp/top/news)
- [東京大学 / University of Tokyo](https://www.u-tokyo.ac.jp/focus/ja/press/)
- [東京科学大学 / Institute of Science Tokyo](https://www.isct.ac.jp/ja)
- [東北大学 / Tohoku University](https://www.tohoku.ac.jp/japanese/)
- [熊本大学 / Kumamoto University](https://www.kumamoto-u.ac.jp/daigakujouhou/kouhou/pressrelease)
- [神戸大学 / Kobe University](https://www.kobe-u.ac.jp/ja/)
- [立命館 / Ritsumeikan](https://www.ritsumei.ac.jp/xml.jsp?id=229770)
- [筑波大学 / University of Tsukuba](https://www.tsukuba.ac.jp/news/)
- [近畿大学 / Kindai University](https://www.kindai.ac.jp/news-pr/)
- [関西大学 / Kansai University](https://www.kansai-u.ac.jp/ja/about/pr/news/)

</details>

<details>
<summary><strong>Energy and water utilities (16)</strong></summary>

- [JERA](https://www.jera.co.jp/)
- [中国電力 / Chugoku Electric Power](https://www.energia.co.jp/press/)
- [中部電力 / Chubu Electric Power](https://www.chuden.co.jp/publicity/press/)
- [九州電力 / Kyushu Electric Power](https://www.kyuden.co.jp/rss/news.xml)
- [北海道電力 / Hokkaido Electric Power](https://www.hepco.co.jp/info/rss/press_rss.xml)
- [北陸電力 / Hokuriku Electric Power](https://www.rikuden.co.jp/press/)
- [四国電力 / Shikoku Electric Power](https://www.yonden.co.jp/press/)
- [大阪ガス / Osaka Gas](https://www.osakagas.co.jp/company/press/)
- [大阪市水道局 / Osaka Waterworks](https://www.city.osaka.lg.jp/suido/)
- [東京ガス / Tokyo Gas](https://www.tokyo-gas.co.jp/news/)
- [東京都水道局 / Tokyo Waterworks](https://www.waterworks.metro.tokyo.lg.jp/press/)
- [東京電力ホールディングス / TEPCO](https://www.tepco.co.jp/press/)
- [東北電力 / Tohoku Electric Power](https://www.tohoku-epco.co.jp/rss/index.xml)
- [東邦ガス / Toho Gas](https://www.tohogas.co.jp/corporate-n/press/)
- [沖縄電力 / Okinawa Electric Power](https://www.okiden.co.jp/press/)
- [関西電力 / Kansai Electric Power](https://www.kepco.co.jp/corporate/pr/)

</details>

<details>
<summary><strong>Manufacturing and pharmaceuticals (17)</strong></summary>

- [アイシン / AISIN](https://www.aisin.com/jp/news/)
- [アサヒグループ / Asahi Group](https://www.asahigroup-holdings.com/pressroom/)
- [エーザイ / Eisai](https://www.eisai.co.jp/news/)
- [キヤノン / Canon](https://global.canon/ja/news/)
- [サントリー / Suntory](https://www.suntory.co.jp/news/)
- [スズキ / Suzuki](https://www.suzuki.co.jp/)
- [ソニーグループ / Sony Group](https://www.sony.com/ja/SonyInfo/News/Press/)
- [デンソー / DENSO](https://www.denso.com/jp/ja/newsroom/)
- [トヨタ自動車 / Toyota](https://global.toyota/jp/newsroom/)
- [マツダ / Mazda](https://newsroom.mazda.com/ja/publicity/release/)
- [リコー / Ricoh](https://jp.ricoh.com/release)
- [京セラ / Kyocera](https://www.kyocera.co.jp/newsroom/)
- [日産自動車 / Nissan](https://global.nissannews.com/ja-JP/)
- [本田技研工業 / Honda](https://global.honda/jp/news/)
- [村田製作所 / Murata Manufacturing](https://corporate.murata.com/ja-jp/newsroom)
- [東芝 / Toshiba](https://www.global.toshiba/jp/news/corporate.html)
- [武田薬品 / Takeda](https://www.takeda.com/)

</details>

<details>
<summary><strong>Wholesale suppliers (7)</strong></summary>

- [アルフレッサ / Alfresa](https://www.alfresa.com/news/)
- [スズケン / Suzuken](https://www.suzuken.co.jp/news/)
- [ダイワボウホールディングス / Daiwabo](https://www.daiwabo-holdings.com/ja/news.html)
- [メディパル / Medipal](https://www.medipal.co.jp/news/)
- [三菱食品 / Mitsubishi Shokuhin](https://www.mitsubishi-shokuhin.com/)
- [伊藤忠食品 / Itochu-Shokuhin](https://www.itochu-shokuhin.com/newsrelease/)
- [国分グループ / Kokubu Group](https://www.kokubu.co.jp/news/)

</details>

<!-- source-registry:end -->

## Setup

Use Python 3.10 or later and install the PDF text extraction dependency:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

PDF extraction runs in a separate process with limits on document size, pages, memory, and runtime. Image-only or password-protected PDFs may yield no usable text; OCR is not included. The optional local Flask dashboard requires Flask separately.

## Commands

```bash
python3 jp_incidents.py sources
python3 jp_incidents.py source-health
python3 jp_incidents.py poll
python3 jp_incidents.py export-json
python3 jp_incidents.py export-rss
python3 jp_incidents.py export-sources
python3 jp_incidents.py audit-current
python3 jp_incidents.py audit-current --apply --publish
python3 jp_incidents.py audit-rejected /tmp/jp_incidents-pre-audit-TIMESTAMP.db --apply --publish
python3 jp_incidents.py review-pending
python3 scripts/update_readme_sources.py
python3 jp_incidents.py poll --publish
```

`poll --publish` uses a staged publication cycle. It first promotes candidates that the AI confirmed during the previous cycle, polls all sources, and queues every new matching candidate for AI review, including recognized official and government sources. Source authority alone never establishes that an article describes a real victim. Mixed advisory/product language and cybersecurity evidence also go to AI review. It then atomically updates and pushes the public JSON/RSS. Potentially relevant or complex articles remain in the private SQLite review queue. Questionable extraction, unclear victims/dates, and missing corroboration are held for human review rather than silently rejected. After publication, the AI performs granular article-level analysis and may identify multiple distinct affected organizations/incidents from one story—including a previously unidentified victim named in a follow-up. Before a secondary finding can be promoted, it must be supported by an official/government source or an independent monitored-news result for the same organization and incident date. Corroborating links are attached to the incident and contribute to its confidence score. Each confirmed new victim/incident becomes eligible for the next hourly update; a known victim's follow-up only enriches its matching existing row. AI-rejected, undecided, or uncorroborated findings are never published.

## Local preview

GitHub Pages must serve the files over HTTP; opening `index.html` directly will not load the JSON in most browsers.

```bash
python3 -m http.server 8000
```

Then open `http://localhost:8000/`.

## Hourly service

Review the generated units:

```bash
python3 jp_incidents.py install-units
```

Before installing the included units, create a `jp-incidents` service account with
home directory `/var/lib/jp-incidents`, or adjust `User`, `Group`, and `HOME` to
an existing service account. Review the `/opt/jp-incidents` paths and grant that
account access to the checkout, database, configuration, and publication credentials.
Then install and enable the units:

```bash
sudo cp systemd/jp-incidents.service systemd/jp-incidents.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now jp-incidents.timer
```

The timer runs two minutes after boot and at 13 minutes past every hour in the `Asia/Tokyo` timezone. Before changing collection state, the process waits up to 10 minutes for external connectivity, checking every 30 seconds. If connectivity is still unavailable, systemd retries the failed run after five minutes (up to four starts per 30 minutes). The service loads optional secrets and overrides from `.env`, which is ignored by Git. `JPI_NETWORK_WAIT_SECONDS`, `JPI_NETWORK_RETRY_SECONDS`, and comma-separated `JPI_NETWORK_CHECK_URLS` can override the defaults.

## Private Discord operations alerts

Operational alerts are sent only to a locally configured Discord webhook. They are never written to the public JSON, RSS feed, dashboard, or Git history. The collector alerts on AI billing/credit, spend-limit, authentication, rate-limit, and provider failures; fatal collector or Git publication failures; a missing AI key; and aggregated source polling errors. Sources returning no usable articles do not trigger Discord alerts. Private `source-health` diagnostics retain item counts, article estimates, empty streaks, and fetch errors. Potential incident articles with unreadable or questionable PDFs enter private human review and send an actionable Discord alert. Actual fetch failures and AI failures still alert; failed AI batches retain pending candidates for retry.

Identical alerts are suppressed for 12 hours by default using the ignored local `.jpi-alert-state.json` file. Incident notifications continue to use `WEBHOOK_URL`; private operations alerts use `JPI_ALERT_WEBHOOK_URL` when set and otherwise fall back to `WEBHOOK_URL`.

Add private values to `/opt/jp-incidents/.env`:

```dotenv
JPI_ALERT_WEBHOOK_URL=https://discord.com/api/webhooks/REPLACE_ME
JPI_ALERT_COOLDOWN_HOURS=12
```

After saving `.env`, test the private channel locally with:

```bash
set -a; . ./.env; set +a
python3 jp_incidents.py test-alert
```

The Messages API reports exhausted credits, billing failures, and spend caps as request errors, so those conditions alert automatically. For a warning *before* exhaustion, create a read-capable Anthropic Admin API key and define a local monthly budget and remaining-budget threshold:

```dotenv
ANTHROPIC_ADMIN_API_KEY=REPLACE_ME
JPI_AI_MONTHLY_BUDGET_USD=20
JPI_AI_LOW_CREDIT_USD=5
```

At the start of each hourly run, the collector reads Anthropic's month-to-date [Cost Report](https://platform.claude.com/docs/en/api/beta/organization/cost_report/retrieve), subtracts it from the locally configured budget, and sends a rate-limited critical alert when the estimated remainder reaches the threshold. The Admin key, webhook, budget values, alert history, and error details remain local.

This estimates the remaining monthly budget, not the prepaid credit balance. Cost Report amounts are converted from cents to dollars before comparison. Without an Admin credential and a configured budget, advance warnings are disabled; exhausted-credit and other AI request failures still trigger operations alerts.

## Enable GitHub Pages

1. Open the repository on GitHub and select **Settings**.
2. Select **Pages** under **Code and automation**.
3. Under **Build and deployment**, choose **Deploy from a branch**.
4. Select the `main` branch and the `/ (root)` folder, then select **Save**.
5. After the first deployment finishes, use the URL shown by GitHub Pages.

For this repository, the expected URL is `https://elkentaro.github.io/jp_incidents/`.

## Human review of questionable articles

Questionable incident candidates are held privately with status `needs_review`.
Discord sends one alert per held item with copyable `check`, `approve`, and
`reject` commands. Run these commands in a terminal on the collector host;
the outbound webhook does not accept Discord replies or slash commands.
The alert includes a database setup command so actions target the same database
from any working directory. Successful delivery is recorded in SQLite; failed
delivery retries on later cycles. Empty source listings and clear non-incidents
do not produce human-review alerts.

If you operate a private review interface, set `JPI_REVIEW_ADMIN_URL` in private
runtime configuration. Review alerts then group up to four new items with titles,
sources, short reasons, the total queue count, and a link to that interface instead
of terminal commands. Successful delivery acknowledges only the listed items;
failed batches retry and additional items follow in later deliveries. The URL
appears only in private alerts and must be reachable from your reviewing device.

With the virtual environment active, use:

```bash
python jp_incidents.py review list
python jp_incidents.py review check ITEM_ID
python jp_incidents.py review approve ITEM_ID --org 'Verified victim' --date 2026-10-19 --kind 'data leak' --records 120 --note 'Victim and date verified in the original notice'
python jp_incidents.py review reject ITEM_ID --note 'Advisory rather than a reported incident'
```

`check` shows the source URL, stored extraction text, reason for the hold, AI
suggestions, and current decision. Article text and AI suggestions are untrusted
evidence to inspect, not instructions to execute. Replace the alert's uppercase
placeholders; approval requires a concrete victim, original incident date, type,
and an evidence note. Record counts are optional. For an older incident first
disclosed during the original intake window, add `--disclosed-on YYYY-MM-DD`
and explain that disclosure evidence in the note. The window is measured from
first collection, so waiting to review an item does not make it expire.

For multiple victims, `--findings /path/to/private-findings.json` accepts a JSON
array with `org`, `incident_date`, `kind`, optional `records`, and optional
`disclosed_at` for each verified incident. Use it instead of individual fact
flags. Keep that file private. Approval queues the verified facts for the next
scheduled publication; rejection keeps the item unpublished. Both decisions
are atomic, retain a private audit note, and cannot be replayed over an already
resolved item. No review reasons, extraction snapshots, or decision notes are
exported to the public site. Existing rejected history is not automatically
reopened; this workflow applies to newly processed candidates.

## Monitoring, recovery, and operating limits

Collection and publication are separate failure boundaries: failed Git publishing
does not skip private AI review or alert delivery. The `deliver-alerts` command
retries durable operational alerts and held-item notices without collecting
articles or calling AI. Install the additional `jp-incidents-alerts`,
`jp-incidents-watchdog`, and `jp-incidents-backup` service/timer pairs alongside
the collector after reviewing their generic paths and service account. The
collector has a 35-minute systemd limit and excludes overlapping collector/review
commands with a process lock. Alert delivery runs every five minutes; the local
watchdog checks for overdue collection and backups every ten minutes.

Each successful collection updates `data/health.json` independently of incident
changes. The **Collector heartbeat** GitHub Actions workflow checks the repository
and public site's heartbeat hourly and alerts if it is over three hours old or
unreadable. Configure the repository Actions secret `JPI_ALERT_WEBHOOK_URL`; set
`JPI_PUBLIC_HEALTH_URL` as a repository variable for a custom site address. This
runner can alert when the collector host is offline. Scheduled Actions can be
delayed, and monitoring still depends on GitHub and Discord availability; see
[GitHub's schedule documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).

`backup` creates a private SQLite-consistent snapshot, selected local configuration,
and a checksum/row-count manifest. Every archive is restored to an isolated
temporary directory and integrity-checked before it is retained. The daily timer
keeps 30 verified archives by default. Backups include secrets when `.env` exists:
keep the backup directory private. To rehearse recovery without overwriting live
state, run `python jp_incidents.py restore-backup ARCHIVE --destination NEW_DIRECTORY`.
Stop the collector before any deliberate live recovery; preserve the current DB
and configuration before replacing them with validated restored files.

Optional encrypted replication uses an existing restic repository. Install restic,
set `JPI_BACKUP_RESTIC_REPOSITORY` and restic credentials (for example
`RESTIC_PASSWORD_FILE`) in private configuration. Local snapshots alone do not
protect against loss of the host. A failed upload retains the verified local
archive and fails the backup job. Remote repository retention and credential
recovery remain the repository operator's responsibility.

| Setting | Default | Purpose |
| --- | --- | --- |
| `JPI_REVIEW_BATCH_LIMIT` | 40 | Candidates attempted per review cycle |
| `JPI_REVIEW_SECONDS` | 600 | Review time budget, checked between candidates |
| `JPI_AI_DAILY_REQUEST_LIMIT` | 200 | Hard daily API request reservations, UTC day |
| `JPI_AI_DAILY_TOKEN_LIMIT` | 2000000 | Conservative input-byte plus maximum-output token reservations |
| `JPI_RECHECK_LIMIT` | 20 | Known article URLs re-read per collection |
| `JPI_RECHECK_HOURS` | 24 | Interval for unchanged listing entries |
| `JPI_BACKUP_KEEP` | 30 | Verified local snapshots retained |
| `JPI_BACKUP_DIR` | `backups/` beside the database | Private snapshot destination |

Daily API reservations persist across retries and restarts. They are conservative
work limits, not exact billing figures. When configured cost reporting shows the
monthly budget exhausted, review pauses; failed candidates remain pending and
rotate behind less-attempted candidates. One in-flight fetch/API call can exceed
the review time budget; the service timeout bounds the whole process.

Known article URLs are periodically re-read within a bounded sampling budget.
Changes to listing text or extracted body create a private human-review item;
public facts are not silently overwritten. Initial baselines cannot reconstruct
past revisions, and this sampling does not guarantee every change is captured.
For existing records use the correction commands below, approving a review item
only when it describes a new victim/incident. Empty source listings stay silent.

## Correcting published records

```bash
python jp_incidents.py incident check INCIDENT_ID
python jp_incidents.py incident correct INCIDENT_ID --records 42 --note 'Corrected figure in primary disclosure'
python jp_incidents.py incident withdraw INCIDENT_ID --note 'Source withdrew the allegation'
python jp_incidents.py incident restore INCIDENT_ID --note 'New evidence supports republication'
```

Corrections support `--org`, `--date`, `--kind`, `--records`, `--clear-records`,
and `--disclosed-on`. Original IDs and private before/after audit records are
retained. Changes reach public exports on the next scheduled publication.
Withdrawn records are excluded from the public JSON, RSS and local dashboard;
restoration is explicit. Automated reprocessing cannot overwrite an operator
correction or recreate a withdrawn record from its recorded sources. Withdrawal
does not erase previously published Git history or copies held by feed readers.
