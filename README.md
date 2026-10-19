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

For official sites, the collector discovers advertised RSS/Atom feeds and scans current same-site links. Health and environmental uses of terms such as “virus infection” and “leak” are excluded before analysis.

Confidence is based on source authority and independent corroboration: direct official/government disclosures score highly, while single aggregators and social sources score lower. It is a guide to the reliability of the collected record, not incident severity. The dashboard can sort every column—including confidence—across the complete dataset before applying its 100-row pagination.

The displayed date is the incident's occurrence, discovery, or first-disclosure date—not a webpage's later update date. New candidates must fall within the collector's 14-day intake window when first discovered. If a report states no incident date, its source publication date is used as a fallback. Once a valid incident is collected it remains in the all-history dataset as it ages.

One database row represents one affected organization and underlying incident, not one article. Follow-up reports, second notices, reactions, remediation, recovery, and impact stories add sources or facts when that organization/incident is already listed. A follow-up may also reveal a previously unidentified victim organization; after secondary AI evaluation confirms the victim, original incident date, relevance, and source corroboration, that organization can receive its own row. A follow-up remains unpublished when its original incident date is unknown, and an underlying incident is admitted only when that date falls inside the intake window.

<!-- source-registry:begin -->
## Complete source registry

The collector currently polls **213 configured sources**. This list is generated from [`data/sources.json`](data/sources.json); run `python3 scripts/update_readme_sources.py` after changing the registry.

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

<!-- source-registry:end -->

## Commands

```bash
python3 jp_incidents.py sources
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

`poll --publish` uses a staged publication cycle. It first promotes candidates that the AI confirmed during the previous cycle, polls all sources, and immediately accepts only deterministic high-confidence notices from recognized official or government sources with an explicit incident date. It then atomically updates and pushes the public JSON/RSS. Potentially relevant or complex articles remain in the private SQLite review queue. After publication, the AI performs granular article-level analysis and may identify multiple distinct affected organizations/incidents from one story—including a previously unidentified victim named in a follow-up. Before a secondary finding can be promoted, it must be supported by an official/government source or an independent monitored-news result for the same organization and incident date. Corroborating links are attached to the incident and contribute to its confidence score. Each confirmed new victim/incident becomes eligible for the next hourly update; a known victim's follow-up only enriches its matching existing row. AI-rejected, undecided, or uncorroborated findings are never published.

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

Install and enable the included units on this host:

```bash
sudo cp systemd/jp-incidents.service systemd/jp-incidents.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now jp-incidents.timer
```

The timer runs two minutes after boot and at 13 minutes past every hour in the `Asia/Tokyo` timezone as the `kentaro` user. The 03:13 run deliberately starts after the host's usual 03:00–03:05 network reset. Before changing collection state, the process waits up to 10 minutes for external connectivity, checking every 30 seconds. If connectivity is still unavailable, systemd retries the failed run after five minutes (up to four starts per 30 minutes). The service loads optional secrets and overrides from `.env`, which is ignored by Git. `JPI_NETWORK_WAIT_SECONDS`, `JPI_NETWORK_RETRY_SECONDS`, and comma-separated `JPI_NETWORK_CHECK_URLS` can override the defaults.

## Enable GitHub Pages

1. Open the repository on GitHub and select **Settings**.
2. Select **Pages** under **Code and automation**.
3. Under **Build and deployment**, choose **Deploy from a branch**.
4. Select the `main` branch and the `/ (root)` folder, then select **Save**.
5. After the first deployment finishes, use the URL shown by GitHub Pages.

For this repository, the expected URL is `https://elkentaro.github.io/jp_incidents/`.
