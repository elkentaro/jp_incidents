# JP Incident Monitor

A Python collector and static, bilingual dashboard for publicly reported cybersecurity incidents affecting organizations in Japan.

The collector stores normalized incidents in SQLite, polls its sources hourly on the host machine, and writes the complete public dataset to `data/incidents.json` and `feed.xml`. The GitHub Pages site reads the JSON in the browser and paginates it at 100 records per page; feed readers can subscribe to the full-history RSS feed.

## Commands

```bash
python3 jp_incidents.py sources
python3 jp_incidents.py poll
python3 jp_incidents.py export-json
python3 jp_incidents.py export-rss
python3 jp_incidents.py poll --publish
```

`poll --publish` polls all sources, atomically updates the JSON and RSS files only when their content changed, commits only those published data files, and pushes pending data commits to `origin/main`.

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

The timer runs two minutes after boot and once per hour thereafter as the `kentaro` user. The service loads optional secrets and overrides from `.env`, which is ignored by Git.

## Enable GitHub Pages

1. Open the repository on GitHub and select **Settings**.
2. Select **Pages** under **Code and automation**.
3. Under **Build and deployment**, choose **Deploy from a branch**.
4. Select the `main` branch and the `/ (root)` folder, then select **Save**.
5. After the first deployment finishes, use the URL shown by GitHub Pages.

For this repository, the expected URL is `https://elkentaro.github.io/jp_incidents/`.
