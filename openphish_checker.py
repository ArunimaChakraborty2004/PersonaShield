import requests
import time
import threading
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class OpenPhishChecker:
    """
    Downloads and caches the OpenPhish Community feed to detect known malicious URLs.
    Automatically refreshes the feed if the cache has expired.
    """
    def __init__(self, cache_duration=3600):
        self.feed_url = "https://openphish.com/feed.txt"
        self.cache_duration = cache_duration
        self.phish_urls = set()
        self.last_updated = 0
        self.lock = threading.Lock()
    
    def update_feed(self):
        try:
            response = requests.get(self.feed_url, timeout=10, verify=False)
            if response.status_code == 200:
                urls = response.text.splitlines()
                with self.lock:
                    self.phish_urls = set(url.strip() for url in urls if url.strip())
                    self.last_updated = time.time()
                print(f"[OpenPhish] Loaded {len(self.phish_urls)} malicious URLs.")
        except Exception as e:
            print(f"[OpenPhish] Error updating feed: {e}")

    def check_url(self, url):
        # Refresh if cache is expired or empty
        if time.time() - self.last_updated > self.cache_duration or not self.phish_urls:
            self.update_feed()
            
        with self.lock:
            return url.strip() in self.phish_urls

# Singleton instance
openphish = OpenPhishChecker()

def is_openphish_url(url):
    """
    Check if a URL is in the OpenPhish database.
    Returns True if malicious, False otherwise.
    """
    return openphish.check_url(url)
