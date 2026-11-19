import requests

# Calls the vulnerable helper directly on a Session instance.
# rebuild_proxies recomputes/reattaches the Proxy-Authorization header and
# leaks it to the proxy destination when following HTTPS redirects.
s = requests.Session()
proxies = {"http": "http://user:secret@proxy.example:8080"}
s.rebuild_proxies(proxies)
print("rebuild_proxies returned:", s.proxies)
