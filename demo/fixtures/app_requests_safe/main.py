import requests

# Only uses an unrelated leaf helper; never touches rebuild_proxies or
# redirect handling, so the vulnerable function is not reachable.
ua = requests.utils.default_user_agent()
print("user-agent:", ua)
