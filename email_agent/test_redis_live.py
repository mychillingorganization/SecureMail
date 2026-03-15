from email_agent.redis_client import RedisWhitelistCache
import time

cache = RedisWhitelistCache(host="localhost", port=6379)

print("Redis ping:", cache.ping())

# Add trusted domains
cache.bulk_add(["google.com", "microsoft.com", "internal.corp"],
               metadata={"reason": "trusted"})

# Time a whitelist lookup
start = time.perf_counter()
result = cache.is_whitelisted("google.com")
elapsed_ms = (time.perf_counter() - start) * 1000
print(f"google.com whitelisted: {result} | Lookup: {elapsed_ms:.3f}ms")

# Miss
cache.is_whitelisted("evil.com")
cache.is_whitelisted("phishing.site")

print("Metrics:", cache.get_metrics())
