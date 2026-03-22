Task 1.4: Cache whitelist trên Redis 
redis_client.py: class RedisWhitelistCache — tra cứu O(1), TTL 24 giờ, connection pooling (tối đa 10)
Tiêu chí hoàn thành: Tra cứu whitelist < 1ms, ghi lại số liệu cache hit/miss
Hướng dẫn tui test thử trên máy tui luôn
