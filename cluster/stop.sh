#!/bin/bash

# 定义要停止的 Redis 实例的端口号
redis_ports=(7001 7002 7003 7011 7012 7013 7021 7022 7023)

# 定义要停止的 Redis 哨兵实例的端口号
sentinel_ports=(27001 27002 27011 27012 27021 27022)

# 定义 Redis 实例的密码
redis_password="12345687"

# 停止 Redis 实例
for port in "${redis_ports[@]}"; do
    echo "Stopping Redis on port $port..."
    /home/user00/redis/src/redis-cli -a $redis_password -p $port SHUTDOWN
done

# 停止 Redis 哨兵实例
for port in "${sentinel_ports[@]}"; do
    echo "Stopping Redis Sentinel on port $port..."
    /home/user00/redis/src/redis-cli -a $redis_password -p $port SHUTDOWN
done

echo "All Redis and Sentinel instances have been stopped."
