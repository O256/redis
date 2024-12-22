#!/bin/bash

# set -x

root_dir=/home/user00/cluster

# 启动所有Redis节点
for port in 7001 7002 7003 7011 7012 7013 7021 7022 7023; do
    /home/user00/redis/src/redis-server ${root_dir}/shard${port:2:1}/redis-${port}/redis.conf
done

# 启动所有哨兵节点
for port in 27001 27002 27011 27012 27021 27022; do
    /home/user00/redis/src/redis-sentinel ${root_dir}/shard${port:3:1}/sentinel-${port}/sentinel.conf
done
