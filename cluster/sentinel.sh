#! /bin/bash

root_dir=/home/user00/cluster

# 清理sentinel动态生成的配置
sentinel_ports=(27001 27002 27011 27012 27021 27022)

# 停止sentinel
for port in ${sentinel_ports[@]}; do
    ~/redis/src/redis-cli -p ${port} -a 12345687 shutdown
done

# 清理
for port in ${sentinel_ports[@]}; do
    # 清理日志
    rm -rf ${root_dir}/shard${port:3:1}/sentinel-${port}/*.log
    # 清理pid
    rm -rf ${root_dir}/shard${port:3:1}/sentinel-${port}/*.pid
    # 清理配置
    sed -i '/sentinel known-sentinel shard/d' ${root_dir}/shard${port:3:1}/sentinel-${port}/sentinel.conf     
    sed -i '/sentinel known-replica shard/d' ${root_dir}/shard${port:3:1}/sentinel-${port}/sentinel.conf  
done

# 重新启动sentinel
for port in ${sentinel_ports[@]}; do
    ~/redis/src/redis-sentinel ${root_dir}/shard${port:3:1}/sentinel-${port}/sentinel.conf
done

