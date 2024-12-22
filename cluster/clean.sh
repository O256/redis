# 清理所有的pid，log，data

root_dir=/home/user00/cluster

redis_ports=(7001 7002 7003 7011 7012 7013 7021 7022 7023)
sentinel_ports=(27001 27002 27011 27012 27021 27022)

for port in ${redis_ports[@]}; do
    rm -rf ${root_dir}/shard${port:2:1}/redis-${port}/*.pid
    rm -rf ${root_dir}/shard${port:2:1}/redis-${port}/*.log
    rm -rf ${root_dir}/shard${port:2:1}/redis-${port}/*.rdb

    rm -rf ${root_dir}/shard${port:2:1}/redis-${port}/*.aof
    rm -rf ${root_dir}/shard${port:2:1}/redis-${port}/node*.conf
done


for port in ${sentinel_ports[@]}; do
    rm -rf ${root_dir}/shard${port:3:1}/sentinel-${port}/*.pid
    rm -rf ${root_dir}/shard${port:3:1}/sentinel-${port}/*.log

    # 删除对应目录 sentinel.conf中动态生成的内容
    sed -i '/sentinel known-sentinel shard/d' ${root_dir}/shard${port:3:1}/sentinel-${port}/sentinel.conf
    sed -i '/sentinel known-replica shard/d' ${root_dir}/shard${port:3:1}/sentinel-${port}/sentinel.conf  
done

