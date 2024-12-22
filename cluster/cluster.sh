
root_dir=/home/user00/cluster

# 单条指令创建主节点+从节点(这种方式自动分配主节点和从节点)
~/redis/src/redis-cli --cluster create \
127.0.0.1:7001 127.0.0.1:7011 127.0.0.1:7021 \
127.0.0.1:7002 127.0.0.1:7012 127.0.0.1:7022 \
127.0.0.1:7003 127.0.0.1:7013 127.0.0.1:7023 \
-a 12345687 --cluster-replicas 2

# 连接到主节点
# ~/redis/src/redis-cli -p 7001 -a 12345687

# 创建主节点
~/redis/src/redis-cli --cluster create \
127.0.0.1:7001 127.0.0.1:7011 127.0.0.1:7021 \
--cluster-replicas 0 \
-a 12345687 

~/redis/src/redis-cli -p 7001 -a 12345687
127.0.0.1:7001> cluster nodes
e3e7982f29d2d4805a27a2bce9b541129d5d2016 127.0.0.1:7001@17001 myself,master - 0 1734853130000 1 connected 0-5460
8f56811a0b12059fb6a957fe619707fe934b80db 127.0.0.1:7011@17011 master - 0 1734853132197 2 connected 5461-10922
e547a6986276eb7022ce8e7d2502d0b3bbde93d3 127.0.0.1:7021@17021 master - 0 1734853131000 3 connected 10923-16383

# 创建从节点
~/redis/src/redis-cli --cluster add-node 127.0.0.1:7002 127.0.0.1:7001 \
--cluster-slave \
--cluster-master-id 0de8b1e4e7a4dcbdf4bbdc36f1e2a116210e62cd \
-a 12345687 

# 创建从节点
~/redis/src/redis-cli --cluster add-node 127.0.0.1:7003 127.0.0.1:7001 \
--cluster-slave \
--cluster-master-id 0de8b1e4e7a4dcbdf4bbdc36f1e2a116210e62cd \
-a 12345687 

# 创建从节点
~/redis/src/redis-cli --cluster add-node 127.0.0.1:7012 127.0.0.1:7011 \
--cluster-slave \
--cluster-master-id 1978e52e55a92d59816c92d29f848e85d7bb9084 \
-a 12345687 

# 创建从节点
~/redis/src/redis-cli --cluster add-node 127.0.0.1:7013 127.0.0.1:7011 \
    --cluster-slave \
--cluster-master-id 1978e52e55a92d59816c92d29f848e85d7bb9084 \
-a 12345687 

# 创建从节点
~/redis/src/redis-cli --cluster add-node 127.0.0.1:7022 127.0.0.1:7021 \
--cluster-slave \
--cluster-master-id 305011c2003c5645bb96c793883463681cb1b906 \
-a 12345687 

# 创建从节点
~/redis/src/redis-cli --cluster add-node 127.0.0.1:7023 127.0.0.1:7021 \
--cluster-slave \
--cluster-master-id 305011c2003c5645bb96c793883463681cb1b906 \
-a 12345687 

