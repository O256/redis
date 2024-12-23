import redis
client = redis.Redis(host='localhost', port=6379, db=0, password='123456')

# 测试hashtable的listpack编码，边界值为512
def test_hashtable_listpack():
    # 先清理
    client.delete('myhash')
    client.hset('myhash', mapping={f'a{i}': i for i in range(512)})
    print(client.object('encoding', 'myhash'))  

    # 单个元素超过64字节
    client.delete('myhash')
    client.hset('myhash', 'a512', 'a' * 64)
    print(client.object('encoding', 'myhash'))  

# 测试hashtable的hashtable编码，边界值为512元素，或者单个元素超过64字节
def test_hashtable_hashtable():
    # 先清理
    client.delete('myhash')
    client.hset('myhash', mapping={f'a{i}': i for i in range(513)})
    print(client.object('encoding', 'myhash'))  

    # 单个元素超过64字节
    client.delete('myhash')
    client.hset('myhash', 'a512', 'a' * 65)
    print(client.object('encoding', 'myhash'))  

test_hashtable_listpack()
test_hashtable_hashtable()