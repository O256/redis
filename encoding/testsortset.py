import redis
client = redis.Redis(host='localhost', port=6379, db=0, password='123456')

# 测试sortedset的hashtable编码，边界值为8kb
def test_sortedset_hashtable():
    # 先清理
    client.delete('mysortedset')
    client.zadd('mysortedset', {f'a{i}': i for i in range(128)})
    print(client.object('encoding', 'mysortedset'))

    # 单个元素超过64字节
    client.delete('mysortedset')
    client.zadd('mysortedset', {'a' * 64: 1})
    print(client.object('encoding', 'mysortedset'))

# 测试sortedset的skiplist编码，边界值为8kb
# 如果有序集合中的元素数量超过 128 个，或者其中某个元素的长度超过 64 字节，则使用 skiplist 编码
def test_sortedset_skiplist():
    # 先清理
    client.delete('mysortedset')
    client.zadd('mysortedset', {f'a{i}': i for i in range(129)})
    print(client.object('encoding', 'mysortedset'), client.memory_usage('mysortedset'))

test_sortedset_hashtable()
test_sortedset_skiplist()