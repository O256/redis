import redis
client = redis.Redis(host='localhost', port=6379, db=0, password='123456')

# 测试list的listpack编码，边界值为512
def test_list_listpack():
    # 先清理
    client.delete('mylist')
    client.rpush('mylist', *range(513))
    print(client.object('encoding', 'mylist'), client.memory_usage('mylist'))  

    # 插入一个64字节元素
    client.delete('mylist')
    client.rpush('mylist', 'a' * 8185)
    print(client.object('encoding', 'mylist'), client.memory_usage('mylist'))  

# 测试list的hashtable编码，边界值为8192
def test_list_hashtable():
    # 先清理
    client.delete('mylist')
    client.rpush('mylist', *range(8186))
    print(client.object('encoding', 'mylist'), client.memory_usage('mylist'))

test_list_listpack()
test_list_hashtable()