import redis
client = redis.Redis(host='localhost', port=6379, db=0, password='123456')

# 测试stream的listpack编码，边界值为512
def test_stream_listpack():
    # 先清理
    client.delete('mystream')
    for i in range(512):
        client.xadd('mystream', {'a': 'b'})
    print(client.object('encoding', 'mystream'))

# 测试stream的hashtable编码，边界值为8kb
def test_stream_hashtable():
    # 先清理
    client.delete('mystream')
    for i in range(8192):
        client.xadd('mystream', {'a': 'b'})
    print(client.object('encoding', 'mystream'))

test_stream_listpack()
test_stream_hashtable()

# 所以stream其实只有一种编码类型，那就是stream