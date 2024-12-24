import redis
client = redis.Redis(host='localhost', port=6379, db=0, password='123456')

# 测试string的int编码，边界值为2^32-1
def test_string_int():
    # 先清理
    client.delete('mykey')
    client.set('mykey', 2**63-1)
    print(client.object('encoding', 'mykey'))

# 测试string的embstr编码，边界值为39
def test_string_embstr():
    # 先清理
    client.delete('mykey')
    # 设置一个长度为39的字符串
    client.set('mykey', 'a' * 44)
    print(client.object('encoding', 'mykey'))

# 测试string的raw编码，边界值为44
def test_string_raw():
    # 先清理
    client.delete('mykey')
    client.set('mykey', 'a' * 45)
    print(client.object('encoding', 'mykey'))


test_string_int()
test_string_embstr()
test_string_raw()