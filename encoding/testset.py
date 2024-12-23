import redis
client = redis.Redis(host='localhost', port=6379, db=0, password='123456')

# 测试set的intset编码，边界值为512
def test_set_intset():
    # 先清理
    client.delete('myset')
    client.sadd('myset', *range(512))
    print(client.object('encoding', 'myset'))

    # 先清理
    client.delete('myset')
    client.sadd('myset', 2**63-1)
    print(client.object('encoding', 'myset'))

def test_set_listpack():
    # 先清理
    client.delete('myset')
    client.sadd('myset', *['a'] * 128)
    print(client.object('encoding', 'myset'))

    # 先清理
    client.delete('myset')
    client.sadd('myset','a' * 64)
    print(client.object('encoding', 'myset'), client.memory_usage('myset'))

def test_set_hashtable():
    # 添加513个元素
    client.delete('myset')
    client.sadd('myset', *range(513))
    print(client.object('encoding', 'myset'))

    # 添加8kb的字符串元素
    client.delete('myset')
    client.sadd('myset', *['a'] * 129)
    print(client.object('encoding', 'myset'))

    # 先清理
    client.delete('myset')
    client.sadd('myset','a' * 65)
    print(client.object('encoding', 'myset'), client.memory_usage('myset'))

    # 先清理
    client.delete('myset')
    client.sadd('myset', *range(10000))
    print(client.object('encoding', 'myset'))

test_set_intset()
test_set_listpack()
test_set_hashtable()
