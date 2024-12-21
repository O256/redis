本 README 仅是一个快速入门文档。您可以在 [redis.io](https://redis.io) 找到更详细的文档。

什么是 Redis?
--------------

Redis 通常被称为数据结构服务器。这意味着 Redis 通过一组命令提供对可变数据结构的访问,这些命令使用 TCP 套接字和简单协议的服务器-客户端模型发送。因此不同的进程可以以共享方式查询和修改相同的数据结构。

Redis 中实现的数据结构具有以下特殊属性:

* Redis 会将它们存储在磁盘上,即使它们始终在服务器内存中提供服务和修改。这意味着 Redis 速度快,但同时也是非易失性的。
* 数据结构的实现强调内存效率,因此与使用高级编程语言建模的相同数据结构相比,Redis 内部的数据结构可能使用更少的内存。
* Redis 提供了许多在数据库中自然存在的功能,如复制、可调节的持久性级别、集群和高可用性。

另一个很好的例子是将 Redis 视为 memcached 的更复杂版本,其中操作不仅仅是 SET 和 GET,还包括使用列表、集合、有序数据结构等复杂数据类型的操作。

如果您想了解更多信息,以下是一些精选的起点:

* Redis 数据类型介绍: https://redis.io/topics/data-types-intro
* 直接在浏览器中试用 Redis: https://try.redis.io
* Redis 命令完整列表: https://redis.io/commands
* 官方 Redis 文档中还有更多内容: https://redis.io/documentation

构建 Redis
--------------

Redis 可以在 Linux、OSX、OpenBSD、NetBSD、FreeBSD 上编译和使用。
我们支持大端和小端架构,同时支持 32 位和 64 位系统。

Redis 可能在基于 Solaris 的系统(例如 SmartOS)上编译,但我们对这个平台的支持是"尽力而为",不能保证 Redis 能像在 Linux、OSX 和 *BSD 上运行得那么好。

构建非常简单:

    % make

要构建带 TLS 支持的版本,您需要 OpenSSL 开发库(例如 Debian/Ubuntu 上的 libssl-dev),然后运行:

    % make BUILD_TLS=yes

要构建带 systemd 支持的版本,您需要 systemd 开发库(如 Debian/Ubuntu 上的 libsystemd-dev 或 CentOS 上的 systemd-devel),然后运行:

    % make USE_SYSTEMD=yes

要为 Redis 程序名称添加后缀,使用:

    % make PROG_SUFFIX="-alt"

您可以构建 32 位的 Redis 二进制文件:

    % make 32bit

构建 Redis 后,建议进行测试:

    % make test

如果构建了 TLS,运行启用 TLS 的测试(您需要安装 tcl-tls):

    % ./utils/gen-test-certs.sh
    % ./runtest --tls

修复依赖项或缓存构建选项的问题
---------

Redis 有一些包含在 `deps` 目录中的依赖项。即使依赖项的源代码发生变化,`make` 也不会自动重新构建依赖项。

当您使用 `git pull` 更新源代码或以其他方式修改依赖项树中的代码时,请确保使用以下命令彻底清理并从头重新构建:

    % make distclean

这将清理: jemalloc、lua、hiredis、linenoise 和其他依赖项。

另外,如果您强制使用某些构建选项,如 32 位目标、无 C 编译器优化(用于调试)等构建时选项,这些选项会被无限期缓存,直到您执行 `make distclean` 命令。

修复构建 32 位二进制文件的问题
---------

如果在构建 32 位目标的 Redis 后需要重新构建 64 位目标,或相反,您需要在 Redis 发行版的根目录中执行 `make distclean`。

如果在尝试构建 Redis 的 32 位二进制文件时遇到构建错误,请尝试以下步骤:

* 安装 libc6-dev-i386 包(也可以尝试 g++-multilib)。
* 尝试使用以下命令行代替 `make 32bit`:
  `make CFLAGS="-m32 -march=native" LDFLAGS="-m32"`

内存分配器
---------

在构建 Redis 时选择非默认内存分配器是通过设置 `MALLOC` 环境变量完成的。Redis 默认编译并链接到 libc malloc,但在 Linux 系统上默认使用 jemalloc。之所以选择这个默认值,是因为 jemalloc 已被证明比 libc malloc 具有更少的碎片问题。

要强制编译使用 libc malloc,使用:

    % make MALLOC=libc

要在 Mac OS X 系统上编译使用 jemalloc,使用:

    % make MALLOC=jemalloc

单调时钟
---------------

默认情况下,Redis 将使用 POSIX clock_gettime 函数作为单调时钟源。在大多数现代系统上,可以使用内部处理器时钟来提高性能。注意事项可以在这里找到:
    http://oliveryang.net/2015/09/pitfalls-of-TSC-usage/

要构建支持处理器内部指令时钟的版本,使用:

    % make CFLAGS="-DUSE_PROCESSOR_CLOCK"

详细构建输出
-------------

Redis 默认会以用户友好的彩色输出方式构建。
如果您想看到更详细的输出,使用:

    % make V=1

运行 Redis
-------------

要使用默认配置运行 Redis,只需输入:

    % cd src
    % ./redis-server

如果要提供自己的 redis.conf,需要使用额外的参数(配置文件的路径)运行:

    % cd src
    % ./redis-server /path/to/redis.conf

可以通过直接在命令行中传递参数来更改 Redis 配置。例如:

    % ./redis-server --port 9999 --replicaof 127.0.0.1 6379
    % ./redis-server /etc/redis/6379.conf --loglevel debug

redis.conf 中的所有选项都可以作为命令行选项使用,名称完全相同。

使用 TLS 运行 Redis:
------------------

请查阅 [TLS.md](TLS.md) 文件,了解更多关于如何使用 TLS 的 Redis 信息。

体验 Redis
------------------

您可以使用 redis-cli 来体验 Redis。启动一个 redis-server 实例,然后在另一个终端中尝试以下操作:

    % cd src
    % ./redis-cli
    redis> ping
    PONG
    redis> set foo bar
    OK
    redis> get foo
    "bar"
    redis> incr mycounter
    (integer) 1
    redis> incr mycounter
    (integer) 2
    redis>

您可以在 https://redis.io/commands 找到所有可用命令的列表。

安装 Redis
-----------------

要将 Redis 二进制文件安装到 /usr/local/bin,只需使用:

    % make install

如果您希望使用不同的目标目录,可以使用 `make PREFIX=/some/other/directory install`。

`make install` 只会在您的系统中安装二进制文件,但不会在适当的位置配置初始化脚本和配置文件。如果您只是想体验一下 Redis,这不是必需的,但如果您要为生产系统正确安装它,我们有一个适用于 Ubuntu 和 Debian 系统的脚本:

    % cd utils
    % ./install_server.sh

_注意_: `install_server.sh` 在 Mac OSX 上不起作用;它仅适用于 Linux。

该脚本会询问您一些问题,并设置运行 Redis 所需的一切,使其作为后台守护进程运行,并在系统重启时重新启动。

您可以使用名为 `/etc/init.d/redis_<端口号>` 的脚本来停止和启动 Redis,例如 `/etc/init.d/redis_6379`。

代码贡献
-----------------

注意: 通过任何形式向 Redis 项目贡献代码,包括通过 Github 发送拉取请求、通过私人电子邮件或公共讨论组发送代码片段或补丁,即表示您同意根据 BSD 许可证的条款发布您的代码,该许可证可以在 Redis 源代码分发中的 [COPYING][1] 文件中找到。

更多信息请参见源代码分发中的 [CONTRIBUTING.md][2] 文件。对于安全漏洞和漏洞,请参见 [SECURITY.md][3]。

[1]: https://github.com/redis/redis/blob/unstable/COPYING
[2]: https://github.com/redis/redis/blob/unstable/CONTRIBUTING.md
[3]: https://github.com/redis/redis/blob/unstable/SECURITY.md

Redis 内部结构
===

如果您正在阅读这个 README,您可能正在查看 Github 页面或者刚刚解压了 Redis 发行版压缩包。在这两种情况下,您基本上离源代码只有一步之遥,所以在这里我们解释 Redis 源代码布局,每个文件中有什么内容的大致概念,Redis 服务器内部最重要的函数和结构等等。我们将所有讨论保持在高层次,而不深入细节,因为否则这个文档会非常庞大,而且我们的代码库在不断变化,但一个总体概念应该是理解更多内容的良好起点。此外,大部分代码都有大量注释,易于理解。

源代码布局
---

Redis 根目录只包含这个 README、调用 `src` 目录中真正的 Makefile 的 Makefile,以及 Redis 和 Sentinel 的示例配置。您可以找到一些 shell 脚本,用于执行 Redis、Redis Cluster 和 Redis Sentinel 单元测试,这些测试在 `tests` 目录中实现。

根目录中有以下重要目录:

* `src`: 包含用 C 语言编写的 Redis 实现。
* `tests`: 包含用 Tcl 实现的单元测试。
* `deps`: 包含 Redis 使用的库。编译 Redis 所需的一切都在这个目录中;您的系统只需要提供 `libc`、POSIX 兼容接口和 C 编译器。值得注意的是,`deps` 包含 `jemalloc` 的副本,它是 Linux 下 Redis 的默认分配器。请注意,`deps` 下还有一些起源于 Redis 项目的东西,但其主要存储库不是 `redis/redis`。

还有一些其他目录,但对我们的目标来说不是很重要。我们将主要关注 `src`,其中包含 Redis 的实现,探索每个文件中有什么内容。文件的展示顺序是逐步揭示不同复杂性层次的逻辑顺序。

注意: 最近 Redis 进行了相当大的重构。函数名和文件名已经改变,所以您可能会发现这个文档更接近 `unstable` 分支。例如,在 Redis 3.0 中,`server.c` 和 `server.h` 文件被命名为 `redis.c` 和 `redis.h`。但总体结构是相同的。请记住,所有新的开发和拉取请求都应该针对 `unstable` 分支进行。

server.h
---

理解程序如何工作的最简单方法是理解它使用的数据结构。所以我们从 Redis 的主要头文件 `server.h` 开始。

所有服务器配置和一般的所有共享状态都定义在一个名为 `server` 的全局结构中,类型为 `struct redisServer`。
这个结构中的一些重要字段是:

* `server.db` 是 Redis 数据库的数组,数据存储在其中。
* `server.commands` 是命令表。
* `server.clients` 是连接到服务器的客户端的链表。
* `server.master` 是一个特殊的客户端,如果实例是副本,则为主服务器。

还有大量其他字段。大多数字段都直接在结构定义中有注释。

另一个重要的 Redis 数据结构是定义客户端的结构。过去它被称为 `redisClient`,现在简称为 `client`。该结构有许多字段,这里我们只展示主要的:

```c
struct client {
    int fd;
    sds querybuf;
    int argc;
    robj **argv;
    redisDb *db;
    int flags;
    list *reply;
    // ... 许多其他字段 ...
    char buf[PROTO_REPLY_CHUNK_BYTES];
}
```

client 结构定义了一个已连接的客户端:

* `fd` 字段是客户端套接字文件描述符。
* `argc` 和 `argv` 填充了客户端正在执行的命令,这样实现给定 Redis 命令的函数就可以读取参数。
* `querybuf` 累积来自客户端的请求,Redis 服务器根据 Redis 协议解析这些请求,并通过调用客户端正在执行的命令的实现来执行。
* `reply` 和 `buf` 是动态和静态缓冲区,累积服务器发送给客户端的回复。一旦文件描述符可写,这些缓冲区就会逐步写入套接字。

如您在上面的客户端结构中所见,命令中的参数被描述为 `robj` 结构。以下是完整的 `robj` 结构,它定义了一个 Redis 对象:

```c
struct redisObject {
    unsigned type:4;
    unsigned encoding:4;
    unsigned lru:LRU_BITS; /* LRU 时间(相对于全局 lru_clock)或
                            * LFU 数据(最低有效 8 位频率
                            * 和最高有效 16 位访问时间)。*/
    int refcount;
    void *ptr;
};
```

基本上这个结构可以表示所有基本的 Redis 数据类型,如字符串、列表、集合、有序集合等。有趣的是它有一个 `type` 字段,所以可以知道给定对象的类型,还有一个 `refcount`,这样同一个对象就可以在多个地方引用而不需要多次分配。最后,`ptr` 字段指向对象的实际表示,即使对于相同的类型,根据使用的 `encoding`,也可能有所不同。

Redis 对象在 Redis 内部广泛使用,但是为了避免间接访问的开销,最近在许多地方我们只使用不包装在 Redis 对象中的普通动态字符串。

server.c
---

这是 Redis 服务器的入口点,其中定义了 `main()` 函数。以下是启动 Redis 服务器的最重要步骤。

* `initServerConfig()` 设置 `server` 结构的默认值。
* `initServer()` 分配操作所需的数据结构,设置监听套接字等。
* `aeMain()` 启动事件循环,监听新连接。

事件循环定期调用两个特殊函数:

1. `serverCron()` 根据 `server.hz` 频率定期调用,执行必须不时执行的任务,如检查超时客户端。
2. `beforeSleep()` 在事件循环触发、Redis 服务了一些请求并返回事件循环之前每次都会调用。

在 server.c 中,您可以找到处理 Redis 服务器其他重要事项的代码:

* `call()` 用于在给定客户端的上下文中调用给定命令。
* `activeExpireCycle()` 处理通过 `EXPIRE` 命令设置了生存时间的键的过期。
* `performEvictions()` 在应该执行新的写命令但 Redis 根据 `maxmemory` 指令耗尽内存时调用。
* 全局变量 `redisCommandTable` 定义了所有 Redis 命令,指定命令名称、实现命令的函数、所需参数数量和每个命令的其他属性。

commands.c
---

此文件由 utils/generate-command-code.py 自动生成,内容基于 src/commands 文件夹中的 JSON 文件。
这些文件旨在成为 Redis 命令的唯一真实来源,以及关于它们的所有元数据。
这些 JSON 文件不是供任何人直接使用的,相反,可以通过 `COMMAND` 命令获取该元数据。

networking.c
---

此文件定义了与客户端、主服务器和副本(在 Redis 中只是特殊的客户端)的所有 I/O 函数:

* `createClient()` 分配并初始化一个新客户端。
* `addReply*()` 系列函数由命令实现使用,以便将数据附加到客户端结构中,这些数据将作为给定命令执行的回复传输给客户端。
* `writeToClient()` 将输出缓冲区中待处理的数据传输给客户端,由可写事件处理程序 `sendReplyToClient()` 调用。
* `readQueryFromClient()` 是可读事件处理程序,将从客户端读取的数据累积到查询缓冲区中。
* `processInputBuffer()` 是根据 Redis 协议解析客户端查询缓冲区的入口点。一旦命令准备好处理,它就会调用 `server.c` 中定义的 `processCommand()` 来实际执行命令。
* `freeClient()` 释放、断开连接并移除客户端。

aof.c 和 rdb.c
---

顾名思义,这些文件实现了 Redis 的 RDB 和 AOF 持久性。Redis 使用基于 `fork()` 系统调用的持久性模型,以创建一个与主 Redis 进程具有相同(共享)内存内容的进程。这个辅助进程将内存内容转储到磁盘上。`rdb.c` 使用这种方式在磁盘上创建快照,`aof.c` 在追加文件变得太大时用于执行 AOF 重写。

`aof.c` 中的实现有额外的函数,用于实现一个 API,允许命令在客户端执行时将新命令追加到 AOF 文件中。

`server.c` 中定义的 `call()` 函数负责调用将命令写入 AOF 的函数。

db.c
---

某些 Redis 命令操作特定的数据类型;其他的是通用的。通用命令的例子是 `DEL` 和 `EXPIRE`。它们操作键而不是特定的值。所有这些通用命令都在 `db.c` 中定义。

此外,`db.c` 实现了一个 API,可以在不直接访问内部数据结构的情况下对 Redis 数据集执行某些操作。

`db.c` 中最重要的函数,在许多命令实现中使用的是:

* `lookupKeyRead()` 和 `lookupKeyWrite()` 用于获取与给定键关联的值的指针,如果键不存在则返回 `NULL`。
* `dbAdd()` 和它的高级对应项 `setKey()` 在 Redis 数据库中创建一个新键。
* `dbDelete()` 移除一个键及其关联的值。
* `emptyDb()` 移除单个整个数据库或所有定义的数据库。

文件的其余部分实现了向客户端公开的通用命令。

object.c
---

定义 Redis 对象的 `robj` 结构已经描述过了。在 `object.c` 中有所有在基本级别操作 Redis 对象的函数,如用于分配新对象、处理引用计数等的函数。此文件中的重要函数:

* `incrRefCount()` 和 `decrRefCount()` 用于增加或减少对象引用计数。当计数降到 0 时,对象最终被释放。
* `createObject()` 分配一个新对象。还有一些专门用于分配具有特定内容的字符串对象的函数,如 `createStringObjectFromLongLong()` 和类似函数。

此文件还实现了 `OBJECT` 命令。

replication.c
---

这是 Redis 中最复杂的文件之一,建议只有在对代码库的其他部分有一定熟悉度后才接触它。
此文件中包含了 Redis 的主服务器和副本角色的实现。

此文件中最重要的函数之一是 `replicationFeedSlaves()`,它将命令写入连接到我们主服务器的代表副本实例的客户端,这样副本就可以获得客户端执行的写操作:这样它们的数据集将与主服务器中的保持同步。

此文件还实现了 `SYNC` 和 `PSYNC` 命令,这些命令用于执行主服务器和副本之间的首次同步,或在断开连接后继续复制。

脚本
---

脚本单元由 3 个单元组成:
* `script.c` - 脚本与 Redis 的集成(命令执行、设置复制/resp 等)
* `script_lua.c` - 负责执行 Lua 代码,使用 script.c 从 Lua 代码中与 Redis 交互。
* `function_lua.c` - 包含 Lua 引擎实现,使用 script_lua.c 执行 Lua 代码。
* `functions.c` - 包含 Redis Functions 实现(FUNCTION 命令),如果要调用的函数需要 Lua 引擎,则使用 functions_lua.c。
* `eval.c` - 包含使用 `script_lua.c` 调用 Lua 代码的 `eval` 实现。

其他 C 文件
---

* `t_hash.c`、`t_list.c`、`t_set.c`、`t_string.c`、`t_zset.c` 和 `t_stream.c` 包含 Redis 数据类型的实现。它们既实现了访问给定数据类型的 API,也实现了这些数据类型的客户端命令。
* `ae.c` 实现了 Redis 事件循环,它是一个独立的库,简单易读易懂。
* `sds.c` 是 Redis 字符串库,更多信息请查看 https://github.com/antirez/sds。
* `anet.c` 是一个库,用于以比内核公开的原始接口更简单的方式使用 POSIX 网络。
* `dict.c` 是一个非阻塞哈希表的实现,它逐步重新哈希。
* `cluster.c` 实现了 Redis Cluster。可能只有在非常熟悉 Redis 代码库的其他部分后才值得阅读。如果您想阅读 `cluster.c`,请确保阅读 [Redis Cluster 规范][4]。

[4]: https://redis.io/topics/cluster-spec

Redis 命令剖析
---

所有 Redis 命令都以以下方式定义:

```c
void foobarCommand(client *c) {
    printf("%s",c->argv[1]->ptr); /* 对参数做一些处理。*/
    addReply(c,shared.ok); /* 向客户端回复一些内容。*/
}
```

命令函数由 JSON 文件引用,同时还有其元数据,有关详细信息请参见上面描述的 `commands.c`。
命令标志在 `server.h` 中 `struct redisCommand` 上方的注释中有文档说明。
有关其他详细信息,请参考 `COMMAND` 命令。https://redis.io/commands/command/

命令以某种方式操作后,它会向客户端返回回复,通常使用 `addReply()` 或 `networking.c` 中定义的类似函数。

Redis 源代码中有大量命令实现可以作为实际命令实现的示例(例如 pingCommand)。编写一些玩具命令可能是熟悉代码库的好练习。

还有许多其他未在此处描述的文件,但涵盖所有内容是没有意义的。我们只是想帮助您迈出第一步。
最终您会在 Redis 代码库中找到自己的方向 :-)

祝您使用愉快!