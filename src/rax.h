/* Rax -- 基数树实现
 *
 * 版权所有 (c) 2017-2018, Salvatore Sanfilippo <antirez at gmail dot com>
 * 保留所有权利。
 *
 * 在满足以下条件的情况下，允许以源代码和二进制形式重新分发和使用，
 * 无论是否进行修改：
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef RAX_H
#define RAX_H

#include <stdint.h>

/* 本文件实现的基数树表示方法，包含了在插入每个单词后的字符串
 * "foo"、"foobar" 和 "footer"。当节点在基数树中代表一个键时，
 * 我们用 [] 括起来表示，否则用 () 括起来表示。
 *
 * 这是最基本的表示方法:
 *
 *              (f) ""
 *                \
 *                (o) "f"
 *                  \
 *                  (o) "fo"
 *                    \
 *                  [t   b] "foo"
 *                  /     \
 *         "foot" (e)     (a) "foob"
 *                /         \
 *      "foote" (r)         (r) "fooba"
 *              /             \
 *    "footer" []             [] "foobar"
 *
 * 然而，本实现采用了一种非常常见的优化方式，其中连续的只有单个子节点的节点
 * 被"压缩"到节点本身中，形成一个字符串，每个字符代表下一级子节点，
 * 并且在表示中只提供指向代表最后一个字符节点的链接。因此上述表示变为:
 *
 *                  ["foo"] ""
 *                     |
 *                  [t   b] "foo"
 *                  /     \
 *        "foot" ("er")    ("ar") "foob"
 *                 /          \
 *       "footer" []          [] "foobar"
 *
 * 但是这种优化使得实现变得更加复杂。
 * 例如，如果在上述基数树中添加一个键 "first"，就需要进行
 * "节点分裂"操作，因为 "foo" 前缀不再是由一系列只有单个子节点
 * 的节点组成。这是发生这个事件后的上述树和结果节点分裂:
 *
 *                    (f) ""
 *                    /
 *                 (i o) "f"
 *                 /   \
 *    "firs"  ("rst")  (o) "fo"
 *              /        \
 *    "first" []       [t   b] "foo"
 *                     /     \
 *           "foot" ("er")    ("ar") "foob"
 *                    /          \
 *          "footer" []          [] "foobar"
 *
 * 类似地，在删除操作后，如果创建了一个新的只有单个子节点的节点链
 * (该链还必须不包含表示键的节点)，它必须被压缩回单个节点。
 *
 */

#define RAX_NODE_MAX_SIZE ((1<<29)-1) /* 节点最大大小是 2^29 - 1 = 536870911 */
typedef struct raxNode {
    uint32_t iskey:1;    /* 节点是否包含键 */
    uint32_t isnull:1;   /* 关联值为 NULL（不存储） */
    uint32_t iscompr:1;  /* 节点是否被压缩 */
    uint32_t size:29;    /* 子节点数量，或压缩字符串长度 */
    /* 数据布局如下：
     *
     * 如果节点未被压缩，则有 'size' 字节，每个字节代表一个子节点字符，
     * 以及 'size' 个 raxNode 指针，指向每个子节点。注意字符并未存储在
     * 子节点中，而是存储在父节点的边上：
     *
     * [header iscompr=0][abc][a-ptr][b-ptr][c-ptr](value-ptr?)
     *
     * 如果节点被压缩（iscompr 位为 1），则该节点有 1 个子节点。在这种情况下，
     * 数据段开头的 'size' 字节表示一个连续的子节点链，每个子节点字符存储在
     * 该链中。只有链中的最后一个节点实际表示为一个节点，并由当前压缩节点指向。
     *
     * [header iscompr=1][xyz][z-ptr](value-ptr?)
     *
     * 无论是压缩节点还是未压缩节点，都可以在基数树的任何级别（不仅仅是终端节点）
     * 中表示一个键及其关联数据。
     *
     * 如果节点有相关联的键（iskey=1）且不为 NULL（isnull=0），则在指向子节点的
     * raxNode 指针之后，会额外存在一个值指针（如上所示的 "value-ptr" 字段）。
     */
    unsigned char data[];
} raxNode;

typedef struct rax {
    raxNode *head; /* 树的根节点 */
    uint64_t numele; /* 树中元素的数量 */
    uint64_t numnodes; /* 树中节点的数量 */
} rax;

/* 栈数据结构，用于 raxLowWalk() 中，可选地返回一个包含父节点的列表。
 * 节点没有 "parent" 字段，因此当需要时使用辅助栈。 */
#define RAX_STACK_STATIC_ITEMS 32 /* 栈中静态项数 */
typedef struct raxStack {
    void **stack; /* 指向 static_items 或堆分配的数组。 */
    size_t items, maxitems; /* 包含的项数和总空间。 */
    /* 在 RAXSTACK_STACK_ITEMS 项以内，我们避免在堆上分配，
     * 而是使用这个静态数组指针。 */
    void *static_items[RAX_STACK_STATIC_ITEMS];
    int oom; /* 如果向此栈中推入时发生 OOM，则为 true。 */
} raxStack;

/* 可选回调，用于迭代器，并在每个 rax 节点上通知。
 * 包括不表示键的节点。如果回调返回 true，
 * 回调改变了迭代器结构中的节点指针，迭代器实现将不得不
 * 在基数树内部替换指针。这允许回调重新分配节点以执行
 * 非常特殊操作，通常不需要正常应用程序。
 *
 * 此回调用于执行基数树的非常低级别的分析，扫描每个可能的节点
 * （但根节点），或者重新分配节点以减少分配碎片（这是此回调的 Redis 应用程序）。
 *
 * 目前仅支持正向迭代（raxNext） */
typedef int (*raxNodeCallback)(raxNode **noderef);

/* 基数树迭代器状态封装在此数据结构中。 */
#define RAX_ITER_STATIC_LEN 128
#define RAX_ITER_JUST_SEEKED (1<<0) /* 迭代器刚被 seek。返回当前元素
                                       for the first iteration and
                                       clear the flag. */
#define RAX_ITER_EOF (1<<1)    /* 迭代结束。 */
#define RAX_ITER_SAFE (1<<2)   /* 安全迭代器，允许在迭代时进行操作。但速度较慢。 */
typedef struct raxIterator {
    int flags;
    rax *rt;                /* 正在迭代的基数树。 */
    unsigned char *key;     /* 当前字符串。 */
    void *data;             /* 与此键关联的数据。 */
    size_t key_len;         /* 当前键长度。 */
    size_t key_max;         /* 当前键缓冲区可以容纳的最大长度。 */
    unsigned char key_static_string[RAX_ITER_STATIC_LEN];
    raxNode *node;          /* 当前节点。仅用于不安全的迭代。 */
    raxStack stack;         /* 用于不安全迭代的栈。 */
    raxNodeCallback node_cb; /* 可选节点回调。通常设置为 NULL。 */
} raxIterator;

/* 未找到项的特殊指针。 */
extern void *raxNotFound;

/* 导出 API。 */
rax *raxNew(void);
int raxInsert(rax *rax, unsigned char *s, size_t len, void *data, void **old);
int raxTryInsert(rax *rax, unsigned char *s, size_t len, void *data, void **old);
int raxRemove(rax *rax, unsigned char *s, size_t len, void **old);
void *raxFind(rax *rax, unsigned char *s, size_t len);
void raxFree(rax *rax);
void raxFreeWithCallback(rax *rax, void (*free_callback)(void*));
void raxStart(raxIterator *it, rax *rt);
int raxSeek(raxIterator *it, const char *op, unsigned char *ele, size_t len);
int raxNext(raxIterator *it);
int raxPrev(raxIterator *it);
int raxRandomWalk(raxIterator *it, size_t steps);
int raxCompare(raxIterator *iter, const char *op, unsigned char *key, size_t key_len);
void raxStop(raxIterator *it);
int raxEOF(raxIterator *it);
void raxShow(rax *rax);
uint64_t raxSize(rax *rax);
unsigned long raxTouch(raxNode *n);
void raxSetDebugMsg(int onoff);

/* 内部 API。可能由节点回调使用，以低级方式访问基数树节点，因此此函数也导出。 */
void raxSetData(raxNode *n, void *data);

#endif
