#ifndef STREAM_H
#define STREAM_H

#include "rax.h"
#include "listpack.h"

/* Stream的item ID: 一个128位的数字，由一个毫秒时间和一个序列号组成。在同一毫秒（或过去某个毫秒，如果时钟向后跳跃）生成的ID将使用最新生成的ID的毫秒时间
 * 和递增的序列号。 */
typedef struct streamID {
    uint64_t ms;        /* unix 时间戳，单位为毫秒 */
    uint64_t seq;       /* 序列号 */
} streamID;

typedef struct stream {
    rax *rax;               /* 存储stream的radix tree */
    uint64_t length;        /* 当前stream中的元素数量 */
    streamID last_id;       /* 如果stream为空，则为0 */
    streamID first_id;      /* 第一个非tombstone entry，如果stream为空，则为0 */
    streamID max_deleted_entry_id;  /* 被删除的最大ID */
    uint64_t entries_added; /* 所有添加的元素数量 */
    rax *cgroups;           /* 消费组: name -> streamCG */
} stream;

/* We define an iterator to iterate stream items in an abstract way, without
 * caring about the radix tree + listpack representation. Technically speaking
 * the iterator is only used inside streamReplyWithRange(), so could just
 * be implemented inside the function, but practically there is the AOF
 * rewriting code that also needs to iterate the stream to emit the XADD
 * commands. */
typedef struct streamIterator {
    stream *stream;         /* The stream we are iterating. */
    streamID master_id;     /* ID of the master entry at listpack head. */
    uint64_t master_fields_count;       /* Master entries # of fields. */
    unsigned char *master_fields_start; /* Master entries start in listpack. */
    unsigned char *master_fields_ptr;   /* Master field to emit next. */
    int entry_flags;                    /* Flags of entry we are emitting. */
    int rev;                /* True if iterating end to start (reverse). */
    int skip_tombstones;    /* True if not emitting tombstone entries. */
    uint64_t start_key[2];  /* Start key as 128 bit big endian. */
    uint64_t end_key[2];    /* End key as 128 bit big endian. */
    raxIterator ri;         /* Rax iterator. */
    unsigned char *lp;      /* Current listpack. */
    unsigned char *lp_ele;  /* Current listpack cursor. */
    unsigned char *lp_flags; /* Current entry flags pointer. */
    /* Buffers used to hold the string of lpGet() when the element is
     * integer encoded, so that there is no string representation of the
     * element inside the listpack itself. */
    unsigned char field_buf[LP_INTBUF_SIZE];
    unsigned char value_buf[LP_INTBUF_SIZE];
} streamIterator;

/* Consumer group. */
typedef struct streamCG {
    streamID last_id;       /* 此组最后交付（未确认）的ID。消费者只需请求更多消息，就会使用大于此ID的消息。 */
    long long entries_read; /* 在理想世界中（CG从0-0开始，没有删除，没有XGROUP SETID，...），这是组读取的总次数。
                              在现实世界中，这个值的推理细节在
                               streamEstimateDistanceFromFirstEverEntry()的顶部注释中。 */
    rax *pel;               /* 待处理条目列表。这是一个radix树，包含所有已交付但未确认的消息（不包括NOACK选项）。
                               radix树的键是64位大端数表示的ID，而关联值是streamNACK结构。*/
    rax *consumers;         /* 一个radix树，表示消费者名称及其关联的streamConsumer结构。 */
} streamCG;

/* 一个特定消费者在消费者组中。 */
typedef struct streamConsumer {
    mstime_t seen_time;         /* 上次尝试执行操作（读取/声明）的时间。 */
    mstime_t active_time;       /* 上次此消费者活跃（成功读取/声明）的时间。 */
    sds name;                   /* 消费者名称。这是消费者在消费者组协议中将如何识别。区分大小写。 */
    rax *pel;                   /* 消费者特定待处理条目列表：所有待处理消息，未确认。键是64位大端数表示的ID，值是streamNACK结构。 */
} streamConsumer;

/* 消费者组中待处理（尚未确认）的消息。 */
typedef struct streamNACK {
    mstime_t delivery_time;     /* 上次此消息被交付的时间。 */
    uint64_t delivery_count;    /* 此消息被交付的次数。*/
    streamConsumer *consumer;   /* 此消息被交付到的消费者。 */
} streamNACK;

/* Stream传播信息，传递给函数以传播XCLAIM命令到AOF和从属服务器。 */
typedef struct streamPropInfo {
    robj *keyname;
    robj *groupname;
} streamPropInfo;

/* Prototypes of exported APIs. */
struct client;

/* 用于 streamCreateConsumer 的标志 */
#define SCC_DEFAULT       0
#define SCC_NO_NOTIFY     (1<<0) /* 如果创建消费者,则不通知键空间 */
#define SCC_NO_DIRTIFY    (1<<1) /* 如果创建消费者,则不增加脏位 */

#define SCG_INVALID_ENTRIES_READ -1

stream *streamNew(void);
void freeStream(stream *s);
unsigned long streamLength(const robj *subject);
size_t streamReplyWithRange(client *c, stream *s, streamID *start, streamID *end, size_t count, int rev, streamCG *group, streamConsumer *consumer, int flags, streamPropInfo *spi);
void streamIteratorStart(streamIterator *si, stream *s, streamID *start, streamID *end, int rev);
int streamIteratorGetID(streamIterator *si, streamID *id, int64_t *numfields);
void streamIteratorGetField(streamIterator *si, unsigned char **fieldptr, unsigned char **valueptr, int64_t *fieldlen, int64_t *valuelen);
void streamIteratorRemoveEntry(streamIterator *si, streamID *current);
void streamIteratorStop(streamIterator *si);
streamCG *streamLookupCG(stream *s, sds groupname);
streamConsumer *streamLookupConsumer(streamCG *cg, sds name);
streamConsumer *streamCreateConsumer(streamCG *cg, sds name, robj *key, int dbid, int flags);
streamCG *streamCreateCG(stream *s, char *name, size_t namelen, streamID *id, long long entries_read);
streamNACK *streamCreateNACK(streamConsumer *consumer);
void streamDecodeID(void *buf, streamID *id);
int streamCompareID(streamID *a, streamID *b);
void streamFreeNACK(streamNACK *na);
int streamIncrID(streamID *id);
int streamDecrID(streamID *id);
void streamPropagateConsumerCreation(client *c, robj *key, robj *groupname, sds consumername);
robj *streamDup(robj *o);
int streamValidateListpackIntegrity(unsigned char *lp, size_t size, int deep);
int streamParseID(const robj *o, streamID *id);
robj *createObjectFromStreamID(streamID *id);
int streamAppendItem(stream *s, robj **argv, int64_t numfields, streamID *added_id, streamID *use_id, int seq_given);
int streamDeleteItem(stream *s, streamID *id);
void streamGetEdgeID(stream *s, int first, int skip_tombstones, streamID *edge_id);
long long streamEstimateDistanceFromFirstEverEntry(stream *s, streamID *id);
int64_t streamTrimByLength(stream *s, long long maxlen, int approx);
int64_t streamTrimByID(stream *s, streamID minid, int approx);

#endif
