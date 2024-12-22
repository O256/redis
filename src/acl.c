/*
 * 版权所有 (c) 2018, Salvatore Sanfilippo <antirez at gmail dot com>
 * 保留所有权利。
 *
 * 在满足以下条件的情况下，允许以源代码和二进制形式重新分发和使用，
 * 无论是否进行修改：
 *
 *   * 源代码的再分发必须保留上述版权声明、本条件列表和以下免责声明。
 *   * 以二进制形式再分发必须在随分发提供的文档和/或其他材料中复制上述
 *     版权声明、本条件列表和以下免责声明。
 *   * 未经特定的事先书面许可，不得使用Redis或其贡献者的名字来为衍生的
 *     产品背书或推广。
 *
 * 本软件由版权所有者和贡献者"按原样"提供，不提供任何明示或暗示的保证，
 * 包括但不限于对适销性和特定用途适用性的保证。在任何情况下，版权所有者
 * 或贡献者均不对任何直接、间接、偶然、特殊、惩戒性或后果性损害（包括但
 * 不限于采购替代商品或服务；使用价值、数据或利润的损失；或业务中断）承担
 * 责任，无论是在合同、严格责任或侵权（包括疏忽或其他）行为中产生，即使
 * 已被告知发生此类损害的可能性。
 */

#include "server.h"
#include "sha256.h"
#include <fcntl.h>
#include <ctype.h>

/* =============================================================================
 * ACL 的全局状态
 * ==========================================================================*/

/* 用户名到用户结构的映射表 */
rax *Users; 

/* 默认用户的全局引用。每个新连接都会关联到它,
 * 除非使用 AUTH 或 HELLO 命令认证为其他用户。 */
user *DefaultUser;

/* 这是配置文件中找到的需要加载的用户列表,
 * 我们需要在 Redis 初始化的最后阶段加载它们,
 * 在所有模块都已加载之后。每个列表元素是一个以 NULL 结尾的
 * SDS 指针数组:第一个是用户名,
 * 其余的指针是与 ACLSetUser() 格式相同的 ACL 规则。*/
list *UsersToLoad;

/* 我们的安全日志,用户可以使用 ACL LOG 命令查看它 */
list *ACLLog;

/* 创建的 ACL 日志条目数量 */
long long ACLLogEntryCount = 0;

/* 命令名称到 id 的映射 */
static rax *commandId = NULL;

/* 尚未分配的下一个命令 id */
static unsigned long nextid = 0;

/* 比较两个字符串是否相同,返回零表示相同,非零表示不同。
 * 比较以一种防止攻击者通过监控函数执行时间来获取
 * 字符串性质信息的方式进行。
 * 注意:两个字符串必须长度相同。*/
int time_independent_strcmp(char *a, char *b, int len) {
    int diff = 0;
    for (int j = 0; j < len; j++) {
        diff |= (a[j] ^ b[j]);
    }
    return diff; /* If zero strings are the same. */
}

/* 给定一个 SDS 字符串,返回其 SHA256 十六进制表示形式,
 * 作为一个新的 SDS 字符串。*/
sds ACLHashPassword(unsigned char *cleartext, size_t len) {
    SHA256_CTX ctx;
    unsigned char hash[SHA256_BLOCK_SIZE];
    char hex[HASH_PASSWORD_LEN];
    char *cset = "0123456789abcdef";

    sha256_init(&ctx);
    sha256_update(&ctx,(unsigned char*)cleartext,len);
    sha256_final(&ctx,hash);

    for (int j = 0; j < SHA256_BLOCK_SIZE; j++) {
        hex[j*2] = cset[((hash[j]&0xF0)>>4)];
        hex[j*2+1] = cset[(hash[j]&0xF)];
    }
    return sdsnewlen(hex,HASH_PASSWORD_LEN);
}

/* 给定一个哈希和哈希长度,如果它是一个有效的密码哈希,
 * 则返回 C_OK,否则返回 C_ERR。*/
int ACLCheckPasswordHash(unsigned char *hash, int hashlen) {
    if (hashlen != HASH_PASSWORD_LEN) {
        return C_ERR;
    }

    /* Password hashes can only be characters that represent
     * hexadecimal values, which are numbers and lowercase
     * characters 'a' through 'f'. */
    for(int i = 0; i < HASH_PASSWORD_LEN; i++) {
        char c = hash[i];
        if ((c < 'a' || c > 'f') && (c < '0' || c > '9')) {
            return C_ERR;
        }
    }
    return C_OK;
}

/* =============================================================================
 * 低级 ACL API
 * ==========================================================================*/

/* 如果指定的字符串包含空格或空字符,返回 1。
 * 我们这样做是为了简化 ACL 规则的重写、ACL list 的展示,
 * 并避免在解析带有转义的规则时可能出现的微妙安全漏洞。
 * 如果字符串没有空格,函数返回 0。*/
int ACLStringHasSpaces(const char *s, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (isspace(s[i]) || s[i] == 0) return 1;
    }
    return 0;
}

/* 给定类别名称,命令返回相应的标志,如果没有匹配则返回零。*/
uint64_t ACLGetCommandCategoryFlagByName(const char *name) {
    for (int j = 0; ACLCommandCategories[j].flag != 0; j++) {
        if (!strcasecmp(name,ACLCommandCategories[j].name)) {
            return ACLCommandCategories[j].flag;
        }
    }
    return 0; /* No match. */
}

/* 用于搜索用户定义列表的方法。该列表包含用户参数数组,
 * 我们只搜索第一个参数,即用户名,是否匹配。*/
int ACLListMatchLoadedUser(void *definition, void *user) {
    sds *user_definition = definition;
    return sdscmp(user_definition[0], user) == 0;
}

/* 用于用户->密码/模式列表的密码/模式比较方法,
 * 以便我们可以使用 listSearchKey() 搜索项。*/
int ACLListMatchSds(void *a, void *b) {
    return sdscmp(a,b) == 0;
}

/* 用于释放 ACL 用户密码/模式列表元素的方法。*/
void ACLListFreeSds(void *item) {
    sdsfree(item);
}

/* 用于复制 ACL 用户密码/模式列表元素的方法。*/
void *ACLListDupSds(void *item) {
    return sdsdup(item);
}

/* 用于处理具有不同基于键的权限的键模式的结构。*/
typedef struct {
    int flags; /* The CMD_KEYS_* flags for this key pattern */
    sds pattern; /* The pattern to match keys against */
} keyPattern;

/* 创建一个新的键模式。*/
keyPattern *ACLKeyPatternCreate(sds pattern, int flags) {
    keyPattern *new = (keyPattern *) zmalloc(sizeof(keyPattern));
    new->pattern = pattern;
    new->flags = flags;
    return new;
}

/* 释放键模式和内部结构。*/
void ACLKeyPatternFree(keyPattern *pattern) {
    sdsfree(pattern->pattern);
    zfree(pattern);
}

/* 用于用户->密码/模式列表的密码/模式比较方法,
 * 以便我们可以使用 listSearchKey() 搜索项。*/
int ACLListMatchKeyPattern(void *a, void *b) {
    return sdscmp(((keyPattern *) a)->pattern,((keyPattern *) b)->pattern) == 0;
}

/* 用于释放 ACL 用户密码/模式列表元素的方法。*/
void ACLListFreeKeyPattern(void *item) {
    ACLKeyPatternFree(item);
}

/* 用于复制 ACL 用户密码/模式列表元素的方法。*/
void *ACLListDupKeyPattern(void *item) {
    keyPattern *old = (keyPattern *) item;
    return ACLKeyPatternCreate(sdsdup(old->pattern), old->flags);
}

/* 将键模式的字符串表示附加到提供的基础字符串上。*/
sds sdsCatPatternString(sds base, keyPattern *pat) {
    if (pat->flags == ACL_ALL_PERMISSION) {
        base = sdscatlen(base,"~",1);
    } else if (pat->flags == ACL_READ_PERMISSION) {
        base = sdscatlen(base,"%R~",3);
    } else if (pat->flags == ACL_WRITE_PERMISSION) {
        base = sdscatlen(base,"%W~",3);
    } else {
        serverPanic("Invalid key pattern flag detected");
    }
    return sdscatsds(base, pat->pattern);
}

/* 创建一个空的选择器,并使用提供的初始标志集。
 * 选择器将默认没有权限。*/
aclSelector *ACLCreateSelector(int flags) {
    aclSelector *selector = zmalloc(sizeof(aclSelector));
    selector->flags = flags | server.acl_pubsub_default;
    selector->patterns = listCreate();
    selector->channels = listCreate();
    selector->allowed_firstargs = NULL;
    selector->command_rules = sdsempty();

    listSetMatchMethod(selector->patterns,ACLListMatchKeyPattern);
    listSetFreeMethod(selector->patterns,ACLListFreeKeyPattern);
    listSetDupMethod(selector->patterns,ACLListDupKeyPattern);
    listSetMatchMethod(selector->channels,ACLListMatchSds);
    listSetFreeMethod(selector->channels,ACLListFreeSds);
    listSetDupMethod(selector->channels,ACLListDupSds);
    memset(selector->allowed_commands,0,sizeof(selector->allowed_commands));

    return selector;
}

/* 清理提供的选择器,包括所有内部结构。*/
void ACLFreeSelector(aclSelector *selector) {
    listRelease(selector->patterns);
    listRelease(selector->channels);
    sdsfree(selector->command_rules);
    ACLResetFirstArgs(selector);
    zfree(selector);
}

/* 创建提供的选择器的精确副本。*/
aclSelector *ACLCopySelector(aclSelector *src) {
    aclSelector *dst = zmalloc(sizeof(aclSelector));
    dst->flags = src->flags;
    dst->patterns = listDup(src->patterns);
    dst->channels = listDup(src->channels);
    dst->command_rules = sdsdup(src->command_rules);
    memcpy(dst->allowed_commands,src->allowed_commands,
           sizeof(dst->allowed_commands));
    dst->allowed_firstargs = NULL;
    /* Copy the allowed first-args array of array of SDS strings. */
    if (src->allowed_firstargs) {
        for (int j = 0; j < USER_COMMAND_BITS_COUNT; j++) {
            if (!(src->allowed_firstargs[j])) continue;
            for (int i = 0; src->allowed_firstargs[j][i]; i++) {
                ACLAddAllowedFirstArg(dst, j, src->allowed_firstargs[j][i]);
            }
        }
    }
    return dst;
}

/* 用于释放选择器的列表方法*/
void ACLListFreeSelector(void *a) {
    ACLFreeSelector((aclSelector *) a);
}

/* 用于复制选择器的列表方法*/
void *ACLListDuplicateSelector(void *src) {
    return ACLCopySelector((aclSelector *)src);
}

/* 所有用户都有一个隐式的根选择器,
 * 它提供了对旧 ACLs-
 * 权限的向后兼容性。*/
aclSelector *ACLUserGetRootSelector(user *u) {
    serverAssert(listLength(u->selectors));
    aclSelector *s = (aclSelector *) listNodeValue(listFirst(u->selectors));
    serverAssert(s->flags & SELECTOR_FLAG_ROOT);
    return s;
}

/* 创建一个具有指定名称的新用户,将其存储在用户列表中(Users 全局基数树),
 * 并返回一个引用该用户结构的指针。
 *
 * 如果已存在具有该名称的用户,则返回 NULL。*/
user *ACLCreateUser(const char *name, size_t namelen) {
    if (raxFind(Users,(unsigned char*)name,namelen) != raxNotFound) return NULL;
    user *u = zmalloc(sizeof(*u));
    u->name = sdsnewlen(name,namelen);
    u->flags = USER_FLAG_DISABLED;
    u->flags |= USER_FLAG_SANITIZE_PAYLOAD;
    u->passwords = listCreate();
    u->acl_string = NULL;
    listSetMatchMethod(u->passwords,ACLListMatchSds);
    listSetFreeMethod(u->passwords,ACLListFreeSds);
    listSetDupMethod(u->passwords,ACLListDupSds);

    u->selectors = listCreate();
    listSetFreeMethod(u->selectors,ACLListFreeSelector);
    listSetDupMethod(u->selectors,ACLListDuplicateSelector);

    /* Add the initial root selector */
    aclSelector *s = ACLCreateSelector(SELECTOR_FLAG_ROOT);
    listAddNodeHead(u->selectors, s);

    raxInsert(Users,(unsigned char*)name,namelen,u,NULL);
    return u;
}

/* 当我们需要一个未链接的"假"用户时,
 * 我们可以使用它来验证 ACL 规则或进行其他类似的操作。
 * 用户不会链接到 Users 基数树。返回的用户应该使用 ACLFreeUser() 释放,
 * 就像通常一样。*/
user *ACLCreateUnlinkedUser(void) {
    char username[64];
    for (int j = 0; ; j++) {
        snprintf(username,sizeof(username),"__fakeuser:%d__",j);
        user *fakeuser = ACLCreateUser(username,strlen(username));
        if (fakeuser == NULL) continue;
        int retval = raxRemove(Users,(unsigned char*) username,
                               strlen(username),NULL);
        serverAssert(retval != 0);
        return fakeuser;
    }
}

/* 释放用户结构使用的内存。注意,此函数
 * 不会从 Users 全局基数树中删除用户。*/
void ACLFreeUser(user *u) {
    sdsfree(u->name);
    if (u->acl_string) {
        decrRefCount(u->acl_string);
        u->acl_string = NULL;
    }
    listRelease(u->passwords);
    listRelease(u->selectors);
    zfree(u);
}

/* 当用户被删除时,我们需要循环遍历活动连接,
 * 以便终止所有使用该用户进行身份验证的挂起连接。*/
void ACLFreeUserAndKillClients(user *u) {
    listIter li;
    listNode *ln;
    listRewind(server.clients,&li);
    while ((ln = listNext(&li)) != NULL) {
        client *c = listNodeValue(ln);
        if (c->user == u) {
            /* 我们将异步释放连接,所以
             * 从技术上讲,不需要设置不同的用户。
             * 但是,如果 Redis 中有错误,不久之后
             * 这可能会导致一些安全漏洞:更加防御性地设置默认用户并将其置于
             * 未经身份验证模式。*/
            c->user = DefaultUser;
            c->authenticated = 0;
            /* 我们将在此客户端写入回复,所以我们不能
             * 直接关闭它,即使是异步的。*/
            if (c == server.current_client) {
                c->flags |= CLIENT_CLOSE_AFTER_COMMAND;
            } else {
                freeClientAsync(c);
            }
        }
    }
    ACLFreeUser(u);
}

/* 将用户 ACL 规则从源用户 'src' 复制到目标用户 'dst',
 * 这样最终它们将具有完全相同的规则(但名称将继续是原始名称)。*/
void ACLCopyUser(user *dst, user *src) {
    listRelease(dst->passwords);
    listRelease(dst->selectors);
    dst->passwords = listDup(src->passwords);
    dst->selectors = listDup(src->selectors);
    dst->flags = src->flags;
    if (dst->acl_string) {
        decrRefCount(dst->acl_string);
    }
    dst->acl_string = src->acl_string;
    if (dst->acl_string) {
        /* if src is NULL, we set it to NULL, if not, need to increment reference count */
        incrRefCount(dst->acl_string);
    }
}

/* 释放存储在基数树 'users' 中的所有用户,并释放
 * 基数树本身。*/
void ACLFreeUsersSet(rax *users) {
    raxFreeWithCallback(users,(void(*)(void*))ACLFreeUserAndKillClients);
}

/* 给定命令 ID,此函数设置 'word' 和 'bit' 的引用,
 * 以便 user->allowed_commands[word] 将地址正确的单词,
 * 其中包含指定 ID 的相应位,并且
 * 以便 user->allowed_commands[word]&bit 将标识该特定位。
 * 如果指定的 ID 溢出了用户内部表示,
 * 该函数将返回 C_ERR。*/
int ACLGetCommandBitCoordinates(uint64_t id, uint64_t *word, uint64_t *bit) {
    if (id >= USER_COMMAND_BITS_COUNT) return C_ERR;
    *word = id / sizeof(uint64_t) / 8;
    *bit = 1ULL << (id % (sizeof(uint64_t) * 8));
    return C_OK;
}

/* 检查指定的命令位是否设置为指定的用户。
 * 如果设置了该位,该函数返回 1,如果未设置则返回 0。
 * 注意,此函数不检查用户的 ALLCOMMANDS 标志,
 * 而只是低级位掩码。
 *
 * 如果位溢出了用户内部表示,则返回零,
 * 以避免在这种边缘情况下执行命令。*/
int ACLGetSelectorCommandBit(const aclSelector *selector, unsigned long id) {
    uint64_t word, bit;
    if (ACLGetCommandBitCoordinates(id,&word,&bit) == C_ERR) return 0;
    return (selector->allowed_commands[word] & bit) != 0;
}

/* 当给出 +@all 或 allcommands 时,我们会设置一个保留位,
 * 以便我们以后可以测试用户是否有权执行"未来命令",
 * 即通过模块加载的命令。*/
int ACLSelectorCanExecuteFutureCommands(aclSelector *selector) {
    return ACLGetSelectorCommandBit(selector,USER_COMMAND_BITS_COUNT-1);
}

/* 将指定用户的指定命令位设置为 'value' (0 或 1)。
 * 如果位溢出了用户内部表示,则不执行任何操作。
 * 作为调用此函数的副作用,如果值为零,
 * 用户标志 ALLCOMMANDS 将被清除,因为不再可能跳过
 * 命令位显式测试。*/
void ACLSetSelectorCommandBit(aclSelector *selector, unsigned long id, int value) {
    uint64_t word, bit;
    if (ACLGetCommandBitCoordinates(id,&word,&bit) == C_ERR) return;
    if (value) {
        selector->allowed_commands[word] |= bit;
    } else {
        selector->allowed_commands[word] &= ~bit;
        selector->flags &= ~SELECTOR_FLAG_ALLCOMMANDS;
    }
}

/* 从保留的命令规则中删除一条规则。始终按原样匹配规则,
 * 但也会删除子命令规则,如果我们正在添加或删除整个命令。*/
void ACLSelectorRemoveCommandRule(aclSelector *selector, sds new_rule) {
    size_t new_len = sdslen(new_rule);
    char *existing_rule = selector->command_rules;

    /* Loop over the existing rules, trying to find a rule that "matches"
     * the new rule. If we find a match, then remove the command from the string by
     * copying the later rules over it. */
    while(existing_rule[0]) {
        /* The first character of the rule is +/-, which we don't need to compare. */
        char *copy_position = existing_rule;
        existing_rule += 1;

        /* Assume a trailing space after a command is part of the command, like '+get ', so trim it
         * as well if the command is removed. */
        char *rule_end = strchr(existing_rule, ' ');
        if (!rule_end) {
            /* This is the last rule, so move it to the end of the string. */
            rule_end = existing_rule + strlen(existing_rule);

            /* This approach can leave a trailing space if the last rule is removed,
             * but only if it's not the first rule, so handle that case. */
            if (copy_position != selector->command_rules) copy_position -= 1;
        }
        char *copy_end = rule_end;
        if (*copy_end == ' ') copy_end++;

        /* Exact match or the rule we are comparing is a subcommand denoted by '|' */
        size_t existing_len = rule_end - existing_rule;
        if (!memcmp(existing_rule, new_rule, min(existing_len, new_len))) {
            if ((existing_len == new_len) || (existing_len > new_len && (existing_rule[new_len]) == '|')) {
                /* Copy the remaining rules starting at the next rule to replace the rule to be
                 * deleted, including the terminating NULL character. */
                memmove(copy_position, copy_end, strlen(copy_end) + 1);
                existing_rule = copy_position;
                continue;
            }
        }
        existing_rule = copy_end;
    }

    /* There is now extra padding at the end of the rules, so clean that up. */
    sdsupdatelen(selector->command_rules);
}

/* This function is resopnsible for updating the command_rules struct so that relative ordering of
 * commands and categories is maintained and can be reproduced without loss. */
void ACLUpdateCommandRules(aclSelector *selector, const char *rule, int allow) {
    sds new_rule = sdsnew(rule);
    sdstolower(new_rule);

    ACLSelectorRemoveCommandRule(selector, new_rule);
    if (sdslen(selector->command_rules)) selector->command_rules = sdscat(selector->command_rules, " ");
    selector->command_rules = sdscatfmt(selector->command_rules, allow ? "+%S" : "-%S", new_rule);
    sdsfree(new_rule);
}

/* This function is used to allow/block a specific command.
 * Allowing/blocking a container command also applies for its subcommands */
void ACLChangeSelectorPerm(aclSelector *selector, struct redisCommand *cmd, int allow) {
    unsigned long id = cmd->id;
    ACLSetSelectorCommandBit(selector,id,allow);
    ACLResetFirstArgsForCommand(selector,id);
    if (cmd->subcommands_dict) {
        dictEntry *de;
        dictIterator *di = dictGetSafeIterator(cmd->subcommands_dict);
        while((de = dictNext(di)) != NULL) {
            struct redisCommand *sub = (struct redisCommand *)dictGetVal(de);
            ACLSetSelectorCommandBit(selector,sub->id,allow);
        }
        dictReleaseIterator(di);
    }
}

/* This is like ACLSetSelectorCommandBit(), but instead of setting the specified
 * ID, it will check all the commands in the category specified as argument,
 * and will set all the bits corresponding to such commands to the specified
 * value. Since the category passed by the user may be non existing, the
 * function returns C_ERR if the category was not found, or C_OK if it was
 * found and the operation was performed. */
void ACLSetSelectorCommandBitsForCategory(dict *commands, aclSelector *selector, uint64_t cflag, int value) {
    dictIterator *di = dictGetIterator(commands);
    dictEntry *de;
    while ((de = dictNext(di)) != NULL) {
        struct redisCommand *cmd = dictGetVal(de);
        if (cmd->acl_categories & cflag) {
            ACLChangeSelectorPerm(selector,cmd,value);
        }
        if (cmd->subcommands_dict) {
            ACLSetSelectorCommandBitsForCategory(cmd->subcommands_dict, selector, cflag, value);
        }
    }
    dictReleaseIterator(di);
}

/* This function is responsible for recomputing the command bits for all selectors of the existing users.
 * It uses the 'command_rules', a string representation of the ordered categories and commands, 
 * to recompute the command bits. */
void ACLRecomputeCommandBitsFromCommandRulesAllUsers(void) {
    raxIterator ri;
    raxStart(&ri,Users);
    raxSeek(&ri,"^",NULL,0);
    while(raxNext(&ri)) {
        user *u = ri.data;
        listIter li;
        listNode *ln;
        listRewind(u->selectors,&li);
        while((ln = listNext(&li))) {
            aclSelector *selector = (aclSelector *) listNodeValue(ln);
            int argc = 0;
            sds *argv = sdssplitargs(selector->command_rules, &argc);
            serverAssert(argv != NULL);
            /* Checking selector's permissions for all commands to start with a clean state. */
            if (ACLSelectorCanExecuteFutureCommands(selector)) {
                int res = ACLSetSelector(selector,"+@all",-1);
                serverAssert(res == C_OK);
            } else {
                int res = ACLSetSelector(selector,"-@all",-1);
                serverAssert(res == C_OK);
            }

            /* Apply all of the commands and categories to this selector. */
            for(int i = 0; i < argc; i++) {
                int res = ACLSetSelector(selector, argv[i], sdslen(argv[i]));
                serverAssert(res == C_OK);
            }
            sdsfreesplitres(argv, argc);
        }
    }
    raxStop(&ri);

}

int ACLSetSelectorCategory(aclSelector *selector, const char *category, int allow) {
    uint64_t cflag = ACLGetCommandCategoryFlagByName(category + 1);
    if (!cflag) return C_ERR;

    ACLUpdateCommandRules(selector, category, allow);

    /* Set the actual command bits on the selector. */
    ACLSetSelectorCommandBitsForCategory(server.orig_commands, selector, cflag, allow);
    return C_OK;
}

void ACLCountCategoryBitsForCommands(dict *commands, aclSelector *selector, unsigned long *on, unsigned long *off, uint64_t cflag) {
    dictIterator *di = dictGetIterator(commands);
    dictEntry *de;
    while ((de = dictNext(di)) != NULL) {
        struct redisCommand *cmd = dictGetVal(de);
        if (cmd->acl_categories & cflag) {
            if (ACLGetSelectorCommandBit(selector,cmd->id))
                (*on)++;
            else
                (*off)++;
        }
        if (cmd->subcommands_dict) {
            ACLCountCategoryBitsForCommands(cmd->subcommands_dict, selector, on, off, cflag);
        }
    }
    dictReleaseIterator(di);
}

/* Return the number of commands allowed (on) and denied (off) for the user 'u'
 * in the subset of commands flagged with the specified category name.
 * If the category name is not valid, C_ERR is returned, otherwise C_OK is
 * returned and on and off are populated by reference. */
int ACLCountCategoryBitsForSelector(aclSelector *selector, unsigned long *on, unsigned long *off,
                                const char *category)
{
    uint64_t cflag = ACLGetCommandCategoryFlagByName(category);
    if (!cflag) return C_ERR;

    *on = *off = 0;
    ACLCountCategoryBitsForCommands(server.orig_commands, selector, on, off, cflag);
    return C_OK;
}

/* This function returns an SDS string representing the specified selector ACL
 * rules related to command execution, in the same format you could set them
 * back using ACL SETUSER. The function will return just the set of rules needed
 * to recreate the user commands bitmap, without including other user flags such
 * as on/off, passwords and so forth. The returned string always starts with
 * the +@all or -@all rule, depending on the user bitmap, and is followed, if
 * needed, by the other rules needed to narrow or extend what the user can do. */
sds ACLDescribeSelectorCommandRules(aclSelector *selector) {
    sds rules = sdsempty();

    /* We use this fake selector as a "sanity" check to make sure the rules
     * we generate have the same bitmap as those on the current selector. */
    aclSelector *fake_selector = ACLCreateSelector(0);

    /* Here we want to understand if we should start with +@all or -@all.
     * Note that when starting with +@all and subtracting, the user
     * will be able to execute future commands, while -@all and adding will just
     * allow the user the run the selected commands and/or categories.
     * How do we test for that? We use the trick of a reserved command ID bit
     * that is set only by +@all (and its alias "allcommands"). */
    if (ACLSelectorCanExecuteFutureCommands(selector)) {
        rules = sdscat(rules,"+@all ");
        ACLSetSelector(fake_selector,"+@all",-1);
    } else {
        rules = sdscat(rules,"-@all ");
        ACLSetSelector(fake_selector,"-@all",-1);
    }

    /* Apply all of the commands and categories to the fake selector. */
    int argc = 0;
    sds *argv = sdssplitargs(selector->command_rules, &argc);
    serverAssert(argv != NULL);

    for(int i = 0; i < argc; i++) {
        int res = ACLSetSelector(fake_selector, argv[i], -1);
        serverAssert(res == C_OK);
    }
    if (sdslen(selector->command_rules)) {
        rules = sdscatfmt(rules, "%S ", selector->command_rules);
    }
    sdsfreesplitres(argv, argc);

    /* Trim the final useless space. */
    sdsrange(rules,0,-2);

    /* This is technically not needed, but we want to verify that now the
     * predicted bitmap is exactly the same as the user bitmap, and abort
     * otherwise, because aborting is better than a security risk in this
     * code path. */
    if (memcmp(fake_selector->allowed_commands,
                        selector->allowed_commands,
                        sizeof(selector->allowed_commands)) != 0)
    {
        serverLog(LL_WARNING,
            "CRITICAL ERROR: User ACLs don't match final bitmap: '%s'",
            rules);
        serverPanic("No bitmap match in ACLDescribeSelectorCommandRules()");
    }
    ACLFreeSelector(fake_selector);
    return rules;
}

sds ACLDescribeSelector(aclSelector *selector) {
    listIter li;
    listNode *ln;
    sds res = sdsempty();
    /* Key patterns. */
    if (selector->flags & SELECTOR_FLAG_ALLKEYS) {
        res = sdscatlen(res,"~* ",3);
    } else {
        listRewind(selector->patterns,&li);
        while((ln = listNext(&li))) {
            keyPattern *thispat = (keyPattern *)listNodeValue(ln);
            res = sdsCatPatternString(res, thispat);
            res = sdscatlen(res," ",1);
        }
    }

    /* Pub/sub channel patterns. */
    if (selector->flags & SELECTOR_FLAG_ALLCHANNELS) {
        res = sdscatlen(res,"&* ",3);
    } else {
        res = sdscatlen(res,"resetchannels ",14);
        listRewind(selector->channels,&li);
        while((ln = listNext(&li))) {
            sds thispat = listNodeValue(ln);
            res = sdscatlen(res,"&",1);
            res = sdscatsds(res,thispat);
            res = sdscatlen(res," ",1);
        }
    }

    /* Command rules. */
    sds rules = ACLDescribeSelectorCommandRules(selector);
    res = sdscatsds(res,rules);
    sdsfree(rules);
    return res;
}

/* This is similar to ACLDescribeSelectorCommandRules(), however instead of
 * describing just the user command rules, everything is described: user
 * flags, keys, passwords and finally the command rules obtained via
 * the ACLDescribeSelectorCommandRules() function. This is the function we call
 * when we want to rewrite the configuration files describing ACLs and
 * in order to show users with ACL LIST. */
robj *ACLDescribeUser(user *u) {
    if (u->acl_string) {
        incrRefCount(u->acl_string);
        return u->acl_string;
    }

    sds res = sdsempty();

    /* Flags. */
    for (int j = 0; ACLUserFlags[j].flag; j++) {
        if (u->flags & ACLUserFlags[j].flag) {
            res = sdscat(res,ACLUserFlags[j].name);
            res = sdscatlen(res," ",1);
        }
    }

    /* Passwords. */
    listIter li;
    listNode *ln;
    listRewind(u->passwords,&li);
    while((ln = listNext(&li))) {
        sds thispass = listNodeValue(ln);
        res = sdscatlen(res,"#",1);
        res = sdscatsds(res,thispass);
        res = sdscatlen(res," ",1);
    }

    /* Selectors (Commands and keys) */
    listRewind(u->selectors,&li);
    while((ln = listNext(&li))) {
        aclSelector *selector = (aclSelector *) listNodeValue(ln);
        sds default_perm = ACLDescribeSelector(selector);
        if (selector->flags & SELECTOR_FLAG_ROOT) {
            res = sdscatfmt(res, "%s", default_perm);
        } else {
            res = sdscatfmt(res, " (%s)", default_perm);
        }
        sdsfree(default_perm);
    }

    u->acl_string = createObject(OBJ_STRING, res);
    /* because we are returning it, have to increase count */
    incrRefCount(u->acl_string);

    return u->acl_string;
}

/* Get a command from the original command table, that is not affected
 * by the command renaming operations: we base all the ACL work from that
 * table, so that ACLs are valid regardless of command renaming. */
struct redisCommand *ACLLookupCommand(const char *name) {
    struct redisCommand *cmd;
    sds sdsname = sdsnew(name);
    cmd = lookupCommandBySdsLogic(server.orig_commands,sdsname);
    sdsfree(sdsname);
    return cmd;
}

/* Flush the array of allowed first-args for the specified user
 * and command ID. */
void ACLResetFirstArgsForCommand(aclSelector *selector, unsigned long id) {
    if (selector->allowed_firstargs && selector->allowed_firstargs[id]) {
        for (int i = 0; selector->allowed_firstargs[id][i]; i++)
            sdsfree(selector->allowed_firstargs[id][i]);
        zfree(selector->allowed_firstargs[id]);
        selector->allowed_firstargs[id] = NULL;
    }
}

/* Flush the entire table of first-args. This is useful on +@all, -@all
 * or similar to return back to the minimal memory usage (and checks to do)
 * for the user. */
void ACLResetFirstArgs(aclSelector *selector) {
    if (selector->allowed_firstargs == NULL) return;
    for (int j = 0; j < USER_COMMAND_BITS_COUNT; j++) {
        if (selector->allowed_firstargs[j]) {
            for (int i = 0; selector->allowed_firstargs[j][i]; i++)
                sdsfree(selector->allowed_firstargs[j][i]);
            zfree(selector->allowed_firstargs[j]);
        }
    }
    zfree(selector->allowed_firstargs);
    selector->allowed_firstargs = NULL;
}

/* Add a first-arh to the list of subcommands for the user 'u' and
 * the command id specified. */
void ACLAddAllowedFirstArg(aclSelector *selector, unsigned long id, const char *sub) {
    /* If this is the first first-arg to be configured for
     * this user, we have to allocate the first-args array. */
    if (selector->allowed_firstargs == NULL) {
        selector->allowed_firstargs = zcalloc(USER_COMMAND_BITS_COUNT * sizeof(sds*));
    }

    /* We also need to enlarge the allocation pointing to the
     * null terminated SDS array, to make space for this one.
     * To start check the current size, and while we are here
     * make sure the first-arg is not already specified inside. */
    long items = 0;
    if (selector->allowed_firstargs[id]) {
        while(selector->allowed_firstargs[id][items]) {
            /* If it's already here do not add it again. */
            if (!strcasecmp(selector->allowed_firstargs[id][items],sub))
                return;
            items++;
        }
    }

    /* Now we can make space for the new item (and the null term). */
    items += 2;
    selector->allowed_firstargs[id] = zrealloc(selector->allowed_firstargs[id], sizeof(sds)*items);
    selector->allowed_firstargs[id][items-2] = sdsnew(sub);
    selector->allowed_firstargs[id][items-1] = NULL;
}

/* Create an ACL selector from the given ACL operations, which should be 
 * a list of space separate ACL operations that starts and ends 
 * with parentheses.
 *
 * If any of the operations are invalid, NULL will be returned instead
 * and errno will be set corresponding to the interior error. */
aclSelector *aclCreateSelectorFromOpSet(const char *opset, size_t opsetlen) {
    serverAssert(opset[0] == '(' && opset[opsetlen - 1] == ')');
    aclSelector *s = ACLCreateSelector(0);

    int argc = 0;
    sds trimmed = sdsnewlen(opset + 1, opsetlen - 2);
    sds *argv = sdssplitargs(trimmed, &argc);
    for (int i = 0; i < argc; i++) {
        if (ACLSetSelector(s, argv[i], sdslen(argv[i])) == C_ERR) {
            ACLFreeSelector(s);
            s = NULL;
            goto cleanup;
        }
    }

cleanup:
    sdsfreesplitres(argv, argc);
    sdsfree(trimmed);
    return s;
}

/* Set a selector's properties with the provided 'op'.
 *
 * +<command>   Allow the execution of that command.
 *              May be used with `|` for allowing subcommands (e.g "+config|get")
 * -<command>   Disallow the execution of that command.
 *              May be used with `|` for blocking subcommands (e.g "-config|set")
 * +@<category> Allow the execution of all the commands in such category
 *              with valid categories are like @admin, @set, @sortedset, ...
 *              and so forth, see the full list in the server.c file where
 *              the Redis command table is described and defined.
 *              The special category @all means all the commands, but currently
 *              present in the server, and that will be loaded in the future
 *              via modules.
 * +<command>|first-arg    Allow a specific first argument of an otherwise
 *                         disabled command. Note that this form is not
 *                         allowed as negative like -SELECT|1, but
 *                         only additive starting with "+".
 * allcommands  Alias for +@all. Note that it implies the ability to execute
 *              all the future commands loaded via the modules system.
 * nocommands   Alias for -@all.
 * ~<pattern>   Add a pattern of keys that can be mentioned as part of
 *              commands. For instance ~* allows all the keys. The pattern
 *              is a glob-style pattern like the one of KEYS.
 *              It is possible to specify multiple patterns.
 * %R~<pattern> Add key read pattern that specifies which keys can be read
 *              from.
 * %W~<pattern> Add key write pattern that specifies which keys can be
 *              written to.
 * allkeys      Alias for ~*
 * resetkeys    Flush the list of allowed keys patterns.
 * &<pattern>   Add a pattern of channels that can be mentioned as part of
 *              Pub/Sub commands. For instance &* allows all the channels. The
 *              pattern is a glob-style pattern like the one of PSUBSCRIBE.
 *              It is possible to specify multiple patterns.
 * allchannels              Alias for &*
 * resetchannels            Flush the list of allowed channel patterns.
 */
int ACLSetSelector(aclSelector *selector, const char* op, size_t oplen) {
    if (!strcasecmp(op,"allkeys") ||
               !strcasecmp(op,"~*"))
    {
        selector->flags |= SELECTOR_FLAG_ALLKEYS;
        listEmpty(selector->patterns);
    } else if (!strcasecmp(op,"resetkeys")) {
        selector->flags &= ~SELECTOR_FLAG_ALLKEYS;
        listEmpty(selector->patterns);
    } else if (!strcasecmp(op,"allchannels") ||
               !strcasecmp(op,"&*"))
    {
        selector->flags |= SELECTOR_FLAG_ALLCHANNELS;
        listEmpty(selector->channels);
    } else if (!strcasecmp(op,"resetchannels")) {
        selector->flags &= ~SELECTOR_FLAG_ALLCHANNELS;
        listEmpty(selector->channels);
    } else if (!strcasecmp(op,"allcommands") ||
               !strcasecmp(op,"+@all"))
    {
        memset(selector->allowed_commands,255,sizeof(selector->allowed_commands));
        selector->flags |= SELECTOR_FLAG_ALLCOMMANDS;
        sdsclear(selector->command_rules);
        ACLResetFirstArgs(selector);
    } else if (!strcasecmp(op,"nocommands") ||
               !strcasecmp(op,"-@all"))
    {
        memset(selector->allowed_commands,0,sizeof(selector->allowed_commands));
        selector->flags &= ~SELECTOR_FLAG_ALLCOMMANDS;
        sdsclear(selector->command_rules);
        ACLResetFirstArgs(selector);
    } else if (op[0] == '~' || op[0] == '%') {
        if (selector->flags & SELECTOR_FLAG_ALLKEYS) {
            errno = EEXIST;
            return C_ERR;
        }
        int flags = 0;
        size_t offset = 1;
        if (op[0] == '%') {
            for (; offset < oplen; offset++) {
                if (toupper(op[offset]) == 'R' && !(flags & ACL_READ_PERMISSION)) {
                    flags |= ACL_READ_PERMISSION;
                } else if (toupper(op[offset]) == 'W' && !(flags & ACL_WRITE_PERMISSION)) {
                    flags |= ACL_WRITE_PERMISSION;
                } else if (op[offset] == '~' && flags) {
                    offset++;
                    break;
                } else {
                    errno = EINVAL;
                    return C_ERR;
                }
            }
        } else {
            flags = ACL_ALL_PERMISSION;
        }

        if (ACLStringHasSpaces(op+offset,oplen-offset)) {
            errno = EINVAL;
            return C_ERR;
        }
        keyPattern *newpat = ACLKeyPatternCreate(sdsnewlen(op+offset,oplen-offset), flags);
        listNode *ln = listSearchKey(selector->patterns,newpat);
        /* Avoid re-adding the same key pattern multiple times. */
        if (ln == NULL) {
            listAddNodeTail(selector->patterns,newpat);
        } else {
            ((keyPattern *)listNodeValue(ln))->flags |= flags;
            ACLKeyPatternFree(newpat);
        }
        selector->flags &= ~SELECTOR_FLAG_ALLKEYS;
    } else if (op[0] == '&') {
        if (selector->flags & SELECTOR_FLAG_ALLCHANNELS) {
            errno = EISDIR;
            return C_ERR;
        }
        if (ACLStringHasSpaces(op+1,oplen-1)) {
            errno = EINVAL;
            return C_ERR;
        }
        sds newpat = sdsnewlen(op+1,oplen-1);
        listNode *ln = listSearchKey(selector->channels,newpat);
        /* Avoid re-adding the same channel pattern multiple times. */
        if (ln == NULL)
            listAddNodeTail(selector->channels,newpat);
        else
            sdsfree(newpat);
        selector->flags &= ~SELECTOR_FLAG_ALLCHANNELS;
    } else if (op[0] == '+' && op[1] != '@') {
        if (strrchr(op,'|') == NULL) {
            struct redisCommand *cmd = ACLLookupCommand(op+1);
            if (cmd == NULL) {
                errno = ENOENT;
                return C_ERR;
            }
            ACLChangeSelectorPerm(selector,cmd,1);
            ACLUpdateCommandRules(selector,cmd->fullname,1);
        } else {
            /* Split the command and subcommand parts. */
            char *copy = zstrdup(op+1);
            char *sub = strrchr(copy,'|');
            sub[0] = '\0';
            sub++;

            struct redisCommand *cmd = ACLLookupCommand(copy);

            /* Check if the command exists. We can't check the
             * first-arg to see if it is valid. */
            if (cmd == NULL) {
                zfree(copy);
                errno = ENOENT;
                return C_ERR;
            }

            /* We do not support allowing first-arg of a subcommand */
            if (cmd->parent) {
                zfree(copy);
                errno = ECHILD;
                return C_ERR;
            }

            /* The subcommand cannot be empty, so things like DEBUG|
             * are syntax errors of course. */
            if (strlen(sub) == 0) {
                zfree(copy);
                errno = EINVAL;
                return C_ERR;
            }

            if (cmd->subcommands_dict) {
                /* If user is trying to allow a valid subcommand we can just add its unique ID */
                cmd = ACLLookupCommand(op+1);
                if (cmd == NULL) {
                    zfree(copy);
                    errno = ENOENT;
                    return C_ERR;
                }
                ACLChangeSelectorPerm(selector,cmd,1);
            } else {
                /* If user is trying to use the ACL mech to block SELECT except SELECT 0 or
                 * block DEBUG except DEBUG OBJECT (DEBUG subcommands are not considered
                 * subcommands for now) we use the allowed_firstargs mechanism. */

                /* Add the first-arg to the list of valid ones. */
                serverLog(LL_WARNING, "Deprecation warning: Allowing a first arg of an otherwise "
                                      "blocked command is a misuse of ACL and may get disabled "
                                      "in the future (offender: +%s)", op+1);
                ACLAddAllowedFirstArg(selector,cmd->id,sub);
            }
            ACLUpdateCommandRules(selector,op+1,1);
            zfree(copy);
        }
    } else if (op[0] == '-' && op[1] != '@') {
        struct redisCommand *cmd = ACLLookupCommand(op+1);
        if (cmd == NULL) {
            errno = ENOENT;
            return C_ERR;
        }
        ACLChangeSelectorPerm(selector,cmd,0);
        ACLUpdateCommandRules(selector,cmd->fullname,0);
    } else if ((op[0] == '+' || op[0] == '-') && op[1] == '@') {
        int bitval = op[0] == '+' ? 1 : 0;
        if (ACLSetSelectorCategory(selector,op+1,bitval) == C_ERR) {
            errno = ENOENT;
            return C_ERR;
        }
    } else {
        errno = EINVAL;
        return C_ERR;
    }
    return C_OK;
}

/* Set user properties according to the string "op". The following
 * is a description of what different strings will do:
 *
 * on           Enable the user: it is possible to authenticate as this user.
 * off          Disable the user: it's no longer possible to authenticate
 *              with this user, however the already authenticated connections
 *              will still work.
 * skip-sanitize-payload    RESTORE dump-payload sanitization is skipped.
 * sanitize-payload         RESTORE dump-payload is sanitized (default).
 * ><password>  Add this password to the list of valid password for the user.
 *              For example >mypass will add "mypass" to the list.
 *              This directive clears the "nopass" flag (see later).
 * #<hash>      Add this password hash to the list of valid hashes for
 *              the user. This is useful if you have previously computed
 *              the hash, and don't want to store it in plaintext.
 *              This directive clears the "nopass" flag (see later).
 * <<password>  Remove this password from the list of valid passwords.
 * !<hash>      Remove this hashed password from the list of valid passwords.
 *              This is useful when you want to remove a password just by
 *              hash without knowing its plaintext version at all.
 * nopass       All the set passwords of the user are removed, and the user
 *              is flagged as requiring no password: it means that every
 *              password will work against this user. If this directive is
 *              used for the default user, every new connection will be
 *              immediately authenticated with the default user without
 *              any explicit AUTH command required. Note that the "resetpass"
 *              directive will clear this condition.
 * resetpass    Flush the list of allowed passwords. Moreover removes the
 *              "nopass" status. After "resetpass" the user has no associated
 *              passwords and there is no way to authenticate without adding
 *              some password (or setting it as "nopass" later).
 * reset        Performs the following actions: resetpass, resetkeys, resetchannels,
 *              allchannels (if acl-pubsub-default is set), off, clearselectors, -@all.
 *              The user returns to the same state it has immediately after its creation.
 * (<options>)  Create a new selector with the options specified within the
 *              parentheses and attach it to the user. Each option should be
 *              space separated. The first character must be ( and the last
 *              character must be ).
 * clearselectors          Remove all of the currently attached selectors. 
 *                         Note this does not change the "root" user permissions,
 *                         which are the permissions directly applied onto the
 *                         user (outside the parentheses).
 * 
 * Selector options can also be specified by this function, in which case
 * they update the root selector for the user.
 *
 * The 'op' string must be null terminated. The 'oplen' argument should
 * specify the length of the 'op' string in case the caller requires to pass
 * binary data (for instance the >password form may use a binary password).
 * Otherwise the field can be set to -1 and the function will use strlen()
 * to determine the length.
 *
 * The function returns C_OK if the action to perform was understood because
 * the 'op' string made sense. Otherwise C_ERR is returned if the operation
 * is unknown or has some syntax error.
 *
 * When an error is returned, errno is set to the following values:
 *
 * EINVAL: The specified opcode is not understood or the key/channel pattern is
 *         invalid (contains non allowed characters).
 * ENOENT: The command name or command category provided with + or - is not
 *         known.
 * EEXIST: You are adding a key pattern after "*" was already added. This is
 *         almost surely an error on the user side.
 * EISDIR: You are adding a channel pattern after "*" was already added. This is
 *         almost surely an error on the user side.
 * ENODEV: The password you are trying to remove from the user does not exist.
 * EBADMSG: The hash you are trying to add is not a valid hash.
 * ECHILD: Attempt to allow a specific first argument of a subcommand
 */
int ACLSetUser(user *u, const char *op, ssize_t oplen) {
    /* as we are changing the ACL, the old generated string is now invalid */
    if (u->acl_string) {
        decrRefCount(u->acl_string);
        u->acl_string = NULL;
    }

    if (oplen == -1) oplen = strlen(op);
    if (oplen == 0) return C_OK; /* Empty string is a no-operation. */
    if (!strcasecmp(op,"on")) {
        u->flags |= USER_FLAG_ENABLED;
        u->flags &= ~USER_FLAG_DISABLED;
    } else if (!strcasecmp(op,"off")) {
        u->flags |= USER_FLAG_DISABLED;
        u->flags &= ~USER_FLAG_ENABLED;
    } else if (!strcasecmp(op,"skip-sanitize-payload")) {
        u->flags |= USER_FLAG_SANITIZE_PAYLOAD_SKIP;
        u->flags &= ~USER_FLAG_SANITIZE_PAYLOAD;
    } else if (!strcasecmp(op,"sanitize-payload")) {
        u->flags &= ~USER_FLAG_SANITIZE_PAYLOAD_SKIP;
        u->flags |= USER_FLAG_SANITIZE_PAYLOAD;
    } else if (!strcasecmp(op,"nopass")) {
        u->flags |= USER_FLAG_NOPASS;
        listEmpty(u->passwords);
    } else if (!strcasecmp(op,"resetpass")) {
        u->flags &= ~USER_FLAG_NOPASS;
        listEmpty(u->passwords);
    } else if (op[0] == '>' || op[0] == '#') {
        sds newpass;
        if (op[0] == '>') {
            newpass = ACLHashPassword((unsigned char*)op+1,oplen-1);
        } else {
            if (ACLCheckPasswordHash((unsigned char*)op+1,oplen-1) == C_ERR) {
                errno = EBADMSG;
                return C_ERR;
            }
            newpass = sdsnewlen(op+1,oplen-1);
        }

        listNode *ln = listSearchKey(u->passwords,newpass);
        /* Avoid re-adding the same password multiple times. */
        if (ln == NULL)
            listAddNodeTail(u->passwords,newpass);
        else
            sdsfree(newpass);
        u->flags &= ~USER_FLAG_NOPASS;
    } else if (op[0] == '<' || op[0] == '!') {
        sds delpass;
        if (op[0] == '<') {
            delpass = ACLHashPassword((unsigned char*)op+1,oplen-1);
        } else {
            if (ACLCheckPasswordHash((unsigned char*)op+1,oplen-1) == C_ERR) {
                errno = EBADMSG;
                return C_ERR;
            }
            delpass = sdsnewlen(op+1,oplen-1);
        }
        listNode *ln = listSearchKey(u->passwords,delpass);
        sdsfree(delpass);
        if (ln) {
            listDelNode(u->passwords,ln);
        } else {
            errno = ENODEV;
            return C_ERR;
        }
    } else if (op[0] == '(' && op[oplen - 1] == ')') {
        aclSelector *selector = aclCreateSelectorFromOpSet(op, oplen);
        if (!selector) {
            /* No errorno set, propagate it from interior error. */
            return C_ERR;
        }
        listAddNodeTail(u->selectors, selector);
        return C_OK;
    } else if (!strcasecmp(op,"clearselectors")) {
        listIter li;
        listNode *ln;
        listRewind(u->selectors,&li);
        /* There has to be a root selector */
        serverAssert(listNext(&li));
        while((ln = listNext(&li))) {
            listDelNode(u->selectors, ln);
        }
        return C_OK;
    } else if (!strcasecmp(op,"reset")) {
        serverAssert(ACLSetUser(u,"resetpass",-1) == C_OK);
        serverAssert(ACLSetUser(u,"resetkeys",-1) == C_OK);
        serverAssert(ACLSetUser(u,"resetchannels",-1) == C_OK);
        if (server.acl_pubsub_default & SELECTOR_FLAG_ALLCHANNELS)
            serverAssert(ACLSetUser(u,"allchannels",-1) == C_OK);
        serverAssert(ACLSetUser(u,"off",-1) == C_OK);
        serverAssert(ACLSetUser(u,"sanitize-payload",-1) == C_OK);
        serverAssert(ACLSetUser(u,"clearselectors",-1) == C_OK);
        serverAssert(ACLSetUser(u,"-@all",-1) == C_OK);
    } else {
        aclSelector *selector = ACLUserGetRootSelector(u);
        if (ACLSetSelector(selector, op, oplen) == C_ERR) {
            return C_ERR;
        }
    }
    return C_OK;
}

/* Return a description of the error that occurred in ACLSetUser() according to
 * the errno value set by the function on error. */
const char *ACLSetUserStringError(void) {
    const char *errmsg = "Wrong format";
    if (errno == ENOENT)
        errmsg = "Unknown command or category name in ACL";
    else if (errno == EINVAL)
        errmsg = "Syntax error";
    else if (errno == EEXIST)
        errmsg = "Adding a pattern after the * pattern (or the "
                 "'allkeys' flag) is not valid and does not have any "
                 "effect. Try 'resetkeys' to start with an empty "
                 "list of patterns";
    else if (errno == EISDIR)
        errmsg = "Adding a pattern after the * pattern (or the "
                 "'allchannels' flag) is not valid and does not have any "
                 "effect. Try 'resetchannels' to start with an empty "
                 "list of channels";
    else if (errno == ENODEV)
        errmsg = "The password you are trying to remove from the user does "
                 "not exist";
    else if (errno == EBADMSG)
        errmsg = "The password hash must be exactly 64 characters and contain "
                 "only lowercase hexadecimal characters";
    else if (errno == EALREADY)
        errmsg = "Duplicate user found. A user can only be defined once in "
                 "config files";
    else if (errno == ECHILD)
        errmsg = "Allowing first-arg of a subcommand is not supported";
    return errmsg;
}

/* Create the default user, this has special permissions. */
user *ACLCreateDefaultUser(void) {
    user *new = ACLCreateUser("default",7);
    ACLSetUser(new,"+@all",-1);
    ACLSetUser(new,"~*",-1);
    ACLSetUser(new,"&*",-1);
    ACLSetUser(new,"on",-1);
    ACLSetUser(new,"nopass",-1);
    return new;
}

/* Initialization of the ACL subsystem. */
void ACLInit(void) {
    Users = raxNew();
    UsersToLoad = listCreate();
    listSetMatchMethod(UsersToLoad, ACLListMatchLoadedUser);
    ACLLog = listCreate();
    DefaultUser = ACLCreateDefaultUser();
}

/* Check the username and password pair and return C_OK if they are valid,
 * otherwise C_ERR is returned and errno is set to:
 *
 *  EINVAL: if the username-password do not match.
 *  ENONENT: if the specified user does not exist at all.
 */
int ACLCheckUserCredentials(robj *username, robj *password) {
    user *u = ACLGetUserByName(username->ptr,sdslen(username->ptr));
    if (u == NULL) {
        errno = ENOENT;
        return C_ERR;
    }

    /* Disabled users can't login. */
    if (u->flags & USER_FLAG_DISABLED) {
        errno = EINVAL;
        return C_ERR;
    }

    /* If the user is configured to don't require any password, we
     * are already fine here. */
    if (u->flags & USER_FLAG_NOPASS) return C_OK;

    /* Check all the user passwords for at least one to match. */
    listIter li;
    listNode *ln;
    listRewind(u->passwords,&li);
    sds hashed = ACLHashPassword(password->ptr,sdslen(password->ptr));
    while((ln = listNext(&li))) {
        sds thispass = listNodeValue(ln);
        if (!time_independent_strcmp(hashed, thispass, HASH_PASSWORD_LEN)) {
            sdsfree(hashed);
            return C_OK;
        }
    }
    sdsfree(hashed);

    /* If we reached this point, no password matched. */
    errno = EINVAL;
    return C_ERR;
}

/* If `err` is provided, this is added as an error reply to the client.
 * Otherwise, the standard Auth error is added as a reply. */
void addAuthErrReply(client *c, robj *err) {
    if (clientHasPendingReplies(c)) return;
    if (!err) {
        addReplyError(c, "-WRONGPASS invalid username-password pair or user is disabled.");
        return;
    }
    addReplyError(c, err->ptr);
}

/* This is like ACLCheckUserCredentials(), however if the user/pass
 * are correct, the connection is put in authenticated state and the
 * connection user reference is populated.
 *
 * The return value is AUTH_OK on success (valid username / password pair) & AUTH_ERR otherwise. */
int checkPasswordBasedAuth(client *c, robj *username, robj *password) {
    if (ACLCheckUserCredentials(username,password) == C_OK) {
        c->authenticated = 1;
        c->user = ACLGetUserByName(username->ptr,sdslen(username->ptr));
        moduleNotifyUserChanged(c);
        return AUTH_OK;
    } else {
        addACLLogEntry(c,ACL_DENIED_AUTH,(c->flags & CLIENT_MULTI) ? ACL_LOG_CTX_MULTI : ACL_LOG_CTX_TOPLEVEL,0,username->ptr,NULL);
        return AUTH_ERR;
    }
}

/* Attempt authenticating the user - first through module based authentication,
 * and then, if needed, with normal password based authentication.
 * Returns one of the following codes:
 * AUTH_OK - Indicates that authentication succeeded.
 * AUTH_ERR - Indicates that authentication failed.
 * AUTH_BLOCKED - Indicates module authentication is in progress through a blocking implementation.
 */
int ACLAuthenticateUser(client *c, robj *username, robj *password, robj **err) {
    int result = checkModuleAuthentication(c, username, password, err);
    /* If authentication was not handled by any Module, attempt normal password based auth. */
    if (result == AUTH_NOT_HANDLED) {
        result = checkPasswordBasedAuth(c, username, password);
    }
    return result;
}

/* For ACL purposes, every user has a bitmap with the commands that such
 * user is allowed to execute. In order to populate the bitmap, every command
 * should have an assigned ID (that is used to index the bitmap). This function
 * creates such an ID: it uses sequential IDs, reusing the same ID for the same
 * command name, so that a command retains the same ID in case of modules that
 * are unloaded and later reloaded.
 *
 * The function does not take ownership of the 'cmdname' SDS string.
 * */
unsigned long ACLGetCommandID(sds cmdname) {
    sds lowername = sdsdup(cmdname);
    sdstolower(lowername);
    if (commandId == NULL) commandId = raxNew();
    void *id = raxFind(commandId,(unsigned char*)lowername,sdslen(lowername));
    if (id != raxNotFound) {
        sdsfree(lowername);
        return (unsigned long)id;
    }
    raxInsert(commandId,(unsigned char*)lowername,strlen(lowername),
              (void*)nextid,NULL);
    sdsfree(lowername);
    unsigned long thisid = nextid;
    nextid++;

    /* We never assign the last bit in the user commands bitmap structure,
     * this way we can later check if this bit is set, understanding if the
     * current ACL for the user was created starting with a +@all to add all
     * the possible commands and just subtracting other single commands or
     * categories, or if, instead, the ACL was created just adding commands
     * and command categories from scratch, not allowing future commands by
     * default (loaded via modules). This is useful when rewriting the ACLs
     * with ACL SAVE. */
    if (nextid == USER_COMMAND_BITS_COUNT-1) nextid++;
    return thisid;
}

/* Clear command id table and reset nextid to 0. */
void ACLClearCommandID(void) {
    if (commandId) raxFree(commandId);
    commandId = NULL;
    nextid = 0;
}

/* Return an username by its name, or NULL if the user does not exist. */
user *ACLGetUserByName(const char *name, size_t namelen) {
    void *myuser = raxFind(Users,(unsigned char*)name,namelen);
    if (myuser == raxNotFound) return NULL;
    return myuser;
}

/* =============================================================================
 * ACL permission checks
 * ==========================================================================*/

/* Check if the key can be accessed by the selector.
 *
 * If the selector can access the key, ACL_OK is returned, otherwise
 * ACL_DENIED_KEY is returned. */
static int ACLSelectorCheckKey(aclSelector *selector, const char *key, int keylen, int keyspec_flags) {
    /* The selector can access any key */
    if (selector->flags & SELECTOR_FLAG_ALLKEYS) return ACL_OK;

    listIter li;
    listNode *ln;
    listRewind(selector->patterns,&li);

    int key_flags = 0;
    if (keyspec_flags & CMD_KEY_ACCESS) key_flags |= ACL_READ_PERMISSION;
    if (keyspec_flags & CMD_KEY_INSERT) key_flags |= ACL_WRITE_PERMISSION;
    if (keyspec_flags & CMD_KEY_DELETE) key_flags |= ACL_WRITE_PERMISSION;
    if (keyspec_flags & CMD_KEY_UPDATE) key_flags |= ACL_WRITE_PERMISSION;

    /* Test this key against every pattern. */
    while((ln = listNext(&li))) {
        keyPattern *pattern = listNodeValue(ln);
        if ((pattern->flags & key_flags) != key_flags)
            continue;
        size_t plen = sdslen(pattern->pattern);
        if (stringmatchlen(pattern->pattern,plen,key,keylen,0))
            return ACL_OK;
    }
    return ACL_DENIED_KEY;
}

/* Checks if the provided selector selector has access specified in flags
 * to all keys in the keyspace. For example, CMD_KEY_READ access requires either
 * '%R~*', '~*', or allkeys to be granted to the selector. Returns 1 if all 
 * the access flags are satisfied with this selector or 0 otherwise.
 */
static int ACLSelectorHasUnrestrictedKeyAccess(aclSelector *selector, int flags) {
    /* The selector can access any key */
    if (selector->flags & SELECTOR_FLAG_ALLKEYS) return 1;

    listIter li;
    listNode *ln;
    listRewind(selector->patterns,&li);

    int access_flags = 0;
    if (flags & CMD_KEY_ACCESS) access_flags |= ACL_READ_PERMISSION;
    if (flags & CMD_KEY_INSERT) access_flags |= ACL_WRITE_PERMISSION;
    if (flags & CMD_KEY_DELETE) access_flags |= ACL_WRITE_PERMISSION;
    if (flags & CMD_KEY_UPDATE) access_flags |= ACL_WRITE_PERMISSION;

    /* Test this key against every pattern. */
    while((ln = listNext(&li))) {
        keyPattern *pattern = listNodeValue(ln);
        if ((pattern->flags & access_flags) != access_flags)
            continue;
        if (!strcmp(pattern->pattern,"*")) {
           return 1;
       }
    }
    return 0;
}

/* Checks a channel against a provided list of channels. The is_pattern 
 * argument should only be used when subscribing (not when publishing)
 * and controls whether the input channel is evaluated as a channel pattern
 * (like in PSUBSCRIBE) or a plain channel name (like in SUBSCRIBE). 
 * 
 * Note that a plain channel name like in PUBLISH or SUBSCRIBE can be
 * matched against ACL channel patterns, but the pattern provided in PSUBSCRIBE
 * can only be matched as a literal against an ACL pattern (using plain string compare). */
static int ACLCheckChannelAgainstList(list *reference, const char *channel, int channellen, int is_pattern) {
    listIter li;
    listNode *ln;

    listRewind(reference, &li);
    while((ln = listNext(&li))) {
        sds pattern = listNodeValue(ln);
        size_t plen = sdslen(pattern);
        /* Channel patterns are matched literally against the channels in
         * the list. Regular channels perform pattern matching. */
        if ((is_pattern && !strcmp(pattern,channel)) || 
            (!is_pattern && stringmatchlen(pattern,plen,channel,channellen,0)))
        {
            return ACL_OK;
        }
    }
    return ACL_DENIED_CHANNEL;
}

/* To prevent duplicate calls to getKeysResult, a cache is maintained
 * in between calls to the various selectors. */
typedef struct {
    int keys_init;
    getKeysResult keys;
} aclKeyResultCache;

void initACLKeyResultCache(aclKeyResultCache *cache) {
    cache->keys_init = 0;
}

void cleanupACLKeyResultCache(aclKeyResultCache *cache) {
    if (cache->keys_init) getKeysFreeResult(&(cache->keys));
}

/* Check if the command is ready to be executed according to the
 * ACLs associated with the specified selector.
 *
 * If the selector can execute the command ACL_OK is returned, otherwise
 * ACL_DENIED_CMD, ACL_DENIED_KEY, or ACL_DENIED_CHANNEL is returned: the first in case the
 * command cannot be executed because the selector is not allowed to run such
 * command, the second and third if the command is denied because the selector is trying
 * to access a key or channel that are not among the specified patterns. */
static int ACLSelectorCheckCmd(aclSelector *selector, struct redisCommand *cmd, robj **argv, int argc, int *keyidxptr, aclKeyResultCache *cache) {
    uint64_t id = cmd->id;
    int ret;
    if (!(selector->flags & SELECTOR_FLAG_ALLCOMMANDS) && !(cmd->flags & CMD_NO_AUTH)) {
        /* If the bit is not set we have to check further, in case the
         * command is allowed just with that specific first argument. */
        if (ACLGetSelectorCommandBit(selector,id) == 0) {
            /* Check if the first argument matches. */
            if (argc < 2 ||
                selector->allowed_firstargs == NULL ||
                selector->allowed_firstargs[id] == NULL)
            {
                return ACL_DENIED_CMD;
            }

            long subid = 0;
            while (1) {
                if (selector->allowed_firstargs[id][subid] == NULL)
                    return ACL_DENIED_CMD;
                int idx = cmd->parent ? 2 : 1;
                if (!strcasecmp(argv[idx]->ptr,selector->allowed_firstargs[id][subid]))
                    break; /* First argument match found. Stop here. */
                subid++;
            }
        }
    }

    /* Check if the user can execute commands explicitly touching the keys
     * mentioned in the command arguments. */
    if (!(selector->flags & SELECTOR_FLAG_ALLKEYS) && doesCommandHaveKeys(cmd)) {
        if (!(cache->keys_init)) {
            cache->keys = (getKeysResult) GETKEYS_RESULT_INIT;
            getKeysFromCommandWithSpecs(cmd, argv, argc, GET_KEYSPEC_DEFAULT, &(cache->keys));
            cache->keys_init = 1;
        }
        getKeysResult *result = &(cache->keys);
        keyReference *resultidx = result->keys;
        for (int j = 0; j < result->numkeys; j++) {
            int idx = resultidx[j].pos;
            ret = ACLSelectorCheckKey(selector, argv[idx]->ptr, sdslen(argv[idx]->ptr), resultidx[j].flags);
            if (ret != ACL_OK) {
                if (keyidxptr) *keyidxptr = resultidx[j].pos;
                return ret;
            }
        }
    }

    /* Check if the user can execute commands explicitly touching the channels
     * mentioned in the command arguments */
    const int channel_flags = CMD_CHANNEL_PUBLISH | CMD_CHANNEL_SUBSCRIBE;
    if (!(selector->flags & SELECTOR_FLAG_ALLCHANNELS) && doesCommandHaveChannelsWithFlags(cmd, channel_flags)) {
        getKeysResult channels = (getKeysResult) GETKEYS_RESULT_INIT;
        getChannelsFromCommand(cmd, argv, argc, &channels);
        keyReference *channelref = channels.keys;
        for (int j = 0; j < channels.numkeys; j++) {
            int idx = channelref[j].pos;
            if (!(channelref[j].flags & channel_flags)) continue;
            int is_pattern = channelref[j].flags & CMD_CHANNEL_PATTERN;
            int ret = ACLCheckChannelAgainstList(selector->channels, argv[idx]->ptr, sdslen(argv[idx]->ptr), is_pattern);
            if (ret != ACL_OK) {
                if (keyidxptr) *keyidxptr = channelref[j].pos;
                getKeysFreeResult(&channels);
                return ret;
            }
        }
        getKeysFreeResult(&channels);
    }
    return ACL_OK;
}

/* Check if the key can be accessed by the client according to
 * the ACLs associated with the specified user according to the
 * keyspec access flags.
 *
 * If the user can access the key, ACL_OK is returned, otherwise
 * ACL_DENIED_KEY is returned. */
int ACLUserCheckKeyPerm(user *u, const char *key, int keylen, int flags) {
    listIter li;
    listNode *ln;

    /* If there is no associated user, the connection can run anything. */
    if (u == NULL) return ACL_OK;

    /* Check all of the selectors */
    listRewind(u->selectors,&li);
    while((ln = listNext(&li))) {
        aclSelector *s = (aclSelector *) listNodeValue(ln);
        if (ACLSelectorCheckKey(s, key, keylen, flags) == ACL_OK) {
            return ACL_OK;
        }
    }
    return ACL_DENIED_KEY;
}

/* Checks if the user can execute the given command with the added restriction
 * it must also have the access specified in flags to any key in the key space. 
 * For example, CMD_KEY_READ access requires either '%R~*', '~*', or allkeys to be 
 * granted in addition to the access required by the command. Returns 1 
 * if the user has access or 0 otherwise.
 */
int ACLUserCheckCmdWithUnrestrictedKeyAccess(user *u, struct redisCommand *cmd, robj **argv, int argc, int flags) {
    listIter li;
    listNode *ln;
    int local_idxptr;

    /* If there is no associated user, the connection can run anything. */
    if (u == NULL) return 1;

    /* For multiple selectors, we cache the key result in between selector
     * calls to prevent duplicate lookups. */
    aclKeyResultCache cache;
    initACLKeyResultCache(&cache);

    /* Check each selector sequentially */
    listRewind(u->selectors,&li);
    while((ln = listNext(&li))) {
        aclSelector *s = (aclSelector *) listNodeValue(ln);
        int acl_retval = ACLSelectorCheckCmd(s, cmd, argv, argc, &local_idxptr, &cache);
        if (acl_retval == ACL_OK && ACLSelectorHasUnrestrictedKeyAccess(s, flags)) {
            cleanupACLKeyResultCache(&cache);
            return 1;
        }
    }
    cleanupACLKeyResultCache(&cache);
    return 0;
}

/* Check if the channel can be accessed by the client according to
 * the ACLs associated with the specified user.
 *
 * If the user can access the key, ACL_OK is returned, otherwise
 * ACL_DENIED_CHANNEL is returned. */
int ACLUserCheckChannelPerm(user *u, sds channel, int is_pattern) {
    listIter li;
    listNode *ln;

    /* If there is no associated user, the connection can run anything. */
    if (u == NULL) return ACL_OK;

    /* Check all of the selectors */
    listRewind(u->selectors,&li);
    while((ln = listNext(&li))) {
        aclSelector *s = (aclSelector *) listNodeValue(ln);
        /* The selector can run any keys */
        if (s->flags & SELECTOR_FLAG_ALLCHANNELS) return ACL_OK;

        /* Otherwise, loop over the selectors list and check each channel */
        if (ACLCheckChannelAgainstList(s->channels, channel, sdslen(channel), is_pattern) == ACL_OK) {
            return ACL_OK;
        }
    }
    return ACL_DENIED_CHANNEL;
}

/* Lower level API that checks if a specified user is able to execute a given command.
 *
 * If the command fails an ACL check, idxptr will be to set to the first argv entry that
 * causes the failure, either 0 if the command itself fails or the idx of the key/channel
 * that causes the failure */
int ACLCheckAllUserCommandPerm(user *u, struct redisCommand *cmd, robj **argv, int argc, int *idxptr) {
    listIter li;
    listNode *ln;

    /* If there is no associated user, the connection can run anything. */
    if (u == NULL) return ACL_OK;

    /* We have to pick a single error to log, the logic for picking is as follows:
     * 1) If no selector can execute the command, return the command.
     * 2) Return the last key or channel that no selector could match. */
    int relevant_error = ACL_DENIED_CMD;
    int local_idxptr = 0, last_idx = 0;

    /* For multiple selectors, we cache the key result in between selector
     * calls to prevent duplicate lookups. */
    aclKeyResultCache cache;
    initACLKeyResultCache(&cache);

    /* Check each selector sequentially */
    listRewind(u->selectors,&li);
    while((ln = listNext(&li))) {
        aclSelector *s = (aclSelector *) listNodeValue(ln);
        int acl_retval = ACLSelectorCheckCmd(s, cmd, argv, argc, &local_idxptr, &cache);
        if (acl_retval == ACL_OK) {
            cleanupACLKeyResultCache(&cache);
            return ACL_OK;
        }
        if (acl_retval > relevant_error ||
            (acl_retval == relevant_error && local_idxptr > last_idx))
        {
            relevant_error = acl_retval;
            last_idx = local_idxptr;
        }
    }

    *idxptr = last_idx;
    cleanupACLKeyResultCache(&cache);
    return relevant_error;
}

/* High level API for checking if a client can execute the queued up command */
int ACLCheckAllPerm(client *c, int *idxptr) {
    return ACLCheckAllUserCommandPerm(c->user, c->cmd, c->argv, c->argc, idxptr);
}

/* Check if the user's existing pub/sub clients violate the ACL pub/sub
 * permissions specified via the upcoming argument, and kill them if so. */
void ACLKillPubsubClientsIfNeeded(user *new, user *original) {
    /* Do nothing if there are no subscribers. */
    if (!dictSize(server.pubsub_patterns) &&
        !dictSize(server.pubsub_channels) &&
        !dictSize(server.pubsubshard_channels))
        return;

    listIter li, lpi;
    listNode *ln, *lpn;
    robj *o;
    int kill = 0;
    
    /* First optimization is we check if any selector has all channel
     * permissions. */
    listRewind(new->selectors,&li);
    while((ln = listNext(&li))) {
        aclSelector *s = (aclSelector *) listNodeValue(ln);
        if (s->flags & SELECTOR_FLAG_ALLCHANNELS) return;
    }

    /* Second optimization is to check if the new list of channels
     * is a strict superset of the original. This is done by
     * created an "upcoming" list of all channels that are in
     * the new user and checking each of the existing channels
     * against it.  */
    list *upcoming = listCreate();
    listRewind(new->selectors,&li);
    while((ln = listNext(&li))) {
        aclSelector *s = (aclSelector *) listNodeValue(ln);
        listRewind(s->channels, &lpi);
        while((lpn = listNext(&lpi))) {
            listAddNodeTail(upcoming, listNodeValue(lpn));
        }
    }

    int match = 1;
    listRewind(original->selectors,&li);
    while((ln = listNext(&li)) && match) {
        aclSelector *s = (aclSelector *) listNodeValue(ln);
        /* If any of the original selectors has the all-channels permission, but
         * the new ones don't (this is checked earlier in this function), then the
         * new list is not a strict superset of the original.  */
        if (s->flags & SELECTOR_FLAG_ALLCHANNELS) {
            match = 0;
            break;
        }
        listRewind(s->channels, &lpi);
        while((lpn = listNext(&lpi)) && match) {
            if (!listSearchKey(upcoming, listNodeValue(lpn))) {
                match = 0;
                break;
            }
        }
    }

    if (match) {
        /* All channels were matched, no need to kill clients. */
        listRelease(upcoming);
        return;
    }
    
    /* Permissions have changed, so we need to iterate through all
     * the clients and disconnect those that are no longer valid.
     * Scan all connected clients to find the user's pub/subs. */
    listRewind(server.clients,&li);
    while ((ln = listNext(&li)) != NULL) {
        client *c = listNodeValue(ln);
        kill = 0;

        if (c->user == original && getClientType(c) == CLIENT_TYPE_PUBSUB) {
            /* Check for pattern violations. */
            dictIterator *di = dictGetIterator(c->pubsub_patterns);
            dictEntry *de;
            while (!kill && ((de = dictNext(di)) != NULL)) {
                o = dictGetKey(de);
                int res = ACLCheckChannelAgainstList(upcoming, o->ptr, sdslen(o->ptr), 1);
                kill = (res == ACL_DENIED_CHANNEL);
            }
            dictReleaseIterator(di);

            /* Check for channel violations. */
            if (!kill) {
                /* Check for global channels violation. */
                di = dictGetIterator(c->pubsub_channels);
                while (!kill && ((de = dictNext(di)) != NULL)) {
                    o = dictGetKey(de);
                    int res = ACLCheckChannelAgainstList(upcoming, o->ptr, sdslen(o->ptr), 0);
                    kill = (res == ACL_DENIED_CHANNEL);
                }
                dictReleaseIterator(di);
            }

            if (!kill) {
                /* Check for shard channels violation. */
                di = dictGetIterator(c->pubsubshard_channels);
                while (!kill && ((de = dictNext(di)) != NULL)) {
                    o = dictGetKey(de);
                    int res = ACLCheckChannelAgainstList(upcoming, o->ptr, sdslen(o->ptr), 0);
                    kill = (res == ACL_DENIED_CHANNEL);
                }
                dictReleaseIterator(di);
            }

            /* Kill it. */
            if (kill) {
                freeClient(c);
            }
        }
    }
    listRelease(upcoming);
}

/* =============================================================================
 * ACL loading / saving functions
 * ==========================================================================*/


/* Selector definitions should be sent as a single argument, however
 * we will be lenient and try to find selector definitions spread 
 * across multiple arguments since it makes for a simpler user experience
 * for ACL SETUSER as well as when loading from conf files. 
 * 
 * This function takes in an array of ACL operators, excluding the username,
 * and merges selector operations that are spread across multiple arguments. The return
 * value is a new SDS array, with length set to the passed in merged_argc. Arguments 
 * that are untouched are still duplicated. If there is an unmatched parenthesis, NULL 
 * is returned and invalid_idx is set to the argument with the start of the opening
 * parenthesis. */
sds *ACLMergeSelectorArguments(sds *argv, int argc, int *merged_argc, int *invalid_idx) {
    *merged_argc = 0;
    int open_bracket_start = -1;

    sds *acl_args = (sds *) zmalloc(sizeof(sds) * argc);

    sds selector = NULL;
    for (int j = 0; j < argc; j++) {
        char *op = argv[j];

        if (open_bracket_start == -1 &&
            (op[0] == '(' && op[sdslen(op) - 1] != ')')) {
            selector = sdsdup(argv[j]);
            open_bracket_start = j;
            continue;
        }

        if (open_bracket_start != -1) {
            selector = sdscatfmt(selector, " %s", op);
            if (op[sdslen(op) - 1] == ')') {
                open_bracket_start = -1;
                acl_args[*merged_argc] = selector;                        
                (*merged_argc)++;
            }
            continue;
        }

        acl_args[*merged_argc] = sdsdup(argv[j]);
        (*merged_argc)++;
    }

    if (open_bracket_start != -1) {
        for (int i = 0; i < *merged_argc; i++) sdsfree(acl_args[i]);
        zfree(acl_args);
        sdsfree(selector);
        if (invalid_idx) *invalid_idx = open_bracket_start;
        return NULL;
    }

    return acl_args;
}

/* takes an acl string already split on spaces and adds it to the given user
 * if the user object is NULL, will create a user with the given username
 *
 * Returns an error as an sds string if the ACL string is not parsable
 */
sds ACLStringSetUser(user *u, sds username, sds *argv, int argc) {
    serverAssert(u != NULL || username != NULL);

    sds error = NULL;

    int merged_argc = 0, invalid_idx = 0;
    sds *acl_args = ACLMergeSelectorArguments(argv, argc, &merged_argc, &invalid_idx);

    if (!acl_args) {
        return sdscatfmt(sdsempty(),
                         "Unmatched parenthesis in acl selector starting "
                         "at '%s'.", (char *) argv[invalid_idx]);
    }

    /* Create a temporary user to validate and stage all changes against
     * before applying to an existing user or creating a new user. If all
     * arguments are valid the user parameters will all be applied together.
     * If there are any errors then none of the changes will be applied. */
    user *tempu = ACLCreateUnlinkedUser();
    if (u) {
        ACLCopyUser(tempu, u);
    }

    for (int j = 0; j < merged_argc; j++) {
        if (ACLSetUser(tempu,acl_args[j],(ssize_t) sdslen(acl_args[j])) != C_OK) {
            const char *errmsg = ACLSetUserStringError();
            error = sdscatfmt(sdsempty(),
                              "Error in ACL SETUSER modifier '%s': %s",
                              (char*)acl_args[j], errmsg);
            goto cleanup;
        }
    }

    /* Existing pub/sub clients authenticated with the user may need to be
     * disconnected if (some of) their channel permissions were revoked. */
    if (u) {
        ACLKillPubsubClientsIfNeeded(tempu, u);
    }

    /* Overwrite the user with the temporary user we modified above. */
    if (!u) {
        u = ACLCreateUser(username,sdslen(username));
    }
    serverAssert(u != NULL);

    ACLCopyUser(u, tempu);

cleanup:
    ACLFreeUser(tempu);
    for (int i = 0; i < merged_argc; i++) {
        sdsfree(acl_args[i]);
    }
    zfree(acl_args);

    return error;
}

/* Given an argument vector describing a user in the form:
 *
 *      user <username> ... ACL rules and flags ...
 *
 * this function validates, and if the syntax is valid, appends
 * the user definition to a list for later loading.
 *
 * The rules are tested for validity and if there obvious syntax errors
 * the function returns C_ERR and does nothing, otherwise C_OK is returned
 * and the user is appended to the list.
 *
 * Note that this function cannot stop in case of commands that are not found
 * and, in that case, the error will be emitted later, because certain
 * commands may be defined later once modules are loaded.
 *
 * When an error is detected and C_ERR is returned, the function populates
 * by reference (if not set to NULL) the argc_err argument with the index
 * of the argv vector that caused the error. */
int ACLAppendUserForLoading(sds *argv, int argc, int *argc_err) {
    if (argc < 2 || strcasecmp(argv[0],"user")) {
        if (argc_err) *argc_err = 0;
        return C_ERR;
    }

    if (listSearchKey(UsersToLoad, argv[1])) {
        if (argc_err) *argc_err = 1;
        errno = EALREADY;
        return C_ERR; 
    }

    /* Merged selectors before trying to process */
    int merged_argc;
    sds *acl_args = ACLMergeSelectorArguments(argv + 2, argc - 2, &merged_argc, argc_err);

    if (!acl_args) {
        return C_ERR;
    }

    /* Try to apply the user rules in a fake user to see if they
     * are actually valid. */
    user *fakeuser = ACLCreateUnlinkedUser();

    for (int j = 0; j < merged_argc; j++) {
        if (ACLSetUser(fakeuser,acl_args[j],sdslen(acl_args[j])) == C_ERR) {
            if (errno != ENOENT) {
                ACLFreeUser(fakeuser);
                if (argc_err) *argc_err = j;
                for (int i = 0; i < merged_argc; i++) sdsfree(acl_args[i]);
                zfree(acl_args);
                return C_ERR;
            }
        }
    }

    /* Rules look valid, let's append the user to the list. */
    sds *copy = zmalloc(sizeof(sds)*(merged_argc + 2));
    copy[0] = sdsdup(argv[1]);
    for (int j = 0; j < merged_argc; j++) copy[j+1] = sdsdup(acl_args[j]);
    copy[merged_argc + 1] = NULL;
    listAddNodeTail(UsersToLoad,copy);
    ACLFreeUser(fakeuser);
    for (int i = 0; i < merged_argc; i++) sdsfree(acl_args[i]);
    zfree(acl_args);
    return C_OK;
}

/* This function will load the configured users appended to the server
 * configuration via ACLAppendUserForLoading(). On loading errors it will
 * log an error and return C_ERR, otherwise C_OK will be returned. */
int ACLLoadConfiguredUsers(void) {
    listIter li;
    listNode *ln;
    listRewind(UsersToLoad,&li);
    while ((ln = listNext(&li)) != NULL) {
        sds *aclrules = listNodeValue(ln);
        sds username = aclrules[0];

        if (ACLStringHasSpaces(aclrules[0],sdslen(aclrules[0]))) {
            serverLog(LL_WARNING,"Spaces not allowed in ACL usernames");
            return C_ERR;
        }

        user *u = ACLCreateUser(username,sdslen(username));
        if (!u) {
            /* Only valid duplicate user is the default one. */
            serverAssert(!strcmp(username, "default"));
            u = ACLGetUserByName("default",7);
            ACLSetUser(u,"reset",-1);
        }

        /* Load every rule defined for this user. */
        for (int j = 1; aclrules[j]; j++) {
            if (ACLSetUser(u,aclrules[j],sdslen(aclrules[j])) != C_OK) {
                const char *errmsg = ACLSetUserStringError();
                serverLog(LL_WARNING,"Error loading ACL rule '%s' for "
                                     "the user named '%s': %s",
                          aclrules[j],aclrules[0],errmsg);
                return C_ERR;
            }
        }

        /* Having a disabled user in the configuration may be an error,
         * warn about it without returning any error to the caller. */
        if (u->flags & USER_FLAG_DISABLED) {
            serverLog(LL_NOTICE, "The user '%s' is disabled (there is no "
                                 "'on' modifier in the user description). Make "
                                 "sure this is not a configuration error.",
                      aclrules[0]);
        }
    }
    return C_OK;
}

/* 这个函数从指定的文件名加载 ACL:每一行
 * 都会被验证,应该是空行或者是在 redis.conf 配置文件或 ACL 文件中指定用户的格式,即:
 *
 *  user <username> ... rules ...
 *
 * 注意,此函数将 '#' 开头的行视为错误,因为 ACL 文件是用于重写的,
 * 注释将在重写后丢失。但是,允许空行以避免过于严格。
 *
 * 实现 ACL LOAD 的一个重要部分,使用此函数,是
 * 如果 ACL 文件由于某种原因无效,避免以损坏的规则结束。
 * 因此,函数将尝试在加载每个用户之前验证规则。
 * 对于将被发现有问题的每一行,函数将收集一条错误消息。
 *
 * 重要提示:如果有任何错误,将不会加载任何内容,
 * 规则将保持不变,就像它们原来的那样。
 *
 * 在整个过程结束时,如果在整个文件中没有找到任何错误,
 * 则返回 NULL。否则,返回一个 SDS 字符串,描述在单行中发现的所有问题。*/
sds ACLLoadFromFile(const char *filename) {
    FILE *fp;
    char buf[1024];

    /* 打开 ACL 文件。*/
    if ((fp = fopen(filename,"r")) == NULL) {
        sds errors = sdscatprintf(sdsempty(),
            "Error loading ACLs, opening file '%s': %s",
            filename, strerror(errno));
        return errors;
    }

    /* 将整个文件作为单个字符串加载到内存中。*/
    sds acls = sdsempty();
    while(fgets(buf,sizeof(buf),fp) != NULL)
        acls = sdscat(acls,buf);
    fclose(fp);

    /* 将文件拆分为行,并尝试加载每一行。*/
    int totlines;
    sds *lines, errors = sdsempty();
    lines = sdssplitlen(acls,strlen(acls),"\n",1,&totlines);
    sdsfree(acls);

    /* 我们将所有加载操作都放在用户基数树的新实例中,
     * 所以如果 ACL 文件有错误,我们可以回滚到旧版本。*/
    rax *old_users = Users;
    Users = raxNew();

    /* 加载文件的每一行。*/
    for (int i = 0; i < totlines; i++) {
        sds *argv;
        int argc;
        int linenum = i+1;

        lines[i] = sdstrim(lines[i]," \t\r\n");

        /* 跳过空行*/
        if (lines[i][0] == '\0') continue;

        /* 分割为参数*/
        argv = sdssplitlen(lines[i],sdslen(lines[i])," ",1,&argc);
        if (argv == NULL) {
            errors = sdscatprintf(errors,
                     "%s:%d: unbalanced quotes in acl line. ",
                     server.acl_filename, linenum);
            continue;
        }

        /* 如果结果命令向量为空,则跳过此行。*/
        if (argc == 0) {
            sdsfreesplitres(argv,argc);
            continue;
        }

        /* 该行应以 "user" 关键字开头。*/
        if (strcmp(argv[0],"user") || argc < 2) {
            errors = sdscatprintf(errors,
                     "%s:%d should start with user keyword followed "
                     "by the username. ", server.acl_filename,
                     linenum);
            sdsfreesplitres(argv,argc);
            continue;
        }

        /* 用户名中不允许有空格。*/
        if (ACLStringHasSpaces(argv[1],sdslen(argv[1]))) {
            errors = sdscatprintf(errors,
                     "'%s:%d: username '%s' contains invalid characters. ",
                     server.acl_filename, linenum, argv[1]);
            sdsfreesplitres(argv,argc);
            continue;
        }

        user *u = ACLCreateUser(argv[1],sdslen(argv[1]));

        /* 如果用户已存在,我们假设这是一个错误,并中止。*/
        if (!u) {
            errors = sdscatprintf(errors,"WARNING: Duplicate user '%s' found on line %d. ", argv[1], linenum);
            sdsfreesplitres(argv,argc);
            continue;
        }

        /* 最后处理选项并验证它们是否可以
         * 干净地应用于用户。如果任何选项无法应用,
         * 其他值将不会应用,因为所有挂起的更改都将被丢弃。*/
        int merged_argc;
        sds *acl_args = ACLMergeSelectorArguments(argv + 2, argc - 2, &merged_argc, NULL);
        if (!acl_args) {
            errors = sdscatprintf(errors,
                    "%s:%d: Unmatched parenthesis in selector definition.",
                    server.acl_filename, linenum);
        }

        int syntax_error = 0;
        for (int j = 0; j < merged_argc; j++) {
            acl_args[j] = sdstrim(acl_args[j],"\t\r\n");
            if (ACLSetUser(u,acl_args[j],sdslen(acl_args[j])) != C_OK) {
                const char *errmsg = ACLSetUserStringError();
                if (errno == ENOENT) {
                    /* 对于缺少的命令,我们会打印出更多信息,因为
                     * 它不应包含任何敏感信息。*/
                    errors = sdscatprintf(errors,
                            "%s:%d: Error in applying operation '%s': %s. ",
                            server.acl_filename, linenum, acl_args[j], errmsg);
                } else if (syntax_error == 0) {
                    /* 对于所有其他错误,只打印出第一个遇到的错误,因为它可能会影响
                     * 未来的操作。*/
                    errors = sdscatprintf(errors,
                            "%s:%d: %s. ",
                            server.acl_filename, linenum, errmsg);
                    syntax_error = 1;
                }
            }
        }

        for (int i = 0; i < merged_argc; i++) sdsfree(acl_args[i]);
        zfree(acl_args);

        /* 仅当没有错误时,将规则应用于新用户集,否则它是无用的,
         * 因为我们将丢弃新用户集。*/
        if (sdslen(errors) != 0) {
            sdsfreesplitres(argv,argc);
            continue;
        }

        sdsfreesplitres(argv,argc);
    }

    sdsfreesplitres(lines,totlines);

    /* 检查是否找到错误并做出相应的反应。*/
    if (sdslen(errors) == 0) {
        /* 默认用户指针在各个地方被引用:直接替换这些引用是更简单的,
         * 而不是复制新的默认用户配置到旧的用户中。*/
        user *new_default = ACLGetUserByName("default",7);
        if (!new_default) {
            new_default = ACLCreateDefaultUser();
        }

        ACLCopyUser(DefaultUser,new_default);
        ACLFreeUser(new_default);
        raxInsert(Users,(unsigned char*)"default",7,DefaultUser,NULL);
        raxRemove(old_users,(unsigned char*)"default",7,NULL);
        ACLFreeUsersSet(old_users);
        sdsfree(errors);
        return NULL;
    } else {
        ACLFreeUsersSet(Users);
        Users = old_users;
        errors = sdscat(errors,"WARNING: ACL errors detected, no change to the previously active ACL rules was performed");
        return errors;
    }
}

/* 将当前内存中的 ACL 生成一份副本,并保存到指定的文件名中。
 * 如果 I/O 过程中出现错误,返回 C_ERR,否则返回 C_OK。
 * 当返回 C_ERR 时,会产生一条日志,其中包含有关问题的提示。*/
int ACLSaveToFile(const char *filename) {
    sds acl = sdsempty();
    int fd = -1;
    sds tmpfilename = NULL;
    int retval = C_ERR;

    /* 生成一个包含新版本 ACL 文件的 SDS 字符串。*/
    raxIterator ri;
    raxStart(&ri,Users);
    raxSeek(&ri,"^",NULL,0);
    while(raxNext(&ri)) {
        user *u = ri.data;
        /* 以配置文件格式返回信息。*/
        sds user = sdsnew("user ");
        user = sdscatsds(user,u->name);
        user = sdscatlen(user," ",1);
        robj *descr = ACLDescribeUser(u);
        user = sdscatsds(user,descr->ptr);
        decrRefCount(descr);
        acl = sdscatsds(acl,user);
        acl = sdscatlen(acl,"\n",1);
        sdsfree(user);
    }
    raxStop(&ri);

    /* 创建一个临时文件,其中包含新内容。*/
    tmpfilename = sdsnew(filename);
    tmpfilename = sdscatfmt(tmpfilename,".tmp-%i-%I",
        (int) getpid(),commandTimeSnapshot());
    if ((fd = open(tmpfilename,O_WRONLY|O_CREAT,0644)) == -1) {
        serverLog(LL_WARNING,"Opening temp ACL file for ACL SAVE: %s",
            strerror(errno));
        goto cleanup;
    }

    /* 写入它。*/
    size_t offset = 0;
    while (offset < sdslen(acl)) {
        ssize_t written_bytes = write(fd,acl + offset,sdslen(acl) - offset);
        if (written_bytes <= 0) {
            if (errno == EINTR) continue;
            serverLog(LL_WARNING,"Writing ACL file for ACL SAVE: %s",
                strerror(errno));
            goto cleanup;
        }
        offset += written_bytes;
    }
    if (redis_fsync(fd) == -1) {
        serverLog(LL_WARNING,"Syncing ACL file for ACL SAVE: %s",
            strerror(errno));
        goto cleanup;
    }
    close(fd); fd = -1;

    /* 用新文件替换旧文件。*/
    if (rename(tmpfilename,filename) == -1) {
        serverLog(LL_WARNING,"Renaming ACL file for ACL SAVE: %s",
            strerror(errno));
        goto cleanup;
    }
    if (fsyncFileDir(filename) == -1) {
        serverLog(LL_WARNING,"Syncing ACL directory for ACL SAVE: %s",
            strerror(errno));
        goto cleanup;
    }
    sdsfree(tmpfilename); tmpfilename = NULL;
    retval = C_OK; /* 如果我们到达这一点,一切都正常。*/

cleanup:
    if (fd != -1) close(fd);
    if (tmpfilename) unlink(tmpfilename);
    sdsfree(tmpfilename);
    sdsfree(acl);
    return retval;
}

/* 此函数在服务器已经运行,模块已加载,我们准备开始时调用,
 * 以从 redis.conf 中配置的用户列表或 ACL 文件加载 ACL。
 * 该函数将在尝试同时使用这两种加载方法时退出并出错。*/
void ACLLoadUsersAtStartup(void) {
    if (server.acl_filename[0] != '\0' && listLength(UsersToLoad) != 0) {
        serverLog(LL_WARNING,
            "Configuring Redis with users defined in redis.conf and at "
            "the same setting an ACL file path is invalid. This setup "
            "is very likely to lead to configuration errors and security "
            "holes, please define either an ACL file or declare users "
            "directly in your redis.conf, but not both.");
        exit(1);
    }

    if (ACLLoadConfiguredUsers() == C_ERR) {
        serverLog(LL_WARNING,
            "Critical error while loading ACLs. Exiting.");
        exit(1);
    }

    if (server.acl_filename[0] != '\0') {
        sds errors = ACLLoadFromFile(server.acl_filename);
        if (errors) {
            serverLog(LL_WARNING,
                "Aborting Redis startup because of ACL errors: %s", errors);
            sdsfree(errors);
            exit(1);
        }
    }
}

/* =============================================================================
 * ACL log
 * ==========================================================================*/

#define ACL_LOG_GROUPING_MAX_TIME_DELTA 60000

/* 此结构定义了 ACL 日志中的一个条目。*/
typedef struct ACLLogEntry {
    uint64_t count;     /* 最近发生的次数。*/
    int reason;         /* 拒绝命令的原因。ACL_DENIED_*. */
    int context;        /* 顶层、Lua 或 MULTI/EXEC？ACL_LOG_CTX_*. */
    sds object;         /* 键名或命令名。*/
    sds username;       /* 客户端已经认证的用户。*/
    mstime_t ctime;     /* 最后更新此条目的毫秒时间。*/
    sds cinfo;          /* 客户端信息(最后一个客户端如果已更新)。*/
    long long entry_id;         /* 此条目的(entry_id, timestamp_created)对是一个唯一标识符
                                  * 如果节点死亡并重新启动,它可以检测到这是否是一个新系列。*/
    mstime_t timestamp_created; /* 此条目创建时的 UNIX 时间(毫秒)。*/
} ACLLogEntry;

/* 此函数将检查 ACL 条目 'a' 和 'b' 是否足够相似,
 * 以便我们实际上应该更新现有的 ACL 日志条目,而不是创建一个新条目。*/
int ACLLogMatchEntry(ACLLogEntry *a, ACLLogEntry *b) {
    if (a->reason != b->reason) return 0;
    if (a->context != b->context) return 0;
    mstime_t delta = a->ctime - b->ctime;
    if (delta < 0) delta = -delta;
    if (delta > ACL_LOG_GROUPING_MAX_TIME_DELTA) return 0;
    if (sdscmp(a->object,b->object) != 0) return 0;
    if (sdscmp(a->username,b->username) != 0) return 0;
    return 1;
}

/* 释放 ACL 日志条目。*/
void ACLFreeLogEntry(void *leptr) {
    ACLLogEntry *le = leptr;
    sdsfree(le->object);
    sdsfree(le->username);
    sdsfree(le->cinfo);
    zfree(le);
}

/* 根据原因更新相关计数器*/
void ACLUpdateInfoMetrics(int reason){
    if (reason == ACL_DENIED_AUTH) {
        server.acl_info.user_auth_failures++;
    } else if (reason == ACL_DENIED_CMD) {
        server.acl_info.invalid_cmd_accesses++;
    } else if (reason == ACL_DENIED_KEY) {
        server.acl_info.invalid_key_accesses++;
    } else if (reason == ACL_DENIED_CHANNEL) {
        server.acl_info.invalid_channel_accesses++;
    } else {
        serverPanic("Unknown ACL_DENIED encoding");
    }
}

/* 添加一个新条目到 ACL 日志中,确保在达到允许的日志最大长度时删除旧条目。
 * 此函数尝试在当前日志中查找类似的条目,以便在实际上只需更新现有条目而不是创建新条目时。
 *
 * argpos 参数在 reason 是 ACL_DENIED_KEY 或 ACL_DENIED_CHANNEL 时使用,
 * 因为它允许函数记录导致问题的键或通道名称。
 *
 * 最后 2 个参数是用于覆盖任何依赖于客户端和原因参数的自动覆盖(使用 NULL 以使用默认值)。
 *
 * 如果 `object` 不是 NULL,此函数会接管它。
 */
void addACLLogEntry(client *c, int reason, int context, int argpos, sds username, sds object) {
    /* 更新 ACL 信息指标*/
    ACLUpdateInfoMetrics(reason);
    
    /* 创建一个新条目。*/
    struct ACLLogEntry *le = zmalloc(sizeof(*le));
    le->count = 1;
    le->reason = reason;
    le->username = sdsdup(username ? username : c->user->name);
    le->ctime = commandTimeSnapshot();
    le->entry_id = ACLLogEntryCount;
    le->timestamp_created = le->ctime;

    if (object) {
        le->object = object;
    } else {
        switch(reason) {
            case ACL_DENIED_CMD: le->object = sdsdup(c->cmd->fullname); break;
            case ACL_DENIED_KEY: le->object = sdsdup(c->argv[argpos]->ptr); break;
            case ACL_DENIED_CHANNEL: le->object = sdsdup(c->argv[argpos]->ptr); break;
            case ACL_DENIED_AUTH: le->object = sdsdup(c->argv[0]->ptr); break;
            default: le->object = sdsempty();
        }
    }

    /* 如果我们有一个来自网络的真实客户端,使用它(可能在模块定时器上缺失)*/
    client *realclient = server.current_client? server.current_client : c;

    le->cinfo = catClientInfoString(sdsempty(),realclient);
    le->context = context;

    /* 尝试将此条目与过去的条目匹配,以查看我们是否可以只更新现有条目,而不是创建一个新条目。*/
    long toscan = 10; /* 只做有限的工作来查找重复的。*/
    listIter li;
    listNode *ln;
    listRewind(ACLLog,&li);
    ACLLogEntry *match = NULL;
    while (toscan-- && (ln = listNext(&li)) != NULL) {
        ACLLogEntry *current = listNodeValue(ln);
        if (ACLLogMatchEntry(current,le)) {
            match = current;
            listDelNode(ACLLog,ln);
            listAddNodeHead(ACLLog,current);
            break;
        }
    }

    /* 如果有匹配,更新条目,否则添加为新条目。*/
    if (match) {
        /* 我们更新现有条目的一些字段,并增加此条目的事件计数器。*/
        sdsfree(match->cinfo);
        match->cinfo = le->cinfo;
        match->ctime = le->ctime;
        match->count++;

        /* 释放旧条目。*/
        le->cinfo = NULL;
        ACLFreeLogEntry(le);
    } else {
        /* 将其添加到我们的条目列表中。我们需要修剪列表
         * 到其最大长度。*/
        ACLLogEntryCount++; /* 增加 entry_id 计数以使日志中的每个记录都是唯一的。*/
        listAddNodeHead(ACLLog, le);
        while(listLength(ACLLog) > server.acllog_max_len) {
            listNode *ln = listLast(ACLLog);
            ACLLogEntry *le = listNodeValue(ln);
            ACLFreeLogEntry(le);
            listDelNode(ACLLog,ln);
        }
    }
}

sds getAclErrorMessage(int acl_res, user *user, struct redisCommand *cmd, sds errored_val, int verbose) {
    switch (acl_res) {
    case ACL_DENIED_CMD:
        return sdscatfmt(sdsempty(), "User %S has no permissions to run "
                                     "the '%S' command", user->name, cmd->fullname);
    case ACL_DENIED_KEY:
        if (verbose) {
            return sdscatfmt(sdsempty(), "User %S has no permissions to access "
                                         "the '%S' key", user->name, errored_val);
        } else {
            return sdsnew("No permissions to access a key");
        }
    case ACL_DENIED_CHANNEL:
        if (verbose) {
            return sdscatfmt(sdsempty(), "User %S has no permissions to access "
                                         "the '%S' channel", user->name, errored_val);
        } else {
            return sdsnew("No permissions to access a channel");
        }
    }
    serverPanic("Reached deadcode on getAclErrorMessage");
}

/* =============================================================================
 * ACL related commands
 * ==========================================================================*/

/* ACL CAT category */
void aclCatWithFlags(client *c, dict *commands, uint64_t cflag, int *arraylen) {
    dictEntry *de;
    dictIterator *di = dictGetIterator(commands);

    while ((de = dictNext(di)) != NULL) {
        struct redisCommand *cmd = dictGetVal(de);
        if (cmd->flags & CMD_MODULE) continue;
        if (cmd->acl_categories & cflag) {
            addReplyBulkCBuffer(c, cmd->fullname, sdslen(cmd->fullname));
            (*arraylen)++;
        }

        if (cmd->subcommands_dict) {
            aclCatWithFlags(c, cmd->subcommands_dict, cflag, arraylen);
        }
    }
    dictReleaseIterator(di);
}

/* Add the formatted response from a single selector to the ACL GETUSER
 * response. This function returns the number of fields added. 
 * 
 * Setting verbose to 1 means that the full qualifier for key and channel
 * permissions are shown.
 */
int aclAddReplySelectorDescription(client *c, aclSelector *s) {
    listIter li;
    listNode *ln;

    /* Commands */
    addReplyBulkCString(c,"commands");
    sds cmddescr = ACLDescribeSelectorCommandRules(s);
    addReplyBulkSds(c,cmddescr);
    
    /* Key patterns */
    addReplyBulkCString(c,"keys");
    if (s->flags & SELECTOR_FLAG_ALLKEYS) {
        addReplyBulkCBuffer(c,"~*",2);
    } else {
        sds dsl = sdsempty();
        listRewind(s->patterns,&li);
        while((ln = listNext(&li))) {
            keyPattern *thispat = (keyPattern *) listNodeValue(ln);
            if (ln != listFirst(s->patterns)) dsl = sdscat(dsl, " ");
            dsl = sdsCatPatternString(dsl, thispat);
        }
        addReplyBulkSds(c, dsl);
    }

    /* Pub/sub patterns */
    addReplyBulkCString(c,"channels");
    if (s->flags & SELECTOR_FLAG_ALLCHANNELS) {
        addReplyBulkCBuffer(c,"&*",2);
    } else {
        sds dsl = sdsempty();
        listRewind(s->channels,&li);
        while((ln = listNext(&li))) {
            sds thispat = listNodeValue(ln);
            if (ln != listFirst(s->channels)) dsl = sdscat(dsl, " ");
            dsl = sdscatfmt(dsl, "&%S", thispat);
        }
        addReplyBulkSds(c, dsl);
    }
    return 3;
}

/* ACL -- show and modify the configuration of ACL users.
 * ACL HELP
 * ACL LOAD
 * ACL SAVE
 * ACL LIST
 * ACL USERS
 * ACL CAT [<category>]
 * ACL SETUSER <username> ... acl rules ...
 * ACL DELUSER <username> [...]
 * ACL GETUSER <username>
 * ACL GENPASS [<bits>]
 * ACL WHOAMI
 * ACL LOG [<count> | RESET]
 */
void aclCommand(client *c) {
    char *sub = c->argv[1]->ptr;
    if (!strcasecmp(sub,"setuser") && c->argc >= 3) {
        /* Initially redact all of the arguments to not leak any information
         * about the user. */
        for (int j = 2; j < c->argc; j++) {
            redactClientCommandArgument(c, j);
        }

        sds username = c->argv[2]->ptr;
        /* Check username validity. */
        if (ACLStringHasSpaces(username,sdslen(username))) {
            addReplyErrorFormat(c,
                "Usernames can't contain spaces or null characters");
            return;
        }

        user *u = ACLGetUserByName(username,sdslen(username));

        sds *temp_argv = zmalloc(c->argc * sizeof(sds));
        for (int i = 3; i < c->argc; i++) temp_argv[i-3] = c->argv[i]->ptr;

        sds error = ACLStringSetUser(u, username, temp_argv, c->argc - 3);
        zfree(temp_argv);
        if (error == NULL) {
            addReply(c,shared.ok);
        } else {
            addReplyErrorSdsSafe(c, error);
        }
        return;
    } else if (!strcasecmp(sub,"deluser") && c->argc >= 3) {
        int deleted = 0;
        for (int j = 2; j < c->argc; j++) {
            sds username = c->argv[j]->ptr;
            if (!strcmp(username,"default")) {
                addReplyError(c,"The 'default' user cannot be removed");
                return;
            }
        }

        for (int j = 2; j < c->argc; j++) {
            sds username = c->argv[j]->ptr;
            user *u;
            if (raxRemove(Users,(unsigned char*)username,
                          sdslen(username),
                          (void**)&u))
            {
                ACLFreeUserAndKillClients(u);
                deleted++;
            }
        }
        addReplyLongLong(c,deleted);
    } else if (!strcasecmp(sub,"getuser") && c->argc == 3) {
        user *u = ACLGetUserByName(c->argv[2]->ptr,sdslen(c->argv[2]->ptr));
        if (u == NULL) {
            addReplyNull(c);
            return;
        }

        void *ufields = addReplyDeferredLen(c);
        int fields = 3;

        /* Flags */
        addReplyBulkCString(c,"flags");
        void *deflen = addReplyDeferredLen(c);
        int numflags = 0;
        for (int j = 0; ACLUserFlags[j].flag; j++) {
            if (u->flags & ACLUserFlags[j].flag) {
                addReplyBulkCString(c,ACLUserFlags[j].name);
                numflags++;
            }
        }
        setDeferredSetLen(c,deflen,numflags);

        /* Passwords */
        addReplyBulkCString(c,"passwords");
        addReplyArrayLen(c,listLength(u->passwords));
        listIter li;
        listNode *ln;
        listRewind(u->passwords,&li);
        while((ln = listNext(&li))) {
            sds thispass = listNodeValue(ln);
            addReplyBulkCBuffer(c,thispass,sdslen(thispass));
        }
        /* Include the root selector at the top level for backwards compatibility */
        fields += aclAddReplySelectorDescription(c, ACLUserGetRootSelector(u));

        /* Describe all of the selectors on this user, including duplicating the root selector */
        addReplyBulkCString(c,"selectors");
        addReplyArrayLen(c, listLength(u->selectors) - 1);
        listRewind(u->selectors,&li);
        serverAssert(listNext(&li));
        while((ln = listNext(&li))) {
            void *slen = addReplyDeferredLen(c);
            int sfields = aclAddReplySelectorDescription(c, (aclSelector *)listNodeValue(ln));
            setDeferredMapLen(c, slen, sfields);
        } 
        setDeferredMapLen(c, ufields, fields);
    } else if ((!strcasecmp(sub,"list") || !strcasecmp(sub,"users")) &&
               c->argc == 2)
    {
        int justnames = !strcasecmp(sub,"users");
        addReplyArrayLen(c,raxSize(Users));
        raxIterator ri;
        raxStart(&ri,Users);
        raxSeek(&ri,"^",NULL,0);
        while(raxNext(&ri)) {
            user *u = ri.data;
            if (justnames) {
                addReplyBulkCBuffer(c,u->name,sdslen(u->name));
            } else {
                /* Return information in the configuration file format. */
                sds config = sdsnew("user ");
                config = sdscatsds(config,u->name);
                config = sdscatlen(config," ",1);
                robj *descr = ACLDescribeUser(u);
                config = sdscatsds(config,descr->ptr);
                decrRefCount(descr);
                addReplyBulkSds(c,config);
            }
        }
        raxStop(&ri);
    } else if (!strcasecmp(sub,"whoami") && c->argc == 2) {
        if (c->user != NULL) {
            addReplyBulkCBuffer(c,c->user->name,sdslen(c->user->name));
        } else {
            addReplyNull(c);
        }
    } else if (server.acl_filename[0] == '\0' &&
               (!strcasecmp(sub,"load") || !strcasecmp(sub,"save")))
    {
        addReplyError(c,"This Redis instance is not configured to use an ACL file. You may want to specify users via the ACL SETUSER command and then issue a CONFIG REWRITE (assuming you have a Redis configuration file set) in order to store users in the Redis configuration.");
        return;
    } else if (!strcasecmp(sub,"load") && c->argc == 2) {
        sds errors = ACLLoadFromFile(server.acl_filename);
        if (errors == NULL) {
            addReply(c,shared.ok);
        } else {
            addReplyError(c,errors);
            sdsfree(errors);
        }
    } else if (!strcasecmp(sub,"save") && c->argc == 2) {
        if (ACLSaveToFile(server.acl_filename) == C_OK) {
            addReply(c,shared.ok);
        } else {
            addReplyError(c,"There was an error trying to save the ACLs. "
                            "Please check the server logs for more "
                            "information");
        }
    } else if (!strcasecmp(sub,"cat") && c->argc == 2) {
        void *dl = addReplyDeferredLen(c);
        int j;
        for (j = 0; ACLCommandCategories[j].flag != 0; j++)
            addReplyBulkCString(c,ACLCommandCategories[j].name);
        setDeferredArrayLen(c,dl,j);
    } else if (!strcasecmp(sub,"cat") && c->argc == 3) {
        uint64_t cflag = ACLGetCommandCategoryFlagByName(c->argv[2]->ptr);
        if (cflag == 0) {
            addReplyErrorFormat(c, "Unknown category '%.128s'", (char*)c->argv[2]->ptr);
            return;
        }
        int arraylen = 0;
        void *dl = addReplyDeferredLen(c);
        aclCatWithFlags(c, server.orig_commands, cflag, &arraylen);
        setDeferredArrayLen(c,dl,arraylen);
    } else if (!strcasecmp(sub,"genpass") && (c->argc == 2 || c->argc == 3)) {
        #define GENPASS_MAX_BITS 4096
        char pass[GENPASS_MAX_BITS/8*2]; /* Hex representation. */
        long bits = 256; /* By default generate 256 bits passwords. */

        if (c->argc == 3 && getLongFromObjectOrReply(c,c->argv[2],&bits,NULL)
            != C_OK) return;

        if (bits <= 0 || bits > GENPASS_MAX_BITS) {
            addReplyErrorFormat(c,
                "ACL GENPASS argument must be the number of "
                "bits for the output password, a positive number "
                "up to %d",GENPASS_MAX_BITS);
            return;
        }

        long chars = (bits+3)/4; /* Round to number of characters to emit. */
        getRandomHexChars(pass,chars);
        addReplyBulkCBuffer(c,pass,chars);
    } else if (!strcasecmp(sub,"log") && (c->argc == 2 || c->argc ==3)) {
        long count = 10; /* Number of entries to emit by default. */

        /* Parse the only argument that LOG may have: it could be either
         * the number of entries the user wants to display, or alternatively
         * the "RESET" command in order to flush the old entries. */
        if (c->argc == 3) {
            if (!strcasecmp(c->argv[2]->ptr,"reset")) {
                listSetFreeMethod(ACLLog,ACLFreeLogEntry);
                listEmpty(ACLLog);
                listSetFreeMethod(ACLLog,NULL);
                addReply(c,shared.ok);
                return;
            } else if (getLongFromObjectOrReply(c,c->argv[2],&count,NULL)
                       != C_OK)
            {
                return;
            }
            if (count < 0) count = 0;
        }

        /* Fix the count according to the number of entries we got. */
        if ((size_t)count > listLength(ACLLog))
            count = listLength(ACLLog);

        addReplyArrayLen(c,count);
        listIter li;
        listNode *ln;
        listRewind(ACLLog,&li);
        mstime_t now = commandTimeSnapshot();
        while (count-- && (ln = listNext(&li)) != NULL) {
            ACLLogEntry *le = listNodeValue(ln);
            addReplyMapLen(c,10);
            addReplyBulkCString(c,"count");
            addReplyLongLong(c,le->count);

            addReplyBulkCString(c,"reason");
            char *reasonstr;
            switch(le->reason) {
            case ACL_DENIED_CMD: reasonstr="command"; break;
            case ACL_DENIED_KEY: reasonstr="key"; break;
            case ACL_DENIED_CHANNEL: reasonstr="channel"; break;
            case ACL_DENIED_AUTH: reasonstr="auth"; break;
            default: reasonstr="unknown";
            }
            addReplyBulkCString(c,reasonstr);

            addReplyBulkCString(c,"context");
            char *ctxstr;
            switch(le->context) {
            case ACL_LOG_CTX_TOPLEVEL: ctxstr="toplevel"; break;
            case ACL_LOG_CTX_MULTI: ctxstr="multi"; break;
            case ACL_LOG_CTX_LUA: ctxstr="lua"; break;
            case ACL_LOG_CTX_MODULE: ctxstr="module"; break;
            default: ctxstr="unknown";
            }
            addReplyBulkCString(c,ctxstr);

            addReplyBulkCString(c,"object");
            addReplyBulkCBuffer(c,le->object,sdslen(le->object));
            addReplyBulkCString(c,"username");
            addReplyBulkCBuffer(c,le->username,sdslen(le->username));
            addReplyBulkCString(c,"age-seconds");
            double age = (double)(now - le->ctime)/1000;
            addReplyDouble(c,age);
            addReplyBulkCString(c,"client-info");
            addReplyBulkCBuffer(c,le->cinfo,sdslen(le->cinfo));
            addReplyBulkCString(c, "entry-id");
            addReplyLongLong(c, le->entry_id);
            addReplyBulkCString(c, "timestamp-created");
            addReplyLongLong(c, le->timestamp_created);
            addReplyBulkCString(c, "timestamp-last-updated");
            addReplyLongLong(c, le->ctime);
        }
    } else if (!strcasecmp(sub,"dryrun") && c->argc >= 4) {
        struct redisCommand *cmd;
        user *u = ACLGetUserByName(c->argv[2]->ptr,sdslen(c->argv[2]->ptr));
        if (u == NULL) {
            addReplyErrorFormat(c, "User '%s' not found", (char *)c->argv[2]->ptr);
            return;
        }

        if ((cmd = lookupCommand(c->argv + 3, c->argc - 3)) == NULL) {
            addReplyErrorFormat(c, "Command '%s' not found", (char *)c->argv[3]->ptr);
            return;
        }

        if ((cmd->arity > 0 && cmd->arity != c->argc-3) ||
            (c->argc-3 < -cmd->arity))
        {
            addReplyErrorFormat(c,"wrong number of arguments for '%s' command", cmd->fullname);
            return;
        }

        int idx;
        int result = ACLCheckAllUserCommandPerm(u, cmd, c->argv + 3, c->argc - 3, &idx);
        if (result != ACL_OK) {
            sds err = getAclErrorMessage(result, u, cmd,  c->argv[idx+3]->ptr, 1);
            addReplyBulkSds(c, err);
            return;
        }

        addReply(c,shared.ok);
    } else if (c->argc == 2 && !strcasecmp(sub,"help")) {
        const char *help[] = {
"CAT [<category>]",
"    List all commands that belong to <category>, or all command categories",
"    when no category is specified.",
"DELUSER <username> [<username> ...]",
"    Delete a list of users.",
"DRYRUN <username> <command> [<arg> ...]",
"    Returns whether the user can execute the given command without executing the command.",
"GETUSER <username>",
"    Get the user's details.",
"GENPASS [<bits>]",
"    Generate a secure 256-bit user password. The optional `bits` argument can",
"    be used to specify a different size.",
"LIST",
"    Show users details in config file format.",
"LOAD",
"    Reload users from the ACL file.",
"LOG [<count> | RESET]",
"    Show the ACL log entries.",
"SAVE",
"    Save the current config to the ACL file.",
"SETUSER <username> <attribute> [<attribute> ...]",
"    Create or modify a user with the specified attributes.",
"USERS",
"    List all the registered usernames.",
"WHOAMI",
"    Return the current connection username.",
NULL
        };
        addReplyHelp(c,help);
    } else {
        addReplySubcommandSyntaxError(c);
    }
}

void addReplyCommandCategories(client *c, struct redisCommand *cmd) {
    int flagcount = 0;
    void *flaglen = addReplyDeferredLen(c);
    for (int j = 0; ACLCommandCategories[j].flag != 0; j++) {
        if (cmd->acl_categories & ACLCommandCategories[j].flag) {
            addReplyStatusFormat(c, "@%s", ACLCommandCategories[j].name);
            flagcount++;
        }
    }
    setDeferredSetLen(c, flaglen, flagcount);
}

/* AUTH <password>
 * AUTH <username> <password> (Redis >= 6.0 form)
 *
 * When the user is omitted it means that we are trying to authenticate
 * against the default user. */
void authCommand(client *c) {
    /* Only two or three argument forms are allowed. */
    if (c->argc > 3) {
        addReplyErrorObject(c,shared.syntaxerr);
        return;
    }
    /* Always redact the second argument */
    redactClientCommandArgument(c, 1);

    /* Handle the two different forms here. The form with two arguments
     * will just use "default" as username. */
    robj *username, *password;
    if (c->argc == 2) {
        /* Mimic the old behavior of giving an error for the two argument
         * form if no password is configured. */
        if (DefaultUser->flags & USER_FLAG_NOPASS) {
            addReplyError(c,"AUTH <password> called without any password "
                            "configured for the default user. Are you sure "
                            "your configuration is correct?");
            return;
        }

        username = shared.default_username; 
        password = c->argv[1];
    } else {
        username = c->argv[1];
        password = c->argv[2];
        redactClientCommandArgument(c, 2);
    }

    robj *err = NULL;
    int result = ACLAuthenticateUser(c, username, password, &err);
    if (result == AUTH_OK) {
        addReply(c, shared.ok);
    } else if (result == AUTH_ERR) {
        addAuthErrReply(c, err);
    }
    if (err) decrRefCount(err);
}

/* Set the password for the "default" ACL user. This implements supports for
 * requirepass config, so passing in NULL will set the user to be nopass. */
void ACLUpdateDefaultUserPassword(sds password) {
    ACLSetUser(DefaultUser,"resetpass",-1);
    if (password) {
        sds aclop = sdscatlen(sdsnew(">"), password, sdslen(password));
        ACLSetUser(DefaultUser,aclop,sdslen(aclop));
        sdsfree(aclop);
    } else {
        ACLSetUser(DefaultUser,"nopass",-1);
    }
}
