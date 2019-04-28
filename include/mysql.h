/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#ifndef SW_MYSQL_H_
#define SW_MYSQL_H_

#include "swoole_cxx.h"

#ifdef SW_USE_OPENSSL
#ifndef OPENSSL_NO_RSA
#define SW_MYSQL_RSA_SUPPORT
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#endif
#endif

#include <string>

enum sw_mysql_command
{
    SW_MYSQL_COM_NULL = -1,
    SW_MYSQL_COM_SLEEP = 0,
    SW_MYSQL_COM_QUIT,
    SW_MYSQL_COM_INIT_DB,
    SW_MYSQL_COM_QUERY = 3,
    SW_MYSQL_COM_FIELD_LIST,
    SW_MYSQL_COM_CREATE_DB,
    SW_MYSQL_COM_DROP_DB,
    SW_MYSQL_COM_REFRESH,
    SW_MYSQL_COM_SHUTDOWN,
    SW_MYSQL_COM_STATISTICS,
    SW_MYSQL_COM_PROCESS_INFO,
    SW_MYSQL_COM_CONNECT,
    SW_MYSQL_COM_PROCESS_KILL,
    SW_MYSQL_COM_DEBUG,
    SW_MYSQL_COM_PING,
    SW_MYSQL_COM_TIME,
    SW_MYSQL_COM_DELAYED_INSERT,
    SW_MYSQL_COM_CHANGE_USER,
    SW_MYSQL_COM_BINLOG_DUMP,
    SW_MYSQL_COM_TABLE_DUMP,
    SW_MYSQL_COM_CONNECT_OUT,
    SW_MYSQL_COM_REGISTER_SLAVE,
    SW_MYSQL_COM_STMT_PREPARE,
    SW_MYSQL_COM_STMT_EXECUTE,
    SW_MYSQL_COM_STMT_SEND_LONG_DATA,
    SW_MYSQL_COM_STMT_CLOSE,
    SW_MYSQL_COM_STMT_RESET,
    SW_MYSQL_COM_SET_OPTION,
    SW_MYSQL_COM_STMT_FETCH,
    SW_MYSQL_COM_DAEMON,
    SW_MYSQL_COM_END
};

enum sw_mysql_handshake_state
{
    SW_MYSQL_HANDSHAKE_WAIT_REQUEST,
    SW_MYSQL_HANDSHAKE_WAIT_SWITCH,
    SW_MYSQL_HANDSHAKE_WAIT_SIGNATURE,
    SW_MYSQL_HANDSHAKE_WAIT_RSA,
    SW_MYSQL_HANDSHAKE_WAIT_RESULT,
    SW_MYSQL_HANDSHAKE_COMPLETED,
};

#define SW_MYSQL_AUTH_SIGNATRUE_PACKET_LENGTH 2

enum sw_mysql_auth_signature
{
    SW_MYSQL_AUTH_SIGNATURE_ERROR = 0x00, // get signature failed
    SW_MYSQL_AUTH_SIGNATURE = 0x01,
    SW_MYSQL_AUTH_SIGNATURE_RSA_PREPARED = 0x02,
    SW_MYSQL_AUTH_SIGNATURE_SUCCESS = 0x03,
    SW_MYSQL_AUTH_SIGNATURE_FULL_AUTH_REQUIRED = 0x04, //rsa required
};

enum sw_mysql_state_flag
{
    SW_MYSQL_STATE_FLAG_QUERY   = 1 << 4,
    SW_MYSQL_STATE_FLAG_EXECUTE = 1 << 5,
};

enum sw_mysql_state
{
    SW_MYSQL_STATE_IDLE                 = 0,
    SW_MYSQL_STATE_QUERY                = 1 | SW_MYSQL_STATE_FLAG_QUERY,
    SW_MYSQL_STATE_QUERY_FETCH          = 2 | SW_MYSQL_STATE_FLAG_QUERY,
    SW_MYSQL_STATE_QUERY_MORE_RESULTS   = 3 | SW_MYSQL_STATE_FLAG_QUERY,
    SW_MYSQL_STATE_PREPARE              = 4 | SW_MYSQL_STATE_FLAG_QUERY,
    SW_MYSQL_STATE_EXECUTE              = 5 | SW_MYSQL_STATE_FLAG_EXECUTE,
    SW_MYSQL_STATE_EXECUTE_FETCH        = 6 | SW_MYSQL_STATE_FLAG_EXECUTE,
    SW_MYSQL_STATE_EXECUTE_MORE_RESULTS = 7 | SW_MYSQL_STATE_FLAG_EXECUTE,
    SW_MYSQL_STATE_CLOSED               = 8 | SW_MYSQL_STATE_FLAG_EXECUTE,
};

enum sw_mysql_error_code
{
    SW_MYSQL_ERR_NULL = 0,
    // it should be bigger than SW_ABORT
    // else may be in conflict with SW_xxx err code.
    SW_MYSQL_ERR_PROTOCOL_ERROR = 101,
    SW_MYSQL_ERR_BUFFER_OVERSIZE,
    SW_MYSQL_ERR_PACKET_CORRUPT,
    SW_MYSQL_ERR_WANT_READ,
    SW_MYSQL_ERR_WANT_WRITE,
    SW_MYSQL_ERR_UNKNOWN_ERROR,

    SW_MYSQL_ERR_MYSQL_ERROR,
    SW_MYSQL_ERR_SERVER_LOST,
    SW_MYSQL_ERR_BAD_PORT,
    SW_MYSQL_ERR_RESOLV_HOST,
    SW_MYSQL_ERR_SYSTEM,
    SW_MYSQL_ERR_CANT_CONNECT,
    SW_MYSQL_ERR_BUFFER_TOO_SMALL,
    SW_MYSQL_ERR_UNEXPECT_R_STATE,
    SW_MYSQL_ERR_STRFIELD_CORRUPT,
    SW_MYSQL_ERR_BINFIELD_CORRUPT,
    SW_MYSQL_ERR_BAD_LCB,
    SW_MYSQL_ERR_LEN_OVER_BUFFER,
    SW_MYSQL_ERR_CONVLONG,
    SW_MYSQL_ERR_CONVLONGLONG,
    SW_MYSQL_ERR_CONVFLOAT,
    SW_MYSQL_ERR_CONVDOUBLE,
    SW_MYSQL_ERR_CONVTIME,
    SW_MYSQL_ERR_CONVTIMESTAMP,
    SW_MYSQL_ERR_CONVDATE
};

enum sw_mysql_packet_types
{
    SW_MYSQL_PACKET_OK   = 0x0,
    SW_MYSQL_PACKET_AUTH_SIGNATURE_REQUEST = 0x01,

    /* not defined in protocol */
    SW_MYSQL_PACKET_RAW_DATA,
    SW_MYSQL_PACKET_GREETING,
    SW_MYSQL_PACKET_LOGIN,
    SW_MYSQL_PACKET_AUTH_SWITCH_RESPONSE,
    SW_MYSQL_PACKET_AUTH_SIGNATURE_RESPONSE,
    SW_MYSQL_PACKET_LCB, // length coded binary
    SW_MYSQL_PACKET_FIELD,
    SW_MYSQL_PACKET_ROW_DATA,
    SW_MYSQL_PACKET_PREPARE_STATEMENT,
    /* ======================= */

    SW_MYSQL_PACKET_NULL = 0xfb,
    SW_MYSQL_PACKET_EOF  = 0xfe,
    SW_MYSQL_PACKET_AUTH_SWITCH_REQUEST = 0xfe,
    SW_MYSQL_PACKET_ERR  = 0xff
};

enum sw_mysql_field_types
{
    SW_MYSQL_TYPE_DECIMAL,
    SW_MYSQL_TYPE_TINY,
    SW_MYSQL_TYPE_SHORT,
    SW_MYSQL_TYPE_LONG,
    SW_MYSQL_TYPE_FLOAT,
    SW_MYSQL_TYPE_DOUBLE,
    SW_MYSQL_TYPE_NULL,
    SW_MYSQL_TYPE_TIMESTAMP,
    SW_MYSQL_TYPE_LONGLONG,
    SW_MYSQL_TYPE_INT24,
    SW_MYSQL_TYPE_DATE,
    SW_MYSQL_TYPE_TIME,
    SW_MYSQL_TYPE_DATETIME,
    SW_MYSQL_TYPE_YEAR,
    SW_MYSQL_TYPE_NEWDATE,
    SW_MYSQL_TYPE_VARCHAR,
    SW_MYSQL_TYPE_BIT,
    SW_MYSQL_TYPE_JSON = 245,
    SW_MYSQL_TYPE_NEWDECIMAL = 246,
    SW_MYSQL_TYPE_ENUM = 247,
    SW_MYSQL_TYPE_SET = 248,
    SW_MYSQL_TYPE_TINY_BLOB = 249,
    SW_MYSQL_TYPE_MEDIUM_BLOB = 250,
    SW_MYSQL_TYPE_LONG_BLOB = 251,
    SW_MYSQL_TYPE_BLOB = 252,
    SW_MYSQL_TYPE_VAR_STRING = 253,
    SW_MYSQL_TYPE_STRING = 254,
    SW_MYSQL_TYPE_GEOMETRY = 255
};

// ref: https://dev.mysql.com/doc/dev/mysql-server/8.0.0/group__group__cs__capabilities__flags.html
// use regex: "\#define[ ]+(CLIENT_[A-Z_\d]+)[ ]+(\(?[\dA-Z <]+\)?)\n[ ]+?[ ]+([\s\S ]+?\.) More\.\.\.\n?"
// to "SW_MYSQL_$1 = $2, /* $3 */"
enum sw_mysql_client_capability_flags
{
    SW_MYSQL_CLIENT_LONG_PASSWORD = 1, /* Use the improved version of Old Password Authentication. */
    SW_MYSQL_CLIENT_FOUND_ROWS = 2, /* Send found rows instead of affected rows in EOF_Packet. */
    SW_MYSQL_CLIENT_LONG_FLAG = 4, /* Get all column flags. */
    SW_MYSQL_CLIENT_CONNECT_WITH_DB = 8, /* Database (schema) name can be specified on connect in Handshake Response Packet. */
    SW_MYSQL_CLIENT_NO_SCHEMA = 16, /* Don't allow database.table.column. */
    SW_MYSQL_CLIENT_COMPRESS = 32, /* Compression protocol supported. */
    SW_MYSQL_CLIENT_ODBC = 64, /* Special handling of ODBC behavior. */
    SW_MYSQL_CLIENT_LOCAL_FILES = 128, /* Can use LOAD DATA LOCAL. */
    SW_MYSQL_CLIENT_IGNORE_SPACE = 256, /* Ignore spaces before '('. */
    SW_MYSQL_CLIENT_PROTOCOL_41 = 512, /* New 4.1 protocol. */
    SW_MYSQL_CLIENT_INTERACTIVE = 1024, /* This is an interactive client. */
    SW_MYSQL_CLIENT_SSL = 2048, /* Use SSL encryption for the session. */
    SW_MYSQL_CLIENT_IGNORE_SIGPIPE = 4096, /* Client only flag. */
    SW_MYSQL_CLIENT_TRANSACTIONS = 8192, /* Client knows about transactions. */
    SW_MYSQL_CLIENT_RESERVED = 16384, /* flag for 4.1 protocol. */
    SW_MYSQL_CLIENT_SECURE_CONNECTION = 32768, /* swoole custom name for RESERVED2.  */
    SW_MYSQL_CLIENT_RESERVED2 = 32768, /* flag for 4.1 authentication. */
    SW_MYSQL_CLIENT_MULTI_STATEMENTS = (1UL << 16), /* Enable/disable multi-stmt support. */
    SW_MYSQL_CLIENT_MULTI_RESULTS = (1UL << 17), /* Enable/disable multi-results. */
    SW_MYSQL_CLIENT_PS_MULTI_RESULTS = (1UL << 18), /* Multi-results and OUT parameters in PS-protocol. */
    SW_MYSQL_CLIENT_PLUGIN_AUTH = (1UL << 19), /* Client supports plugin authentication. */
    SW_MYSQL_CLIENT_CONNECT_ATTRS = (1UL << 20), /* Client supports connection attributes. */
    SW_MYSQL_CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = (1UL << 21), /* Enable authentication response packet to be larger than 255 bytes. */
    SW_MYSQL_CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = (1UL << 22), /* Don't close the connection for a user account with expired password. */
    SW_MYSQL_CLIENT_SESSION_TRACK = (1UL << 23), /* Capable of handling server state change information. */
    SW_MYSQL_CLIENT_DEPRECATE_EOF = (1UL << 24), /* Client no longer needs EOF_Packet and will use OK_Packet instead. */
    SW_MYSQL_CLIENT_SSL_VERIFY_SERVER_CERT = (1UL << 30), /* Verify server certificate. */
    SW_MYSQL_CLIENT_REMEMBER_OPTIONS = (1UL << 31) /* Don't reset the options after an unsuccessful connect. */
};

// ref: https://dev.mysql.com/doc/internals/en/status-flags.html
enum sw_mysql_server_status_flags
{
    SW_MYSQL_SERVER_STATUS_IN_TRANS = 0x0001, // a transaction is active
    SW_MYSQL_SERVER_STATUS_AUTOCOMMIT = 0x0002, //auto-commit is enabled
    SW_MYSQL_SERVER_MORE_RESULTS_EXISTS = 0x0008,
    SW_MYSQL_SERVER_STATUS_NO_GOOD_INDEX_USED = 0x0010,
    SW_MYSQL_SERVER_STATUS_NO_INDEX_USED = 0x0020,
    SW_MYSQL_SERVER_STATUS_CURSOR_EXISTS = 0x0040, // Used by Binary Protocol Resultset to signal that COM_STMT_FETCH must be used to fetch the row-data.
    SW_MYSQL_SERVER_STATUS_LAST_ROW_SENT = 0x0080,
    SW_MYSQL_SERVER_STATUS_DB_DROPPED = 0x0100,
    SW_MYSQL_SERVER_STATUS_NO_BACKSLASH_ESCAPES = 0x0200,
    SW_MYSQL_SERVER_STATUS_METADATA_CHANGED = 0x0400,
    SW_MYSQL_SERVER_QUERY_WAS_SLOW = 0x0800,
    SW_MYSQL_SERVER_PS_OUT_PARAMS = 0x1000,
    SW_MYSQL_SERVER_STATUS_IN_TRANS_READONLY = 0x2000, // in a read-only transaction
    SW_MYSQL_SERVER_SESSION_STATE_CHANGED = 0x4000 // connection state information has changed
};

#define SW_MYSQL_NO_RSA_ERROR "MySQL8 caching_sha2_password authentication plugin need enable OpenSSL support"

#define SW_MYSQL_NOT_NULL_FLAG               1
#define SW_MYSQL_PRI_KEY_FLAG                2
#define SW_MYSQL_UNIQUE_KEY_FLAG             4
#define SW_MYSQL_MULTIPLE_KEY_FLAG           8
#define SW_MYSQL_BLOB_FLAG                  16
#define SW_MYSQL_UNSIGNED_FLAG              32
#define SW_MYSQL_ZEROFILL_FLAG              64
#define SW_MYSQL_BINARY_FLAG               128
#define SW_MYSQL_ENUM_FLAG                 256
#define SW_MYSQL_AUTO_INCREMENT_FLAG       512
#define SW_MYSQL_TIMESTAMP_FLAG           1024
#define SW_MYSQL_SET_FLAG                 2048
#define SW_MYSQL_NO_DEFAULT_VALUE_FLAG    4096
#define SW_MYSQL_ON_UPDATE_NOW_FLAG       8192
#define SW_MYSQL_PART_KEY_FLAG           16384
#define SW_MYSQL_GROUP_FLAG              32768
#define SW_MYSQL_NUM_FLAG                32768

/* int<3>   payload_length + int<1> sequence_id */
#define SW_MYSQL_PACKET_HEADER_SIZE      4
#define SW_MYSQL_PACKET_TYPE_OFFSET      5
#define SW_MYSQL_PACKET_EOF_MAX_SIZE     9
#define SW_MYSQL_PACKET_PREPARED_OK_SIZE 12
#define SW_MYSQL_MAX_PACKET_BODY_SIZE    0x00ffffff
#define SW_MYSQL_MAX_PACKET_SIZE         (SW_MYSQL_PACKET_HEADER_SIZE + SW_MYSQL_MAX_PACKET_BODY_SIZE)

// nonce: a number or bit string used only once, in security engineering
// other names on doc: challenge/scramble/salt
#define SW_MYSQL_NONCE_LENGTH 20

#define sw_mysql_uint2korr2korr(A)  (uint16_t) (((uint16_t) ((uchar) (A)[0])) +\
                               ((uint16_t) ((uchar) (A)[1]) << 8))
#define sw_mysql_uint2korr3korr(A)  (uint32_t) (((uint32_t) ((uchar) (A)[0])) +\
                               (((uint32_t) ((uchar) (A)[1])) << 8) +\
                               (((uint32_t) ((uchar) (A)[2])) << 16))
#define sw_mysql_uint2korr4korr(A)  (uint32_t) (((uint32_t) ((uchar) (A)[0])) +\
                               (((uint32_t) ((uchar) (A)[1])) << 8) +\
                               (((uint32_t) ((uchar) (A)[2])) << 16) +\
                               (((uint32_t) ((uchar) (A)[3])) << 24))
#define sw_mysql_uint2korr8korr(A)    ((uint64_t)(((uint32_t) ((uchar) (A)[0])) +\
                                    (((uint32_t) ((uchar) (A)[1])) << 8) +\
                                    (((uint32_t) ((uchar) (A)[2])) << 16) +\
                                    (((uint32_t) ((uchar) (A)[3])) << 24)) +\
                                    (((uint64_t) (((uint32_t) ((uchar) (A)[4])) +\
                                    (((uint32_t) ((uchar) (A)[5])) << 8) +\
                                    (((uint32_t) ((uchar) (A)[6])) << 16) +\
                                    (((uint32_t) ((uchar) (A)[7])) << 24))) << 32))

#define sw_mysql_int1store(T,A)  do { *((int8_t*) (T)) = (int8_t)(A); } while(0)
#define sw_mysql_int2store(T,A)  do { uint32_t def_temp= (uint32_t) (A) ;\
                  *((uchar*) (T))  =  (uchar)(def_temp); \
                  *((uchar*) (T+1)) = (uchar)((def_temp >> 8)); } while (0)
#define sw_mysql_int3store(T,A)  do { /*lint -save -e734 */\
                  *(((char *)(T)))   = (char) ((A));\
                  *(((char *)(T))+1) = (char) (((A) >> 8));\
                  *(((char *)(T))+2) = (char) (((A) >> 16)); \
                  /*lint -restore */} while (0)
#define sw_mysql_int4store(T,A)  do { \
                  *(((char *)(T)))   = (char) ((A));\
                  *(((char *)(T))+1) = (char) (((A) >> 8));\
                  *(((char *)(T))+2) = (char) (((A) >> 16));\
                  *(((char *)(T))+3) = (char) (((A) >> 24)); } while (0)
#define sw_mysql_int5store(T,A)  do { \
                  *(((char *)(T)))   = (char)((A));\
                  *(((char *)(T))+1) = (char)(((A) >> 8));\
                  *(((char *)(T))+2) = (char)(((A) >> 16));\
                  *(((char *)(T))+3) = (char)(((A) >> 24)); \
                  *(((char *)(T))+4) = (char)(((A) >> 32)); } while (0)
/* Based on int5store() from Andrey Hristov */
#define sw_mysql_int6store(T,A)  do { \
                  *(((char *)(T)))   = (char)((A));\
                  *(((char *)(T))+1) = (char)(((A) >> 8));\
                  *(((char *)(T))+2) = (char)(((A) >> 16));\
                  *(((char *)(T))+3) = (char)(((A) >> 24)); \
                  *(((char *)(T))+4) = (char)(((A) >> 32)); \
                  *(((char *)(T))+5) = (char)(((A) >> 40)); } while (0)

#define sw_mysql_int8store(T,A)  do { \
                uint32_t def_temp= (uint32_t) (A), def_temp2= (uint32_t) ((A) >> 32); \
                sw_mysql_int4store((T),def_temp); \
                sw_mysql_int4store((T+4),def_temp2); } while (0)

#if defined(SW_DEBUG) && defined(SW_LOG_TRACE_OPEN)
#define swMysqlPacketDump(length, number, data, title) \
    if (SW_LOG_TRACE >= SwooleG.log_level && (SW_TRACE_MYSQL_CLIENT & SwooleG.trace_flags)) \
    { \
        swDebug("+----------+------------+-------------------------------------------------------+"); \
        swDebug("| P#%-6u | L%-9u | %-10u %42s |", number, SW_MYSQL_PACKET_HEADER_SIZE + length, length, title); \
        swHexDump(data, length); \
    }
#else
#define swMysqlPacketDump(length, number, data, title)
#endif

namespace swoole
{
namespace mysql
{
typedef struct
{
    unsigned int nr;
    const char *name;
    const char *collation;
} charset_t;

inline int get_charset(const char *name)
{
    static const charset_t charsets[] =
    {
        { 1, "big5", "big5_chinese_ci" },
        { 3, "dec8", "dec8_swedish_ci" },
        { 4, "cp850", "cp850_general_ci" },
        { 6, "hp8", "hp8_english_ci" },
        { 7, "koi8r", "koi8r_general_ci" },
        { 8, "latin1", "latin1_swedish_ci" },
        { 5, "latin1", "latin1_german1_ci" },
        { 9, "latin2", "latin2_general_ci" },
        { 2, "latin2", "latin2_czech_cs" },
        { 10, "swe7", "swe7_swedish_ci" },
        { 11, "ascii", "ascii_general_ci" },
        { 12, "ujis", "ujis_japanese_ci" },
        { 13, "sjis", "sjis_japanese_ci" },
        { 16, "hebrew", "hebrew_general_ci" },
        { 17, "filename", "filename" },
        { 18, "tis620", "tis620_thai_ci" },
        { 19, "euckr", "euckr_korean_ci" },
        { 21, "latin2", "latin2_hungarian_ci" },
        { 27, "latin2", "latin2_croatian_ci" },
        { 22, "koi8u", "koi8u_general_ci" },
        { 24, "gb2312", "gb2312_chinese_ci" },
        { 25, "greek", "greek_general_ci" },
        { 26, "cp1250", "cp1250_general_ci" },
        { 28, "gbk", "gbk_chinese_ci" },
        { 30, "latin5", "latin5_turkish_ci" },
        { 31, "latin1", "latin1_german2_ci" },
        { 15, "latin1", "latin1_danish_ci" },
        { 32, "armscii8", "armscii8_general_ci" },
        { 33, "utf8", "utf8_general_ci" },
        { 35, "ucs2", "ucs2_general_ci" },
        { 36, "cp866", "cp866_general_ci" },
        { 37, "keybcs2", "keybcs2_general_ci" },
        { 38, "macce", "macce_general_ci" },
        { 39, "macroman", "macroman_general_ci" },
        { 40, "cp852", "cp852_general_ci" },
        { 41, "latin7", "latin7_general_ci" },
        { 20, "latin7", "latin7_estonian_cs" },
        { 57, "cp1256", "cp1256_general_ci" },
        { 59, "cp1257", "cp1257_general_ci" },
        { 63, "binary", "binary" },
        { 97, "eucjpms", "eucjpms_japanese_ci" },
        { 29, "cp1257", "cp1257_lithuanian_ci" },
        { 31, "latin1", "latin1_german2_ci" },
        { 34, "cp1250", "cp1250_czech_cs" },
        { 42, "latin7", "latin7_general_cs" },
        { 43, "macce", "macce_bin" },
        { 44, "cp1250", "cp1250_croatian_ci" },
        { 45, "utf8mb4", "utf8mb4_general_ci" },
        { 46, "utf8mb4", "utf8mb4_bin" },
        { 47, "latin1", "latin1_bin" },
        { 48, "latin1", "latin1_general_ci" },
        { 49, "latin1", "latin1_general_cs" },
        { 51, "cp1251", "cp1251_general_ci" },
        { 14, "cp1251", "cp1251_bulgarian_ci" },
        { 23, "cp1251", "cp1251_ukrainian_ci" },
        { 50, "cp1251", "cp1251_bin" },
        { 52, "cp1251", "cp1251_general_cs" },
        { 53, "macroman", "macroman_bin" },
        { 54, "utf16", "utf16_general_ci" },
        { 55, "utf16", "utf16_bin" },
        { 56, "utf16le", "utf16le_general_ci" },
        { 58, "cp1257", "cp1257_bin" },
        { 60, "utf32", "utf32_general_ci" },
        { 61, "utf32", "utf32_bin" },
        { 62, "utf16le", "utf16le_bin" },
        { 64, "armscii8", "armscii8_bin" },
        { 65, "ascii", "ascii_bin" },
        { 66, "cp1250", "cp1250_bin" },
        { 67, "cp1256", "cp1256_bin" },
        { 68, "cp866", "cp866_bin" },
        { 69, "dec8", "dec8_bin" },
        { 70, "greek", "greek_bin" },
        { 71, "hebrew", "hebrew_bin" },
        { 72, "hp8", "hp8_bin" },
        { 73, "keybcs2", "keybcs2_bin" },
        { 74, "koi8r", "koi8r_bin" },
        { 75, "koi8u", "koi8u_bin" },
        { 77, "latin2", "latin2_bin" },
        { 78, "latin5", "latin5_bin" },
        { 79, "latin7", "latin7_bin" },
        { 80, "cp850", "cp850_bin" },
        { 81, "cp852", "cp852_bin" },
        { 82, "swe7", "swe7_bin" },
        { 83, "utf8", "utf8_bin" },
        { 84, "big5", "big5_bin" },
        { 85, "euckr", "euckr_bin" },
        { 86, "gb2312", "gb2312_bin" },
        { 87, "gbk", "gbk_bin" },
        { 88, "sjis", "sjis_bin" },
        { 89, "tis620", "tis620_bin" },
        { 90, "ucs2", "ucs2_bin" },
        { 91, "ujis", "ujis_bin" },
        { 92, "geostd8", "geostd8_general_ci" },
        { 93, "geostd8", "geostd8_bin" },
        { 94, "latin1", "latin1_spanish_ci" },
        { 95, "cp932", "cp932_japanese_ci" },
        { 96, "cp932", "cp932_bin" },
        { 97, "eucjpms", "eucjpms_japanese_ci" },
        { 98, "eucjpms", "eucjpms_bin" },
        { 99, "cp1250", "cp1250_polish_ci" },
        { 128, "ucs2", "ucs2_unicode_ci" },
        { 129, "ucs2", "ucs2_icelandic_ci" },
        { 130, "ucs2", "ucs2_latvian_ci" },
        { 131, "ucs2", "ucs2_romanian_ci" },
        { 132, "ucs2", "ucs2_slovenian_ci" },
        { 133, "ucs2", "ucs2_polish_ci" },
        { 134, "ucs2", "ucs2_estonian_ci" },
        { 135, "ucs2", "ucs2_spanish_ci" },
        { 136, "ucs2", "ucs2_swedish_ci" },
        { 137, "ucs2", "ucs2_turkish_ci" },
        { 138, "ucs2", "ucs2_czech_ci" },
        { 139, "ucs2", "ucs2_danish_ci" },
        { 140, "ucs2", "ucs2_lithuanian_ci" },
        { 141, "ucs2", "ucs2_slovak_ci" },
        { 142, "ucs2", "ucs2_spanish2_ci" },
        { 143, "ucs2", "ucs2_roman_ci" },
        { 144, "ucs2", "ucs2_persian_ci" },
        { 145, "ucs2", "ucs2_esperanto_ci" },
        { 146, "ucs2", "ucs2_hungarian_ci" },
        { 147, "ucs2", "ucs2_sinhala_ci" },
        { 148, "ucs2", "ucs2_german2_ci" },
        { 149, "ucs2", "ucs2_croatian_ci" },
        { 150, "ucs2", "ucs2_unicode_520_ci" },
        { 151, "ucs2", "ucs2_vietnamese_ci" },
        { 160, "utf32", "utf32_unicode_ci" },
        { 161, "utf32", "utf32_icelandic_ci" },
        { 162, "utf32", "utf32_latvian_ci" },
        { 163, "utf32", "utf32_romanian_ci" },
        { 164, "utf32", "utf32_slovenian_ci" },
        { 165, "utf32", "utf32_polish_ci" },
        { 166, "utf32", "utf32_estonian_ci" },
        { 167, "utf32", "utf32_spanish_ci" },
        { 168, "utf32", "utf32_swedish_ci" },
        { 169, "utf32", "utf32_turkish_ci" },
        { 170, "utf32", "utf32_czech_ci" },
        { 171, "utf32", "utf32_danish_ci" },
        { 172, "utf32", "utf32_lithuanian_ci" },
        { 173, "utf32", "utf32_slovak_ci" },
        { 174, "utf32", "utf32_spanish2_ci" },
        { 175, "utf32", "utf32_roman_ci" },
        { 176, "utf32", "utf32_persian_ci" },
        { 177, "utf32", "utf32_esperanto_ci" },
        { 178, "utf32", "utf32_hungarian_ci" },
        { 179, "utf32", "utf32_sinhala_ci" },
        { 180, "utf32", "utf32_german2_ci" },
        { 181, "utf32", "utf32_croatian_ci" },
        { 182, "utf32", "utf32_unicode_520_ci" },
        { 183, "utf32", "utf32_vietnamese_ci" },
        { 192, "utf8", "utf8_unicode_ci" },
        { 193, "utf8", "utf8_icelandic_ci" },
        { 194, "utf8", "utf8_latvian_ci" },
        { 195, "utf8", "utf8_romanian_ci" },
        { 196, "utf8", "utf8_slovenian_ci" },
        { 197, "utf8", "utf8_polish_ci" },
        { 198, "utf8", "utf8_estonian_ci" },
        { 199, "utf8", "utf8_spanish_ci" },
        { 200, "utf8", "utf8_swedish_ci" },
        { 201, "utf8", "utf8_turkish_ci" },
        { 202, "utf8", "utf8_czech_ci" },
        { 203, "utf8", "utf8_danish_ci" },
        { 204, "utf8", "utf8_lithuanian_ci" },
        { 205, "utf8", "utf8_slovak_ci" },
        { 206, "utf8", "utf8_spanish2_ci" },
        { 207, "utf8", "utf8_roman_ci" },
        { 208, "utf8", "utf8_persian_ci" },
        { 209, "utf8", "utf8_esperanto_ci" },
        { 210, "utf8", "utf8_hungarian_ci" },
        { 211, "utf8", "utf8_sinhala_ci" },
        { 212, "utf8", "utf8_german2_ci" },
        { 213, "utf8", "utf8_croatian_ci" },
        { 214, "utf8", "utf8_unicode_520_ci" },
        { 215, "utf8", "utf8_vietnamese_ci" },

        { 224, "utf8mb4", "utf8mb4_unicode_ci" },
        { 225, "utf8mb4", "utf8mb4_icelandic_ci" },
        { 226, "utf8mb4", "utf8mb4_latvian_ci" },
        { 227, "utf8mb4", "utf8mb4_romanian_ci" },
        { 228, "utf8mb4", "utf8mb4_slovenian_ci" },
        { 229, "utf8mb4", "utf8mb4_polish_ci" },
        { 230, "utf8mb4", "utf8mb4_estonian_ci" },
        { 231, "utf8mb4", "utf8mb4_spanish_ci" },
        { 232, "utf8mb4", "utf8mb4_swedish_ci" },
        { 233, "utf8mb4", "utf8mb4_turkish_ci" },
        { 234, "utf8mb4", "utf8mb4_czech_ci" },
        { 235, "utf8mb4", "utf8mb4_danish_ci" },
        { 236, "utf8mb4", "utf8mb4_lithuanian_ci" },
        { 237, "utf8mb4", "utf8mb4_slovak_ci" },
        { 238, "utf8mb4", "utf8mb4_spanish2_ci" },
        { 239, "utf8mb4", "utf8mb4_roman_ci" },
        { 240, "utf8mb4", "utf8mb4_persian_ci" },
        { 241, "utf8mb4", "utf8mb4_esperanto_ci" },
        { 242, "utf8mb4", "utf8mb4_hungarian_ci" },
        { 243, "utf8mb4", "utf8mb4_sinhala_ci" },
        { 244, "utf8mb4", "utf8mb4_german2_ci" },
        { 245, "utf8mb4", "utf8mb4_croatian_ci" },
        { 246, "utf8mb4", "utf8mb4_unicode_520_ci" },
        { 247, "utf8mb4", "utf8mb4_vietnamese_ci" },
        { 248, "gb18030", "gb18030_chinese_ci" },
        { 249, "gb18030", "gb18030_bin" },
        { 254, "utf8", "utf8_general_cs" },
        { 0, NULL, NULL},
    };
    const charset_t *c = charsets;
    while (c[0].nr)
    {
        if (!strcasecmp(c->name, name))
        {
            return c->nr;
        }
        ++c;
    }
    return -1;
}

inline uint8_t read_lcb(const char *p, uint64_t *length, bool *nul)
{
    switch ((uchar) p[0])
    {
    case 251: /* fb : 1 octet */
        *length = 0;
        *nul = true;
        return 1;
    case 252: /* fc : 2 octets */
        *length = sw_mysql_uint2korr2korr(p + 1);
        *nul = false;
        return 3;
    case 253: /* fd : 3 octets */
        *length = sw_mysql_uint2korr3korr(p + 1);
        *nul = false;
        return 4;
    case 254: /* fe : 8 octets */
        *length = sw_mysql_uint2korr8korr(p + 1);
        *nul = false;
        return 9;
    default:
        *length = (uchar) p[0];
        *nul = false;
        return 1;
    }
}

inline uint8_t read_lcb(const char *p, uint32_t *length, bool *nul)
{
    uint64_t _r;
    uint8_t ret = read_lcb(p, &_r, nul);
    *length = _r;
    return ret;
}

inline uint8_t write_lcb(char *p, uint64_t length)
{
    if (length <= 250)
    {
        sw_mysql_int1store(p, length);
        return 1;
    }
    else if (length <= 0xffff)
    {
        sw_mysql_int2store(p, length);
        return 2;
    }
    else if (length <= 0xffffff)
    {
        sw_mysql_int3store(p, length);
        return 3;
    }
    else
    {
        sw_mysql_int1store(p, 254);
        sw_mysql_int8store(p, length);
        return 9;
    }
}

class server_packet
{
public:
    struct header {
        uint32_t length :24;
        uint32_t number :8;
        header() : length(0), number(0) { }
    } header;
    server_packet() { }
    server_packet(const char *data)
    {
        parse(data);
    }
    inline void parse(const char *data)
    {
        header.length = sw_mysql_uint2korr3korr(data);
        header.number = (uint8_t) data[3];
    }
    static inline uint8_t parse_type(const char *data)
    {
        if (unlikely(!data))
        {
            return SW_MYSQL_PACKET_NULL;
        }
        return (uint8_t) data[SW_MYSQL_PACKET_HEADER_SIZE];
    }
    static inline uint32_t get_length(const char *data)
    {
        return sw_mysql_uint2korr3korr(data);
    }
    static inline uint32_t get_number(const char *data)
    {
        return  (uint8_t) data[3];
    }
    static inline bool is_eof(const char *data)
    {
        return (uint8_t) data[SW_MYSQL_PACKET_HEADER_SIZE] == SW_MYSQL_PACKET_EOF;
    }
    static inline bool is_ok(const char *data)
    {
        return (uint8_t) data[SW_MYSQL_PACKET_HEADER_SIZE] == SW_MYSQL_PACKET_OK;
    }
    static inline bool is_err(const char *data)
    {
        return (uint8_t) data[SW_MYSQL_PACKET_HEADER_SIZE] == SW_MYSQL_PACKET_ERR;
    }
};

class server_status_t
{
public:
    int16_t status = 0;
    void operator =(uint16_t status)
    {
        this->status = status;
    }
    inline bool more_results_exists()
    {
        bool b = !!(status & SW_MYSQL_SERVER_MORE_RESULTS_EXISTS);
        swTraceLog(SW_TRACE_MYSQL_CLIENT, "More results exist = %u", b);
        return b;
    }
};

class client_packet
{
public:
    static inline void set_header(char *buffer, uint32_t length, uint8_t number)
    {
        buffer[0] = length;
        buffer[1] = length >> 8;
        buffer[2] = length >> 16;
        buffer[3] = number;
    }

    client_packet(size_t body_size = 1024 - SW_MYSQL_PACKET_HEADER_SIZE)
    {
        SW_ASSERT(body_size > 0);
        if (body_size <= 4)
        {
            data.header = stack_buffer;
        }
        else
        {
            data.header = new char[SW_MEM_ALIGNED_SIZE(SW_MYSQL_PACKET_HEADER_SIZE + body_size)]();
        }
        data.body = data.header + SW_MYSQL_PACKET_HEADER_SIZE;
    }
    inline const char* get_data()
    {
        return data.header;
    }
    inline uint32_t get_data_length()
    {
        return SW_MYSQL_PACKET_HEADER_SIZE + get_length();
    }
    inline uint32_t get_length()
    {
        return sw_mysql_uint2korr3korr(data.header);
    }
    inline uint8_t get_number()
    {
        return (uint8_t) data.header[3];
    }
    inline const char* get_body()
    {
        return data.body;
    }
    inline void set_header(uint32_t length, uint8_t number)
    {
        set_header(data.header, length, number);
    }
    ~client_packet()
    {
        if (data.header != stack_buffer)
        {
            delete[] data.header;
        }
    }
protected:
    struct {
        char *header = nullptr;
        char *body = nullptr;
    } data;
    char stack_buffer[SW_MYSQL_PACKET_HEADER_SIZE + 4] = {0};
};

class command_packet : public client_packet
{
public:
    command_packet(enum sw_mysql_command command, const char *sql = nullptr, size_t length = 0) : client_packet(1 + length)
    {
        set_command(command);
        set_header(1 + length, 0);
        if (length > 0)
        {
            memcpy(data.body + 1, sql, length);
        }
    };
    inline void set_command(enum sw_mysql_command command)
    {
        data.body[0] = (char) command;
    }
};

class err_packet : public server_packet
{
public:
    uint16_t code;
    std::string msg;
    char sql_state[5 + 1];
    err_packet(const char *data);
};

class ok_packet : public server_packet
{
public:
    uint64_t affected_rows = 0;
    uint64_t last_insert_id = 0;
    server_status_t server_status;
    unsigned int warning_count = 0;
    ok_packet() { }
    ok_packet(const char *data);
};

class eof_packet : public server_packet
{
public:
    uint16_t warning_count;
    server_status_t server_status;
    eof_packet(const char *data);
};

class raw_data_packet : public server_packet
{
public:
    const char *body;
    raw_data_packet(const char *data) : server_packet(data), body(data + SW_MYSQL_PACKET_HEADER_SIZE)
    {
        swMysqlPacketDump(header.length, header.number, data, "Protocol::RawData");
    }
};

class greeting_packet : public server_packet
{
public:
    uint8_t protocol_version = 0;
    std::string server_version = "";
    int connection_id = 0;
    char auth_plugin_data[SW_MYSQL_NONCE_LENGTH + 1] = {0}; // nonce + '\0'
    uint8_t auth_plugin_data_length = 0;
    char filler = 0;
    int capability_flags = 0;
    char charset = SW_MYSQL_DEFAULT_CHARSET;
    server_status_t status_flags;
    char reserved[10] = {0};
    std::string auth_plugin_name = "";
    greeting_packet(const char *data);
};

class login_packet : public client_packet
{
public:
    login_packet(
        greeting_packet *greeting_packet,
        const std::string user,
        const std::string password,
        std::string database,
        char charset
    );
};

class auth_switch_request_packet : public server_packet
{
public:
    std::string auth_method_name = "mysql_native_password";
    char auth_method_data[SW_MYSQL_NONCE_LENGTH + 1] = {0};
    auth_switch_request_packet(const char *data);
};

class auth_switch_response_packet : public client_packet
{
public:
    auth_switch_response_packet(auth_switch_request_packet *req, const std::string password);
};

class auth_signature_request_packet : public server_packet
{
public:
    char data[2] = {0};
    auth_signature_request_packet(const char *data) :server_packet(data)
    {
        swMysqlPacketDump(header.length, header.number, data, "Protocol::AuthSignatureRequest");
        memcpy(&this->data, data + SW_MYSQL_PACKET_HEADER_SIZE, 2);
    }
    inline bool is_full_auth_required()
    {
        return data[1] == SW_MYSQL_AUTH_SIGNATURE_FULL_AUTH_REQUIRED;
    }
    inline bool is_vaild()
    {
        return data[0] == SW_MYSQL_AUTH_SIGNATURE && (data[1] == SW_MYSQL_AUTH_SIGNATURE_SUCCESS || data[1] == SW_MYSQL_AUTH_SIGNATURE_FULL_AUTH_REQUIRED);
    }
};

class auth_signature_prepared_packet : public client_packet
{
public:
    auth_signature_prepared_packet(uint8_t number) : client_packet(1)
    {
        set_header(1, number);
        data.body[0] = SW_MYSQL_AUTH_SIGNATURE_RSA_PREPARED;
    }
};

class auth_signature_response_packet : public client_packet
{
public:
    auth_signature_response_packet(raw_data_packet *raw_data_pakcet, const std::string password, const char *auth_plugin_data);
};

class lcb_packet : public server_packet
{
public:
    uint32_t length = 0;
    bool nul = 0;
    lcb_packet(const char *data) : server_packet(data)
    {
        swMysqlPacketDump(header.length, header.number, data, "Protocol::LengthCodedBinary");
        bytes_length = read_lcb(data + SW_MYSQL_PACKET_HEADER_SIZE, &length, &nul);
        swTraceLog(SW_TRACE_MYSQL_CLIENT, "binary_length=%" PRIu64 ", nul=%u", header.length, nul);
    }
    bool is_vaild()
    {
        return header.length == bytes_length;
    }
private:
    uint8_t bytes_length;
};

class field_packet : public server_packet
{
public:
    char *catalog = nullptr; /* Catalog for table */
    uint32_t catalog_length = 0;
    char *database = nullptr; /* Database for table */
    uint32_t database_length = 0;
    char *table = nullptr; /* Table of column if column was a field */
    uint32_t table_length = 0;
    char *org_table = nullptr; /* Org table name, if table was an alias */
    uint32_t org_table_length = 0;
    char *name = nullptr; /* Name of column */
    uint32_t name_length = 0;
    char *org_name = nullptr; /* Original column name, if an alias */
    uint32_t org_name_length = 0;
    char charset = 0;
    uint64_t length = 0; /* Width of column (create length) */
    uint8_t type = 0; /* Type of field. See mysql_com.h for types */
    uint32_t flags = 0; /* Div flags */
    uint32_t decimals = 0; /* Number of decimals in field */
    char *def = nullptr; /* Default value (set by mysql_list_fields) */
    uint32_t def_length = 0;
    void *extension = nullptr;
    field_packet() { }
    field_packet(const char *data) {
        parse(data);
    }
    void parse(const char *data);
    ~field_packet()
    {
        if (body)
        {
            delete[] body;
        }
    }
protected:
    char *body = nullptr;
};

typedef field_packet param_packet;

class row_data_text
{
public:
    uint64_t length = 0;
    bool nul = false;
    const char *body = nullptr;
    row_data_text(const char **pp)
    {
        body = *pp + read_lcb(*pp, &length, &nul);
        *pp = body + length;
        swTraceLog(
            SW_TRACE_MYSQL_CLIENT, "text[%" PRIu64 "]: %.*s%s, nul=%u",
            length, MIN(64, length), body, length > 64 ? "..." : "", nul
        );
    }
};

//    typedef union
//    {
//        signed char stiny;
//        uchar utiny;
//        uchar mbool;
//        short ssmall;
//        unsigned short small;
//        int sint;
//        uint32_t uint;
//        long long sbigint;
//        unsigned long long ubigint;
//        float mfloat;
//        double mdouble;
//    } row;

class string
{
public:
    inline const char* str()
    {
        return self.c_str();
    }
    inline size_t len()
    {
        return self.length();
    }
protected:
    std::string self;
};

class datetime : public string
{
public:
    datetime(const char **pp)
    {
        const char *p = *pp;
        uint16_t y = 0;
        uint8_t M = 0, d = 0, h = 0, m = 0, s = 0, n;
        n = *(uint8_t *) (p);
        if (n != 0)
        {
            y = *(uint16_t *) (p + 1);
            M = *(uint8_t *) (p + 3);
            d = *(uint8_t *) (p + 4);
            if (n > 4)
            {
                h = *(uint8_t *) (p + 5);
                m = *(uint8_t *) (p + 6);
                s = *(uint8_t *) (p + 7);
            }
        }
        self = swoole::cpp_string::format("%.4u-%.2u-%.2u %.2u:%.2u:%.2u", y, M, d, h, m, s);
        *pp += n;
    }
};

class time : public string
{
public:
    time(const char **pp)
    {
        const char *p = *pp;
        uint8_t h = 0, m = 0, s = 0;
        uint8_t n = *(uint8_t *) (p);
        if (n != 0)
        {
            h = *(uint8_t *) (p + 6);
            m = *(uint8_t *) (p + 7);
            s = *(uint8_t *) (p + 8);
        }
        self = swoole::cpp_string::format("%.2u:%.2u:%.2u", h, m, s);
        *pp += n;
    }
};

class date : public string
{
public:
    date(const char **pp)
    {
        const char *p = *pp;
        uint8_t M = 0, d = 0, n;
        uint16_t y = 0;
        n = *(uint8_t *) (p);
        if (n != 0)
        {
            y = *(uint16_t *) (p + 1);
            M = *(uint8_t *) (p + 3);
            d = *(uint8_t *) (p + 4);
        }
        self = swoole::cpp_string::format("%.4u-%.2u-%.2u", y, M, d);
        *pp += n;
    }
};

class year : public string
{
public:
    year(const char **pp)
    {
        uint16_t y = *(uint16_t *) (*pp);
        self = swoole::cpp_string::format("%.4u", y);
        *pp += 2;
    }
};

class result_info
{
public:
    ok_packet ok;

    inline void alloc_fields(uint32_t length)
    {
        clear_fields();
        if (likely(length != 0))
        {
            fields.info = new field_packet[length];
            fields.length = length;
        }
        else
        {
            fields.length = 0;
            fields.info = nullptr;
        }
    }
    inline uint32_t get_fields_length()
    {
        return fields.length;
    }
    inline field_packet* get_fields(uint32_t index)
    {
        return fields.info;
    }
    inline field_packet* get_field(uint32_t index)
    {
        return &fields.info[index];
    }
    inline void set_field(uint32_t index, const char *data)
    {
        fields.info[index].parse(data);
    }
    inline void clear_fields()
    {
        if (fields.length > 0)
        {
            delete[] fields.info;
        }
    }
    ~result_info()
    {
        clear_fields();
    }
protected:
    struct {
        uint32_t length = 0;
        field_packet *info = nullptr;
    } fields;
};

class statement : public server_packet
{
public:
    uint32_t id = 0;
    uint16_t field_count = 0;
    uint16_t param_count = 0;
    uint16_t warning_count = 0;
    statement() { }
    statement(const char* data) : server_packet(data)
    {
        swMysqlPacketDump(header.length, header.number, data, "COM_STMT_PREPARE_OK_Packet");
        // skip the packet header
        data += SW_MYSQL_PACKET_HEADER_SIZE;
        // status (1) -- [00] OK
        SW_ASSERT(data[0] == SW_MYSQL_PACKET_OK);
        data += 1;
        // statement_id (4) -- statement-id
        id = sw_mysql_uint2korr4korr(data);
        data += 4;
        // num_columns (2) -- number of columns
        field_count = sw_mysql_uint2korr2korr(data);
        data += 2;
        // num_params (2) -- number of params
        param_count = sw_mysql_uint2korr2korr(data);
        data += 2;
        // reserved_1 (1) -- [00] filler
        data += 1;
        // warning_count (2) -- number of warnings
        warning_count = sw_mysql_uint2korr2korr(data);
        swTraceLog(
            SW_TRACE_MYSQL_CLIENT, "statement_id=%u, field_count=%u, param_count=%u, warning_count=%u",
            id, field_count, param_count, warning_count
        );
    }
};
}
}

#endif /* SW_MYSQL_H_ */
