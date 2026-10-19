/*
 * dlrenative.c -- replacements for Trifork's native Lua modules, as used by
 * the MDG pairing path (pace.lua, ec.lua, pairing_procedure.lua).
 *
 * Provides, against OpenSSL 1.1.1:
 *   lbn        big numbers        (lhf-style: number/text/totext/random, metamethods)
 *   ecgroup    EC over GF(p)      (new_GFp + group methods used by ec.lua/pace.lua)
 *   ecpoint    point helpers      (same object type, exposed for symmetry)
 *   crypto     LuaCrypto subset   (digest, hmac.digest, pbkdf2, encrypt, decrypt, rand)
 *   cryptomisc alias of crypto    (pace.lua reaches for both names)
 *
 * Built for Lua 5.1.
 */
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define BN_MT "dlre.bn"
#define GROUP_MT "dlre.ecgroup"
#define POINT_MT "dlre.ecpoint"

/* ------------------------------------------------------------------ lbn ---- */

typedef struct { BIGNUM *bn; } LBN;

static LBN *bn_push(lua_State *L)
{
    LBN *x = (LBN *)lua_newuserdata(L, sizeof(LBN));
    x->bn = BN_new();
    if (x->bn == NULL) luaL_error(L, "BN_new failed");
    luaL_getmetatable(L, BN_MT);
    lua_setmetatable(L, -2);
    return x;
}

static BIGNUM *bn_check(lua_State *L, int idx)
{
    LBN *x = (LBN *)luaL_checkudata(L, idx, BN_MT);
    return x->bn;
}

/* Accepts an lbn number, a Lua number, "x<hex>" (lhf convention) or decimal. */
static BIGNUM *bn_coerce(lua_State *L, int idx, BIGNUM **owned)
{
    *owned = NULL;
    if (lua_type(L, idx) == LUA_TUSERDATA) return bn_check(L, idx);

    BIGNUM *bn = BN_new();
    if (bn == NULL) luaL_error(L, "BN_new failed");
    *owned = bn;

    if (lua_type(L, idx) == LUA_TNUMBER) {
        char buf[64];
        lua_Number n = lua_tonumber(L, idx);
        snprintf(buf, sizeof(buf), "%.0f", (double)n);
        if (!BN_dec2bn(&bn, buf)) luaL_error(L, "bad number");
        return bn;
    }

    const char *s = luaL_checkstring(L, idx);
    int ok;
    if (s[0] == 'x' || s[0] == 'X') ok = BN_hex2bn(&bn, s + 1);
    else if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ok = BN_hex2bn(&bn, s + 2);
    else ok = BN_dec2bn(&bn, s);
    if (!ok) luaL_error(L, "cannot parse number '%s'", s);
    return bn;
}

static void bn_release(BIGNUM *owned)
{
    if (owned != NULL) BN_free(owned);
}

static int lbn_number(lua_State *L)
{
    BIGNUM *owned = NULL;
    BIGNUM *src = bn_coerce(L, 1, &owned);
    LBN *out = bn_push(L);
    BN_copy(out->bn, src);
    bn_release(owned);
    return 1;
}

/* lbn.text(s): big-endian octets -> number */
static int lbn_text(lua_State *L)
{
    size_t len;
    const char *s = luaL_checklstring(L, 1, &len);
    LBN *out = bn_push(L);
    if (BN_bin2bn((const unsigned char *)s, (int)len, out->bn) == NULL)
        return luaL_error(L, "BN_bin2bn failed");
    return 1;
}

/* lbn.totext(n): number -> big-endian octets */
static int lbn_totext(lua_State *L)
{
    BIGNUM *bn = bn_check(L, 1);
    int len = BN_num_bytes(bn);
    unsigned char *buf = (unsigned char *)lua_newuserdata(L, len > 0 ? len : 1);
    BN_bn2bin(bn, buf);
    lua_pushlstring(L, (const char *)buf, (size_t)len);
    return 1;
}

static int lbn_random(lua_State *L)
{
    int bits;
    if (lua_type(L, 1) == LUA_TUSERDATA) bits = BN_num_bits(bn_check(L, 1));
    else bits = (int)luaL_checkinteger(L, 1);
    if (bits <= 0) return luaL_error(L, "bad bit count %d", bits);
    LBN *out = bn_push(L);
    if (!BN_rand(out->bn, bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        return luaL_error(L, "BN_rand failed");
    return 1;
}

static int lbn_tohex(lua_State *L)
{
    char *hex = BN_bn2hex(bn_check(L, 1));
    lua_pushstring(L, hex);
    OPENSSL_free(hex);
    return 1;
}

static int lbn_tostring(lua_State *L)
{
    char *dec = BN_bn2dec(bn_check(L, 1));
    lua_pushstring(L, dec);
    OPENSSL_free(dec);
    return 1;
}

static int lbn_tonumber(lua_State *L)
{
    BIGNUM *bn = bn_check(L, 1);
    char *dec = BN_bn2dec(bn);
    lua_pushnumber(L, (lua_Number)strtod(dec, NULL));
    OPENSSL_free(dec);
    return 1;
}

static int lbn_bits(lua_State *L)
{
    lua_pushinteger(L, BN_num_bits(bn_check(L, 1)));
    return 1;
}

#define BN_BINOP(name, call)                                                   \
    static int name(lua_State *L)                                              \
    {                                                                          \
        BIGNUM *oa = NULL, *ob = NULL;                                         \
        BIGNUM *a = bn_coerce(L, 1, &oa);                                      \
        BIGNUM *b = bn_coerce(L, 2, &ob);                                      \
        LBN *out = bn_push(L);                                                 \
        BN_CTX *ctx = BN_CTX_new();                                            \
        int ok = (call);                                                       \
        BN_CTX_free(ctx);                                                      \
        bn_release(oa); bn_release(ob);                                        \
        if (!ok) return luaL_error(L, "bignum operation failed");              \
        return 1;                                                              \
    }

BN_BINOP(lbn_add, BN_add(out->bn, a, b))
BN_BINOP(lbn_sub, BN_sub(out->bn, a, b))
BN_BINOP(lbn_mul, BN_mul(out->bn, a, b, ctx))
BN_BINOP(lbn_mod, BN_mod(out->bn, a, b, ctx))

static int bn_compare(lua_State *L)
{
    BIGNUM *oa = NULL, *ob = NULL;
    int cmp = BN_cmp(bn_coerce(L, 1, &oa), bn_coerce(L, 2, &ob));
    bn_release(oa); bn_release(ob);
    return cmp;
}

static int lbn_eq(lua_State *L) { lua_pushboolean(L, bn_compare(L) == 0); return 1; }
static int lbn_lt(lua_State *L) { lua_pushboolean(L, bn_compare(L) < 0); return 1; }
static int lbn_le(lua_State *L) { lua_pushboolean(L, bn_compare(L) <= 0); return 1; }

static int lbn_gc(lua_State *L)
{
    LBN *x = (LBN *)luaL_checkudata(L, 1, BN_MT);
    if (x->bn != NULL) { BN_clear_free(x->bn); x->bn = NULL; }
    return 0;
}

/* -------------------------------------------------------------- ecgroup ---- */

typedef struct { EC_GROUP *group; } LGroup;
typedef struct { EC_POINT *point; EC_GROUP *group; } LPoint;

static LGroup *group_check(lua_State *L, int idx)
{
    return (LGroup *)luaL_checkudata(L, idx, GROUP_MT);
}

static LPoint *point_push(lua_State *L, EC_GROUP *group)
{
    LPoint *p = (LPoint *)lua_newuserdata(L, sizeof(LPoint));
    p->group = group;
    p->point = EC_POINT_new(group);
    if (p->point == NULL) luaL_error(L, "EC_POINT_new failed");
    luaL_getmetatable(L, POINT_MT);
    lua_setmetatable(L, -2);
    return p;
}

static LPoint *point_check(lua_State *L, int idx)
{
    return (LPoint *)luaL_checkudata(L, idx, POINT_MT);
}

/* ecgroup.new_GFp(p, a, b, Gx, Gy, order, cofactor) */
static int ecgroup_new_GFp(lua_State *L)
{
    BIGNUM *op = NULL, *oa = NULL, *ob = NULL, *ox = NULL, *oy = NULL, *oq = NULL, *oh = NULL;
    BIGNUM *p = bn_coerce(L, 1, &op);
    BIGNUM *a = bn_coerce(L, 2, &oa);
    BIGNUM *b = bn_coerce(L, 3, &ob);
    BIGNUM *gx = bn_coerce(L, 4, &ox);
    BIGNUM *gy = bn_coerce(L, 5, &oy);
    BIGNUM *order = bn_coerce(L, 6, &oq);
    BIGNUM *cofactor = bn_coerce(L, 7, &oh);

    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *group = EC_GROUP_new_curve_GFp(p, a, b, ctx);
    int ok = 0;
    if (group != NULL) {
        EC_POINT *gen = EC_POINT_new(group);
        if (gen != NULL) {
            ok = EC_POINT_set_affine_coordinates_GFp(group, gen, gx, gy, ctx)
                 && EC_GROUP_set_generator(group, gen, order, cofactor);
            EC_POINT_free(gen);
        }
    }
    BN_CTX_free(ctx);
    bn_release(op); bn_release(oa); bn_release(ob);
    bn_release(ox); bn_release(oy); bn_release(oq); bn_release(oh);

    if (!ok) {
        if (group != NULL) EC_GROUP_free(group);
        return luaL_error(L, "cannot build curve over GF(p)");
    }

    LGroup *out = (LGroup *)lua_newuserdata(L, sizeof(LGroup));
    out->group = group;
    luaL_getmetatable(L, GROUP_MT);
    lua_setmetatable(L, -2);
    return 1;
}

static int ecgroup_degree(lua_State *L)
{
    lua_pushinteger(L, EC_GROUP_get_degree(group_check(L, 1)->group));
    return 1;
}

static int ecgroup_order(lua_State *L)
{
    LGroup *g = group_check(L, 1);
    LBN *out = bn_push(L);
    if (!EC_GROUP_get_order(g->group, out->bn, NULL))
        return luaL_error(L, "EC_GROUP_get_order failed");
    return 1;
}

static int ecgroup_generator(lua_State *L)
{
    LGroup *g = group_check(L, 1);
    LPoint *out = point_push(L, g->group);
    if (!EC_POINT_copy(out->point, EC_GROUP_get0_generator(g->group)))
        return luaL_error(L, "EC_POINT_copy failed");
    return 1;
}

/* group:mul(point, scalar) -> point * scalar */
static int ecgroup_mul(lua_State *L)
{
    LGroup *g = group_check(L, 1);
    LPoint *p = point_check(L, 2);
    BIGNUM *owned = NULL;
    BIGNUM *k = bn_coerce(L, 3, &owned);
    LPoint *out = point_push(L, g->group);
    BN_CTX *ctx = BN_CTX_new();
    int ok = EC_POINT_mul(g->group, out->point, NULL, p->point, k, ctx);
    BN_CTX_free(ctx);
    bn_release(owned);
    if (!ok) return luaL_error(L, "EC_POINT_mul failed");
    return 1;
}

static int ecgroup_add(lua_State *L)
{
    LGroup *g = group_check(L, 1);
    LPoint *a = point_check(L, 2);
    LPoint *b = point_check(L, 3);
    LPoint *out = point_push(L, g->group);
    BN_CTX *ctx = BN_CTX_new();
    int ok = EC_POINT_add(g->group, out->point, a->point, b->point, ctx);
    BN_CTX_free(ctx);
    if (!ok) return luaL_error(L, "EC_POINT_add failed");
    return 1;
}

/* group:sub(a, b) -> a + (-b) */
static int ecgroup_sub(lua_State *L)
{
    LGroup *g = group_check(L, 1);
    LPoint *a = point_check(L, 2);
    LPoint *b = point_check(L, 3);
    LPoint *out = point_push(L, g->group);
    BN_CTX *ctx = BN_CTX_new();
    int ok = EC_POINT_copy(out->point, b->point)
             && EC_POINT_invert(g->group, out->point, ctx)
             && EC_POINT_add(g->group, out->point, a->point, out->point, ctx);
    BN_CTX_free(ctx);
    if (!ok) return luaL_error(L, "EC_POINT_sub failed");
    return 1;
}

static int ecgroup_is_on_curve(lua_State *L)
{
    LGroup *g = group_check(L, 1);
    LPoint *p = point_check(L, 2);
    BN_CTX *ctx = BN_CTX_new();
    int r = EC_POINT_is_on_curve(g->group, p->point, ctx);
    BN_CTX_free(ctx);
    lua_pushboolean(L, r == 1);
    return 1;
}

static int ecgroup_is_at_infinity(lua_State *L)
{
    LGroup *g = group_check(L, 1);
    LPoint *p = point_check(L, 2);
    lua_pushboolean(L, EC_POINT_is_at_infinity(g->group, p->point) == 1);
    return 1;
}

/* group:point2text(point) -> uncompressed octet string */
static int ecgroup_point2text(lua_State *L)
{
    LGroup *g = group_check(L, 1);
    LPoint *p = point_check(L, 2);
    BN_CTX *ctx = BN_CTX_new();
    size_t len = EC_POINT_point2oct(g->group, p->point,
                                   POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    if (len == 0) { BN_CTX_free(ctx); return luaL_error(L, "point2oct sizing failed"); }
    unsigned char *buf = (unsigned char *)lua_newuserdata(L, len);
    size_t got = EC_POINT_point2oct(g->group, p->point,
                                   POINT_CONVERSION_UNCOMPRESSED, buf, len, ctx);
    BN_CTX_free(ctx);
    if (got != len) return luaL_error(L, "point2oct failed");
    lua_pushlstring(L, (const char *)buf, got);
    return 1;
}

static int ecgroup_text2point(lua_State *L)
{
    LGroup *g = group_check(L, 1);
    size_t len;
    const char *s = luaL_checklstring(L, 2, &len);
    LPoint *out = point_push(L, g->group);
    BN_CTX *ctx = BN_CTX_new();
    int ok = EC_POINT_oct2point(g->group, out->point,
                                (const unsigned char *)s, len, ctx);
    BN_CTX_free(ctx);
    if (!ok) return luaL_error(L, "oct2point failed");
    return 1;
}

static int ecgroup_coordinates(lua_State *L)
{
    LGroup *g = group_check(L, 1);
    LPoint *p = point_check(L, 2);
    LBN *x = bn_push(L);
    LBN *y = bn_push(L);
    BN_CTX *ctx = BN_CTX_new();
    int ok = EC_POINT_get_affine_coordinates_GFp(g->group, p->point, x->bn, y->bn, ctx);
    BN_CTX_free(ctx);
    if (!ok) return luaL_error(L, "get_affine_coordinates failed");
    return 2;
}

static int ecgroup_gc(lua_State *L)
{
    LGroup *g = (LGroup *)luaL_checkudata(L, 1, GROUP_MT);
    if (g->group != NULL) { EC_GROUP_free(g->group); g->group = NULL; }
    return 0;
}

static int ecpoint_gc(lua_State *L)
{
    LPoint *p = (LPoint *)luaL_checkudata(L, 1, POINT_MT);
    if (p->point != NULL) { EC_POINT_free(p->point); p->point = NULL; }
    return 0;
}

/* --------------------------------------------------------------- crypto ---- */

static int push_digest_result(lua_State *L, const unsigned char *md,
                              unsigned int len, int raw)
{
    if (raw) {
        lua_pushlstring(L, (const char *)md, len);
        return 1;
    }
    char hex[EVP_MAX_MD_SIZE * 2 + 1];
    static const char *d = "0123456789abcdef";
    for (unsigned int i = 0; i < len; i++) {
        hex[i * 2] = d[md[i] >> 4];
        hex[i * 2 + 1] = d[md[i] & 0x0f];
    }
    lua_pushlstring(L, hex, (size_t)len * 2);
    return 1;
}

/* crypto.digest(alg, data [, key] [, raw]) -- non-empty key means HMAC */
static int crypto_digest(lua_State *L)
{
    const char *alg = luaL_checkstring(L, 1);
    size_t dlen, klen = 0;
    const char *data = luaL_checklstring(L, 2, &dlen);
    const char *key = NULL;
    if (lua_isstring(L, 3)) key = lua_tolstring(L, 3, &klen);
    int raw = lua_toboolean(L, 4);

    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (md == NULL) return luaL_error(L, "unknown digest '%s'", alg);

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen = 0;

    if (key != NULL && klen > 0) {
        if (HMAC(md, key, (int)klen, (const unsigned char *)data, dlen, out, &outlen) == NULL)
            return luaL_error(L, "HMAC failed");
    } else {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        int ok = ctx != NULL
                 && EVP_DigestInit_ex(ctx, md, NULL)
                 && EVP_DigestUpdate(ctx, data, dlen)
                 && EVP_DigestFinal_ex(ctx, out, &outlen);
        if (ctx != NULL) EVP_MD_CTX_free(ctx);
        if (!ok) return luaL_error(L, "digest failed");
    }
    return push_digest_result(L, out, outlen, raw);
}

/* crypto.hmac.digest(alg, data, key [, raw]) */
static int crypto_hmac_digest(lua_State *L)
{
    const char *alg = luaL_checkstring(L, 1);
    size_t dlen, klen;
    const char *data = luaL_checklstring(L, 2, &dlen);
    const char *key = luaL_checklstring(L, 3, &klen);
    int raw = lua_toboolean(L, 4);

    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (md == NULL) return luaL_error(L, "unknown digest '%s'", alg);

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen = 0;
    if (HMAC(md, key, (int)klen, (const unsigned char *)data, dlen, out, &outlen) == NULL)
        return luaL_error(L, "HMAC failed");
    return push_digest_result(L, out, outlen, raw);
}

/* crypto.pbkdf2(password, salt, iterations, alg, keylen) -> raw key */
static int crypto_pbkdf2(lua_State *L)
{
    size_t plen, slen;
    const char *pass = luaL_checklstring(L, 1, &plen);
    const char *salt = luaL_checklstring(L, 2, &slen);
    int iter = (int)luaL_checkinteger(L, 3);
    const char *alg = luaL_optstring(L, 4, "sha1");
    int keylen = (int)luaL_optinteger(L, 5, 32);

    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (md == NULL) return luaL_error(L, "unknown digest '%s'", alg);
    if (keylen <= 0 || keylen > 1024) return luaL_error(L, "bad key length");

    unsigned char *out = (unsigned char *)lua_newuserdata(L, (size_t)keylen);
    if (!PKCS5_PBKDF2_HMAC(pass, (int)plen, (const unsigned char *)salt, (int)slen,
                           iter, md, keylen, out))
        return luaL_error(L, "PBKDF2 failed");
    lua_pushlstring(L, (const char *)out, (size_t)keylen);
    return 1;
}

static int cipher_run(lua_State *L, int encrypt)
{
    const char *name = luaL_checkstring(L, 1);
    size_t dlen, klen, ivlen = 0;
    const char *data = luaL_checklstring(L, 2, &dlen);
    const char *key = luaL_checklstring(L, 3, &klen);
    const char *iv = NULL;
    if (lua_isstring(L, 4)) iv = lua_tolstring(L, 4, &ivlen);
    int padding = lua_isnoneornil(L, 5) ? 1 : lua_toboolean(L, 5);

    const EVP_CIPHER *cipher = EVP_get_cipherbyname(name);
    if (cipher == NULL) return luaL_error(L, "unknown cipher '%s'", name);

    int need_key = EVP_CIPHER_key_length(cipher);
    int need_iv = EVP_CIPHER_iv_length(cipher);

    /* The vendor derives short keys/IVs and lets OpenSSL zero-extend. */
    unsigned char kbuf[EVP_MAX_KEY_LENGTH], ivbuf[EVP_MAX_IV_LENGTH];
    memset(kbuf, 0, sizeof(kbuf));
    memset(ivbuf, 0, sizeof(ivbuf));
    memcpy(kbuf, key, klen < (size_t)need_key ? klen : (size_t)need_key);
    if (iv != NULL && need_iv > 0)
        memcpy(ivbuf, iv, ivlen < (size_t)need_iv ? ivlen : (size_t)need_iv);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return luaL_error(L, "EVP_CIPHER_CTX_new failed");

    int outlen = 0, finlen = 0;
    size_t cap = dlen + (size_t)EVP_CIPHER_block_size(cipher) + 1;
    unsigned char *out = (unsigned char *)lua_newuserdata(L, cap);

    int ok = EVP_CipherInit_ex(ctx, cipher, NULL, kbuf, need_iv > 0 ? ivbuf : NULL, encrypt)
             && EVP_CIPHER_CTX_set_padding(ctx, padding)
             && EVP_CipherUpdate(ctx, out, &outlen, (const unsigned char *)data, (int)dlen)
             && EVP_CipherFinal_ex(ctx, out + outlen, &finlen);
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        lua_pushnil(L);
        lua_pushstring(L, encrypt ? "encrypt failed" : "decrypt failed");
        return 2;
    }
    lua_pushlstring(L, (const char *)out, (size_t)(outlen + finlen));
    return 1;
}

static int crypto_encrypt(lua_State *L) { return cipher_run(L, 1); }
static int crypto_decrypt(lua_State *L) { return cipher_run(L, 0); }

static int crypto_rand_bytes(lua_State *L)
{
    int n = (int)luaL_checkinteger(L, 1);
    if (n <= 0 || n > 65536) return luaL_error(L, "bad byte count");
    unsigned char *buf = (unsigned char *)lua_newuserdata(L, (size_t)n);
    if (RAND_bytes(buf, n) != 1) return luaL_error(L, "RAND_bytes failed");
    lua_pushlstring(L, (const char *)buf, (size_t)n);
    return 1;
}

/* ------------------------------------------------------------ registration -- */

static const luaL_Reg lbn_funcs[] = {
    { "number", lbn_number },
    { "text", lbn_text },
    { "totext", lbn_totext },
    { "random", lbn_random },
    { "tohex", lbn_tohex },
    { "tostring", lbn_tostring },
    { "bits", lbn_bits },
    { "tonumber", lbn_tonumber },
    { "add", lbn_add },
    { "sub", lbn_sub },
    { "mul", lbn_mul },
    { "mod", lbn_mod },
    { NULL, NULL }
};

static const luaL_Reg group_methods[] = {
    { "degree", ecgroup_degree },
    { "order", ecgroup_order },
    { "generator", ecgroup_generator },
    { "mul", ecgroup_mul },
    { "add", ecgroup_add },
    { "sub", ecgroup_sub },
    { "is_on_curve", ecgroup_is_on_curve },
    { "is_at_infinity", ecgroup_is_at_infinity },
    { "point2text", ecgroup_point2text },
    { "text2point", ecgroup_text2point },
    { "coordinates", ecgroup_coordinates },
    { NULL, NULL }
};

static const luaL_Reg crypto_funcs[] = {
    { "digest", crypto_digest },
    { "pbkdf2", crypto_pbkdf2 },
    { "encrypt", crypto_encrypt },
    { "decrypt", crypto_decrypt },
    { NULL, NULL }
};

/*
 * The vendor's native modules expose the *method table* itself: ec.lua does
 *   require("ecgroup").random_scalar = function(group) ... end
 * and pace.lua then calls curve:random_scalar(). So the module table must be
 * the metatable's __index, not a separate namespace.
 */
static void push_method_table(lua_State *L, const char *mt_name,
                              const luaL_Reg *methods, lua_CFunction gc)
{
    luaL_newmetatable(L, mt_name);          /* mt */
    if (gc != NULL) {
        lua_pushcfunction(L, gc);
        lua_setfield(L, -2, "__gc");
    }
    lua_newtable(L);                        /* mt, methods */
    if (methods != NULL) luaL_register(L, NULL, methods);
    lua_pushvalue(L, -1);                   /* mt, methods, methods */
    lua_setfield(L, -3, "__index");         /* mt.__index = methods */
    lua_remove(L, -2);                      /* methods */
}

static void add_bn_metamethods(lua_State *L)
{
    luaL_getmetatable(L, BN_MT);
    lua_pushcfunction(L, lbn_tostring); lua_setfield(L, -2, "__tostring");
    lua_pushcfunction(L, lbn_eq);       lua_setfield(L, -2, "__eq");
    lua_pushcfunction(L, lbn_lt);       lua_setfield(L, -2, "__lt");
    lua_pushcfunction(L, lbn_le);       lua_setfield(L, -2, "__le");
    lua_pushcfunction(L, lbn_add);      lua_setfield(L, -2, "__add");
    lua_pushcfunction(L, lbn_sub);      lua_setfield(L, -2, "__sub");
    lua_pushcfunction(L, lbn_mul);      lua_setfield(L, -2, "__mul");
    lua_pushcfunction(L, lbn_mod);      lua_setfield(L, -2, "__mod");
    lua_pop(L, 1);
}

static void push_crypto(lua_State *L)
{
    lua_newtable(L);
    luaL_register(L, NULL, crypto_funcs);

    lua_newtable(L);
    lua_pushcfunction(L, crypto_hmac_digest);
    lua_setfield(L, -2, "digest");
    lua_setfield(L, -2, "hmac");

    lua_newtable(L);
    lua_pushcfunction(L, crypto_rand_bytes);
    lua_setfield(L, -2, "bytes");
    lua_pushcfunction(L, crypto_rand_bytes);
    lua_setfield(L, -2, "pseudo_bytes");
    lua_setfield(L, -2, "rand");
}

int luaopen_dlrenative(lua_State *L)
{
    lua_newtable(L);                            /* module */

    push_method_table(L, BN_MT, lbn_funcs, lbn_gc);
    add_bn_metamethods(L);
    lua_setfield(L, -2, "lbn");

    push_method_table(L, GROUP_MT, group_methods, ecgroup_gc);
    lua_pushcfunction(L, ecgroup_new_GFp);
    lua_setfield(L, -2, "new_GFp");
    lua_setfield(L, -2, "ecgroup");

    push_method_table(L, POINT_MT, NULL, ecpoint_gc);
    lua_setfield(L, -2, "ecpoint");

    push_crypto(L);
    lua_setfield(L, -2, "crypto");

    return 1;
}
