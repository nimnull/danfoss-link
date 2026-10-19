-- Trifork's `crypto` module is stock **LuaCrypto**. Confirmed from the vendor
-- binary (work/extracted/lib/arm64-v8a/libluavm-java.so, not stripped):
-- symbols `encrypt_fencrypt`, `decrypt_fdecrypt`, `digest_fdigest`,
-- `init_encryptor_decryptor`, `luacrypto_createmeta`.
--
-- That fixes the signatures, and one of them does not match what this project
-- assumed:
--
--   crypto.digest(type, message, raw)          -- raw is argument 3
--   crypto.hmac.digest(type, message, key, raw) -- raw is argument 4
--
-- pace.lua calls `crypto.digest("sha256", oct, "", false)`. Argument 3 is the
-- empty string, and in Lua only nil and false are falsy, so LuaCrypto takes
-- raw = true and returns 32 raw bytes; the trailing `false` is ignored. Our
-- native module instead read argument 3 as an optional HMAC key and argument 4
-- as the raw flag, so it returned 64 hex characters -- a different value fed
-- into the PACE transcript, and therefore a different proof.
--
-- Nothing failed loudly because pace.lua also disables AES padding
-- (`crypto.decrypt("aes-256-cbc", z, key, iv, false)`), so a mismatch only
-- surfaces as the misleading top-level error "invalid password".
--
-- Verified as *correct* against the same binary and left alone:
--   * cryptomisc.pbkdf2 -> PKCS5_PBKDF2_HMAC then lua_pushlstring, no hex
--     conversion, so it returns raw bytes (not hex)
--   * init_encryptor_decryptor copies the key with memcpy into a zeroed
--     EVP_MAX_KEY_LENGTH buffer, so a short key is zero-extended -- no
--     EVP_BytesToKey, no EVP_CIPHER_CTX_set_key_length
--   * crypto.hmac.digest with three arguments returns hex, which matches the
--     64-character proof token seen on the wire
local native = require("dlrenative").crypto

local function unhex(s)
  return (s:gsub("%x%x", function(cc) return string.char(tonumber(cc, 16)) end))
end

if type(native.digest) == "function" and not native.__dlre_digest_luacrypto then
  native.__dlre_digest_luacrypto = true
  local real_digest = native.digest
  native.digest = function(alg, message, raw)
    -- Two arguments on the native side means "no HMAC key, hex output".
    local hex = real_digest(alg, message)
    if type(hex) ~= "string" then return hex end
    if raw then return unhex(hex) end
    return hex
  end
end

return native
