#include <assert.h>
#include <bare.h>
#include <js.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <utf.h>
#include <uv.h>

#include <hc.h>
#include <hc/core.h>
#include <hc/crypto.h>
#include <hc/hashes.h>
#include <hc/manifest.h>
#include <hc/store.h>

static js_value_t *
bare_hc_crypto_keypair (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  uint8_t *seed = NULL;
  if (argc >= 1) {
    js_value_type_t type;
    err = js_typeof(env, argv[0], &type);
    assert(err == 0);

    if (type != js_undefined && type != js_null) {
      size_t seed_len;
      err = js_get_typedarray_info(env, argv[0], NULL, (void **) &seed, &seed_len, NULL, NULL);
      assert(err == 0);
      assert(seed_len == HC_CRYPTO_KEY_SIZE);
    }
  }

  hc_crypto_keypair_t kp;
  hc_crypto_keypair(&kp, seed);

  void *data;
  js_value_t *result;
  err = js_create_unsafe_arraybuffer(env, HC_CRYPTO_KEY_SIZE + HC_CRYPTO_SECRET_KEY_SIZE, &data, &result);
  assert(err == 0);

  memcpy(data, kp.public_key, HC_CRYPTO_KEY_SIZE);
  memcpy((uint8_t *) data + HC_CRYPTO_KEY_SIZE, kp.secret_key, HC_CRYPTO_SECRET_KEY_SIZE);

  return result;
}

static js_value_t *
bare_hc_crypto_discovery_key (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 1);

  void *key;
  size_t key_len;
  err = js_get_typedarray_info(env, argv[0], NULL, &key, &key_len, NULL, NULL);
  assert(err == 0);
  assert(key_len == HC_CRYPTO_KEY_SIZE);

  void *data;
  js_value_t *result;
  err = js_create_unsafe_arraybuffer(env, HC_CRYPTO_HASH_SIZE, &data, &result);
  assert(err == 0);

  hc_crypto_discovery_key(data, key);

  return result;
}

static js_value_t *
bare_hc_manifest_init_single_signer (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 1);

  void *kp_data;
  size_t kp_len;
  err = js_get_typedarray_info(env, argv[0], NULL, &kp_data, &kp_len, NULL, NULL);
  assert(err == 0);
  assert(kp_len == HC_CRYPTO_KEY_SIZE + HC_CRYPTO_SECRET_KEY_SIZE);

  hc_crypto_keypair_t kp;
  memcpy(kp.public_key, kp_data, HC_CRYPTO_KEY_SIZE);
  memcpy(kp.secret_key, (uint8_t *) kp_data + HC_CRYPTO_KEY_SIZE, HC_CRYPTO_SECRET_KEY_SIZE);

  void *data;
  js_value_t *result;
  err = js_create_unsafe_arraybuffer(env, sizeof(hc_manifest_t), &data, &result);
  assert(err == 0);

  err = hc_manifest_init_single_signer((hc_manifest_t *) data, &kp);
  if (err != 0) {
    err = js_throw_error(env, NULL, "hc_manifest_init_single_signer failed");
    assert(err == 0);
    return NULL;
  }

  return result;
}

static js_value_t *
bare_hc_manifest_destroy (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 1);

  void *data;
  size_t len;
  err = js_get_arraybuffer_info(env, argv[0], &data, &len);
  assert(err == 0);
  assert(len == sizeof(hc_manifest_t));

  hc_manifest_destroy((hc_manifest_t *) data);

  return NULL;
}

static js_value_t *
bare_hc_hashes_manifest (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 1);

  void *manifest_data;
  size_t manifest_len;
  err = js_get_arraybuffer_info(env, argv[0], &manifest_data, &manifest_len);
  assert(err == 0);
  assert(manifest_len == sizeof(hc_manifest_t));

  void *data;
  js_value_t *result;
  err = js_create_unsafe_arraybuffer(env, HC_CRYPTO_HASH_SIZE, &data, &result);
  assert(err == 0);

  err = hc_hashes_manifest(data, (hc_manifest_t *) manifest_data);
  if (err != 0) {
    err = js_throw_error(env, NULL, "hc_hashes_manifest failed");
    assert(err == 0);
    return NULL;
  }

  return result;
}

static js_value_t *
bare_hc_store_init (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 1);

  size_t path_len;
  err = js_get_value_string_utf8(env, argv[0], NULL, 0, &path_len);
  assert(err == 0);

  utf8_t *path = malloc(path_len + 1);
  err = js_get_value_string_utf8(env, argv[0], path, path_len + 1, NULL);
  assert(err == 0);

  uv_loop_t *loop;
  err = js_get_env_loop(env, &loop);
  assert(err == 0);

  void *data;
  js_value_t *result;
  err = js_create_unsafe_arraybuffer(env, sizeof(hc_store_t), &data, &result);
  assert(err == 0);

  err = hc_store_init((hc_store_t *) data, (const char *) path, loop);
  free(path);

  if (err != 0) {
    err = js_throw_error(env, NULL, "hc_store_init failed");
    assert(err == 0);
    return NULL;
  }

  return result;
}

static js_value_t *
bare_hc_store_destroy (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 1);

  void *data;
  size_t len;
  err = js_get_arraybuffer_info(env, argv[0], &data, &len);
  assert(err == 0);
  assert(len == sizeof(hc_store_t));

  hc_store_destroy((hc_store_t *) data);

  return NULL;
}

static js_value_t *
bare_hc_store_create (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 3;
  js_value_t *argv[3];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 3);

  void *store_data;
  size_t store_len;
  err = js_get_arraybuffer_info(env, argv[0], &store_data, &store_len);
  assert(err == 0);
  assert(store_len == sizeof(hc_store_t));

  void *key;
  size_t key_len;
  err = js_get_typedarray_info(env, argv[1], NULL, &key, &key_len, NULL, NULL);
  assert(err == 0);
  assert(key_len == HC_CRYPTO_HASH_SIZE);

  void *discovery_key;
  size_t dk_len;
  err = js_get_typedarray_info(env, argv[2], NULL, &discovery_key, &dk_len, NULL, NULL);
  assert(err == 0);
  assert(dk_len == HC_CRYPTO_HASH_SIZE);

  void *data;
  js_value_t *result;
  err = js_create_unsafe_arraybuffer(env, sizeof(hc_core_t), &data, &result);
  assert(err == 0);

  err = hc_store_create((hc_store_t *) store_data, (hc_core_t *) data, key, discovery_key);
  if (err != 0) {
    err = js_throw_error(env, NULL, "hc_store_create failed");
    assert(err == 0);
    return NULL;
  }

  return result;
}

static js_value_t *
bare_hc_store_get (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 3;
  js_value_t *argv[3];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 3);

  void *store_data;
  size_t store_len;
  err = js_get_arraybuffer_info(env, argv[0], &store_data, &store_len);
  assert(err == 0);
  assert(store_len == sizeof(hc_store_t));

  void *key;
  size_t key_len;
  err = js_get_typedarray_info(env, argv[1], NULL, &key, &key_len, NULL, NULL);
  assert(err == 0);
  assert(key_len == HC_CRYPTO_HASH_SIZE);

  void *discovery_key;
  size_t dk_len;
  err = js_get_typedarray_info(env, argv[2], NULL, &discovery_key, &dk_len, NULL, NULL);
  assert(err == 0);
  assert(dk_len == HC_CRYPTO_HASH_SIZE);

  void *data;
  js_value_t *result;
  err = js_create_unsafe_arraybuffer(env, sizeof(hc_core_t), &data, &result);
  assert(err == 0);

  err = hc_store_get((hc_store_t *) store_data, (hc_core_t *) data, key, discovery_key);
  if (err != 0) {
    err = js_throw_error(env, NULL, "hc_store_get failed");
    assert(err == 0);
    return NULL;
  }

  return result;
}

static js_value_t *
bare_hc_core_append (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 2;
  js_value_t *argv[2];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 2);

  void *core_data;
  size_t core_len;
  err = js_get_arraybuffer_info(env, argv[0], &core_data, &core_len);
  assert(err == 0);
  assert(core_len == sizeof(hc_core_t));

  uint32_t count;
  err = js_get_array_length(env, argv[1], &count);
  assert(err == 0);

  hc_buf_t *bufs = malloc(sizeof(hc_buf_t) * count);

  for (uint32_t i = 0; i < count; i++) {
    js_value_t *element;
    err = js_get_element(env, argv[1], i, &element);
    assert(err == 0);

    void *buf_data;
    size_t buf_len;
    err = js_get_typedarray_info(env, element, NULL, &buf_data, &buf_len, NULL, NULL);
    assert(err == 0);

    bufs[i].buffer = buf_data;
    bufs[i].len = buf_len;
  }

  err = hc_core_append((hc_core_t *) core_data, bufs, count);
  free(bufs);

  if (err != 0) {
    err = js_throw_error(env, NULL, "hc_core_append failed");
    assert(err == 0);
    return NULL;
  }

  return NULL;
}

static js_value_t *
bare_hc_core_destroy (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 1);

  void *data;
  size_t len;
  err = js_get_arraybuffer_info(env, argv[0], &data, &len);
  assert(err == 0);
  assert(len == sizeof(hc_core_t));

  hc_core_destroy((hc_core_t *) data);

  return NULL;
}

static js_value_t *
bare_hc_core_length (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 1);

  void *data;
  size_t len;
  err = js_get_arraybuffer_info(env, argv[0], &data, &len);
  assert(err == 0);
  assert(len == sizeof(hc_core_t));

  hc_core_t *core = (hc_core_t *) data;

  js_value_t *result;
  err = js_create_int64(env, (int64_t) core->length, &result);
  assert(err == 0);

  return result;
}

static js_value_t *
bare_hc_core_byte_length (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 1);

  void *data;
  size_t len;
  err = js_get_arraybuffer_info(env, argv[0], &data, &len);
  assert(err == 0);
  assert(len == sizeof(hc_core_t));

  hc_core_t *core = (hc_core_t *) data;

  js_value_t *result;
  err = js_create_int64(env, (int64_t) core->byte_length, &result);
  assert(err == 0);

  return result;
}

static js_value_t *
bare_hc_exports (js_env_t *env, js_value_t *exports) {
  int err;

  if (hc_init() < 0) {
    err = js_throw_error(env, NULL, "hc_init failed");
    assert(err == 0);
    return NULL;
  }

#define V(name, fn) \
  { \
    js_value_t *val; \
    err = js_create_function(env, name, -1, fn, NULL, &val); \
    assert(err == 0); \
    err = js_set_named_property(env, exports, name, val); \
    assert(err == 0); \
  }

  V("cryptoKeypair", bare_hc_crypto_keypair)
  V("cryptoDiscoveryKey", bare_hc_crypto_discovery_key)
  V("manifestInitSingleSigner", bare_hc_manifest_init_single_signer)
  V("manifestDestroy", bare_hc_manifest_destroy)
  V("hashesManifest", bare_hc_hashes_manifest)
  V("storeInit", bare_hc_store_init)
  V("storeDestroy", bare_hc_store_destroy)
  V("storeCreate", bare_hc_store_create)
  V("storeGet", bare_hc_store_get)
  V("coreAppend", bare_hc_core_append)
  V("coreDestroy", bare_hc_core_destroy)
  V("coreLength", bare_hc_core_length)
  V("coreByteLength", bare_hc_core_byte_length)
#undef V

  return exports;
}

BARE_MODULE(bare_hc, bare_hc_exports)
