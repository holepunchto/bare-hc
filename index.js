const binding = require('./binding')

const KEY_SIZE = 32
const SECRET_KEY_SIZE = 64
const HASH_SIZE = 32

exports.KEY_SIZE = KEY_SIZE
exports.SECRET_KEY_SIZE = SECRET_KEY_SIZE
exports.HASH_SIZE = HASH_SIZE

exports.keypair = function keypair(seed) {
  const buf = Buffer.from(binding.cryptoKeypair(seed || null))

  return {
    publicKey: buf.subarray(0, KEY_SIZE),
    secretKey: buf.subarray(KEY_SIZE, KEY_SIZE + SECRET_KEY_SIZE)
  }
}

exports.discoveryKey = function discoveryKey(publicKey) {
  return Buffer.from(binding.cryptoDiscoveryKey(publicKey))
}

exports.Manifest = class Manifest {
  constructor(keypair) {
    const kp = Buffer.concat([keypair.publicKey, keypair.secretKey])
    this._handle = binding.manifestInitSingleSigner(kp)
  }

  hash() {
    return Buffer.from(binding.hashesManifest(this._handle))
  }

  destroy() {
    binding.manifestDestroy(this._handle)
  }
}

exports.Store = class Store {
  constructor(path) {
    this._handle = binding.storeInit(path)
  }

  create(key, discoveryKey) {
    return new Core(binding.storeCreate(this._handle, key, discoveryKey))
  }

  get(key, discoveryKey) {
    return new Core(binding.storeGet(this._handle, key, discoveryKey))
  }

  destroy() {
    binding.storeDestroy(this._handle)
  }
}

class Core {
  constructor(handle) {
    this._handle = handle
  }

  get length() {
    return binding.coreLength(this._handle)
  }

  get byteLength() {
    return binding.coreByteLength(this._handle)
  }

  append(blocks) {
    binding.coreAppend(this._handle, blocks)
  }

  destroy() {
    binding.coreDestroy(this._handle)
  }
}

exports.Core = Core
