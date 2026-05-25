const test = require('brittle')
const hc = require('.')

test('keypair', (t) => {
  const kp = hc.keypair()
  t.is(kp.publicKey.byteLength, hc.KEY_SIZE)
  t.is(kp.secretKey.byteLength, hc.SECRET_KEY_SIZE)
})

test('keypair from seed is deterministic', (t) => {
  const seed = Buffer.alloc(hc.KEY_SIZE, 0x42)
  const a = hc.keypair(seed)
  const b = hc.keypair(seed)
  t.alike(a.publicKey, b.publicKey)
  t.alike(a.secretKey, b.secretKey)
})

test('discoveryKey', (t) => {
  const kp = hc.keypair()
  const dk = hc.discoveryKey(kp.publicKey)
  t.is(dk.byteLength, hc.HASH_SIZE)
})

test('hello world', async (t) => {
  const dir = await t.tmp()

  const kp = hc.keypair()
  const manifest = new hc.Manifest(kp)
  const key = manifest.hash()
  const dk = hc.discoveryKey(kp.publicKey)

  const store = new hc.Store(dir)
  const core = store.create(key, dk)

  core.append([Buffer.from('hello world')])
  t.is(core.length, 1)
  t.is(core.byteLength, 11)

  core.destroy()
  store.destroy()
  manifest.destroy()
})

test('reopen core', async (t) => {
  const dir = await t.tmp()

  const kp = hc.keypair()
  const manifest = new hc.Manifest(kp)
  const key = manifest.hash()
  const dk = hc.discoveryKey(kp.publicKey)

  const store = new hc.Store(dir)

  const a = store.create(key, dk)
  a.append([Buffer.from('one')])
  a.destroy()

  const b = store.get(key, dk)
  t.is(b.length, 1)
  t.is(b.byteLength, 3)
  b.append([Buffer.from('two!')])
  t.is(b.length, 2)
  t.is(b.byteLength, 7)
  b.destroy()

  store.destroy()
  manifest.destroy()
})
