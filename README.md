# bare-hc

Bare bindings for [libhc](https://github.com/holepunchto/libhc).

```
npm i bare-hc
```

## Usage

```js
const hc = require('bare-hc')

const kp = hc.keypair()
const manifest = new hc.Manifest(kp)
const key = manifest.hash()
const discoveryKey = hc.discoveryKey(kp.publicKey)

const store = new hc.Store('/tmp/bare-hc-example')
const core = store.create(key, discoveryKey)

core.append([Buffer.from('hello world')])

core.destroy()
store.destroy()
manifest.destroy()
```

## License

Apache-2.0
