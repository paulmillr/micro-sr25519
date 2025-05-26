# micro-sr25519

Minimal JS implementation of sr25519 cryptography for Polkadot.

- 🧜‍♂️ [sr25519 curve](https://wiki.polkadot.network/docs/learn-cryptography)
- Schnorr signature on Ristretto compressed Ed25519
- Hierarchical Deterministic Key Derivation (HDKD)
- Verifiable random function (VRF)
- Uses [Merlin](https://merlin.cool/index.html), which is based on [Strobe128](https://strobe.sourceforge.io).
  - **_NOTE_**: We implement only parts of these protocols which required for sr25519.
- ➰ Uses [noble-curves](https://github.com/paulmillr/noble-curves) for underlying arithmetics

## Usage

> npm install micro-sr25519

```ts
import * as sr25519 from 'micro-sr25519';
```

We support all major platforms and runtimes. For [Deno](https://deno.land), ensure to use
[npm specifier](https://deno.land/manual@v1.28.0/node/npm_specifiers).

### Basic

```ts
const signature = sr25519.sign(pair.secretKey, msg);
const isValid = sr25519.verify(msg, polkaSig, pair.publicKey);
const secretKey = sr25519.secretFromSeed(seed);
const publicKey = sr25519.getPublicKey(secretKey);
const sharedSecret = sr25519.getSharedSecret(secretKey, publicKey);
```

### HDKD

```ts
// hard
const secretKey = sr25519.HDKD.secretHard(pair.secretKey, cc);
const publicKey = sr25519.getPublicKey(secretKey);

// soft
const secretKey = sr25519.HDKD.secretSoft(pair.secretKey, cc);
const publicKey = sr25519.getPublicKey(secretKey);

// public
const publicKey = sr25519.HDKD.publicSoft(pubSelf, cc);
```

### VRF

```ts
const signature = sr25519.vrf.sign(msg, pair.secretKey);
const isValid = sr25519.vrf.verify(msg, sig, pair.publicKey);
```

### Migration from `@polkadot/utils-crypto`

- most derive methods in original return `{publicKey, privateKey}`, we always return only privateKey,
  you can get publicKey via `getPublicKey`
- privateKey is 64 byte (instead of 32 byte in ed25519), this is because we need nonce and privateKey can be
  derived from others (HDKD), and there would be no seed for that.

## Security

The library has not been independently audited yet. Use at your own risk.

Low-level operations are done using noble-curves and noble-hashes.
Consult their README for more information about constant-timeness, memory dumping and supply chain security.


## Speed

Benchmark results on Apple M4:

```
secretFromSeed x 493,827 ops/sec @ 2μs/op ± 1.37% (1μs..651μs)
getSharedSecret x 1,135 ops/sec @ 880μs/op
HDKD.secretHard x 54,121 ops/sec @ 18μs/op
HDKD.secretSoft x 4,108 ops/sec @ 243μs/op
HDKD.publicSoft x 4,499 ops/sec @ 222μs/op
sign x 2,475 ops/sec @ 403μs/op
verify x 955 ops/sec @ 1ms/op
vrfSign x 442 ops/sec @ 2ms/op
vrfVerify x 344 ops/sec @ 2ms/op
```

Comparison with wasm:

```
secretFromSeed wasm x 21,615 ops/sec @ 46μs/op
getSharedSecret wasm x 6,681 ops/sec @ 149μs/op
HDKD.secretHard wasm x 16,958 ops/sec @ 58μs/op
HDKD.secretSoft wasm x 16,075 ops/sec @ 62μs/op
HDKD.publicSoft wasm x 16,981 ops/sec @ 58μs/op
sign wasm x 16,559 ops/sec @ 60μs/op
verify wasm x 6,741 ops/sec @ 148μs/op
vrfSign wasm x 2,470 ops/sec @ 404μs/op
vrfVerify wasm x 2,917 ops/sec @ 342μs/op
```

## Contributing & testing

1. Clone the repository
2. `npm install` to install build dependencies like TypeScript
3. `npm run build` to compile TypeScript code
4. `npm run test` will execute all main tests

## License

The MIT License (MIT)

Copyright (c) 2024 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)

See LICENSE file.
