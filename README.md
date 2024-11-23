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

## Speed

Benchmark results on Apple M2 with node v22:

```
sr25519
secretFromSeed
├─wasm x 15,323 ops/sec @ 65μs/op
└─micro x 116,509 ops/sec @ 8μs/op
getSharedSecret
├─wasm x 4,516 ops/sec @ 221μs/op
└─micro x 799 ops/sec @ 1ms/op
HDKD.secretHard
├─wasm x 11,930 ops/sec @ 83μs/op
└─micro x 26,340 ops/sec @ 37μs/op
HDKD.secretSoft
├─wasm x 12,147 ops/sec @ 82μs/op
└─micro x 2,756 ops/sec @ 362μs/op
HDKD.publicSoft
├─wasm x 12,627 ops/sec @ 79μs/op
└─micro x 3,134 ops/sec @ 319μs/op
sign
├─wasm x 12,223 ops/sec @ 81μs/op
└─micro x 1,741 ops/sec @ 574μs/op
verify
├─wasm x 5,085 ops/sec @ 196μs/op
└─micro x 669 ops/sec @ 1ms/op
vrfSign
├─wasm x 1,847 ops/sec @ 541μs/op
└─micro x 313 ops/sec @ 3ms/op
vrfVerify
├─wasm x 2,181 ops/sec @ 458μs/op
└─micro x 243 ops/sec @ 4ms/op
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
