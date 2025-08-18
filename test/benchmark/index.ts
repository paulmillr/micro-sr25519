import { hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { mark } from '@paulmillr/jsbt/bench.js';
import * as polka from '@polkadot/util-crypto';
import { deepStrictEqual } from 'assert';
import * as sr25519 from '../../index.ts';

async function compare(title, runs, kinds) {
  for (let [name, fn] of Object.entries(kinds)) {
    await mark(`${title} ${name}`, runs, fn);
  }
}

(async () => {
  await polka.cryptoWaitReady();
  const BENCH = true;
  // This also works as cross-test
  console.log(`\x1b[36msr25519\x1b[0m`);

  const selfSeed = hexToBytes('98b3d305d5a5eace562387e47e59badd4d77e3f72cabfb10a60f8a197059f0a8');
  const otherSeed = hexToBytes('9732eea001851ff862d949a1699c9971f3a26edbede2ad7922cbbe9a0701f366');
  // Self
  const skSelf = sr25519.secretFromSeed(selfSeed);
  const pubSelf = sr25519.getPublicKey(skSelf);
  const selfPairPolka = polka.sr25519PairFromSeed(selfSeed);
  deepStrictEqual(skSelf, selfPairPolka.secretKey);
  deepStrictEqual(pubSelf, selfPairPolka.publicKey);
  // Other
  const skOther = sr25519.secretFromSeed(otherSeed);
  const pubOther = sr25519.getPublicKey(skOther);
  const otherPairPolka = polka.sr25519PairFromSeed(otherSeed);
  deepStrictEqual(skOther, otherPairPolka.secretKey);
  deepStrictEqual(pubOther, otherPairPolka.publicKey);

  if (BENCH) {
    await compare('secretFromSeed', 100_000, {
      wasm: () => polka.sr25519PairFromSeed(selfSeed),
      scure: () => sr25519.secretFromSeed(selfSeed),
    });
  }

  const sharedPolka = polka.sr25519Agreement(skSelf, pubOther);
  const sharedNoble = sr25519.getSharedSecret(skSelf, pubOther);
  deepStrictEqual(sharedPolka, sharedNoble);
  const sharedPolka2 = polka.sr25519Agreement(skOther, pubSelf);
  const sharedNoble2 = sr25519.getSharedSecret(skOther, pubSelf);
  deepStrictEqual(sharedPolka2, sharedNoble2);

  if (BENCH) {
    await compare('getSharedSecret', 1_000, {
      wasm: () => polka.sr25519Agreement(skSelf, pubOther),
      scure: () => sr25519.getSharedSecret(skSelf, pubOther),
    });
  }

  const cc = hexToBytes('0c666f6f00000000000000000000000000000000000000000000000000000000'); // foo
  const pair = { publicKey: pubSelf, secretKey: skSelf };

  const hardPolka = polka.sr25519DeriveHard(pair, cc);
  const hardNoble = sr25519.HDKD.secretHard(skSelf, cc);
  deepStrictEqual(hardPolka.secretKey, hardNoble);
  deepStrictEqual(hardPolka.publicKey, sr25519.getPublicKey(hardNoble));

  if (BENCH) {
    await compare('HDKD.secretHard', 50_000, {
      wasm: () => polka.sr25519DeriveHard(pair, cc),
      scure: () => sr25519.HDKD.secretHard(skSelf, cc),
    });
  }

  const softPolka = polka.sr25519DeriveSoft(pair, cc);
  const softNobleSecret = sr25519.HDKD.secretSoft(skSelf, cc);
  const softNoblePub = sr25519.getPublicKey(softNobleSecret);
  deepStrictEqual(softPolka.publicKey, softNoblePub);
  // Nonce random
  deepStrictEqual(softPolka.secretKey.subarray(0, 32), softNobleSecret.subarray(0, 32));

  if (BENCH) {
    await compare('HDKD.secretSoft', 1_000, {
      wasm: () => polka.sr25519DeriveSoft(pair, cc),
      scure: () => sr25519.HDKD.secretSoft(skSelf, cc),
    });
  }

  const publicPolka = polka.sr25519DerivePublic(pubSelf, cc);
  const publicNoble = sr25519.HDKD.publicSoft(pubSelf, cc);
  deepStrictEqual(publicPolka, publicNoble);
  deepStrictEqual(publicPolka, softPolka.publicKey);
  deepStrictEqual(publicPolka, softNoblePub);
  if (BENCH) {
    await compare('HDKD.publicSoft', 1_000, {
      wasm: () => polka.sr25519DerivePublic(pubSelf, cc),
      scure: () => sr25519.HDKD.publicSoft(pubSelf, cc),
    });
  }

  const msg = utf8ToBytes('some message');
  const polkaSig = polka.sr25519Sign(msg, pair);
  const nobleSig = sr25519.sign(pair.secretKey, msg);
  deepStrictEqual(polka.sr25519Verify(msg, polkaSig, pair.publicKey), true);
  deepStrictEqual(polka.sr25519Verify(msg, nobleSig, pair.publicKey), true);
  deepStrictEqual(sr25519.verify(msg, polkaSig, pair.publicKey), true);
  deepStrictEqual(sr25519.verify(msg, nobleSig, pair.publicKey), true);

  if (BENCH) {
    await compare('sign', 1_000, {
      wasm: () => polka.sr25519Sign(msg, pair),
      scure: () => sr25519.sign(pair.secretKey, msg),
    });
    await compare('verify', 1_000, {
      wasm: () => polka.sr25519Verify(msg, nobleSig, pair.publicKey),
      scure: () => sr25519.verify(msg, nobleSig, pair.publicKey),
    });
  }
  // VRF
  const polkaVrfSig = polka.sr25519VrfSign(msg, pair);
  const nobleVrfSig = sr25519.vrf.sign(msg, pair.secretKey);

  deepStrictEqual(polka.sr25519VrfVerify(msg, polkaVrfSig, pair.publicKey), true);
  deepStrictEqual(sr25519.vrf.verify(msg, nobleVrfSig, pair.publicKey), true);
  deepStrictEqual(polka.sr25519VrfVerify(msg, nobleVrfSig, pair.publicKey), true);
  deepStrictEqual(sr25519.vrf.verify(msg, polkaVrfSig, pair.publicKey), true);

  if (BENCH) {
    await compare('vrfSign', 1_000, {
      wasm: () => polka.sr25519VrfSign(msg, pair),
      scure: () => sr25519.vrf.sign(msg, pair.secretKey),
    });
    await compare('vrfVerify', 1_000, {
      wasm: () => polka.sr25519VrfVerify(msg, polkaVrfSig, pair.publicKey),
      scure: () => sr25519.vrf.verify(msg, nobleVrfSig, pair.publicKey),
    });
  }
})();
