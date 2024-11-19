import * as sr25519 from '../lib/esm/index.js';
import * as ed25519 from '@noble/curves/ed25519';

import { describe, should } from 'micro-should';
import { deepStrictEqual, notDeepStrictEqual, throws } from 'node:assert';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils';

const { Strobe128, Merlin, SigningContext } = sr25519.__tests;
const ZeroRNG = (n) => new Uint8Array(n);

describe('sr25519', () => {
  describe('utils', () => {
    should('strobe128', () => {
      const s = new Strobe128('Conformance Test Protocol');
      let msg = new Uint8Array(1024).fill(99);
      s.metaAD('ms', false);
      s.metaAD('g', true);
      s.AD(msg, false);
      s.metaAD('prf', false);
      let prf1 = s.PRF(32, false);
      deepStrictEqual(
        prf1,
        new Uint8Array([
          180, 142, 100, 92, 161, 124, 102, 127, 213, 32, 107, 165, 122, 106, 34, 141, 114, 216,
          225, 144, 56, 20, 211, 241, 127, 98, 41, 150, 215, 207, 239, 176,
        ])
      );
      s.metaAD('key', false);
      s.KEY(prf1, false);
      s.metaAD('prf', false);
      prf1 = s.PRF(32, false);
      deepStrictEqual(
        prf1,
        new Uint8Array([
          7, 228, 92, 206, 128, 120, 206, 226, 89, 227, 227, 117, 187, 133, 215, 86, 16, 226, 209,
          225, 32, 28, 95, 100, 80, 69, 161, 148, 237, 212, 159, 248,
        ])
      );
    });
    should('SigningContext', () => {
      // This is for merlin test
      const t = new SigningContext('SigningContext', ZeroRNG);
      t.label('substrate');
      t.bytes(utf8ToBytes('this is a message'));
      deepStrictEqual(
        t.strobe.state,
        new Uint8Array([
          156, 127, 91, 234, 138, 145, 60, 180, 10, 209, 13, 13, 101, 100, 39, 7, 179, 97, 106, 47,
          48, 101, 40, 246, 115, 59, 228, 32, 162, 5, 210, 18, 186, 113, 15, 109, 9, 96, 157, 119,
          250, 62, 108, 48, 8, 238, 19, 148, 9, 109, 57, 137, 212, 94, 71, 96, 242, 184, 247, 217,
          180, 87, 197, 145, 143, 155, 98, 236, 151, 71, 200, 234, 200, 69, 229, 142, 107, 225, 150,
          20, 15, 164, 122, 7, 241, 158, 120, 245, 172, 93, 147, 2, 12, 99, 114, 115, 33, 201, 42,
          96, 57, 7, 3, 83, 73, 204, 187, 27, 146, 183, 176, 5, 126, 143, 168, 127, 206, 188, 126,
          136, 101, 111, 203, 69, 174, 4, 188, 52, 202, 190, 174, 190, 121, 217, 23, 80, 192, 232,
          191, 19, 185, 102, 80, 77, 19, 67, 89, 114, 101, 221, 136, 101, 173, 249, 20, 9, 204, 155,
          32, 213, 244, 116, 68, 4, 31, 151, 182, 153, 221, 251, 222, 233, 30, 168, 123, 208, 155,
          248, 176, 45, 167, 90, 150, 233, 71, 240, 127, 91, 101, 187, 78, 110, 254, 250, 161, 106,
          191, 217, 251, 246,
        ])
      );
      deepStrictEqual(t.strobe.pos, 94);
      deepStrictEqual(t.strobe.posBegin, 76);
      deepStrictEqual(t.strobe.curFlags, 2);

      t.protoName('Schnorr-sig');
      deepStrictEqual(
        t.strobe.state,
        new Uint8Array([
          156, 127, 91, 234, 138, 145, 60, 180, 10, 209, 13, 13, 101, 100, 39, 7, 179, 97, 106, 47,
          48, 101, 40, 246, 115, 59, 228, 32, 162, 5, 210, 18, 186, 113, 15, 109, 9, 96, 157, 119,
          250, 62, 108, 48, 8, 238, 19, 148, 9, 109, 57, 137, 212, 94, 71, 96, 242, 184, 247, 217,
          180, 87, 197, 145, 143, 155, 98, 236, 151, 71, 200, 234, 200, 69, 229, 142, 107, 225, 150,
          20, 15, 164, 122, 7, 241, 158, 120, 245, 172, 93, 147, 2, 12, 99, 62, 97, 81, 187, 69, 20,
          86, 42, 109, 50, 36, 169, 176, 27, 146, 183, 239, 7, 45, 236, 192, 17, 161, 206, 12, 165,
          22, 6, 172, 69, 174, 4, 188, 52, 202, 190, 174, 190, 121, 217, 23, 80, 192, 232, 191, 19,
          185, 102, 80, 77, 19, 67, 89, 114, 101, 221, 136, 101, 173, 249, 20, 9, 204, 155, 32, 213,
          244, 116, 68, 4, 31, 151, 182, 153, 221, 251, 222, 233, 30, 168, 123, 208, 155, 248, 176,
          45, 167, 90, 150, 233, 71, 240, 127, 91, 101, 187, 78, 110, 254, 250, 161, 106, 191, 217,
          251, 246,
        ])
      );
      deepStrictEqual(t.strobe.pos, 123);
      deepStrictEqual(t.strobe.posBegin, 111);
      deepStrictEqual(t.strobe.curFlags, 2);

      const pub = ed25519.RistrettoPoint.fromHex(
        new Uint8Array([
          70, 235, 221, 239, 140, 217, 187, 22, 125, 195, 8, 120, 215, 17, 59, 126, 22, 142, 111, 6,
          70, 190, 255, 215, 125, 105, 211, 155, 173, 118, 180, 122,
        ])
      );
      t.commitPoint('sign:pk', pub);
      deepStrictEqual(
        t.strobe.state,
        new Uint8Array([
          37, 152, 52, 120, 213, 82, 103, 101, 12, 150, 166, 26, 55, 44, 235, 240, 181, 43, 182, 24,
          191, 120, 119, 176, 1, 116, 193, 35, 129, 221, 64, 172, 74, 200, 62, 233, 14, 21, 141, 51,
          216, 155, 236, 14, 109, 57, 67, 198, 36, 179, 51, 145, 206, 9, 130, 147, 15, 116, 184,
          126, 28, 72, 10, 205, 7, 182, 72, 208, 94, 246, 23, 241, 156, 164, 141, 197, 131, 188, 53,
          37, 45, 127, 9, 115, 103, 108, 234, 13, 28, 4, 240, 101, 250, 100, 38, 91, 114, 0, 104,
          194, 248, 254, 123, 230, 2, 51, 97, 50, 137, 166, 225, 142, 216, 117, 164, 134, 58, 196,
          192, 193, 116, 151, 74, 125, 228, 71, 101, 165, 176, 205, 79, 215, 70, 237, 196, 220, 110,
          109, 3, 26, 66, 157, 120, 197, 192, 178, 19, 207, 61, 245, 26, 63, 3, 109, 91, 155, 143,
          157, 194, 93, 231, 82, 248, 22, 224, 94, 215, 246, 33, 124, 128, 22, 132, 132, 10, 97,
          106, 255, 132, 72, 23, 110, 160, 195, 251, 99, 17, 202, 34, 155, 79, 52, 11, 0, 133, 201,
          66, 63, 246, 161,
        ])
      );
      deepStrictEqual(t.strobe.pos, 4);
      deepStrictEqual(t.strobe.posBegin, 0);
      deepStrictEqual(t.strobe.curFlags, 2);

      const nonce = new Uint8Array([
        253, 25, 12, 206, 116, 223, 53, 100, 50, 180, 16, 189, 100, 104, 35, 9, 214, 222, 219, 39,
        199, 104, 69, 218, 243, 136, 85, 124, 186, 195, 202, 52,
      ]);
      const r = t.witnessScalar('signing', [nonce]);
      deepStrictEqual(
        r,
        4917907422413454981120839959394883085636993534673566917378047043755653218809n
      );
      deepStrictEqual(
        t.strobe.state,
        new Uint8Array([
          37, 152, 52, 120, 213, 82, 103, 101, 12, 150, 166, 26, 55, 44, 235, 240, 181, 43, 182, 24,
          191, 120, 119, 176, 1, 116, 193, 35, 129, 221, 64, 172, 74, 200, 62, 233, 14, 21, 141, 51,
          216, 155, 236, 14, 109, 57, 67, 198, 36, 179, 51, 145, 206, 9, 130, 147, 15, 116, 184,
          126, 28, 72, 10, 205, 7, 182, 72, 208, 94, 246, 23, 241, 156, 164, 141, 197, 131, 188, 53,
          37, 45, 127, 9, 115, 103, 108, 234, 13, 28, 4, 240, 101, 250, 100, 38, 91, 114, 0, 104,
          194, 248, 254, 123, 230, 2, 51, 97, 50, 137, 166, 225, 142, 216, 117, 164, 134, 58, 196,
          192, 193, 116, 151, 74, 125, 228, 71, 101, 165, 176, 205, 79, 215, 70, 237, 196, 220, 110,
          109, 3, 26, 66, 157, 120, 197, 192, 178, 19, 207, 61, 245, 26, 63, 3, 109, 91, 155, 143,
          157, 194, 93, 231, 82, 248, 22, 224, 94, 215, 246, 33, 124, 128, 22, 132, 132, 10, 97,
          106, 255, 132, 72, 23, 110, 160, 195, 251, 99, 17, 202, 34, 155, 79, 52, 11, 0, 133, 201,
          66, 63, 246, 161,
        ])
      );
      deepStrictEqual(t.strobe.pos, 4);
      deepStrictEqual(t.strobe.posBegin, 0);
      deepStrictEqual(t.strobe.curFlags, 2);

      t.commitPoint('sign:R', ed25519.RistrettoPoint.BASE.multiply(r));
      deepStrictEqual(
        t.strobe.state,
        new Uint8Array([
          37, 152, 52, 120, 213, 64, 20, 12, 107, 248, 156, 72, 23, 44, 235, 240, 176, 41, 106, 80,
          142, 75, 228, 246, 221, 93, 140, 2, 92, 179, 186, 142, 138, 176, 136, 2, 104, 23, 46, 60,
          97, 93, 153, 78, 172, 194, 13, 230, 183, 221, 51, 145, 206, 9, 130, 147, 15, 116, 184,
          126, 28, 72, 10, 205, 7, 182, 72, 208, 94, 246, 23, 241, 156, 164, 141, 197, 131, 188, 53,
          37, 45, 127, 9, 115, 103, 108, 234, 13, 28, 4, 240, 101, 250, 100, 38, 91, 114, 0, 104,
          194, 248, 254, 123, 230, 2, 51, 97, 50, 137, 166, 225, 142, 216, 117, 164, 134, 58, 196,
          192, 193, 116, 151, 74, 125, 228, 71, 101, 165, 176, 205, 79, 215, 70, 237, 196, 220, 110,
          109, 3, 26, 66, 157, 120, 197, 192, 178, 19, 207, 61, 245, 26, 63, 3, 109, 91, 155, 143,
          157, 194, 93, 231, 82, 248, 22, 224, 94, 215, 246, 33, 124, 128, 22, 132, 132, 10, 97,
          106, 255, 132, 72, 23, 110, 160, 195, 251, 99, 17, 202, 34, 155, 79, 52, 11, 0, 133, 201,
          66, 63, 246, 161,
        ])
      );
      deepStrictEqual(t.strobe.pos, 50);
      deepStrictEqual(t.strobe.posBegin, 17);
      deepStrictEqual(t.strobe.curFlags, 2);

      const k = t.challengeScalar('sign:c');
      deepStrictEqual(
        k,
        5050163945839268349359244384829094214629736112004612159941092858045259002507n
      );
      deepStrictEqual(
        t.strobe.state,
        new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 94, 117, 37, 152, 41, 109, 61, 63, 55, 79, 101, 62, 169, 237, 239, 208, 30,
          69, 7, 10, 144, 76, 187, 0, 163, 180, 199, 173, 93, 20, 9, 99, 86, 163, 96, 149, 15, 70,
          115, 186, 110, 198, 136, 191, 192, 13, 71, 10, 145, 60, 57, 43, 114, 42, 241, 28, 62, 145,
          197, 37, 202, 184, 73, 161, 181, 34, 54, 59, 38, 141, 52, 237, 52, 178, 159, 183, 109,
          179, 97, 11, 64, 194, 90, 202, 253, 174, 66, 238, 184, 204, 70, 139, 213, 65, 245, 91,
          121, 205, 243, 216, 176, 195, 239, 118, 31, 69, 170, 221, 71, 12, 167, 91, 226, 122, 141,
          43, 144, 31, 159, 44, 230, 1, 253, 115, 223, 231, 64, 14, 212, 17, 7, 55, 90, 137, 116,
          155,
        ])
      );
      deepStrictEqual(t.strobe.pos, 64);
      deepStrictEqual(t.strobe.posBegin, 0);
      deepStrictEqual(t.strobe.curFlags, 7);
    });
  });
  should('secretFromSeed', () => {
    const seed = hexToBytes('fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e');
    const secretKey = sr25519.secretFromSeed(seed);
    deepStrictEqual(
      bytesToHex(sr25519.getPublicKey(secretKey)),
      '46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a'
    );
  });
  should('sign', () => {
    const input = hexToBytes('fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e');
    const secretKey = sr25519.secretFromSeed(input);
    const publicKey = sr25519.getPublicKey(secretKey);
    const signature = sr25519.sign(secretKey, utf8ToBytes('this is a message'), ZeroRNG);
    deepStrictEqual(sr25519.getPublicKey(secretKey), publicKey);
    deepStrictEqual(
      signature,
      hexToBytes(
        'dc4831339346dc294d21dd6efa22c078b6eb6602a30fb9c67540c1fb4e20936e17489f36dbe14aec6d2b1e56d979f7b420ca34143aca1691db0bab9535c49a86'
      )
    );
  });
  should('verify', () => {
    const message = utf8ToBytes(
      'I hereby verify that I control 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY'
    );
    const pub = hexToBytes('d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d');
    const signature = hexToBytes(
      '1037eb7e51613d0dcf5930ae518819c87d655056605764840d9280984e1b7063c4566b55bf292fcab07b369d01095879b50517beca4d26e6a65866e25fec0d83'
    );
    deepStrictEqual(sr25519.verify(message, signature, pub), true);
  });
  should('verify (immutable)', () => {
    const message = utf8ToBytes(
      'I hereby verify that I control 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY'
    );
    const pub = hexToBytes('d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d');
    const signature = hexToBytes(
      '1037eb7e51613d0dcf5930ae518819c87d655056605764840d9280984e1b7063c4566b55bf292fcab07b369d01095879b50517beca4d26e6a65866e25fec0d83'
    );
    const s1 = signature.slice();
    deepStrictEqual(sr25519.verify(message, s1, pub), true);
    deepStrictEqual(s1, signature);
  });
  should('verify (signed)', () => {
    const input = hexToBytes('fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e');
    const secretKey = sr25519.secretFromSeed(input);
    const publicKey = sr25519.getPublicKey(secretKey);
    deepStrictEqual(sr25519.getPublicKey(secretKey), publicKey);
    const message = utf8ToBytes('this is a message');
    const signature = sr25519.sign(secretKey, message, ZeroRNG);
    deepStrictEqual(sr25519.verify(message, signature, publicKey), true);
    const signature2 = sr25519.sign(secretKey, message);
    deepStrictEqual(sr25519.verify(message, signature2, publicKey), true);
  });
  should('verify (wrapped)', () => {
    const message = utf8ToBytes('<Bytes>message to sign</Bytes>');
    const pub = hexToBytes('f84d048da2ddae2d9d8fd6763f469566e8817a26114f39408de15547f6d47805');
    const signature = hexToBytes(
      '48ce2c90e08651adfc8ecef84e916f6d1bb51ebebd16150ee12df247841a5437951ea0f9d632ca165e6ab391532e75e701be6a1caa88c8a6bcca3511f55b4183'
    );
    deepStrictEqual(sr25519.verify(message, signature, pub), true);
  });
  should('verify (wrapped, fail)', () => {
    const message = utf8ToBytes('message to sign');
    const pub = hexToBytes('f84d048da2ddae2d9d8fd6763f469566e8817a26114f39408de15547f6d47805');
    const signature = hexToBytes(
      '48ce2c90e08651adfc8ecef84e916f6d1bb51ebebd16150ee12df247841a5437951ea0f9d632ca165e6ab391532e75e701be6a1caa88c8a6bcca3511f55b4183'
    );
    deepStrictEqual(sr25519.verify(message, signature, pub), false);
  });
  should('getSharedSecret', () => {
    const selfSeed = hexToBytes('98b3d305d5a5eace562387e47e59badd4d77e3f72cabfb10a60f8a197059f0a8');
    const otherSeed = hexToBytes(
      '9732eea001851ff862d949a1699c9971f3a26edbede2ad7922cbbe9a0701f366'
    );
    // Self
    const skSelf = sr25519.secretFromSeed(selfSeed);
    const pubSelf = sr25519.getPublicKey(skSelf);
    // Other
    const skOther = sr25519.secretFromSeed(otherSeed);
    const pubOther = sr25519.getPublicKey(skOther);

    const exp = hexToBytes('b03a0b198c34c16f35cae933d88b16341b4cef3e84e851f20e664c6a30527f4e');
    deepStrictEqual(sr25519.getSharedSecret(skOther, pubSelf), exp);
    deepStrictEqual(sr25519.getSharedSecret(skSelf, pubOther), exp);
  });
  should('fromKeypair', () => {
    const input = hexToBytes(
      '28b0ae221c6bb06856b287f60d7ea0d98552ea5a16db16956849aa371db3eb51fd190cce74df356432b410bd64682309d6dedb27c76845daf388557cbac3ca3446ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a'
    );
    const keypair = sr25519.fromKeypair(input);
    const pub = keypair.subarray(64, 96);
    deepStrictEqual(
      bytesToHex(pub),
      '46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a'
    );
    deepStrictEqual(
      bytesToHex(keypair),
      '40817515e1588345b3923db46ff003cd2e9452d7b2d8b6a8444b52bde9985d8ffd190cce74df356432b410bd64682309d6dedb27c76845daf388557cbac3ca3446ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a'
    );
  });
  describe('HDKD', () => {
    should('secretSoft', () => {
      const cc = hexToBytes('0c666f6f00000000000000000000000000000000000000000000000000000000'); // foo
      const seed = hexToBytes('fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e');
      const masterSecret = sr25519.secretFromSeed(seed);
      const secretKey = sr25519.HDKD.secretSoft(masterSecret, cc, ZeroRNG);
      const publicKey = sr25519.getPublicKey(secretKey);
      deepStrictEqual(
        bytesToHex(publicKey),
        '40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a'
      );
      deepStrictEqual(
        concatBytes(secretKey, publicKey),
        new Uint8Array([
          136, 26, 5, 162, 154, 100, 197, 230, 89, 130, 165, 134, 88, 249, 175, 20, 166, 189, 175,
          249, 120, 14, 125, 142, 210, 0, 116, 203, 76, 230, 198, 115, 182, 183, 12, 145, 47, 231,
          78, 13, 253, 187, 92, 176, 251, 179, 169, 207, 47, 28, 50, 150, 32, 153, 132, 121, 43, 50,
          14, 150, 207, 186, 184, 136, 64, 185, 103, 93, 249, 14, 250, 96, 105, 255, 98, 59, 15,
          223, 207, 112, 108, 212, 124, 167, 69, 42, 80, 86, 199, 173, 88, 25, 77, 35, 68, 10,
        ])
      );
    });
    should('publicSoft', () => {
      const cc = hexToBytes('0c666f6f00000000000000000000000000000000000000000000000000000000'); // foo
      const pub = hexToBytes('46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a');
      const derived = sr25519.HDKD.publicSoft(pub, cc);
      deepStrictEqual(
        bytesToHex(derived),
        '40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a'
      );
    });
    should('secretHard', () => {
      const cc = hexToBytes('14416c6963650000000000000000000000000000000000000000000000000000'); // Alice
      const seed = hexToBytes('fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e');
      const masterSecret = sr25519.secretFromSeed(seed);
      const secretKey = sr25519.HDKD.secretHard(masterSecret, cc);
      const publicKey = sr25519.getPublicKey(secretKey);
      deepStrictEqual(
        bytesToHex(publicKey),
        'd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d'
      );
      deepStrictEqual(
        bytesToHex(secretKey),
        '98319d4ff8a9508c4bb0cf0b5a78d760a0b2082c02775e6e82370816fedfff48925a225d97aa00682d6a59b95b18780c10d7032336e88f3442b42361f4a66011'
      );
    });
  });
  describe('VRF', () => {
    const priv = new Uint8Array([
      56, 82, 192, 174, 222, 220, 23, 124, 77, 128, 98, 178, 107, 63, 170, 140, 253, 180, 214, 66,
      28, 171, 162, 3, 246, 101, 111, 245, 190, 174, 100, 75, 225, 158, 138, 253, 107, 227, 106, 78,
      186, 224, 98, 141, 44, 17, 58, 11, 150, 30, 119, 239, 81, 52, 44, 178, 4, 60, 16, 194, 78,
      186, 124, 72,
    ]);
    const ctx = utf8ToBytes('my VRF context');
    const msg = utf8ToBytes('this is a message');
    const extra = utf8ToBytes('extra param');
    should('basic', () => {
      const sig = sr25519.vrf.sign(msg, priv, ctx, extra, ZeroRNG);
      deepStrictEqual(
        bytesToHex(sig.subarray(0, 32)),
        'a0eb55b1e206d16625d36987f6a9d16fce4190e427d017dbfad583ab7838e54b'
      );
      deepStrictEqual(
        sig,
        new Uint8Array([
          160, 235, 85, 177, 226, 6, 209, 102, 37, 211, 105, 135, 246, 169, 209, 111, 206, 65, 144,
          228, 39, 208, 23, 219, 250, 213, 131, 171, 120, 56, 229, 75, 240, 116, 8, 28, 64, 110,
          197, 49, 122, 75, 136, 12, 9, 60, 81, 232, 37, 83, 223, 202, 202, 114, 154, 145, 197, 177,
          24, 100, 163, 238, 107, 4, 116, 30, 210, 66, 190, 16, 201, 154, 250, 254, 80, 27, 211,
          208, 124, 186, 160, 36, 45, 84, 189, 248, 0, 156, 89, 81, 29, 89, 253, 232, 52, 6,
        ])
      );
      const pub = sr25519.getPublicKey(priv);
      deepStrictEqual(sr25519.vrf.verify(msg, sig, pub, ctx, extra), true);
    });
    should('verify random', () => {
      const msg2 = utf8ToBytes('this is a message1');
      const out1 = sr25519.vrf.sign(msg, priv, ctx, extra);
      const out2 = sr25519.vrf.sign(msg, priv, ctx, extra);
      const out3 = sr25519.vrf.sign(msg2, priv, ctx, extra);
      deepStrictEqual(out1.length, 96);
      deepStrictEqual(out2.length, 96);
      deepStrictEqual(out3.length, 96);
      deepStrictEqual(out1.subarray(0, 32), out2.subarray(0, 32));
      notDeepStrictEqual(out1, out2);
      notDeepStrictEqual(out1.subarray(0, 32), out3.subarray(0, 32));
      const pub = sr25519.getPublicKey(priv);
      deepStrictEqual(sr25519.vrf.verify(msg, out1, pub, ctx, extra), true);
      deepStrictEqual(sr25519.vrf.verify(msg, out2, pub, ctx, extra), true);
      deepStrictEqual(sr25519.vrf.verify(msg, out3, pub, ctx, extra), false);
      deepStrictEqual(sr25519.vrf.verify(msg2, out3, pub, ctx, extra), true);
    });
    should('no extra', () => {
      const out = sr25519.vrf.sign(msg, priv, ctx, new Uint8Array());
      const pub = sr25519.getPublicKey(priv);
      deepStrictEqual(sr25519.vrf.verify(msg, out, pub, ctx, new Uint8Array()), true);
      deepStrictEqual(sr25519.vrf.verify(msg, out, pub, ctx, extra), false);
    });
    should('errors', () => {
      const out = sr25519.vrf.sign(msg, priv, ctx, extra);
      const pub = sr25519.getPublicKey(priv);
      deepStrictEqual(sr25519.vrf.verify(msg, out, pub, ctx, extra), true);

      throws(() => sr25519.vrf.verify(pub, ctx, msg, extra, new Uint8Array(32)));
      throws(() => sr25519.vrf.verify(new Uint8Array(10), ctx, msg, extra, out));
      const out2 = out.slice();
      deepStrictEqual(sr25519.vrf.verify(msg, out2, pub, ctx, extra), true);
      out2.subarray(0, 32).fill(0);
      throws(() => sr25519.vrf.verify(msg, out2, pub, ctx, extra));

      out2.set(out);
      deepStrictEqual(sr25519.vrf.verify(msg, out2, pub, ctx, extra), true);
      out2.subarray(0, 32).fill(0xff);
      throws(() => sr25519.vrf.verify(msg, out2, pub, ctx, extra));

      out2.set(out);
      deepStrictEqual(sr25519.vrf.verify(msg, out2, pub, ctx, extra), true);
      out2.subarray(32, 64).fill(0);
      // Our point multiplication doesn't support '0' and throws error, so error here
      // It is false in original implementation
      throws(() => sr25519.vrf.verify(msg, out2, pub, ctx, extra));

      out2.set(out);
      deepStrictEqual(sr25519.vrf.verify(msg, out2, pub, ctx, extra), true);
      out2.subarray(64).fill(0);
      throws(() => sr25519.vrf.verify(msg, out2, pub, ctx, extra));

      out2.set(out);
      deepStrictEqual(sr25519.vrf.verify(msg, out2, pub, ctx, extra), true);
      out2.subarray(64).fill(0xff);
      throws(() => sr25519.vrf.verify(msg, out2, pub, ctx, extra));

      out2.set(out);
      deepStrictEqual(sr25519.vrf.verify(msg, out2, pub, ctx, extra), true);
      out2.subarray(32, 64).fill(0xff);
      throws(() => sr25519.vrf.verify(msg, out2, pub, ctx, extra));
      // 0
      // - i: VER: Err(PointDecompressionError)
      // - i+32: Err(EquationFalse)
      // - i+64: Err(EquationFalse)
      // ff
      // - i: PointDecompressionError
      // - i+32: (panic): called `Result::unwrap()` on an `Err` value: ScalarFormatError
      // - i+64: (panic): called `Result::unwrap()` on an `Err` value: ScalarFormatError
    });
  });
});

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
