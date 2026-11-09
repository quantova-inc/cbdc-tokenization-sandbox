/**
 * Known-answer and negative-reject vectors for the sealed-bid crypto path.
 *
 * The round-trip suites in encryption.test.ts and bidder-bid.test.ts use
 * freshly generated keys, so they prove the code agrees with itself but pin
 * nothing a second implementation could reproduce. These vectors fix the
 * private keys, domain, and plaintext so the EIP-712 BidIntent digest and
 * signature, the canonical plaintext hash, and a captured dual-seal blob all
 * become reproducible constants. An independent implementation of the flow in
 * scripts/bid-encryption/ can check interop against these values, and any drift
 * in the domain, typed-data layout, hashing, wire format, or key-derivation
 * breaks the suite loudly.
 *
 * The negative vectors pin the rejection behaviour of the format parser and
 * the AES-256-GCM and ECDH-wrap authentication so tampering, truncation, and
 * malformed keys stay rejected.
 *
 * All keys here are throwaway test scalars and never leave this file.
 */
import { TypedDataEncoder, Wallet, getAddress, verifyTypedData } from 'ethers';

import {
  type BidPlaintext,
  decryptBid,
  encryptBid,
  hashBidPlaintext,
  parseCiphertext,
} from '../src/encryption';

const BIDDER_PRIVATE_KEY = '0x0000000000000000000000000000000000000000000000000000000000000001';
const AUCTIONEER_PRIVATE_KEY = '0x0000000000000000000000000000000000000000000000000000000000000002';
const BIDDER_ADDRESS = '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf';

const CHAIN_ID = 2018n;
const VERIFYING_CONTRACT = getAddress('0xcd15b8265e41c5a7ae4bd97eaac932e22ededb9b');
const AUCTION_ID = '0x1111111111111111111111111111111111111111111111111111111111111111';

const DOMAIN = {
  name: 'BondAuctionBid',
  version: '1',
  chainId: CHAIN_ID,
  verifyingContract: VERIFYING_CONTRACT,
};

const TYPES = {
  BidIntent: [
    { name: 'bidder', type: 'address' },
    { name: 'auctionId', type: 'bytes32' },
    { name: 'plaintextHash', type: 'bytes32' },
    { name: 'bidderNonce', type: 'uint256' },
  ],
};

const EXPECTED_PLAINTEXT_HASH =
  '0xaa78a571a20be4121965a13152cd3500b1ec4d3ddbd3d2a2a2f091330cc11332';
const EXPECTED_DIGEST = '0x633ade4147b77a15d95b2304f7dc415b50a9654574492c9c55b9330eb09deab1';
const EXPECTED_SIGNATURE =
  '0x6b7814f930c2e0ed6adad5c57d7f72b1f8e1aea4ba9310d2bc54f886a7aafd475557afb71054b60e4ef6923f4516bc1bd7c5cca5f679c3919a138db5356ceea11b';

const BID_NONCE = '7';

// Plaintext before signing: bidderSig is the placeholder the hash is taken
// over, matching the staging step in scripts/bid-encryption/ and bidder-bid.ts.
const UNSIGNED_PLAINTEXT: BidPlaintext = {
  isin: 'NO0012345678',
  bidder: BIDDER_ADDRESS,
  nonce: '0xaaaaaaaaaaaaaaaaaaaaaaaa',
  rate: '425',
  units: '100',
  salt: '0xbbbbbbbbbbbbbbbb',
  bidderNonce: BID_NONCE,
  bidderSig: '0x',
};

// Same plaintext carrying the real EIP-712 signature; this is what the dual
// seal below encrypts and what decryption must return byte for byte.
const SEALED_PLAINTEXT: BidPlaintext = { ...UNSIGNED_PLAINTEXT, bidderSig: EXPECTED_SIGNATURE };

const INTENT_VALUE = {
  bidder: BIDDER_ADDRESS,
  auctionId: AUCTION_ID,
  plaintextHash: EXPECTED_PLAINTEXT_HASH,
  bidderNonce: BigInt(BID_NONCE),
};

// A dual-seal blob captured once from encryptBid with the two fixed keys
// above (bidder wrap from scalar 1, auctioneer wrap from scalar 2). encryptBid
// is randomised, so this value is a fixture; decryption of it is deterministic.
const CAPTURED_CIPHERTEXT =
  '0x01005d02124e759d8fd8b6d2a9a1ce01a506d495e68a40c0ccf61d5f5dffa476650cd9c74ed6bacebe8ab9e297a04992fe9cbfb0a9b5128831fff7112c57e84b88c18541ef17d16fdb5e851ae2a613fdc7c7e44957ca7b661b55eb424aacbbe1005d023d547f57cff1c3524f121cc3bad95cfc560ef261d199276466b78b511c952d34c41871916624d7f9e1f396332e731513a8e8b413f1571d17ac739bc0c44c5c527cd281867820fb8917aadf8c6ac00838c783372a850c1b4a9a01ac7456d6ed5c9b9121a216d488e5f65d0cf8a3e1702c219ec26f9c7be7e3bf47b9047e8a000e30fd98defeb7ce82ce87423d15a056c5459716c0dcf1ea8b469ad1328eb90f01d6f0b919cb9139a4f2a09a31049fceaf39132844caa0fc356a4c756005da47ec89af4644608909f298208b3bc3c24e2dad21ee34f77b36f0ba9e07bca092ea9b8686eadbf86ebe28bb6f016ba1b5a9b590b5a1e8963b873e5663d94ca36aef0dc2209f98aa764d89b24d79de02bae6e95f7a0297be0c0af01ff932886ea8990ab68f063af78f28276d5690c45bf5425c87715185bf8f235d189e1f694b3f640f26def56aa81aa5591f8cea70726bdaccf47f5c00888db0f59afc5489c7173e33e78925ab05a21459a02327fe3c1d96ee989df584287939f05e6d2619c0be047d7de868dfeed9d9bf9248c561c79ac4c7a86b33b153a83c7d70f1637bff7de7246fc2830c90b607602e974eb8a7a21fc9f648daa84049334d6e38f4208ca170f507ede9c1d26a';
const CAPTURED_CIPHERTEXT_HASH =
  '0xfb6b37533c7b7c533820d85885a0b9e19663b5bfc62042e4f6097f05e4e51d22';

// Byte offsets inside the captured blob: version(1) wrapLen(2) wrap(93)
// wrapLen(2) wrap(93) symNonce(12) symTag(16) symCiphertext(rest).
const WRAP_LEN = 93;
const AUCTIONEER_WRAP_LEN_OFFSET = 1;
const BIDDER_WRAP_LEN_OFFSET = 1 + 2 + WRAP_LEN;
const SYM_TAG_OFFSET = 1 + 2 + WRAP_LEN + 2 + WRAP_LEN + 12;

function ciphertextBytes(): Buffer {
  return Buffer.from(CAPTURED_CIPHERTEXT.slice(2), 'hex');
}

function toHex(buffer: Buffer): string {
  return `0x${buffer.toString('hex')}`;
}

describe('BidIntent EIP-712 known-answer vectors', () => {
  it('pins the canonical plaintext hash (bidderSig excluded)', () => {
    expect(hashBidPlaintext(UNSIGNED_PLAINTEXT)).toBe(EXPECTED_PLAINTEXT_HASH);
    expect(hashBidPlaintext(SEALED_PLAINTEXT)).toBe(EXPECTED_PLAINTEXT_HASH);
  });

  it('pins the typed-data digest for the BondAuctionBid domain', () => {
    expect(TypedDataEncoder.hash(DOMAIN, TYPES, INTENT_VALUE)).toBe(EXPECTED_DIGEST);
  });

  it('pins the deterministic signature produced by the fixed bidder key', async () => {
    const signature = await new Wallet(BIDDER_PRIVATE_KEY).signTypedData(
      DOMAIN,
      TYPES,
      INTENT_VALUE,
    );
    expect(signature).toBe(EXPECTED_SIGNATURE);
  });

  it('recovers the bidder address from the signature', () => {
    expect(getAddress(verifyTypedData(DOMAIN, TYPES, INTENT_VALUE, EXPECTED_SIGNATURE))).toBe(
      BIDDER_ADDRESS,
    );
  });

  it('does not recover the bidder when the chainId differs', () => {
    const recovered = verifyTypedData(
      { ...DOMAIN, chainId: CHAIN_ID + 1n },
      TYPES,
      INTENT_VALUE,
      EXPECTED_SIGNATURE,
    );
    expect(getAddress(recovered)).not.toBe(BIDDER_ADDRESS);
  });

  it('does not recover the bidder when the verifyingContract differs', () => {
    const recovered = verifyTypedData(
      { ...DOMAIN, verifyingContract: getAddress('0x0000000000000000000000000000000000000001') },
      TYPES,
      INTENT_VALUE,
      EXPECTED_SIGNATURE,
    );
    expect(getAddress(recovered)).not.toBe(BIDDER_ADDRESS);
  });

  it('does not recover the bidder when the auctionId differs', () => {
    const recovered = verifyTypedData(
      DOMAIN,
      TYPES,
      { ...INTENT_VALUE, auctionId: `0x${'22'.repeat(32)}` },
      EXPECTED_SIGNATURE,
    );
    expect(getAddress(recovered)).not.toBe(BIDDER_ADDRESS);
  });

  it('does not recover the bidder when the plaintextHash differs', () => {
    const recovered = verifyTypedData(
      DOMAIN,
      TYPES,
      { ...INTENT_VALUE, plaintextHash: `0x${'33'.repeat(32)}` },
      EXPECTED_SIGNATURE,
    );
    expect(getAddress(recovered)).not.toBe(BIDDER_ADDRESS);
  });

  it('does not recover the bidder when the bidderNonce differs', () => {
    const recovered = verifyTypedData(
      DOMAIN,
      TYPES,
      { ...INTENT_VALUE, bidderNonce: INTENT_VALUE.bidderNonce + 1n },
      EXPECTED_SIGNATURE,
    );
    expect(getAddress(recovered)).not.toBe(BIDDER_ADDRESS);
  });

  it('changes the plaintext hash when an economic field changes', () => {
    expect(hashBidPlaintext({ ...UNSIGNED_PLAINTEXT, rate: '426' })).not.toBe(
      EXPECTED_PLAINTEXT_HASH,
    );
    expect(hashBidPlaintext({ ...UNSIGNED_PLAINTEXT, units: '101' })).not.toBe(
      EXPECTED_PLAINTEXT_HASH,
    );
  });
});

describe('dual-seal decryption known-answer vectors', () => {
  it('decrypts the captured blob with the auctioneer key', () => {
    const decrypted = decryptBid(CAPTURED_CIPHERTEXT, AUCTIONEER_PRIVATE_KEY, 'auctioneer');
    expect(decrypted.usedWrap).toBe('auctioneer');
    expect(decrypted.plaintext).toEqual(SEALED_PLAINTEXT);
    expect(decrypted.plaintextHash).toBe(EXPECTED_PLAINTEXT_HASH);
    expect(decrypted.ciphertextHash).toBe(CAPTURED_CIPHERTEXT_HASH);
  });

  it('decrypts the captured blob with the bidder key (dual-wrap symmetry)', () => {
    const decrypted = decryptBid(CAPTURED_CIPHERTEXT, BIDDER_PRIVATE_KEY, 'bidder');
    expect(decrypted.usedWrap).toBe('bidder');
    expect(decrypted.plaintext).toEqual(SEALED_PLAINTEXT);
    expect(decrypted.plaintextHash).toBe(EXPECTED_PLAINTEXT_HASH);
  });

  it('recovers the embedded signature so it verifies against the recovered hash', () => {
    const decrypted = decryptBid(CAPTURED_CIPHERTEXT, AUCTIONEER_PRIVATE_KEY, 'auctioneer');
    const recovered = verifyTypedData(
      DOMAIN,
      TYPES,
      { ...INTENT_VALUE, plaintextHash: decrypted.plaintextHash },
      decrypted.plaintext.bidderSig,
    );
    expect(getAddress(recovered)).toBe(BIDDER_ADDRESS);
  });
});

describe('dual-seal negative-reject vectors', () => {
  it('rejects decryption with an unrelated key', () => {
    expect(() =>
      decryptBid(
        CAPTURED_CIPHERTEXT,
        '0x0000000000000000000000000000000000000000000000000000000000000009',
      ),
    ).toThrow('private key could not decrypt any wrapped symmetric key');
  });

  it('rejects a flipped symmetric ciphertext byte (GCM authentication)', () => {
    const tampered = ciphertextBytes();
    tampered[tampered.length - 1] ^= 0xff;
    expect(() => decryptBid(toHex(tampered), AUCTIONEER_PRIVATE_KEY)).toThrow();
  });

  it('rejects a flipped symmetric auth tag byte (GCM authentication)', () => {
    const tampered = ciphertextBytes();
    tampered[SYM_TAG_OFFSET] ^= 0xff;
    expect(() => decryptBid(toHex(tampered), AUCTIONEER_PRIVATE_KEY)).toThrow();
  });

  it('rejects a corrupted auctioneer wrap length', () => {
    const tampered = ciphertextBytes();
    tampered.writeUInt16BE(0xffff, AUCTIONEER_WRAP_LEN_OFFSET);
    expect(() => parseCiphertext(toHex(tampered))).toThrow('invalid auctioneer wrap length');
  });

  it('rejects a corrupted bidder wrap length', () => {
    const tampered = ciphertextBytes();
    tampered.writeUInt16BE(0xffff, BIDDER_WRAP_LEN_OFFSET);
    expect(() => parseCiphertext(toHex(tampered))).toThrow('invalid bidder wrap length');
  });

  it('rejects a blob truncated before the symmetric segment', () => {
    const truncated = ciphertextBytes().subarray(0, BIDDER_WRAP_LEN_OFFSET + 2 + WRAP_LEN + 5);
    expect(() => parseCiphertext(toHex(truncated))).toThrow('ciphertext missing symmetric segment');
  });

  it('rejects a blob shorter than the header', () => {
    expect(() => parseCiphertext('0x0100')).toThrow('ciphertext too short');
  });

  it('rejects an encrypt recipient key with a bad compressed prefix', () => {
    expect(() =>
      encryptBid({
        plaintext: UNSIGNED_PLAINTEXT,
        auctioneerPubKey: `0x04${'ab'.repeat(32)}`,
        bidderPubKey: `0x02${'ab'.repeat(32)}`,
      }),
    ).toThrow('compressed public key must start with 02 or 03');
  });

  it('rejects an encrypt recipient key of the wrong length', () => {
    expect(() =>
      encryptBid({
        plaintext: UNSIGNED_PLAINTEXT,
        auctioneerPubKey: '0x02ab',
        bidderPubKey: `0x02${'ab'.repeat(32)}`,
      }),
    ).toThrow('compressed public key must be 33 bytes hex');
  });
});
