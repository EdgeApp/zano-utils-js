import {
  getAccountBySecretSpendKey,
  isSeedPhrasePasswordProtected,
  mnemonicToSeed,
  verifySeedPhrase,
} from '../src';
import { getTimestampFromWord } from '../src/mnemonic/seed-to-mnemonic';

/**
 * Known-answer vectors taken verbatim from the reference implementation's own
 * unit test, `tests/unit_tests/wallet_seed_test.cpp` in hyle-team/zano. Every
 * other test in this suite checks that we agree with ourselves, which any
 * self-consistent but wrong implementation would also pass. These are the only
 * assertions that pin us to Zano core.
 *
 * If one of these fails, this library derives different keys from the same
 * words than the reference wallet does, and any wallet created from an
 * affected phrase would be unrecoverable there.
 */

interface Vector {
  /** True when the phrase's address is auditable. */
  auditable: boolean;
  name: string;
  seedPhrase: string;
  spendSecretKey: string;
  /** Unix seconds the phrase encodes, or 0 when core does not assert one. */
  timestamp: number;
  viewSecretKey: string;
}

const repeat = (word: string, count: number): string =>
  new Array(count).fill(word).join(' ');

const validVectors: Vector[] = [
  {
    name: 'old-style 25-word seed phrase',
    seedPhrase: `${repeat('dew', 24)} god`,
    spendSecretKey:
      '5e051454d7226b5734ebd64f754b57db4c655ecda00bd324f1b241d0b6381c0f',
    viewSecretKey:
      '7dde5590fdf430568c00556ac2accf09da6cde9a29a4bc7d1cb6fd267130f006',
    timestamp: 0,
    auditable: false,
  },
  {
    name: 'old-style 25-word seed phrase, one repeated word',
    seedPhrase: repeat('conversation', 25),
    spendSecretKey:
      '71162f207499bc16260957c36a6586bb931d54be33ff56b94d565dfedbb3c70e',
    viewSecretKey:
      '8454372096986c457f4e7dceef2f39b6050c35d87b31d9c9eb8d37bf8f1f430f',
    timestamp: 0,
    auditable: false,
  },
  {
    name: 'new-style 26-word seed phrase',
    seedPhrase: `${repeat('six', 25)} frown`,
    spendSecretKey:
      'F54F61E3B974AD86171AE4944205C7BD0395BD7845899CDA8B1FBC5C947BB402',
    viewSecretKey:
      'A18715058BBD914959C3A735B2022E9AE1D04452BC1FAD9E63C53668B7F57907',
    timestamp: 1922832000,
    auditable: false,
  },
  {
    // Differs from the entry above only in the checksum word's low bit, which
    // carries the auditable flag rather than any key material.
    name: 'new-style 26-word seed phrase, auditable',
    seedPhrase: `${repeat('six', 25)} grace`,
    spendSecretKey:
      'F54F61E3B974AD86171AE4944205C7BD0395BD7845899CDA8B1FBC5C947BB402',
    viewSecretKey:
      'A18715058BBD914959C3A735B2022E9AE1D04452BC1FAD9E63C53668B7F57907',
    timestamp: 1922832000,
    auditable: true,
  },
];

describe('known-answer vectors from Zano core', () => {
  for (const vector of validVectors) {
    describe(`${vector.name}`, () => {
      it('derives the spend secret key core derives', () => {
        expect(mnemonicToSeed(vector.seedPhrase).toLowerCase()).toBe(
          vector.spendSecretKey.toLowerCase(),
        );
      });

      it('derives the view secret key core derives', () => {
        const account = getAccountBySecretSpendKey(
          mnemonicToSeed(vector.seedPhrase),
        );
        expect(account.secretViewKey.toLowerCase()).toBe(
          vector.viewSecretKey.toLowerCase(),
        );
      });

      it('verifies', () => {
        expect(verifySeedPhrase(vector.seedPhrase)).toBe(true);
        expect(isSeedPhrasePasswordProtected(vector.seedPhrase)).toBe(false);
      });
    });
  }

  // Core only asserts a creation timestamp for its 26-word entries; the
  // 25-word ones predate the field and it lists them as 0.
  for (const vector of validVectors.filter(entry => entry.timestamp !== 0)) {
    describe(`${vector.name}`, () => {
      it('encodes the creation timestamp core reads from it', () => {
        const timestampWord = vector.seedPhrase.split(' ')[24];
        expect(getTimestampFromWord(timestampWord, false)).toBe(
          vector.timestamp,
        );
      });
    });
  }

  // Core lists these alongside the valid ones, all expecting `valid = false`.
  // We reject each of them, though a malformed word count or an out-of-
  // dictionary word throws where a bad checksum returns false.
  describe('phrases core rejects', () => {
    it('rejects a 24-word phrase', () => {
      expect(() => verifySeedPhrase(repeat('dew', 24))).toThrow(
        'Invalid seed phrase word count',
      );
    });

    it('rejects a word outside the dictionary', () => {
      expect(() => verifySeedPhrase(`${repeat('dew', 24)} dew!`)).toThrow(
        'dew!',
      );
      expect(() => verifySeedPhrase(`${repeat('six', 25)} sex`)).toThrow('sex');
    });

    it('rejects a 26-word phrase whose checksum does not match', () => {
      // The valid form of this phrase ends in `frown`; `six` is a wrong
      // checksum word made of dictionary words throughout, which is the
      // realistic transcription error.
      expect(verifySeedPhrase(repeat('six', 26))).toBe(false);
    });
  });

  // From `TEST(wallet_seed, word_from_timestamp)`, which asserts the encoding
  // direction; these check that we decode the same words back.
  describe('timestamp words', () => {
    it('maps the epoch word to the brain-date offset', () => {
      // Core: get_word_from_timestamp(0, false) and
      // get_word_from_timestamp(1543622400, false) are both "like".
      expect(getTimestampFromWord('like', false)).toBe(1543622400);
    });

    it('treats the password-flagged epoch word as protected', () => {
      // Core: get_word_from_timestamp(0, true) is "among".
      expect(isSeedPhrasePasswordProtected(`${repeat('dew', 24)} among`)).toBe(
        true,
      );
      expect(isSeedPhrasePasswordProtected(`${repeat('dew', 24)} like`)).toBe(
        false,
      );
    });
  });
});
