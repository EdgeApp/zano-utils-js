import { randomBytes } from 'crypto';

import { mnemonicToSeed, seedToMnemonic } from '../src/mnemonic';
import { phrases } from '../src/mnemonic/consts/phrases';

const NUMWORDS = 1626;
const CHECKSUM_MAX = NUMWORDS >> 1;

describe('checksum word encoding', () => {
  // The checksum is salted with the creation-timestamp word, which advances
  // once a week, so these vectors only reproduce with the clock frozen.
  const FIXED_TIME = Date.UTC(2025, 0, 1);

  beforeEach(() => {
    jest.spyOn(Date, 'now').mockReturnValue(FIXED_TIME);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  // Each of these seeds drives the checksum onto CHECKSUM_MAX (813). Before
  // the clamp, `(813 << 1) | 0` asked for index 1626 of a 1626-word
  // dictionary, and the resulting `undefined` became an empty checksum word:
  // a 25-word phrase with a trailing space, produced silently.
  const boundarySeeds = [
    '0000000000000000000000000000000000000000000000000000000000000af1',
    '0000000000000000000000000000000000000000000000000000000000000afa',
    '0000000000000000000000000000000000000000000000000000000000001561',
  ];

  it.each(boundarySeeds)('produces a complete 26-word phrase for seed %s', (seedHex: string) => {
    const mnemonic = seedToMnemonic(seedHex);
    const words = mnemonic.split(/\s+/);

    expect(mnemonic).toBe(mnemonic.trim());
    expect(words).toHaveLength(26);
    expect(words.every(word => word.length > 0)).toBe(true);
  });

  it('clamps a checksum of CHECKSUM_MAX to the first dictionary word', () => {
    // Zano core maps CHECKSUM_MAX back to 0, so the checksum word is
    // `(0 << 1) | 0` -- the first entry in the dictionary.
    const words = seedToMnemonic(boundarySeeds[0]).split(/\s+/);
    expect(words[25]).toBe(phrases[0].phrase);
  });

  it('leaves the derived spend key unchanged at the boundary', () => {
    // The clamp rewrites only the checksum word. The 24 seed words, and so the
    // secret spend key, must be identical to what the unclamped code produced.
    expect(mnemonicToSeed(seedToMnemonic(boundarySeeds[0])))
      .toBe('7895962a31b0a5348645dcacc65e55fd45d1cb1b1a4017d6718d6eb5e950b106');
  });

  it('never addresses a word outside the dictionary', () => {
    // (CHECKSUM_MAX - 1) is the largest checksum the clamp can emit.
    expect(((CHECKSUM_MAX - 1) << 1) | 1).toBeLessThan(phrases.length);
  });
});

describe('mnemonic generation is always well-formed', () => {
  it('produces 26 non-empty words for random seeds', () => {
    const malformed: string[] = [];

    // Roughly 1 seed in 814 lands on the boundary, so this sample covers it.
    for (let i = 0; i < 10000; i++) {
      const seedHex = randomBytes(32).toString('hex');
      const mnemonic = seedToMnemonic(seedHex);
      const words = mnemonic.split(/\s+/);

      if (mnemonic !== mnemonic.trim() || words.length !== 26 || words.some(w => w === '')) {
        malformed.push(`${seedHex} -> ${JSON.stringify(mnemonic)}`);
      }
    }

    expect(malformed).toStrictEqual([]);
  });
});
