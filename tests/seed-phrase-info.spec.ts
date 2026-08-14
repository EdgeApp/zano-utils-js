import { randomBytes } from 'crypto';

import {
  isSeedPhrasePasswordProtected,
  seedToMnemonic,
  verifySeedPhrase,
} from '../src/mnemonic';
import { isPasswordProtectedTimestampWord } from '../src/mnemonic/seed-to-mnemonic';
import { phrases } from '../src/mnemonic/consts/phrases';
import { WALLET_BRAIN_DATE_MAX_WEEKS_COUNT } from '../src/mnemonic/seed-to-mnemonic';

const FIXED_TIME = Date.UTC(2025, 0, 1);
const SEED_HEX = 'a'.repeat(64);

/** Replaces the timestamp word (index 24) of a phrase. */
function withTimestampWord(mnemonic: string, word: string): string {
  const words = mnemonic.split(/\s+/);
  words[24] = word;
  return words.join(' ');
}

describe('verifySeedPhrase', () => {
  let mnemonic: string;

  beforeEach(() => {
    jest.spyOn(Date, 'now').mockReturnValue(FIXED_TIME);
    mnemonic = seedToMnemonic(SEED_HEX);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('accepts a freshly generated 26-word phrase', () => {
    expect(verifySeedPhrase(mnemonic)).toBe(true);
  });

  it('accepts a phrase with surrounding whitespace', () => {
    expect(verifySeedPhrase(`  ${mnemonic}  `)).toBe(true);
  });

  it('accepts a 25-word phrase, which carries no checksum', () => {
    const v1 = mnemonic.split(/\s+/).slice(0, 25).join(' ');
    expect(verifySeedPhrase(v1)).toBe(true);
  });

  it('rejects a phrase whose checksum word was altered', () => {
    const words = mnemonic.split(/\s+/);
    // Shift the checksum word to a different dictionary entry:
    const wrong = phrases[(phrases.findIndex(p => p.phrase === words[25]) + 2) % phrases.length];
    words[25] = wrong.phrase;
    expect(verifySeedPhrase(words.join(' '))).toBe(false);
  });

  it('rejects a phrase whose seed words were altered', () => {
    const words = mnemonic.split(/\s+/);
    const index = phrases.findIndex(p => p.phrase === words[0]);
    words[0] = phrases[(index + 1) % phrases.length].phrase;
    expect(verifySeedPhrase(words.join(' '))).toBe(false);
  });

  it('throws on the wrong word count', () => {
    expect(() => verifySeedPhrase('like like like')).toThrow('Invalid seed phrase word count');
  });

  it('throws on a word outside the dictionary', () => {
    const words = mnemonic.split(/\s+/);
    words[3] = 'notazanoword';
    expect(() => verifySeedPhrase(words.join(' '))).toThrow('Invalid word in mnemonic text');
  });

  it('throws on an address rather than a seed phrase', () => {
    expect(() =>
      verifySeedPhrase(
        'ZxDFpn4k7xVYyc9VZ3LphrJbkpc46xfREace5bme1aXiMzKPAHA8jsTWcHSXhv9AdodSaoGXK9Mg7bk3ec4FkQrj357fZPWZX',
      ),
    ).toThrow('Invalid seed phrase word count');
  });

  it('throws for a password-protected phrase', () => {
    // The flag lives in the timestamp word: any index >= 800 sets it.
    const protectedPhrase = withTimestampWord(
      mnemonic,
      phrases[WALLET_BRAIN_DATE_MAX_WEEKS_COUNT + 5].phrase,
    );
    expect(() => verifySeedPhrase(protectedPhrase)).toThrow('password-protected');
  });

  it('accepts every phrase this library generates', () => {
    const rejected: string[] = [];
    for (let i = 0; i < 2000; i++) {
      const seedHex = randomBytes(32).toString('hex');
      if (!verifySeedPhrase(seedToMnemonic(seedHex))) {
        rejected.push(seedHex);
      }
    }
    expect(rejected).toStrictEqual([]);
  });
});

describe('isSeedPhrasePasswordProtected', () => {
  let mnemonic: string;

  beforeEach(() => {
    jest.spyOn(Date, 'now').mockReturnValue(FIXED_TIME);
    mnemonic = seedToMnemonic(SEED_HEX);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('is false for a phrase generated without a seed password', () => {
    expect(isSeedPhrasePasswordProtected(mnemonic)).toBe(false);
  });

  it('is true when the timestamp word carries the flag', () => {
    const flagged = withTimestampWord(
      mnemonic,
      phrases[WALLET_BRAIN_DATE_MAX_WEEKS_COUNT].phrase,
    );
    expect(isSeedPhrasePasswordProtected(flagged)).toBe(true);
  });

  it('is false at the last unflagged timestamp word', () => {
    const boundary = withTimestampWord(
      mnemonic,
      phrases[WALLET_BRAIN_DATE_MAX_WEEKS_COUNT - 1].phrase,
    );
    expect(isSeedPhrasePasswordProtected(boundary)).toBe(false);
  });
});

describe('isPasswordProtectedTimestampWord', () => {
  // Zano marks a phrase as password-protected by pushing the
  // creation-timestamp word index past WALLET_BRAIN_DATE_MAX_WEEKS_COUNT
  // (800), so the flag is decided entirely by which side of that the word
  // sits on. `ugly` is the last unflagged word and `among` the first
  // flagged one.
  it('splits on the word index, not the word', () => {
    expect(isPasswordProtectedTimestampWord('slide')).toBe(false);
    expect(isPasswordProtectedTimestampWord('ugly')).toBe(false);
    expect(isPasswordProtectedTimestampWord('among')).toBe(true);
    expect(isPasswordProtectedTimestampWord('blade')).toBe(true);
  });

  it('agrees with the whole-phrase check', () => {
    const withWord = (word: string): string =>
      `${new Array(24).fill('like').join(' ')} ${word} mom`;
    for (const word of ['slide', 'ugly', 'among', 'blade']) {
      expect(isSeedPhrasePasswordProtected(withWord(word))).toBe(
        isPasswordProtectedTimestampWord(word),
      );
    }
  });

  it('rejects a word outside the dictionary', () => {
    expect(() => isPasswordProtectedTimestampWord('notazanoword')).toThrow(
      'notazanoword',
    );
  });
});
