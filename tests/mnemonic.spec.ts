import { mnemonicToSeed, seedToMnemonic } from '../src/mnemonic';

describe('mnemonic round-trip', () => {
  it('seedToMnemonic produces a 26-word phrase from a 32-byte seed', () => {
    const seedHex = 'a'.repeat(64); // 32 bytes of 0xAA
    const mnemonic = seedToMnemonic(seedHex);

    expect(typeof mnemonic).toBe('string');
    const words = (mnemonic ).split(/\s+/);
    // 24 seed words + 1 timestamp word + 1 checksum word = 26
    expect(words).toHaveLength(26);
  });

  it('mnemonicToSeed recovers a secret spend key from a mnemonic', () => {
    const seedHex = 'b'.repeat(64);
    const mnemonic = seedToMnemonic(seedHex);

    const result = mnemonicToSeed(mnemonic );
    expect(result).not.toBe(false);
    expect(typeof result).toBe('string');
    expect((result as string)).toHaveLength(64);
  });

  it('mnemonicToSeed returns false for invalid word count', () => {
    const spy = jest.spyOn(console, 'error').mockImplementation();
    expect(mnemonicToSeed('one two three')).toBe(false);
    spy.mockRestore();
  });

  it('mnemonicToSeed returns false for empty input', () => {
    const spy = jest.spyOn(console, 'error').mockImplementation();
    expect(mnemonicToSeed('')).toBe(false);
    spy.mockRestore();
  });

  it('seedToMnemonic throws for empty input', () => {
    expect(() => seedToMnemonic('')).toThrow('Invalid seed hex');
  });
});

describe('full seed round-trip', () => {
  it('mnemonicToSeed(phrase, true) returns an expanded seed hex', () => {
    const seedHex = 'c'.repeat(64);
    const mnemonic = seedToMnemonic(seedHex);

    const fullSeed = mnemonicToSeed(mnemonic , true);
    expect(fullSeed).not.toBe(false);
    expect(typeof fullSeed).toBe('string');

    const fullSeedStr = fullSeed as string;
    // 32 bytes seed + 2 bytes timestamp + 2 bytes checksum = 36 bytes = 72 hex chars
    expect(fullSeedStr).toHaveLength(72);
    // First 64 hex chars should be the original seed
    expect(fullSeedStr.slice(0, 64)).toBe(seedHex);
  });

  it('seedToMnemonic re-encodes a full v2 seed back to the same mnemonic', () => {
    const seedHex = 'd'.repeat(64);
    const mnemonic = seedToMnemonic(seedHex);

    const fullSeed = mnemonicToSeed(mnemonic , true) as string;
    const recovered = seedToMnemonic(fullSeed);

    expect(recovered).toBe(mnemonic);
  });

  it('full seed round-trip for a v1 (25-word) phrase works', () => {
    const seedHex = 'e'.repeat(64);
    const mnemonic26 = seedToMnemonic(seedHex) ;
    const words = mnemonic26.split(/\s+/);

    // Build a 25-word phrase by dropping the checksum word
    const mnemonic25 = words.slice(0, 25).join(' ');

    const fullSeed = mnemonicToSeed(mnemonic25, true) as string;
    expect(fullSeed).not.toBe(false);
    // 32 bytes seed + 2 bytes timestamp = 34 bytes = 68 hex chars
    expect(fullSeed).toHaveLength(68);

    const recovered = seedToMnemonic(fullSeed) ;
    const recoveredWords = recovered.split(/\s+/);
    // Should recover the 24 seed words + the 1 timestamp word = 25 words
    expect(recoveredWords).toHaveLength(25);
    expect(recoveredWords.join(' ')).toBe(mnemonic25);
  });

  it('seedToMnemonic detects full seed by length and skips timestamp generation', () => {
    const seedHex = 'f'.repeat(64);
    const mnemonic1 = seedToMnemonic(seedHex) ;
    const fullSeed = mnemonicToSeed(mnemonic1, true) as string;

    // Calling seedToMnemonic twice with the full seed should be deterministic
    const recovered1 = seedToMnemonic(fullSeed);
    const recovered2 = seedToMnemonic(fullSeed);
    expect(recovered1).toBe(recovered2);
  });
});
