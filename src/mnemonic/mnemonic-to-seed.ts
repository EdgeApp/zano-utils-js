import { phrases } from './consts/phrases';
import { MnemonicToSeedResult } from './types';
import { keysFromDefault } from '../core/crypto';

export const NUMWORDS = 1626;

const wordsMap: Map<string, number> = new Map(phrases.map(item => [item.phrase, item.value]));

export const SEED_PHRASE_V1_WORDS_COUNT = 25;
export const SEED_PHRASE_V2_WORDS_COUNT = 26;
const BINARY_SIZE_SEED = 32;

/**
 * Converts a mnemonic seed phrase (25 or 26 words) into a secret spend key.
 *
 * The last one or two words of the phrase represent metadata:
 * - If 25 words: the 25th word is the creation timestamp.
 * - If 26 words: the 25th word is the timestamp, the 26th is a checksum + audit flag.
 *
 * @param seedPhraseRaw - Raw seed phrase string (mnemonic) containing 25 or 26 words.
 * @returns The secret spend key as a hex string, or `false` if parsing failed.
 */
export function mnemonicToSeed(seedPhraseRaw: string, full = false): MnemonicToSeedResult {
  const seedPhrase: string = seedPhraseRaw.trim();
  const words: string[] = seedPhrase.split(/\s+/);

  let keysSeedText: string;
  let timestampWord: string;
  let checksumWord: string;

  if (words.length === SEED_PHRASE_V1_WORDS_COUNT) {
    timestampWord = words.pop()!;
    keysSeedText = words.join(' ');
  } else if (words.length === SEED_PHRASE_V2_WORDS_COUNT) {
    checksumWord = words.pop()!;
    timestampWord = words.pop()!;
    keysSeedText = words.join(' ');
  } else {
    throw new Error(`Invalid seed phrase word count: ${words.length}`);
  }

  let keysSeedBinary: Buffer;
  try {
    keysSeedBinary = text2binary(keysSeedText);
  } catch (error) {
    throw new Error(`Failed to convert seed text to binary: ${String(error)}`);
  }

  if (!keysSeedBinary.length) {
    throw new Error('Empty binary seed after conversion');
  }

  if (full) {
    const extraWords: string[] = [];
    if (timestampWord != null) {
      extraWords.push(timestampWord);
    }
    if (checksumWord != null) {
      extraWords.push(checksumWord);
    }
    let expandedSeedHex = keysSeedBinary.toString('hex');
    for (const word of extraWords) {
      const value = wordsMap.get(word);
      if (value == null) {
        throw new Error(`Invalid extra word in mnemonic text: ${word}`);
      }
      expandedSeedHex += value.toString(16).padStart(4, '0');
    }
    return expandedSeedHex;
  }

  const { secretSpendKey } = keysFromDefault(keysSeedBinary, BINARY_SIZE_SEED);
  return secretSpendKey;
}

export function text2binary(text: string): Buffer {
  const tokens: string[] = text.trim().split(/\s+/);

  if (tokens.length % 3 !== 0) {
    throw new Error('Invalid word count in mnemonic text');
  }

  const res: Buffer = Buffer.alloc((tokens.length / 3) * 4);

  for (let i = 0; i < tokens.length / 3; i++) {
    const w1: number = wordsMap.get(tokens[i * 3]);
    const w2: number = wordsMap.get(tokens[i * 3 + 1]);
    const w3: number = wordsMap.get(tokens[i * 3 + 2]);

    if (w1 === undefined || w2 === undefined || w3 === undefined) {
      throw new Error('Invalid word in mnemonic text');
    }

    const val: number = w1 + NUMWORDS * (((NUMWORDS - w1) + w2) % NUMWORDS) + NUMWORDS * NUMWORDS * (((NUMWORDS - w2) + w3) % NUMWORDS);

    const byteIndex: number = i * 4;
    res[byteIndex] = val & 0xFF;
    res[byteIndex + 1] = (val >> 8) & 0xFF;
    res[byteIndex + 2] = (val >> 16) & 0xFF;
    res[byteIndex + 3] = (val >> 24) & 0xFF;
  }

  return res;
}
