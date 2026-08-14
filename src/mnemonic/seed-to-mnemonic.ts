import { phrases } from './consts/phrases';
import { NUMWORDS } from './mnemonic-to-seed';
import type { SeedToMnemonicResult } from './types';
import { fastHash } from '../core/crypto';

export const wordsArray: string[] = phrases.map(p => p.phrase);

const WALLET_BRAIN_DATE_OFFSET = 1543622400;
const WALLET_BRAIN_DATE_QUANTUM = 604800;
export const WALLET_BRAIN_DATE_MAX_WEEKS_COUNT = 800;
export const CHECKSUM_MAX = NUMWORDS >> 1;
const BINARY_SIZE_SEED = 32;
const WORD_INDEX_SIZE = 2;
const FULL_SEED_V1_SIZE = BINARY_SIZE_SEED + WORD_INDEX_SIZE;
const FULL_SEED_V2_SIZE = BINARY_SIZE_SEED + WORD_INDEX_SIZE * 2;

export function seedToMnemonic(keysSeedHex: string): SeedToMnemonicResult {
  if (!keysSeedHex) {
    throw new Error('Invalid seed hex');
  }

  const keysSeedBinary: Buffer = Buffer.from(keysSeedHex, 'hex');

  if (keysSeedBinary.length === FULL_SEED_V1_SIZE ||
      keysSeedBinary.length === FULL_SEED_V2_SIZE) {
    return fullSeedToMnemonic(keysSeedBinary);
  }

  const mnemonic: string = binaryToText(keysSeedBinary);

  const timestamp: number = Math.floor(Date.now() / 1000);
  const creationTimestampWord: string = getWordFromTimestamp(timestamp, false);

  const timestampFromWord: number = getTimestampFromWord(creationTimestampWord, false);

  const checksumValue: number = computeChecksum(keysSeedBinary, timestampFromWord);

  const auditableFlag = 0;
  const checksumWord: string = wordByNum((checksumValue << 1) | (auditableFlag & 1));

  return `${mnemonic} ${creationTimestampWord} ${checksumWord}`;
}

/**
 * Computes the checksum carried by the last word of a 26-word seed phrase.
 *
 * Mirrors `account_base::get_seed_phrase` in Zano core. Only valid for
 * phrases without a seed password; a password-protected phrase folds the
 * decrypted seed and the password itself into the hash.
 *
 * @param keysSeedBinary - The 32-byte seed the phrase encodes.
 * @param creationTimestamp - Timestamp decoded from the phrase's timestamp
 * word, not the raw clock, since the word is only week-granular.
 */
export function computeChecksum(keysSeedBinary: Buffer, creationTimestamp: number): number {
  const hashWithTimestamp: Buffer = Buffer.from(fastHash(keysSeedBinary));
  hashWithTimestamp.writeBigUInt64LE(BigInt(creationTimestamp), 0);

  const checksumHash: Buffer = fastHash(hashWithTimestamp);
  const checksumValue = Number(checksumHash.readBigUInt64LE(0) % BigInt(CHECKSUM_MAX + 1));

  // The checksum shares its word with the auditable flag as
  // `(checksum << 1) | auditableFlag`, so a checksum of CHECKSUM_MAX would
  // address index NUMWORDS -- one past the end of the dictionary. Zano core
  // maps that case back to zero rather than changing the encoding; see the
  // matching workaround in `account_base::get_seed_phrase` and
  // `account_base::restore_from_seed_phrase`.
  return checksumValue === CHECKSUM_MAX ? 0 : checksumValue;
}

function fullSeedToMnemonic(fullSeedBinary: Buffer): string {
  const keysSeedBinary = fullSeedBinary.subarray(0, BINARY_SIZE_SEED);
  const mnemonic = binaryToText(keysSeedBinary);
  const words: string[] = [mnemonic];

  for (let offset = BINARY_SIZE_SEED; offset < fullSeedBinary.length; offset += WORD_INDEX_SIZE) {
    // `wordByNum` makes the same range check, with its own message:
    words.push(wordByNum(fullSeedBinary.readUInt16BE(offset)));
  }

  return words.join(' ');
}

function wordByNum(index: number): string {
  const entry = phrases[index];
  if (entry == null) {
    throw new Error(`Mnemonic word index out of range: ${index}`);
  }
  return entry.phrase;
}

const valuesByWord: Map<string, number> = new Map(
  phrases.map(item => [item.phrase, item.value]),
);

export function numByWord(word: string): number {
  const value = valuesByWord.get(word);
  if (value == null) {
    throw new Error(`Unable to find word "${word}" in mnemonic dictionary`);
  }
  return value;
}

/**
 * Reports whether a creation-timestamp word index carries the "password
 * used" flag, which Zano encodes by offsetting the index past the range a
 * real date can reach.
 *
 * Takes the index rather than the word so callers that already resolved one
 * do not look it up twice.
 */
export function isPasswordProtectedIndex(timestampValue: number): boolean {
  return timestampValue >= WALLET_BRAIN_DATE_MAX_WEEKS_COUNT;
}

/**
 * Reports whether a creation-timestamp word carries the "password used"
 * flag.
 *
 * The rule is a single comparison, but it is read at three sites and
 * written at a fourth, so it lives here rather than being spelled out at
 * each one.
 *
 * @throws If the word is outside the dictionary.
 */
export function isPasswordProtectedTimestampWord(word: string): boolean {
  return isPasswordProtectedIndex(numByWord(word));
}

function binaryToText(binary: Buffer): string {
  if (binary.length % 4 !== 0) {
    throw new Error('Invalid binary data size for mnemonic encoding');
  }

  const words: string[] = [];

  for (let i = 0; i < binary.length; i += 4) {
    const val: number = binary.readUInt32LE(i);

    const w1: number = val % NUMWORDS;
    const w2: number = (Math.floor(val / NUMWORDS) + w1) % NUMWORDS;
    const w3: number = (Math.floor(val / (NUMWORDS * NUMWORDS)) + w2) % NUMWORDS;

    words.push(wordsArray[w1], wordsArray[w2], wordsArray[w3]);
  }

  return words.join(' ');
}
function getWordFromTimestamp(timestamp: number, usePassword: boolean): string {
  const dateOffset: number = Math.max(timestamp - WALLET_BRAIN_DATE_OFFSET, 0);
  let weeksCount = Math.trunc(dateOffset / WALLET_BRAIN_DATE_QUANTUM);

  if (weeksCount >= WALLET_BRAIN_DATE_MAX_WEEKS_COUNT) {
    throw new Error('SEED PHRASE needs to be extended or refactored');
  }

  if (usePassword) {
    weeksCount += WALLET_BRAIN_DATE_MAX_WEEKS_COUNT;
  }

  if (weeksCount > 0xffffffff) {
    throw new Error(`Value too large for uint32: ${weeksCount}`);
  }

  return wordByNum(weeksCount);
}

export function getTimestampFromWord(word: string, passwordUsed: boolean): number {
  let weeks = numByWord(word);

  if (isPasswordProtectedIndex(weeks)) {
    weeks -= WALLET_BRAIN_DATE_MAX_WEEKS_COUNT;
    passwordUsed = true;
  } else {
    passwordUsed = false;
  }

  return weeks * WALLET_BRAIN_DATE_QUANTUM + WALLET_BRAIN_DATE_OFFSET;
}
