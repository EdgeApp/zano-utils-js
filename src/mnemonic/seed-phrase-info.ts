import {
  SEED_PHRASE_V1_WORDS_COUNT,
  SEED_PHRASE_V2_WORDS_COUNT,
  text2binary,
} from './mnemonic-to-seed';
import {
  CHECKSUM_MAX,
  computeChecksum,
  getTimestampFromWord,
  isPasswordProtectedIndex,
  isPasswordProtectedTimestampWord,
  numByWord,
} from './seed-to-mnemonic';

const KEYS_SEED_WORDS_COUNT = 24;

interface SeedPhraseParts {
  checksumWord?: string;
  keysSeedText: string;
  timestampWord: string;
}

function splitSeedPhrase(seedPhraseRaw: string): SeedPhraseParts {
  const words: string[] = seedPhraseRaw.trim().split(/\s+/);

  if (words.length !== SEED_PHRASE_V1_WORDS_COUNT &&
      words.length !== SEED_PHRASE_V2_WORDS_COUNT) {
    throw new Error(`Invalid seed phrase word count: ${words.length}`);
  }

  return {
    checksumWord: words.length === SEED_PHRASE_V2_WORDS_COUNT
      ? words[SEED_PHRASE_V1_WORDS_COUNT]
      : undefined,
    keysSeedText: words.slice(0, KEYS_SEED_WORDS_COUNT).join(' '),
    timestampWord: words[KEYS_SEED_WORDS_COUNT],
  };
}

/**
 * Reports whether a seed phrase is protected by a seed password, which is
 * encoded in the creation-timestamp word.
 *
 * Zano core asserts that this flag matches the password the caller supplies
 * (`account_base::restore_from_seed_phrase`), so decoding a protected phrase
 * without its password produces the wrong keys rather than an error. This
 * library implements no seed-password support, so callers must route such
 * phrases to an implementation that does.
 *
 * @param seedPhraseRaw - A 25- or 26-word seed phrase.
 * @returns True when the phrase requires a seed password.
 */
export function isSeedPhrasePasswordProtected(seedPhraseRaw: string): boolean {
  const { timestampWord } = splitSeedPhrase(seedPhraseRaw);
  return isPasswordProtectedTimestampWord(timestampWord);
}

/**
 * Verifies a seed phrase without touching the Zano native library: word
 * count, dictionary membership of every word, and -- for 26-word phrases --
 * the checksum word.
 *
 * 25-word (v1) phrases carry no checksum, so only their structure is
 * checked, matching Zano core's own behaviour.
 *
 * @param seedPhraseRaw - A 25- or 26-word seed phrase.
 * @returns True when the phrase is well formed and its checksum matches.
 * @throws If the phrase is structurally invalid, contains a word outside the
 * dictionary, or is password-protected -- a protected phrase's checksum
 * covers the decrypted seed and the password, neither of which is reachable
 * here.
 */
export function verifySeedPhrase(seedPhraseRaw: string): boolean {
  const { checksumWord, keysSeedText, timestampWord } = splitSeedPhrase(seedPhraseRaw);

  // Both of these throw on any word outside the dictionary:
  const timestampValue: number = numByWord(timestampWord);
  const keysSeedBinary: Buffer = text2binary(keysSeedText);

  if (isPasswordProtectedIndex(timestampValue)) {
    throw new Error('Cannot verify a password-protected seed phrase');
  }

  if (checksumWord == null) {
    return true;
  }

  const checksumAndFlag: number = numByWord(checksumWord);
  const timestamp: number = getTimestampFromWord(timestampWord, false);

  // The auditable flag occupies the low bit; the checksum is everything else.
  const checksum: number = checksumAndFlag >> 1;
  if (checksum > CHECKSUM_MAX) {
    return false;
  }

  return checksum === computeChecksum(keysSeedBinary, timestamp);
}
