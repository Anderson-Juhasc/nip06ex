import { hexToBytes, bytesToHex } from '@noble/hashes/utils'
import { wordlist } from '@scure/bip39/wordlists/english'
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39'
import { HDKey } from '@scure/bip32'

export function extendedPairFromSeedWords(mnemonic: string, passphrase?: string, extendedAccountIndex = 0): {
  privateExtendedKey: string,
  publicExtendedKey: string
} {
  let root = HDKey.fromMasterSeed(mnemonicToSeedSync(mnemonic, passphrase))
  let privateExtendedKey = root.derive(`m/44'/1237'/${extendedAccountIndex}'`).privateExtendedKey
  let publicExtendedKey = root.derive(`m/44'/1237'/${extendedAccountIndex}'`).publicExtendedKey
  if (!privateExtendedKey) throw new Error('could not derive private extended key')
  return { privateExtendedKey, publicExtendedKey }
}

export function accountFromExtendedKey(base58key: string, accountIndex = 0): {
  privateKey?: string,
  publicKey: string
} {
  let extendedKey = HDKey.fromExtendedKey(base58key)
  let version = base58key.slice(0, 4)
  let child = extendedKey.deriveChild(0).deriveChild(accountIndex)
  let publicKey = bytesToHex(child.publicKey!)
  if (version === 'xprv') {
    let privateKey = bytesToHex(child.privateKey!)
    return { privateKey, publicKey } 
  }
  return { publicKey } 
}

export function generateSeedWords(): string {
  return generateMnemonic(wordlist)
}

export function validateWords(words: string): boolean {
  return validateMnemonic(words, wordlist)
}
