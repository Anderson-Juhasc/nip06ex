import { hexToBytes, bytesToHex } from '@noble/hashes/utils'
import { bech32 } from '@scure/base'
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

function hexToBech32(key: string, prefix: string) {
  const words = bech32.toWords(hexToBytes(key))
  return bech32.encode(prefix, words)
}

export function accountFromExtendedKey(base58key: string, accountIndex = 0): {
  privateKey?: { hex: string, bech32: string },
  publicKey:  { hex: string, bech32: string }
} {
  let extendedKey = HDKey.fromExtendedKey(base58key)
  let version = base58key.slice(0, 4)
  let child = extendedKey.deriveChild(0).deriveChild(accountIndex)
  let publicKeyHex = bytesToHex(child.publicKey!.slice(1))
  let publicKeyBech32 = hexToBech32(publicKeyHex, 'npub')
  if (version === 'xprv') {
    let privateKeyHex = bytesToHex(child.privateKey!)
    let privateKeyBech32 = hexToBech32(privateKeyHex, 'nsec')
    return { 
      privateKey: { hex: privateKeyHex, bech32: privateKeyBech32 },
      publicKey: { hex: publicKeyHex, bech32: publicKeyBech32 } 
    } 
  }
  return { publicKey: { hex: publicKeyHex, bech32: publicKeyBech32 } } 
}

export function generateSeedWords(): string {
  return generateMnemonic(wordlist)
}

export function validateWords(words: string): boolean {
  return validateMnemonic(words, wordlist)
}
