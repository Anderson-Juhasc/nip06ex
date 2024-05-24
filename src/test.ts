import * as nip06ex from './index'

console.log(nip06ex)
const m = 'magic evil wet antique impact finger ignore obey snake grit usual oyster'
console.log(m)

const xpair = nip06ex.extendedPairFromSeedWords(m)
console.log(xpair)

const account0 = nip06ex.accountFromExtendedKey(xpair.privateExtendedKey)
console.log(account0)

const account1 = nip06ex.accountFromExtendedKey(xpair.publicExtendedKey)
console.log(account1)
