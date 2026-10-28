package redact

import "regexp"

// Crypto wallet secrets, masked when the user turns on Mask crypto wallet
// keys (Options.Crypto): the private keys wallets and chain tools export,
// in the shapes they export them in. A wallet key is a secret like an API
// key, but no vendor needs one, and an agent that pastes a keyfile into a
// message sends it to every provider behind magpie.
//
// They are a switch of their own, off until turned on, because two of the
// shapes are shared with values a vendor does read: an EVM key is written
// as 0x and 64 hex digits, which is also a transaction hash, and a Solana
// secret key is 88 base58 characters, which is also a transaction
// signature. Masking those costs the vendor the ability to reason about a
// hash; it costs the agent nothing, since every placeholder comes back as
// it was.
//
// A raw 32-byte key written as bare hex, with no 0x and no field name, is
// in no rule: it is a sha256 digest to every reader. In a field named for
// it (private_key = …, "privateKey": …) the secrets' own rule finds it.
//
// Each shape is the one its chain documents, and each rule takes the whole
// of a key, never a piece: BIP-0032's 78-byte extended key with its
// checksum (111 base58 characters), Bitcoin's WIF (51 or 52), Solana's 64
// byte secret key (87 or 88 base58) and its 64-number keyfile, NEAR's
// ed25519: and 64 bytes, Sui's bech32 suiprivkey1 and 32 bytes (69
// characters), Aptos's AIP-80 ed25519-priv-0x, Stellar's StrKey seed (S
// and 55 base32 characters), NIP-19's nsec (63), age's identity (74) and
// Zcash's extended spending key. The tests carry BIP-0032's test vector 1,
// the Bitcoin wiki's WIF example and NIP-19's nsec, and check each length
// at one character either side.
const catCrypto = "crypto"

// cryptoRules are the shapes. Each is the whole of a key: a base58 or
// bech32 run of the exact length its format has, so a longer identifier is
// no key, and bound keeps a run from being cut out of a longer one.
var cryptoRules = []rule{
	// Ethereum, BSC, Polygon, Arbitrum, Base, Avalanche, TRON, Starknet:
	// 0x and the 32 bytes in hex (Starknet writes fewer digits than 64)
	{kind: "WALLET_KEY", cat: catCrypto, markers: []string{"0x"}, bound: alnum,
		re: regexp.MustCompile(`(?i)0x[0-9a-f]{56,64}`)},

	// Bitcoin, Litecoin, Dogecoin, EOS: WIF, compressed (K, L) or not (5)
	{kind: "WIF_KEY", cat: catCrypto, bound: alnum,
		re: regexp.MustCompile(`[5KL][1-9A-HJ-NP-Za-km-z]{50,51}`)},

	// a BIP32 extended private key: xprv, yprv, zprv, tprv. An xpub is a
	// public key and goes as written.
	{kind: "BIP32_KEY", cat: catCrypto, markers: []string{"prv"}, bound: alnum,
		re: regexp.MustCompile(`[xyzt]prv[1-9A-HJ-NP-Za-km-z]{107}`)},

	// Solana, as Phantom, Backpack and Solflare export it: the 64-byte
	// secret key in base58
	{kind: "SOLANA_KEY", cat: catCrypto, bound: alnum,
		re: regexp.MustCompile(`[1-9A-HJ-NP-Za-km-z]{87,88}`)},

	// Solana's own keyfile (solana-keygen, ~/.config/solana/id.json): the
	// same 64 bytes as 64 numbers
	{kind: "SOLANA_KEYPAIR", cat: catCrypto,
		re: regexp.MustCompile(`\[\s*\d{1,3}(?:\s*,\s*\d{1,3}){63}\s*\]`)},

	// NEAR: ed25519: and the secret key in base58
	{kind: "NEAR_KEY", cat: catCrypto, markers: []string{"ed25519:"}, bound: alnum,
		re: regexp.MustCompile(`ed25519:[1-9A-HJ-NP-Za-km-z]{87,88}`)},

	// Sui: sui keytool export writes suiprivkey1… in bech32
	{kind: "SUI_KEY", cat: catCrypto, markers: []string{"suiprivkey1"}, bound: alnum,
		re: regexp.MustCompile(`suiprivkey1[0-9a-z]{58}`)},

	// Aptos, in AIP-80's form: ed25519-priv-0x…
	{kind: "APTOS_KEY", cat: catCrypto, markers: []string{"ed25519-priv-"}, bound: alnum,
		re: regexp.MustCompile(`ed25519-priv-0x[0-9a-f]{64}`)},

	// Stellar's secret seed: S and 55 base32 characters
	{kind: "STELLAR_KEY", cat: catCrypto, bound: alnum,
		re: regexp.MustCompile(`S[A-Z2-7]{55}`)},

	// a Nostr identity's secret key (NIP-19): nsec1… in bech32
	{kind: "NOSTR_KEY", cat: catCrypto, markers: []string{"nsec1"}, bound: alnum,
		re: regexp.MustCompile(`nsec1[02-9ac-hj-np-z]{58}`)},

	// an age identity: AGE-SECRET-KEY-1… in bech32, in capitals
	{kind: "AGE_KEY", cat: catCrypto, markers: []string{"AGE-SECRET-KEY-"}, bound: alnum,
		re: regexp.MustCompile(`AGE-SECRET-KEY-1[0-9A-Z]{58}`)},

	// Zcash's extended spending key, for the mainnet or the testnet
	{kind: "ZCASH_KEY", cat: catCrypto, markers: []string{"secret-extended-key-"}, bound: alnum,
		re: regexp.MustCompile(`secret-extended-key-(?:main|test)[0-9a-z]{150,320}`)},

	// a seed phrase after the words that say what it is: BIP39's 12 to 24
	// words (Bitcoin, Ethereum, Polkadot, TON, Algorand), Monero's 25, and
	// Electrum's. A run of ordinary words with nothing before it stays:
	// nothing tells it from a sentence.
	{kind: "SEED_PHRASE", cat: catCrypto,
		fold: []string{"seed", "mnemonic", "phrase", "recovery", "wallet", "secret", "助记词", "助記詞", "シード", "시드"},
		re:   regexp.MustCompile(`(?i)(?:seed|mnemonic|phrase|recovery|wallet|secret|助记词|助記詞|シード|시드)[^.\n]{0,24}?(\b[a-z]{3,8}(?: [a-z]{3,8}){11,23}\b)`)},
}
