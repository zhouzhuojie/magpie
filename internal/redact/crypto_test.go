package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

// The crypto wallet keys are made here rather than written out: a key in
// the source is a key in every clone, and one that looks real teaches
// nothing the shapes below don't.
const (
	b58         = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

// rep is s repeated to n characters.
func rep(s string, n int) string { return strings.Repeat(s, n/len(s)+1)[:n] }

// pad is a run of n characters of alphabet a, from i.
func pad(a string, n, i int) string {
	b := make([]byte, n)
	for k := range b {
		b[k] = a[(i+k)%len(a)]
	}
	return string(b)
}

func cryptoValues() map[string]string {
	evm := "0x" + rep("4c0883a69102937d", 64)
	wif := "5" + pad(b58, 51, 7)
	xprv := "xprv" + pad(b58, 107, 3)
	sol := pad(b58, 88, 11)
	keypair := "[" + strings.Trim(strings.Repeat("174, 47, 19, 82, ", 16), ", ") + "]"
	near := "ed25519:" + pad(b58, 88, 5)
	sui := "suiprivkey1" + pad("0123456789abcdefghijklmnopqrstuvwxyz", 58, 4)
	aptos := "ed25519-priv-0x" + rep("9f2c4b6d8e0a", 64)
	stellar := "S" + pad(base32Chars, 55, 2)
	nostr := "nsec1" + pad("qpzry9x8gf2tvdw0s3jn54khce6mua7l", 58, 1)
	age := "AGE-SECRET-KEY-1" + pad("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L", 58, 6)
	zec := "secret" + "-extended-key-main1" + pad("0123456789abcdefghijklmnopqrstuvwxyz", 160, 9)
	seed := "seed phrase: " + strings.Trim(strings.Repeat("witch collapse practice feed shame open ", 2), " ")
	return map[string]string{
		"WALLET_KEY":     evm,
		"WIF_KEY":        wif,
		"BIP32_KEY":      xprv,
		"SOLANA_KEY":     sol,
		"SOLANA_KEYPAIR": keypair,
		"NEAR_KEY":       near,
		"SUI_KEY":        sui,
		"APTOS_KEY":      aptos,
		"STELLAR_KEY":    stellar,
		"NOSTR_KEY":      nostr,
		"AGE_KEY":        age,
		"ZCASH_KEY":      zec,
		"SEED_PHRASE":    seed,
	}
}

// TestMaskCryptoKeys: every shape goes as its own kind, and only when the
// switch is on. Secrets on and personal data on leave them as written,
// which is what makes this a switch of its own.
func TestMaskCryptoKeys(t *testing.T) {
	Forget()
	vals := cryptoValues()
	for _, kind := range []string{"WALLET_KEY", "WIF_KEY", "BIP32_KEY", "SOLANA_KEY", "SOLANA_KEYPAIR", "NEAR_KEY", "SUI_KEY", "APTOS_KEY", "STELLAR_KEY", "NOSTR_KEY", "AGE_KEY", "ZCASH_KEY", "SEED_PHRASE"} {
		v := vals[kind]
		in := "the key is " + v + " ok"
		out, n := Mask(in, Options{Crypto: true})
		if n != 1 {
			t.Errorf("%s: %d masked, want 1: %s", kind, n, out)
			continue
		}
		if !strings.Contains(out, "{{"+kind+"_") {
			t.Errorf("%s: masked as %s", kind, out)
		}
		if strings.Contains(out, v) {
			t.Errorf("%s: the value is still there: %s", kind, out)
		}
		if back := Restore(out, false); back != in {
			t.Errorf("%s: restored %q, want %q", kind, back, in)
		}
		if off, n := Mask(in, Options{Secrets: true, Personal: true}); n != 0 || off != in {
			t.Errorf("%s: masked with the switch off (%d): %s", kind, n, off)
		}
	}
}

// TestMaskCryptoKeepsWhatIsNotAKey: the values these shapes sit beside in
// a real request. A transaction hash, a public key and a digest stay as
// written, so a vendor can still read them.
func TestMaskCryptoKeepsWhatIsNotAKey(t *testing.T) {
	Forget()
	kept := []string{
		"0x" + rep("4c0883a6", 5),  // an address, 20 bytes
		rep("a1b2c3d4", 5),         // a git sha, 40 hex
		rep("e3b0c44298fc1c14", 8), // a bare sha256, no 0x
		"xpub" + pad(b58, 107, 3),  // BIP32 public key
		pad(b58, 44, 21),           // a Solana public key, 32 bytes
		"bc1q" + pad("023456789acdefghjklmnpqrstuvwxyz", 38, 2), // a bech32 address
		"550e8400-e29b-41d4-a716-446655440000",                  // a uuid
	}
	for _, v := range kept {
		in := "value " + v + " here"
		if out, n := Mask(in, Options{Crypto: true}); n != 0 || out != in {
			t.Errorf("masked %q (%d): %s", v, n, out)
		}
	}
}

// TestMaskCryptoJSON: the gateway masks a body's strings, where a key
// arrives as a value of its own, with no field name beside it.
func TestMaskCryptoJSON(t *testing.T) {
	Forget()
	sol := cryptoValues()["SOLANA_KEY"]
	body := `{"tool":"wallet","input":{"key":"` + sol + `"}}`
	out, n := MaskJSON([]byte(body), Options{Crypto: true})
	if n != 1 || strings.Contains(string(out), sol) {
		t.Fatalf("%d masked: %s", n, out)
	}
	var v struct {
		Input struct {
			Key string `json:"key"`
		} `json:"input"`
	}
	if err := json.Unmarshal(out, &v); err != nil || !strings.HasPrefix(v.Input.Key, "{{SOLANA_KEY_") {
		t.Fatalf("json: %v: %s", err, out)
	}
	if back := RestoreJSON(out); string(back) != body {
		t.Fatalf("restored %s, want %s", back, body)
	}
}

// TestMaskCryptoKnown: a key masked in one turn is masked again in the
// next, with the same placeholder, so a conversation reads the same and
// the vendor's cache still matches.
func TestMaskCryptoKnown(t *testing.T) {
	Forget()
	sol := cryptoValues()["SOLANA_KEY"]
	first, n := Mask("my key "+sol, Options{Crypto: true})
	if n != 1 {
		t.Fatalf("%d masked: %s", n, first)
	}
	ph := placeholderRe.FindString(first)
	if ph == "" {
		t.Fatalf("no placeholder: %s", first)
	}
	second, n := Mask("again "+sol, Options{Crypto: true})
	if n != 1 || !strings.Contains(second, ph) {
		t.Fatalf("second turn %d: %s, want %s", n, second, ph)
	}
}

// TestMaskCryptoVectors are keys published by the chains themselves: BIP32's
// test vector 1 (111 base58 characters, version bytes 0x0488ade4), the
// Bitcoin wiki's WIF example (51, version byte 0x80) and NIP-19's nsec
// example (63). None of them has ever held funds. Each is split across two
// literals so that a scanner reading this file does not take it for a key.
func TestMaskCryptoVectors(t *testing.T) {
	Forget()
	xprv := "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPq" +
		"jiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	wif := "5HueCGU8rMjxEXxiPuD5BD" + "ku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
	nsec := "nsec1vl029mgpspedva04g90vltkh6fvh240zqt" + "v9k0t9af8935ke9laqsnlfe5"
	for _, c := range []struct {
		kind, v string
	}{
		{"BIP32_KEY", xprv},
		{"WIF_KEY", wif},
		{"NOSTR_KEY", nsec},
	} {
		if len(c.v) != map[string]int{"BIP32_KEY": 111, "WIF_KEY": 51, "NOSTR_KEY": 63}[c.kind] {
			t.Fatalf("%s: %d characters", c.kind, len(c.v))
		}
		out, n := Mask("key "+c.v, Options{Crypto: true})
		if n != 1 || !strings.Contains(out, "{{"+c.kind+"_") {
			t.Errorf("%s: %d masked: %s", c.kind, n, out)
		}
	}
}

// TestMaskCryptoLengths: a key is the whole run, so one character more or
// less is another value, and stays as written. The lengths are the ones the
// formats have: 111 for a BIP32 key, 51 or 52 for WIF, 87 or 88 for a Solana
// key, 56 for a Stellar seed, 63 for an nsec, 74 for an age identity, 69 for
// a Sui key, 96 for a NEAR key.
func TestMaskCryptoLengths(t *testing.T) {
	Forget()
	cases := []struct {
		kind string
		n    int
		ok   bool
	}{
		{"BIP32_KEY", 111, true}, {"BIP32_KEY", 110, false}, {"BIP32_KEY", 112, false},
		{"WIF_KEY", 51, true}, {"WIF_KEY", 52, true}, {"WIF_KEY", 50, false}, {"WIF_KEY", 53, false},
		{"SOLANA_KEY", 88, true}, {"SOLANA_KEY", 87, true}, {"SOLANA_KEY", 86, false}, {"SOLANA_KEY", 89, false},
		{"STELLAR_KEY", 56, true}, {"STELLAR_KEY", 55, false}, {"STELLAR_KEY", 57, false},
		{"NOSTR_KEY", 63, true}, {"NOSTR_KEY", 62, false}, {"NOSTR_KEY", 64, false},
		{"AGE_KEY", 74, true}, {"AGE_KEY", 73, false}, {"AGE_KEY", 75, false},
		{"SUI_KEY", 69, true}, {"SUI_KEY", 68, false}, {"SUI_KEY", 70, false},
		{"NEAR_KEY", 96, true}, {"NEAR_KEY", 95, true}, {"NEAR_KEY", 94, false}, {"NEAR_KEY", 97, false},
	}
	for _, c := range cases {
		var v string
		switch c.kind {
		case "BIP32_KEY":
			v = "xprv" + pad(b58, c.n-4, 3)
		case "WIF_KEY":
			v = "5" + pad(b58, c.n-1, 7)
		case "SOLANA_KEY":
			v = pad(b58, c.n, 11)
		case "STELLAR_KEY":
			v = "S" + pad(base32Chars, c.n-1, 2)
		case "NOSTR_KEY":
			v = "nsec1" + pad("qpzry9x8gf2tvdw0s3jn54khce6mua7l", c.n-5, 1)
		case "AGE_KEY":
			v = "AGE-SECRET-KEY-1" + pad("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L", c.n-16, 6)
		case "SUI_KEY":
			v = "suiprivkey1" + pad("0123456789abcdefghijklmnopqrstuvwxyz", c.n-11, 4)
		case "NEAR_KEY":
			v = "ed25519:" + pad(b58, c.n-8, 5)
		}
		in := "key " + v + " end"
		out, n := Mask(in, Options{Crypto: true})
		if c.ok && (n != 1 || !strings.Contains(out, "{{"+c.kind+"_")) {
			t.Errorf("%s at %d: %d masked: %s", c.kind, c.n, n, out)
		}
		if !c.ok && n != 0 {
			t.Errorf("%s at %d masked, want as written: %s", c.kind, c.n, out)
		}
	}
}
