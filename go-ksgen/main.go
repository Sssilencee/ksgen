package main

/*
#cgo LDFLAGS: -L ../target/release -l ksgen
#include "../c-ksgen/ksgen.h"
*/
import "C"
import (
	"fmt"
	"runtime"
	"unsafe"
)

const (
	CIPHER_LEN     = C.CIPHER_LEN
	IV_LEN         = C.IV_LEN
	CIPHERTEXT_LEN = C.CIPHERTEXT_LEN
	KDF_LEN        = C.KDF_LEN
	SALT_LEN       = C.SALT_LEN
	MAC_LEN        = C.MAC_LEN

	APTOS_ADDRESS_LEN    = C.APTOS_ADDRESS_LEN
	BITCOIN_ADDRESS_LEN  = C.BITCOIN_ADDRESS_LEN
	ETHEREUM_ADDRESS_LEN = C.ETHEREUM_ADDRESS_LEN
	LITECOIN_ADDRESS_LEN = C.LITECOIN_ADDRESS_LEN
	SOLANA_ADDRESS_LEN   = C.SOLANA_ADDRESS_LEN
	SUI_ADDRESS_LEN      = C.SUI_ADDRESS_LEN
	TRON_ADDRESS_LEN     = C.TRON_ADDRESS_LEN

	NETWORK_APTOS    = C.NETWORK_APTOS
	NETWROK_BITCOIN  = C.NETWROK_BITCOIN
	NETWORK_ETHEREUM = C.NETWORK_ETHEREUM
	NETWORK_LITECOIN = C.NETWORK_LITECOIN
	NETWORK_SOLANA   = C.NETWORK_SOLANA
	NETWORK_SUI      = C.NETWORK_SUI
	NETWORK_TRON     = C.NETWORK_TRON
)

// Your password is securely stored in encrypted config or HSM storage
var PASSWORD = C.sized_str{
	str: C.CString("STRONG_PASSWORD"),
	len: 16,
}

type keystore struct {
	cipher       string
	cipherparams cipherParams
	ciphertext   string
	kdf          string
	kdfparams    kdfParams
	mac          string
}

type cipherParams struct {
	iv string
}

type kdfParams struct {
	dklen uintptr
	n     uint32
	r     uint32
	p     uint32
	salt  string
}

func main() {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	cipher := [CIPHER_LEN]byte{}
	cipherPtr := &cipher[0]
	pinner.Pin(cipherPtr)

	iv := [IV_LEN]byte{}
	ivPtr := &iv[0]
	pinner.Pin(ivPtr)

	cipherparams := C.cipherparams{
		iv: newSizedStr(ivPtr, IV_LEN),
	}

	ciphertext := [CIPHERTEXT_LEN]byte{}
	ciphertextPtr := &ciphertext[0]
	pinner.Pin(ciphertextPtr)

	kdf := [KDF_LEN]byte{}
	kdfPtr := &kdf[0]
	pinner.Pin(kdfPtr)

	var (
		dklen C.usize = 0
		n     C.u32   = 0
		r     C.u32   = 0
		p     C.u32   = 0
	)
	dklenPtr := &dklen
	pinner.Pin(dklenPtr)

	nPtr := &n
	pinner.Pin(nPtr)

	rPtr := &r
	pinner.Pin(rPtr)

	pPtr := &p
	pinner.Pin(pPtr)

	salt := [SALT_LEN]byte{}
	saltPtr := &salt[0]
	pinner.Pin(saltPtr)

	kdfparams := C.kdfparams{
		dklen: dklenPtr,
		n:     nPtr,
		r:     rPtr,
		p:     pPtr,
		salt:  newSizedStr(saltPtr, SALT_LEN),
	}

	mac := [MAC_LEN]byte{}
	macPtr := &mac[0]
	pinner.Pin(macPtr)

	k := C.keystore{
		cipher:       newSizedStr(cipherPtr, CIPHER_LEN),
		cipherparams: cipherparams,
		ciphertext:   newSizedStr(ciphertextPtr, CIPHERTEXT_LEN),
		kdf:          newSizedStr(kdfPtr, KDF_LEN),
		kdfparams:    kdfparams,
		mac:          newSizedStr(macPtr, MAC_LEN),
	}

	address := [ETHEREUM_ADDRESS_LEN]byte{}
	addressPtr := &address[0]
	pinner.Pin(addressPtr)
	addressStr := newSizedStr(addressPtr, ETHEREUM_ADDRESS_LEN)

	err := C.init_keystore(&k, addressStr, PASSWORD, NETWORK_ETHEREUM)

	if err != nil {
		fmt.Println(C.GoString(err))
		C.free_cstring(err)
		return
	}

	fmt.Printf("%+v\n", newKeystore(k))
	fmt.Println("address: ", C.GoString(addressStr.str))
}

func newSizedStr(str *byte, len uint) C.sized_str {
	return C.sized_str{
		str: (*C.char)(unsafe.Pointer(str)),
		len: C.usize(len),
	}
}

func newKeystore(k C.keystore) keystore {
	return keystore{
		cipher:       C.GoString(k.cipher.str),
		cipherparams: newCipherParams(k.cipherparams),
		ciphertext:   C.GoString(k.ciphertext.str),
		kdf:          C.GoString(k.kdf.str),
		kdfparams:    newKdfParams(k.kdfparams),
		mac:          C.GoString(k.mac.str),
	}
}

func newCipherParams(p C.cipherparams) cipherParams {
	return cipherParams{
		iv: C.GoString(p.iv.str),
	}
}

func newKdfParams(p C.kdfparams) kdfParams {
	return kdfParams{
		dklen: uintptr(*p.dklen),
		n:     uint32(*p.n),
		r:     uint32(*p.r),
		p:     uint32(*p.p),
		salt:  C.GoString(p.salt.str),
	}
}
