package messageswitch

import (
	"sync"

	"golang.org/x/crypto/nacl/box"
)

func computeKeyCacheHashKey(pubServiceIdent, priServiceIdent int) (cacheKey uint32) {
	cacheKey = ((uint32(pubServiceIdent) << 16) & 0xFFFF0000) | (uint32(priServiceIdent) & 0xFFFF)
	return
}

type precomputedKeyCache struct {
	lck      sync.Mutex
	keyCache map[uint32]*[32]byte
}

func (c *precomputedKeyCache) getDecryptSharedKey(srcServiceConn, destServiceConn *serviceConnect) (sharedKey *[32]byte) {
	cacheKey := computeKeyCacheHashKey(srcServiceConn.SerialIdent, destServiceConn.SerialIdent)
	c.lck.Lock()
	defer c.lck.Unlock()
	if sharedKey = c.keyCache[cacheKey]; sharedKey != nil {
		return
	}
	sharedKey = new([32]byte)
	box.Precompute(sharedKey, srcServiceConn.PublicKey.Ref(), destServiceConn.PrivateKey.Ref())
	c.keyCache[cacheKey] = sharedKey
	return sharedKey
}

func (c *precomputedKeyCache) getEncryptSharedKey(srcServiceConn, destServiceConn *serviceConnect) (sharedKey *[32]byte) {
	cacheKey := computeKeyCacheHashKey(destServiceConn.SerialIdent, srcServiceConn.SerialIdent)
	c.lck.Lock()
	defer c.lck.Unlock()
	if sharedKey = c.keyCache[cacheKey]; sharedKey != nil {
		return
	}
	sharedKey = new([32]byte)
	box.Precompute(sharedKey, destServiceConn.PublicKey.Ref(), srcServiceConn.PrivateKey.Ref())
	c.keyCache[cacheKey] = sharedKey
	return sharedKey
}
