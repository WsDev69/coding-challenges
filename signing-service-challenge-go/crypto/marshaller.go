package crypto

type KeyPairMarshaller interface {
	Marshal(keyPair interface{}) (public []byte, private []byte, err error)
	UnMarshal(privateKeyBytes []byte) (keyPair interface{}, err error)
}
