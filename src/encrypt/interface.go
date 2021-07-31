package encrypt

import "io"

type Copier interface {
	EncryptCopy(dst io.Writer, src io.Reader) (int, error)
	DecryptCopy(dst io.Writer, src io.Reader) (int, error)
}

type Cipher interface {
	Encrypt(data []byte) int
	Decrypt(data []byte) int
	Copier
}
