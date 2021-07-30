package cipher

import "io"

type none struct {

}

func (n *none) Encrypt(data []byte) int {
	return len(data)
}

func (n *none) Decrypt(data []byte) int {
	return len(data)
}

func (n *none) EncryptCopy(dst io.Writer, src io.Reader) (int, error) {
	b, err := io.Copy(dst, src)
	return int(b), err
}

func (n *none) DecryptCopy(dst io.Writer, src io.Reader) (int, error) {
	b, err := io.Copy(dst, src)
	return int(b), err
}
