package encrypt

import "io"

type None struct{}

func (n *None) Encrypt(data []byte) int {
	return len(data)
}

func (n *None) Decrypt(data []byte) int {
	return len(data)
}

func (n *None) EncryptCopy(dst io.Writer, src io.Reader) (int, error) {
	b, err := io.Copy(dst, src)
	return int(b), err
}

func (n *None) DecryptCopy(dst io.Writer, src io.Reader) (int, error) {
	b, err := io.Copy(dst, src)
	return int(b), err
}
