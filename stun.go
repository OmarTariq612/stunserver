package stunserver

import "io"

func readFullOrPanic(r io.Reader, data []byte) int {
	n, err := io.ReadFull(r, data)
	if err != nil {
		panic(err)
	}
	return n
}

func writeOrPanic(w io.Writer, data []byte) int {
	n, err := w.Write(data)
	if err != nil {
		panic(err)
	}
	return n
}

type transactionIDSetter struct{}

func (transactionIDSetter) AddTo(m *Message) error {
	return m.NewTransactionID()
}

// TransactionID is Setter for m.TransactionID.
var TransactionID Setter = transactionIDSetter{} //nolint:gochecknoglobals
