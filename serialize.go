package sskg

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
)

// MarshalJSON returns the JSON encoding of the (potentially advanced) state Seq.
func (s *Seq) MarshalJSON() ([]byte, error) {
	s.Version = serializationVersion
	j, err := json.Marshal(*s)
	if err != nil {
		return nil, err
	}
	return j, nil
}

// UnmarshalJSON returns a hydrated state Seq from its JSON representation
func UnmarshalJSON(b []byte) (Seq, error) {
	var s Seq
	err := json.Unmarshal(b, &s)

	if err != nil {
		return Seq{}, err
	}

	if s.Version != serializationVersion {
		return Seq{}, errors.New("unknown serialization version")
	}

	s.alg = sha256.New
	return s, nil
}

const serializationVersion = "2020-02-20"
