package sskg_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/oreparaz/sskg"
)

func seqEqual(s1 sskg.Seq, s2 sskg.Seq) bool {
	b1 := s1.Key(32)
	b2 := s2.Key(32)

	return bytes.Equal(b1, b2)
}

func TestSerializeRoundtrip(t *testing.T) {
	seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
	seq.Seek(10000)
	stateMarshaled, err := seq.MarshalJSON()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	seqRecovered, err := sskg.UnmarshalJSON(stateMarshaled)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !seqEqual(seq, seqRecovered) {
		t.Errorf("Seq are not identical")
	}
}

func TestSerializeVector(t *testing.T) {
	const serializedState = "{\"nodes\":[{\"k\":\"sv0teIr43Ynf7u+JSL0of7OWcVwmsqu25m1lfkHAprQ=\",\"h\":32},{\"k\":\"Fq4IhJ+eFsru4EGhfMkP45fM9+CUfaU9+TUtw2vsLpo=\",\"h\":31},{\"k\":\"Kiqz0NxQD0JEfH4KfE+nS5WsyoFxwlVAH5X077aK4Wg=\",\"h\":30},{\"k\":\"WprxJ8XFiWZdL765YjO8RuVHsRtDijhDd3ERpx7g/Dk=\",\"h\":29},{\"k\":\"PcuKd8Q6QYaD2rIyNsc6VlDv3FyZozcJK8u3qsR025c=\",\"h\":28},{\"k\":\"VvrVxoeHHH7jeZupBrWTNhz17z99v+vxBB3Bilyo8A0=\",\"h\":27},{\"k\":\"0JziaME7RldTbb4l6O1is0QV8CFoVFh/pjkcoC2VBR0=\",\"h\":26},{\"k\":\"gem6sCoMjNKIHN9Br//WqcdaV0LhypBJUPx4vWSYgNM=\",\"h\":25},{\"k\":\"/xDLHyYOyqh7Ij4Fi+3/zI2V9eUcH+a6yOBTg1KuQck=\",\"h\":24},{\"k\":\"4dejR4eoLk8FUq/WGGZIJBwY8SgR4aMaPHk/BlD9PnI=\",\"h\":23},{\"k\":\"y8fFqntW7Q1qy+UY1/CF2QErGIjJ0rtw8yjgGdWaRn4=\",\"h\":22},{\"k\":\"2kes1JdlQ20MEN5eyHqzQHguLdMKjxqW0vtYecFZjc8=\",\"h\":21},{\"k\":\"pZiPFq469aPkBkX2zKfi1GjS6nyOc7R+fReydovnhfE=\",\"h\":20},{\"k\":\"i+EZO0HteUdMZKmZzVBYJIOXQkZsrMPxuNT500KCYPk=\",\"h\":19},{\"k\":\"/8qyLS4BtzbSx/PZMHrd3NZ/Ok0vaexjXCm7xDlUxg8=\",\"h\":18},{\"k\":\"1tXAhlsCFzxkitfGSYLhtphg/tSnaLKmzB0Sn8uvkJk=\",\"h\":17},{\"k\":\"cL7YNcPw0dfwZ4t0iO6G2n8gtVEHPlS348v1GkZp0/w=\",\"h\":16},{\"k\":\"2Y+7KwR+teAKUphk6A6xlDd05k7PNsxgIkgrPIbOgm0=\",\"h\":15},{\"k\":\"0q+9a1Qu3TjJZnjUBRehoG3ppnxUZpGxEtdnn99eUTs=\",\"h\":14},{\"k\":\"HJCwoLzwzDTNvHgPewFeKTnb33QeGHZ8ebQiLOvQ7ZM=\",\"h\":12},{\"k\":\"tnYB8D2Q0BzAdmp1MXqKkCa4A71WWZua8ZTM1c9pdSA=\",\"h\":11},{\"k\":\"msS3XAcxgdBvWiFLRLiaz/g0/vpp+k46xoCKwkNCkvs=\",\"h\":8},{\"k\":\"FvAueKwnuUlULJqqKk0emQBYluQ1qSCOXvQapEipewI=\",\"h\":2},{\"k\":\"yeScZDKQ3g/mTxSeMfYr7G4a+jyuUhoVbTcEo/YxUlo=\",\"h\":1},{\"k\":\"bpKNemA5MWKU2J9wipx01qiEFCoVavrL7KbTf1dxhEs=\",\"h\":1}],\"size\":32,\"version\":\"2020-02-20\"}"

	seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
	seq.Seek(10000)
	seqRecovered, err := sskg.UnmarshalJSON([]byte(serializedState))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !seqEqual(seq, seqRecovered) {
		t.Errorf("Seq are not identical")
	}
}
