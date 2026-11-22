package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

const defaultMTProtoSecretHex = "a7c4e91f8b32d6054e19c8a27f50b3d1"

type mtprotoSession struct {
	dc        int
	rawDC     int16
	isMedia   bool
	tag       [4]byte
	protoID   uint32
	clientDec cipher.Stream
	clientEnc cipher.Stream
}

func decodeMTProtoSecret(hexStr string) ([]byte, string, error) {
	s := strings.ToLower(strings.TrimSpace(hexStr))
	if len(s) == 34 && strings.HasPrefix(s, "dd") {
		s = s[2:]
	}
	if len(s) != 32 {
		return nil, "", errors.New("секрет MTProto должен содержать 32 hex-символа (или 34 с префиксом dd)")
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 16 {
		return nil, "", errors.New("некорректный hex-секрет MTProto")
	}
	return raw, s, nil
}

func parseMTProtoClientInit(initBuf []byte, secret []byte) (*mtprotoSession, error) {
	if len(initBuf) != 64 || len(secret) != 16 {
		return nil, errors.New("некорректная длина init или secret")
	}

	hDec := sha256.New()
	hDec.Write(initBuf[8:40])
	hDec.Write(secret)
	decKey := hDec.Sum(nil)
	decIV := initBuf[40:56]

	decBlock, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, err
	}
	clientDec := cipher.NewCTR(decBlock, decIV)

	var dec [64]byte
	clientDec.XORKeyStream(dec[:], initBuf)

	tag := [4]byte{dec[56], dec[57], dec[58], dec[59]}
	var protoID uint32
	switch tag {
	case [4]byte{0xdd, 0xdd, 0xdd, 0xdd}:
		protoID = 0xdddddddd
	case [4]byte{0xee, 0xee, 0xee, 0xee}:
		protoID = 0xeeeeeeee
	case [4]byte{0xef, 0xef, 0xef, 0xef}:
		protoID = 0xefefefef
	default:
		return nil, errors.New("неверный секрет или неподдерживаемый тег MTProto")
	}

	rawDC := int16(binary.LittleEndian.Uint16(dec[60:62]))
	isMedia := rawDC < 0
	dc := int(rawDC)
	if dc < 0 {
		dc = -dc
	}
	if dc >= 10000 {
		dc -= 10000
	}

	var rev [48]byte
	for i := 0; i < 48; i++ {
		rev[i] = initBuf[55-i]
	}

	hEnc := sha256.New()
	hEnc.Write(rev[:32])
	hEnc.Write(secret)
	encKey := hEnc.Sum(nil)
	encIV := rev[32:48]

	encBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	clientEnc := cipher.NewCTR(encBlock, encIV)

	return &mtprotoSession{
		dc:        dc,
		rawDC:     rawDC,
		isMedia:   isMedia,
		tag:       tag,
		protoID:   protoID,
		clientDec: clientDec,
		clientEnc: clientEnc,
	}, nil
}

func isForbiddenInitPrefix(b []byte) bool {
	if b[0] == 0xef {
		return true
	}
	p4 := string(b[:4])
	switch p4 {
	case "HEAD", "POST", "GET ", "OPTI", "\xee\xee\xee\xee", "\xdd\xdd\xdd\xdd", "\x16\x03\x01\x02":
		return true
	}
	if b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 {
		return true
	}
	return false
}

// Генерирует чистый 64-байтовый блок obfuscated2 (без секрета) для стороны Telegram /apiws.
func buildUpstreamInit(tag [4]byte, rawDC int16) ([]byte, cipher.Stream, cipher.Stream, error) {
	var plain [64]byte
	for {
		if _, err := rand.Read(plain[:]); err != nil {
			return nil, nil, nil, err
		}
		if !isForbiddenInitPrefix(plain[:]) {
			break
		}
	}

	copy(plain[56:60], tag[:])
	binary.LittleEndian.PutUint16(plain[60:62], uint16(rawDC))

	upEncBlock, err := aes.NewCipher(plain[8:40])
	if err != nil {
		return nil, nil, nil, err
	}
	upEnc := cipher.NewCTR(upEncBlock, plain[40:56])

	var enc [64]byte
	upEnc.XORKeyStream(enc[:], plain[:])

	outInit := make([]byte, 64)
	copy(outInit[:56], plain[:56])
	copy(outInit[56:], enc[56:])

	var rev [48]byte
	for i := 0; i < 48; i++ {
		rev[i] = plain[55-i]
	}
	upDecBlock, err := aes.NewCipher(rev[:32])
	if err != nil {
		return nil, nil, nil, err
	}
	upDec := cipher.NewCTR(upDecBlock, rev[32:48])

	return outInit, upEnc, upDec, nil
}

// Разрезает расшифрованный поток MTProto на полные сообщения для /apiws.
type plainMTProtoSplitter struct {
	protoID  uint32
	pending  []byte
	disabled bool
}

func newPlainMTProtoSplitter(protoID uint32) *plainMTProtoSplitter {
	return &plainMTProtoSplitter{protoID: protoID}
}

func (s *plainMTProtoSplitter) Push(plain []byte) [][]byte {
	if len(plain) == 0 {
		return nil
	}
	if s.disabled {
		out := make([]byte, len(plain))
		copy(out, plain)
		return [][]byte{out}
	}

	s.pending = append(s.pending, plain...)
	var frames [][]byte

	for len(s.pending) > 0 {
		var frameLen int

		switch s.protoID {
		case 0xdddddddd, 0xeeeeeeee:
			if len(s.pending) < 4 {
				return frames
			}
			rawLen := binary.LittleEndian.Uint32(s.pending[:4])
			payloadLen := int(rawLen & 0x7fffffff)
			if payloadLen <= 0 || payloadLen > 16*1024*1024 {
				s.disabled = true
				rest := make([]byte, len(s.pending))
				copy(rest, s.pending)
				s.pending = nil
				frames = append(frames, rest)
				return frames
			}
			frameLen = 4 + payloadLen

		case 0xefefefef:
			tag := s.pending[0] & 0x7f
			if tag == 0 {
				s.disabled = true
				rest := make([]byte, len(s.pending))
				copy(rest, s.pending)
				s.pending = nil
				frames = append(frames, rest)
				return frames
			}
			if tag < 0x7f {
				frameLen = 1 + int(tag)*4
			} else {
				if len(s.pending) < 4 {
					return frames
				}
				words := int(s.pending[1]) | int(s.pending[2])<<8 | int(s.pending[3])<<16
				if words <= 0 || words > 4*1024*1024 {
					s.disabled = true
					rest := make([]byte, len(s.pending))
					copy(rest, s.pending)
					s.pending = nil
					frames = append(frames, rest)
					return frames
				}
				frameLen = 4 + words*4
			}

		default:
			s.disabled = true
			rest := make([]byte, len(s.pending))
			copy(rest, s.pending)
			s.pending = nil
			frames = append(frames, rest)
			return frames
		}

		if len(s.pending) < frameLen {
			return frames
		}

		frame := make([]byte, frameLen)
		copy(frame, s.pending[:frameLen])
		frames = append(frames, frame)

		remaining := len(s.pending) - frameLen
		if remaining == 0 {
			s.pending = nil
		} else {
			copy(s.pending, s.pending[frameLen:])
			s.pending = s.pending[:remaining]
		}
	}

	return frames
}

// --- Совместимость со старым режимом SOCKS5 ---

type mtprotoInit struct {
	dc      int
	isMedia bool
	protoID uint32
	stream  cipher.Stream
}

func parseObfuscatedInit(initBuf []byte, dstHost string) (mtprotoInit, bool) {
	if len(initBuf) != 64 {
		return mtprotoInit{}, false
	}
	block, err := aes.NewCipher(initBuf[8:40])
	if err != nil {
		return mtprotoInit{}, false
	}
	stream := cipher.NewCTR(block, initBuf[40:56])
	var dec [64]byte
	stream.XORKeyStream(dec[:], initBuf)

	tag := [4]byte{dec[56], dec[57], dec[58], dec[59]}
	var protoID uint32
	switch tag {
	case [4]byte{0xdd, 0xdd, 0xdd, 0xdd}:
		protoID = 0xdddddddd
	case [4]byte{0xee, 0xee, 0xee, 0xee}:
		protoID = 0xeeeeeeee
	case [4]byte{0xef, 0xef, 0xef, 0xef}:
		protoID = 0xefefefef
	default:
		return mtprotoInit{}, false
	}

	rawDC := int16(binary.LittleEndian.Uint16(dec[60:62]))
	isMedia := rawDC < 0
	dc := int(rawDC)
	if dc < 0 {
		dc = -dc
	}
	if dc >= 10000 {
		dc -= 10000
	}
	if dc < 1 || dc > 5 {
		dc = guessDCFromIP(dstHost)
	}
	if dc < 1 || dc > 5 {
		return mtprotoInit{}, false
	}
	return mtprotoInit{dc: dc, isMedia: isMedia, protoID: protoID, stream: stream}, true
}

func guessDCFromIP(host string) int {
	switch {
	case strings.HasPrefix(host, "149.154.175."):
		return 1
	case strings.HasPrefix(host, "149.154.167."):
		return 2
	case strings.HasPrefix(host, "149.154.164."), strings.HasPrefix(host, "149.154.165."), strings.HasPrefix(host, "149.154.166."):
		return 4
	case strings.HasPrefix(host, "91.108.56."):
		return 5
	default:
		return 0
	}
}

type mtprotoSplitter struct {
	protoID   uint32
	stream    cipher.Stream
	cipherBuf []byte
	plainBuf  []byte
	disabled  bool
}

func newMTProtoSplitter(protoID uint32, stream cipher.Stream) *mtprotoSplitter {
	return &mtprotoSplitter{protoID: protoID, stream: stream}
}

func (s *mtprotoSplitter) Push(cipherData []byte) [][]byte {
	if len(cipherData) == 0 {
		return nil
	}
	if s.disabled || s.stream == nil {
		out := make([]byte, len(cipherData))
		copy(out, cipherData)
		return [][]byte{out}
	}

	plain := make([]byte, len(cipherData))
	s.stream.XORKeyStream(plain, cipherData)

	s.cipherBuf = append(s.cipherBuf, cipherData...)
	s.plainBuf = append(s.plainBuf, plain...)

	var frames [][]byte
	for len(s.plainBuf) > 0 {
		var frameLen int
		switch s.protoID {
		case 0xdddddddd, 0xeeeeeeee:
			if len(s.plainBuf) < 4 {
				return frames
			}
			payloadLen := int(binary.LittleEndian.Uint32(s.plainBuf[:4]) & 0x7fffffff)
			if payloadLen <= 0 || payloadLen > 16*1024*1024 {
				s.disabled = true
				rest := make([]byte, len(s.cipherBuf))
				copy(rest, s.cipherBuf)
				s.cipherBuf, s.plainBuf = nil, nil
				return append(frames, rest)
			}
			frameLen = 4 + payloadLen
		case 0xefefefef:
			tag := s.plainBuf[0] & 0x7f
			if tag == 0 {
				s.disabled = true
				rest := make([]byte, len(s.cipherBuf))
				copy(rest, s.cipherBuf)
				s.cipherBuf, s.plainBuf = nil, nil
				return append(frames, rest)
			}
			if tag < 0x7f {
				frameLen = 1 + int(tag)*4
			} else {
				if len(s.plainBuf) < 4 {
					return frames
				}
				words := int(s.plainBuf[1]) | int(s.plainBuf[2])<<8 | int(s.plainBuf[3])<<16
				if words <= 0 || words > 4*1024*1024 {
					s.disabled = true
					rest := make([]byte, len(s.cipherBuf))
					copy(rest, s.cipherBuf)
					s.cipherBuf, s.plainBuf = nil, nil
					return append(frames, rest)
				}
				frameLen = 4 + words*4
			}
		default:
			s.disabled = true
			rest := make([]byte, len(s.cipherBuf))
			copy(rest, s.cipherBuf)
			s.cipherBuf, s.plainBuf = nil, nil
			return append(frames, rest)
		}

		if len(s.plainBuf) < frameLen {
			return frames
		}

		frame := make([]byte, frameLen)
		copy(frame, s.cipherBuf[:frameLen])
		frames = append(frames, frame)

		rem := len(s.plainBuf) - frameLen
		if rem == 0 {
			s.cipherBuf, s.plainBuf = nil, nil
		} else {
			copy(s.cipherBuf, s.cipherBuf[frameLen:])
			copy(s.plainBuf, s.plainBuf[frameLen:])
			s.cipherBuf = s.cipherBuf[:rem]
			s.plainBuf = s.plainBuf[:rem]
		}
	}
	return frames
}
