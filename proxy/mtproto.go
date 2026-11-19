package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"strings"
)

type mtprotoInit struct {
	dc      int
	isMedia bool
	protoID uint32
	stream  cipher.Stream
}

func parseObfuscatedInit(init []byte, dstHost string) (mtprotoInit, bool) {
	if len(init) < 64 {
		return mtprotoInit{}, false
	}

	key := init[8:40]
	iv := init[40:56]

	block, err := aes.NewCipher(key)
	if err != nil {
		return mtprotoInit{}, false
	}

	stream := cipher.NewCTR(block, iv)
	decrypted := make([]byte, 64)
	stream.XORKeyStream(decrypted, init[:64])

	protoID := binary.LittleEndian.Uint32(decrypted[56:60])
	if protoID != 0xefefefef && protoID != 0xeeeeeeee && protoID != 0xdddddddd {
		return mtprotoInit{}, false
	}

	rawDC := int16(binary.LittleEndian.Uint16(decrypted[60:62]))
	var isMedia bool
	var dc int
	if rawDC < 0 {
		isMedia = true
		dc = int(-rawDC)
	} else {
		dc = int(rawDC)
	}

	if dc == 0 {
		dc = dcFromIP(dstHost)
	}

	return mtprotoInit{
		dc:      dc,
		isMedia: isMedia,
		protoID: protoID,
		stream:  stream,
	}, true
}

func dcFromIP(ip string) int {
	switch {
	case strings.HasPrefix(ip, "149.154.175.5"):
		return 1
	case strings.HasPrefix(ip, "149.154.175."):
		return 3
	case strings.HasPrefix(ip, "149.154.164."), strings.HasPrefix(ip, "149.154.165."), strings.HasPrefix(ip, "149.154.166."):
		return 4
	case strings.HasPrefix(ip, "149.154.167."):
		return 2
	case strings.HasPrefix(ip, "91.108.56."), strings.HasPrefix(ip, "91.108.57."):
		return 5
	default:
		return 0
	}
}

type mtprotoSplitter struct {
	protoID uint32
	stream  cipher.Stream
	encBuf  []byte
	decBuf  []byte
	broken  bool
}

func newMTProtoSplitter(protoID uint32, stream cipher.Stream) *mtprotoSplitter {
	return &mtprotoSplitter{
		protoID: protoID,
		stream:  stream,
	}
}

func (m *mtprotoSplitter) Push(encChunk []byte) [][]byte {
	if m.broken || m.stream == nil {
		out := make([]byte, len(encChunk))
		copy(out, encChunk)
		return [][]byte{out}
	}

	decChunk := make([]byte, len(encChunk))
	m.stream.XORKeyStream(decChunk, encChunk)

	m.encBuf = append(m.encBuf, encChunk...)
	m.decBuf = append(m.decBuf, decChunk...)

	var frames [][]byte
	for len(m.decBuf) > 0 {
		frameLen, ready := m.nextFrameLen()
		if !ready {
			break
		}
		if frameLen <= 0 || frameLen > 16*1024*1024 {
			m.broken = true
			raw := make([]byte, len(m.encBuf))
			copy(raw, m.encBuf)
			m.encBuf = nil
			m.decBuf = nil
			frames = append(frames, raw)
			return frames
		}
		if len(m.decBuf) < frameLen {
			break
		}
		frame := make([]byte, frameLen)
		copy(frame, m.encBuf[:frameLen])
		frames = append(frames, frame)

		m.encBuf = m.encBuf[frameLen:]
		m.decBuf = m.decBuf[frameLen:]
	}

	if len(m.encBuf) == 0 {
		m.encBuf = nil
		m.decBuf = nil
	} else if cap(m.encBuf) > 256*1024 && len(m.encBuf) < cap(m.encBuf)/2 {
		m.encBuf = append([]byte(nil), m.encBuf...)
		m.decBuf = append([]byte(nil), m.decBuf...)
	}

	return frames
}

func (m *mtprotoSplitter) nextFrameLen() (int, bool) {
	switch m.protoID {
	case 0xefefefef:
		if len(m.decBuf) < 1 {
			return 0, false
		}
		b0 := m.decBuf[0] & 0x7f
		if b0 < 0x7f {
			return 1 + int(b0)*4, true
		}
		if len(m.decBuf) < 4 {
			return 0, false
		}
		words := int(m.decBuf[1]) | int(m.decBuf[2])<<8 | int(m.decBuf[3])<<16
		return 4 + words*4, true
	case 0xeeeeeeee, 0xdddddddd:
		if len(m.decBuf) < 4 {
			return 0, false
		}
		payloadLen := binary.LittleEndian.Uint32(m.decBuf[0:4]) & 0x7fffffff
		return 4 + int(payloadLen), true
	default:
		return -1, true
	}
}
