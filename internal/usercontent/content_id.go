package usercontent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

const (
	contentIDTimestampSz = 8
	contentIDMacSz       = sha256.Size
	contentIDSize        = contentIDTimestampSz + contentIDMacSz
)

var (
	errInvalidLength  = errors.New("usercontent: invalid length")
	errInvalidContent = errors.New("usercontent: invalid content")
)

// MakeContentID deterministically derives a content identifier for the
// provided creation time and secret key. The identifier embeds the timestamp
// and authenticates it via HMAC-SHA256.
func MakeContentID(createdAt time.Time, contentIDKey []byte) ([]byte, error) {
	if len(contentIDKey) == 0 {
		return nil, errors.New("usercontent: empty contentID key")
	}
	ts := make([]byte, contentIDTimestampSz)
	binary.BigEndian.PutUint64(ts, uint64(createdAt.UnixNano()))

	mac := hmac.New(sha256.New, contentIDKey)
	if _, err := mac.Write(ts); err != nil {
		return nil, err
	}
	sum := mac.Sum(nil)

	out := make([]byte, contentIDSize)
	copy(out, ts)
	copy(out[contentIDTimestampSz:], sum)
	return out, nil
}

// ParseContentID verifies the identifier and recovers the embedded timestamp.
func ParseContentID(contentID []byte, contentIDKey []byte) (time.Time, error) {
	if len(contentIDKey) == 0 {
		return time.Time{}, errors.New("usercontent: empty contentID key")
	}
	if len(contentID) != contentIDSize {
		return time.Time{}, errInvalidLength
	}
	tsBytes := contentID[:contentIDTimestampSz]
	macBytes := contentID[contentIDTimestampSz:]

	mac := hmac.New(sha256.New, contentIDKey)
	if _, err := mac.Write(tsBytes); err != nil {
		return time.Time{}, err
	}
	if !hmac.Equal(mac.Sum(nil), macBytes) {
		return time.Time{}, errInvalidContent
	}

	nanos := int64(binary.BigEndian.Uint64(tsBytes))
	return time.Unix(0, nanos), nil
}
