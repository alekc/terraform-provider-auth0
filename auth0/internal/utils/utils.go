package utils

import (
	"crypto/md5"
	"fmt"
	"sort"
	"strings"
)

// StringChecksum takes a string and returns the checksum of the string.
func StringChecksum(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)

	return fmt.Sprintf("%x", bs)
}

// StringListChecksum takes an unordered list of strings and returns the checksum of the strings.
func StringListChecksum(s []string) string {
	sort.Strings(s)
	return StringChecksum(strings.Join(s, ""))
}
