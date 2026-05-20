// Package vaultpath normalises "<mount>/<path>" strings that flow
// between the audit parser, the policy store, and the patcher. One
// helper set, instead of ad-hoc Trim/Split in every package.
package vaultpath

import "strings"

// Join concatenates mount and path into "<mount>/<path>", trimming
// stray slashes on both inputs. Either argument may be empty.
func Join(mount, path string) string {
	m := Normalize(mount)
	p := Normalize(path)
	switch {
	case m == "":
		return p
	case p == "":
		return m
	default:
		return m + "/" + p
	}
}

// Split returns the mount and path components of a "<mount>/<path>"
// key, splitting on the first "/". When there is no "/", the whole
// input is treated as the mount and path is empty. Leading and
// trailing slashes are stripped first.
func Split(key string) (mount, path string) {
	key = Normalize(key)
	if i := strings.IndexByte(key, '/'); i >= 0 {
		return key[:i], key[i+1:]
	}
	return key, ""
}

func Normalize(s string) string {
	return strings.Trim(s, "/")
}
