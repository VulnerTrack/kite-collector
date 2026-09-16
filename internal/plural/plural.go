// Package plural formats counts with a correctly numbered noun, so
// user-facing text reads "1 machine" and "2 machines" instead of
// "1 machines" or "1 machine(s)".
package plural

import "strconv"

// Count returns "<n> <singular>" when n is 1 and "<n> <singular>s" otherwise.
// Use CountWith for nouns with an irregular plural.
func Count(n int, singular string) string {
	return CountWith(n, singular, singular+"s")
}

// CountWith returns "<n> <singular>" when n is 1 and "<n> <plural>" otherwise.
func CountWith(n int, singular, plural string) string {
	if n == 1 || n == -1 {
		return strconv.Itoa(n) + " " + singular
	}
	return strconv.Itoa(n) + " " + plural
}
