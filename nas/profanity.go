package nas

import (
	"bufio"
	"errors"
	"os"
	"regexp"
	"strings"
	"time"
)

var profanityFilePath = "./profanity.txt"
var profanityFileLines []string = nil
var lastModTime time.Time

var symbolEquivalences = map[rune]rune{
    '1': 'i',
    '0': 'o',
    '5': 's',
    '4': 'a',
    '3': 'e',
    '7': 't',
    '9': 'g',
    '2': 'z',
    '(': 'c',
	'©': 'c',
	'®': 'r',
	'&': 'a',
	'@': 'a',
	'!': 'i',
	'$': 's',
	'#': 'h',
	'α': 'a',
	'β': 'b',
	'γ': 'g',
	'δ': 'd',
	'': 'a', // These are symbols with letters in them
	'': 'b',
	'': 'x',
	'': 'y',
	'': 'l',
	'': 'r',
	'': 'a',
	'': 'b',
	'': 'c',
	'': 'd',
	'': 'e',
	// '': 'er', // TODO find a solution to normalize this
	// '': 're',
	'': 'e',
	'': '2',
	'': '2',
	'': 'a',
	'': 'a',
	'': 'a',
	'': 'a',
	'': 'a',
	'': 'a',
	'': 'b',
	'': '1',
	'': 'b',
	'': 'b',
	'': 's',
	'': 's',
}

// This is basically [A-Za-z0-9]+\.[A-Za-z]+/ but with added cases for if the user tries to evade the filter
var urlPattern = regexp.MustCompile(
    `(?i)[a-zA-Z0-9-]+(\.|(\s*[\[\(\{]?\s*dot\s*[\]\)\}]?\s*))+[a-zA-Z0-9-]+(\s*/\s*|\s*[\[\(\{]?\s*slash\s*[\]\)\}]?\s*)`,
)

func CacheProfanityFile() error {
	fileInfo, err := os.Stat(profanityFilePath)
	if err != nil {
		return err
	}

	if !fileInfo.ModTime().After(lastModTime) && profanityFileLines != nil {
		return nil
	}

	file, err := os.Open(profanityFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	profanityFileLines = nil
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			continue
		}

		profanityFileLines = append(profanityFileLines, line)
	}

	if profanityFileLines == nil {
		return errors.New("the file '" + profanityFilePath + "' is empty")
	}

	lastModTime = fileInfo.ModTime()
	return nil
}

func normalizeWord(word string) string {
	var normalized strings.Builder
	for _, char := range word {
		if equivalent, exists := symbolEquivalences[char]; exists {
			normalized.WriteRune(equivalent)
		} else {
			normalized.WriteRune(char)
		}
	}
	return normalized.String()
}

func IsBadWord(word string) (bool, error) {
	if !isProfanityFileCached() {
		err := CacheProfanityFile()
		if err != nil {
			return false, errors.New("the file '" + profanityFilePath + "' has not been cached")
		}

	}

	if urlPattern.MatchString(word) {
		return true, nil
	}
	normalizedWord := normalizeWord(word)
	for _, line := range profanityFileLines {
		if strings.EqualFold(line, normalizedWord) {
			return true, nil
		}
	}

	return false, nil
}

func isProfanityFileCached() bool {
	fileInfo, err := os.Stat(profanityFilePath)
	if err != nil {
		return false
	}
	return profanityFileLines != nil && !fileInfo.ModTime().After(lastModTime)
}
