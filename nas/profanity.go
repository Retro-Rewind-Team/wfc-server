package nas

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"wwfc/logging"

	"github.com/fsnotify/fsnotify"
	"github.com/linkdata/deadlock"
)

var profanityFilePath = "./profanity.txt"
var profanityFileLines []string = nil
var profanityLinesMutex = deadlock.Mutex{}

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

func InitProfanity() error {
	err := initWatcher()
	if err != nil {
		logging.Error("NAS:Profanity", "Failed to setup watcher:", err)
	}

	err = readProfanityFile()
	if err != nil {
		return err
	}

	return nil
}

var ProfanityWatcher *fsnotify.Watcher

func initWatcher() error {
	var err error
	ProfanityWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case event, ok := <-ProfanityWatcher.Events:
				{
					if !ok {
						continue
					}

					if !event.Has(fsnotify.Write) {
						continue
					}

					if event.Name != "./profanity.txt" {
						continue
					}

					err := readProfanityFile()
					if err != nil {
						logging.Error("NAS:Profanity", "Failed to read profanity file:", err)
						continue
					}

					logging.Info("NAS:Profanity", "Updated profanity.txt")
					fmt.Println(profanityFileLines)
				}
			case err, ok := <-ProfanityWatcher.Errors:
				if !ok {
					continue
				}

				logging.Error("NAS:Profanity", err)
			}
		}
	}()

	// Watch the entire root directory since events may not happen only to
	// profanity.txt
	if err = ProfanityWatcher.Add("./"); err != nil {
		return err
	}

	return nil
}

func readProfanityFile() error {
	file, err := os.Open(profanityFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	profanityLinesMutex.Lock()
	defer profanityLinesMutex.Unlock()

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
	if urlPattern.MatchString(word) {
		return true, nil
	}
	normalizedWord := normalizeWord(word)

	profanityLinesMutex.Lock()
	defer profanityLinesMutex.Unlock()

	for _, line := range profanityFileLines {
		if strings.EqualFold(line, normalizedWord) {
			return true, nil
		}
	}

	return false, nil
}
