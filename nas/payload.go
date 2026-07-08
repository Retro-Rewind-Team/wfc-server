package nas

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/logrusorgru/aurora/v3"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"wwfc/logging"
)

func downloadStage1(w http.ResponseWriter, stage1Ver int) {
	// TODO: Actually use the stage 1 version
	dat, err := os.ReadFile("payload/stage1.bin")
	if err != nil {
		panic(err)
	}

	payload := append([]byte{0x01, 0x2C}, dat...)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.Write(payload)
}

type NuggetPayloadManifest struct {
	Format                          string `json:"format"`
	FormatVersion                   int    `json:"formatVersion"`
	Game                            string `json:"game"`
	Target                          string `json:"target"`
	ContractFormat                  string `json:"contractFormat"`
	ContractURL                     string `json:"contractUrl"`
	ContractSHA256                  string `json:"contractSha256"`
	ContractSize                    int    `json:"contractSize"`
	HelperBundleFormat              string `json:"helperBundleFormat,omitempty"`
	HelperBundleURL                 string `json:"helperBundleUrl,omitempty"`
	HelperBundleSHA256              string `json:"helperBundleSha256,omitempty"`
	HelperBundleSize                int    `json:"helperBundleSize,omitempty"`
	PayloadSHA256                   string `json:"payloadSha256"`
	PayloadVersion                  string `json:"payloadVersion"`
	PayloadSize                     int    `json:"payloadSize"`
	MinimumTranslatorVersion        int    `json:"minimumTranslatorVersion"`
	SemanticActions                 int    `json:"semanticActions"`
	PayloadReferences               int    `json:"payloadReferences"`
	PayloadReferencesWithActions    int    `json:"payloadReferencesWithActions"`
	PayloadReferencesWithoutActions int    `json:"payloadReferencesWithoutActions"`
	HelperRequiredActions           int    `json:"helperRequiredActions,omitempty"`
	HelperResolvedActions           int    `json:"helperResolvedActions,omitempty"`
	HelperUnresolvedActions         int    `json:"helperUnresolvedActions,omitempty"`
}

type NuggetContractPayloadInfo struct {
	SHA256  string `json:"sha256"`
	Size    int    `json:"size"`
	Version string `json:"version"`
}

type NuggetContractCompatibility struct {
	MinimumTranslatorVersion int `json:"minimumTranslatorVersion"`
}

type NuggetContractSemanticActionSummary struct {
	ActionsReferenced               int `json:"actionsReferenced"`
	PayloadReferences               int `json:"payloadReferences"`
	PayloadReferencesWithActions    int `json:"payloadReferencesWithActions"`
	PayloadReferencesWithoutActions int `json:"payloadReferencesWithoutActions"`
}

type NuggetContractGeneratedArtifacts struct {
	HelperBundle NuggetContractHelperBundleArtifact `json:"helperBundle"`
}

type NuggetContractHelperBundleArtifact struct {
	Format                 string                       `json:"format"`
	Path                   string                       `json:"path"`
	SHA256                 string                       `json:"sha256"`
	SemanticActionCoverage NuggetSemanticActionCoverage `json:"semanticActionCoverage"`
}

type NuggetSemanticActionCoverage struct {
	RequiredActions   int `json:"requiredActions"`
	ResolvedActions   int `json:"resolvedActions"`
	UnresolvedActions int `json:"unresolvedActions"`
}

type NuggetContractHeader struct {
	Format                string                              `json:"format"`
	Contract              string                              `json:"contract"`
	Target                string                              `json:"target"`
	Payload               NuggetContractPayloadInfo           `json:"payload"`
	Compatibility         NuggetContractCompatibility         `json:"compatibility"`
	SemanticActionSummary NuggetContractSemanticActionSummary `json:"semanticActionSummary"`
	GeneratedArtifacts    NuggetContractGeneratedArtifacts    `json:"generatedArtifacts"`
}

func handleNuggetPayloadRequest(moduleName string, w http.ResponseWriter, r *http.Request) {
	game, err := NuggetPayloadGameID(r)
	if err != nil {
		logging.Error(moduleName, err)
		replyHTTPError(w, http.StatusBadRequest, "400 Bad Request")
		return
	}

	contract, contractHeader, err := NuggetContractForGame(game)
	if err != nil {
		logging.Error(moduleName, "Failed to read Nugget contract:", err)
		replyHTTPError(w, http.StatusNotFound, "404 Not Found")
		return
	}
	contractHash := sha256.Sum256(contract)
	contractHashHex := hex.EncodeToString(contractHash[:])

	switch r.URL.Path {
	case "/payload/Nugget/v1/manifest":
		helperBundle, helperBundleHash, err := NuggetHelperBundleForGame(contractHeader)
		if err != nil {
			logging.Error(moduleName, "Failed to read Nugget helper bundle:", err)
			replyHTTPError(w, http.StatusInternalServerError, "500 Internal Server Error")
			return
		}

		manifest := NuggetPayloadManifest{
			Format:                          "retro-wfc-Nugget-payload-manifest",
			FormatVersion:                   1,
			Game:                            game,
			Target:                          contractHeader.Target,
			ContractFormat:                  contractHeader.Contract,
			ContractURL:                     buildNuggetContractURL(r, game),
			ContractSHA256:                  contractHashHex,
			ContractSize:                    len(contract),
			HelperBundleFormat:              contractHeader.GeneratedArtifacts.HelperBundle.Format,
			HelperBundleURL:                 buildNuggetHelperBundleURL(r, game),
			HelperBundleSHA256:              helperBundleHash,
			HelperBundleSize:                len(helperBundle),
			PayloadSHA256:                   contractHeader.Payload.SHA256,
			PayloadVersion:                  contractHeader.Payload.Version,
			PayloadSize:                     contractHeader.Payload.Size,
			MinimumTranslatorVersion:        contractHeader.Compatibility.MinimumTranslatorVersion,
			SemanticActions:                 contractHeader.SemanticActionSummary.ActionsReferenced,
			PayloadReferences:               contractHeader.SemanticActionSummary.PayloadReferences,
			PayloadReferencesWithActions:    contractHeader.SemanticActionSummary.PayloadReferencesWithActions,
			PayloadReferencesWithoutActions: contractHeader.SemanticActionSummary.PayloadReferencesWithoutActions,
			HelperRequiredActions:           contractHeader.GeneratedArtifacts.HelperBundle.SemanticActionCoverage.RequiredActions,
			HelperResolvedActions:           contractHeader.GeneratedArtifacts.HelperBundle.SemanticActionCoverage.ResolvedActions,
			HelperUnresolvedActions:         contractHeader.GeneratedArtifacts.HelperBundle.SemanticActionCoverage.UnresolvedActions,
		}

		body, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			logging.Error(moduleName, "Failed to marshal Nugget manifest:", err)
			replyHTTPError(w, http.StatusInternalServerError, "500 Internal Server Error")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Write(body)
	case "/payload/Nugget/v1/contract":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(contract)))
		w.Header().Set("X-Retro-WFC-Contract-SHA256", contractHashHex)
		w.Write(contract)
	case "/payload/Nugget/v1/helper-bundle":
		helperBundle, helperBundleHash, err := NuggetHelperBundleForGame(contractHeader)
		if err != nil {
			logging.Error(moduleName, "Failed to read Nugget helper bundle:", err)
			replyHTTPError(w, http.StatusInternalServerError, "500 Internal Server Error")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(helperBundle)))
		w.Header().Set("X-Retro-WFC-Helper-Bundle-SHA256", helperBundleHash)
		w.Write(helperBundle)
	case "/payload/Nugget/v1/binary":
		payload, err := os.ReadFile("payload/binary/payload." + game + ".bin")
		if err != nil {
			logging.Error(moduleName, "Failed to read Nugget payload file:", err)
			replyHTTPError(w, http.StatusNotFound, "404 Not Found")
			return
		}
		payloadHash := sha256.Sum256(payload)
		payloadHashHex := hex.EncodeToString(payloadHash[:])
		if !strings.EqualFold(payloadHashHex, contractHeader.Payload.SHA256) {
			logging.Error(moduleName, "Nugget payload hash mismatch for game ", game)
			replyHTTPError(w, http.StatusInternalServerError, "500 Internal Server Error")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.Header().Set("X-Retro-WFC-Payload-SHA256", payloadHashHex)
		w.Write(payload)
	default:
		replyHTTPError(w, http.StatusNotFound, "404 Not Found")
	}
}

func handlePayloadRequest(moduleName string, w http.ResponseWriter, r *http.Request) {
	// Example request:
	// GET /payload?g=RMCPD00&s=4e44b095817f8cfb62e6cffd57e9cfd411004a492784039ea4b2b7ca64717c91&h=9fdb6f60

	u, err := url.Parse(r.URL.String())
	if err != nil {
		logging.Error(moduleName, "Failed to parse URL")
		return
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		logging.Error(moduleName, "Failed to parse URL query")
		return
	}

	// Read payload ID (g) from URL
	game := query.Get("g")
	if len(game) != 7 && len(game) != 9 {
		logging.Error(moduleName, "Invalid or missing game ID:", aurora.Cyan(game))
		return
	}

	if (len(game) == 7 && game[4] != 'D') || (len(game) == 9 && game[4] != 'N') {
		logging.Error(moduleName, "Invalid game ID:", aurora.Cyan(game))
		return
	}

	for i := 0; i < 4; i++ {
		if (game[i] >= 'A' && game[i] <= 'Z') || (game[i] >= '0' && game[i] <= '9') {
			continue
		}

		logging.Error(moduleName, "Invalid game ID char:", aurora.Cyan(game))
		return
	}

	for i := 5; i < len(game); i++ {
		if (game[i] >= '0' && game[i] <= '9') || (game[i] >= 'a' && game[i] <= 'f') {
			continue
		}

		logging.Error(moduleName, "Invalid game ID version:", aurora.Cyan(game))
		return
	}

	dat, err := os.ReadFile("payload/binary/payload." + game + ".bin")
	if err != nil {
		logging.Error(moduleName, "Failed to read payload file")
		return
	}

	salt, ok := query["s"]
	if ok {
		if len(salt[0]) != 64 {
			logging.Error(moduleName, "Invalid salt length:", aurora.BrightCyan(len(salt[0])))
			return
		}

		_, err := hex.DecodeString(salt[0])
		if err != nil {
			logging.Error(moduleName, "Invalid salt hex string")
			return
		}

		saltHashTest, ok := query["h"]
		if !ok {
			logging.Error(moduleName, "Request is missing salt hash")
			return
		}

		if len(saltHashTest[0]) != 8 {
			logging.Error(moduleName, "Invalid salt hash length:", aurora.BrightCyan(len(saltHashTest[0])))
			return
		}

		saltHashTestData, err := hex.DecodeString(saltHashTest[0])
		if err != nil {
			logging.Error(moduleName, "Invalid salt hash hex string")
			return
		}

		// Generate the salt hash
		saltHashData := "payload?g=" + query["g"][0] + "&s=" + query["s"][0]

		hashCtx := sha256.New()
		_, err = hashCtx.Write([]byte(saltHashData))
		if err != nil {
			panic(err)
		}

		saltHash := hashCtx.Sum(nil)
		if !bytes.Equal(saltHashTestData, saltHash[:4]) {
			logging.Error(moduleName, "Salt hash mismatch")
			return
		}

		dat = append(append(dat[:0x110], saltHash...), dat[0x130:]...)
	}

	// TODO: Cache the request for a zero salt

	rsaData, err := os.ReadFile("payload/private-key.pem")
	if err != nil {
		panic(err)
	}

	rsaBlock, _ := pem.Decode(rsaData)
	parsedKey, err := x509.ParsePKCS8PrivateKey(rsaBlock.Bytes)
	if err != nil {
		panic(err)
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		panic("Unexpected key type")
	}

	// Hash our data then sign
	hash := sha256.New()
	_, err = hash.Write(dat[0x110:])
	if err != nil {
		panic(err)
	}

	contentsHashSum := hash.Sum(nil)

	reader := rand.Reader
	signature, err := rsa.SignPKCS1v15(reader, rsaKey, crypto.SHA256, contentsHashSum)
	if err != nil {
		panic(err)
	}

	dat = append(append(dat[:0x10], signature...), dat[0x110:]...)

	w.Header().Set("Content-Length", strconv.Itoa(len(dat)))
	w.Write(dat)
}

func NuggetPayloadGameID(r *http.Request) (string, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", err
	}

	game := query.Get("g")
	if len(game) != 7 && len(game) != 9 {
		return "", errors.New("invalid or missing game ID: " + game)
	}

	if (len(game) == 7 && game[4] != 'D') || (len(game) == 9 && game[4] != 'N') {
		return "", errors.New("invalid game ID: " + game)
	}

	for i := 0; i < 4; i++ {
		if (game[i] >= 'A' && game[i] <= 'Z') || (game[i] >= '0' && game[i] <= '9') {
			continue
		}
		return "", errors.New("invalid game ID char: " + game)
	}

	for i := 5; i < len(game); i++ {
		if (game[i] >= '0' && game[i] <= '9') || (game[i] >= 'a' && game[i] <= 'f') {
			continue
		}
		return "", errors.New("invalid game ID version: " + game)
	}

	return game, nil
}

func NuggetContractForGame(game string) ([]byte, NuggetContractHeader, error) {
	contractPath := "payload/Nugget/contract." + game + ".json"
	dat, err := os.ReadFile(contractPath)
	if err != nil {
		return nil, NuggetContractHeader{}, err
	}

	header, err := parseNuggetContractHeader(dat)
	return dat, header, err
}

func parseNuggetContractHeader(dat []byte) (NuggetContractHeader, error) {
	var header NuggetContractHeader
	if err := json.Unmarshal(dat, &header); err != nil {
		return header, err
	}
	if header.Format != "retro-wfc-Nugget-contract" {
		return header, errors.New("invalid Nugget contract format: " + header.Format)
	}
	if header.Contract != "retro-wfc-Nugget-contract-v1" {
		return header, errors.New("invalid Nugget contract version: " + header.Contract)
	}
	return header, nil
}

func NuggetHelperBundleForGame(contract NuggetContractHeader) ([]byte, string, error) {
	artifact := contract.GeneratedArtifacts.HelperBundle
	if artifact.Path == "" {
		return nil, "", errors.New("contract does not reference a helper bundle")
	}

	path, err := NuggetArtifactPath(artifact.Path)
	if err != nil {
		return nil, "", err
	}

	dat, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	hash := sha256.Sum256(dat)
	hashHex := hex.EncodeToString(hash[:])
	if artifact.SHA256 != "" && !strings.EqualFold(hashHex, artifact.SHA256) {
		return nil, "", errors.New("helper bundle hash mismatch")
	}

	return dat, hashHex, nil
}

func NuggetArtifactPath(path string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(path))
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", errors.New("invalid Nugget artifact path: " + path)
	}
	return filepath.Join("payload", clean), nil
}

func buildNuggetContractURL(r *http.Request, game string) string {
	return buildNuggetPayloadBaseURL(r) + "/payload/Nugget/v1/contract?g=" + url.QueryEscape(game)
}

func buildNuggetHelperBundleURL(r *http.Request, game string) string {
	return buildNuggetPayloadBaseURL(r) + "/payload/Nugget/v1/helper-bundle?g=" + url.QueryEscape(game)
}

func buildNuggetPayloadBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwardedProto := r.Header.Get("X-Forwarded-Proto"); forwardedProto != "" {
		scheme = strings.Split(forwardedProto, ",")[0]
	}

	host := r.Host
	if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		host = strings.Split(forwardedHost, ",")[0]
	}

	return scheme + "://" + host
}
