package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	// "time"
	"wwfc/database"
	// "wwfc/gpcm"
	// "wwfc/logging"

	// "github.com/logrusorgru/aurora/v3"
)

func HandleLink(w http.ResponseWriter, r *http.Request) {
	var user *database.User
	var statusCode int
	var err error

	if r.Method == http.MethodPost {
		user, statusCode, err = handleLinkImpl(r)
	} else if r.Method == http.MethodOptions {
		statusCode = http.StatusNoContent
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	} else {
		err = ErrPostOnly
		statusCode = http.StatusMethodNotAllowed
		w.Header().Set("Allow", "POST")
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")

	if user == nil {
		user = &database.User{}
	}

	var jsonData []byte

	if statusCode != http.StatusNoContent {
		w.Header().Set("Content-Type", "application/json")
		jsonData, _ = json.Marshal(UserActionResponse{*user, err == nil, resolveError(err)})
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
	w.WriteHeader(statusCode)
	w.Write(jsonData)
}

type LinkRequestSpec struct {
		Secret    string `json:"secret"`
		ProfileID uint32 `json:"pid"`
		DiscordID string `json:"discordId"`
		Action  string `json:"action"`
}

func handleLinkImpl(r *http.Request) (*database.User, int, error) {
	// TODO: Actual authentication rather than a fixed secret

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, http.StatusBadRequest, ErrRequestBody
	}

	var req LinkRequestSpec
	err = json.Unmarshal(body, &req)
	if err != nil {
		return nil, http.StatusBadRequest, ErrRequestBody
	}

	if apiSecret == "" || req.Secret != apiSecret {
		return nil, http.StatusUnauthorized, ErrInvalidSecret
	}

	if req.ProfileID == 0 {
		return nil, http.StatusBadRequest, ErrPIDMissing
	}

	if req.DiscordID == "" {
		return nil, http.StatusBadRequest, ErrDiscordIDMissing
	}

	if req.Action == "" || (req.Action != "link" && req.Action != "check" && req.Action != "unlink") {
		return nil, http.StatusBadRequest, ErrActionMissing
	}

	user, success := database.GetProfile(pool, ctx, req.ProfileID)
	if !success {
		return nil, http.StatusInternalServerError, ErrUserQuery
	}

	if req.Action == "link" {
		if user.DiscordID != "" {
			return nil, http.StatusForbidden, ErrDiscordLinked
		}
		err = user.UpdateDiscordID(pool, ctx, "1")
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
	} else if req.Action == "check" {
		if user.DiscordID != "2" {
			return nil, http.StatusForbidden, ErrDiscordWrongStep
		}
		err = user.UpdateDiscordID(pool, ctx, req.DiscordID)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
	} else if req.Action == "unlink" {
		if user.DiscordID != "1" && user.DiscordID != "2" && user.DiscordID != req.DiscordID {
			return nil, http.StatusForbidden, ErrDiscordCannotUnlink
		}
		err = user.UpdateDiscordID(pool, ctx, "")
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
	}

	return &user, http.StatusOK, nil
}