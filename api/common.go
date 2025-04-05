package api

import (
	"errors"
	"wwfc/database"
)

var (
	ErrPostOnly             = errors.New("Incorrect request. POST only.")
	ErrGetOnly              = errors.New("Incorrect request. GET only.")
	ErrPostGetOnly          = errors.New("Incorrect request. POST and GET only.")
	ErrRequestBody          = errors.New("Unable to read request body")
	ErrInvalidSecret        = errors.New("Invalid API secret in request")
	ErrPIDMissing           = errors.New("Profile ID missing or 0 in request")
	ErrDiscordIDMissing     = errors.New("Discord ID missing in request")
	ErrDiscordLinked	    = errors.New("Discord ID already linked to another profile")
	ErrDiscordWrongStep	    = errors.New("Profile is not in the correct step to link Discord ID")
	ErrDiscordCannotUnlink  = errors.New("Discord ID cannot be unlinked")
	ErrActionMissing        = errors.New("Action missing in request")
	ErrReason               = errors.New("Missing reason in request")
	ErrLength               = errors.New("Ban length missing or 0")
	ErrTransaction          = errors.New("Failed to complete database transaction")
	ErrUserQuery            = errors.New("Failed to find user in the database")
	ErrUserQueryTransaction = errors.New("Failed to find user in the database, but the intended transaction may have gone through")
)

func resolveError(err error) string {
	if err != nil {
		return err.Error()
	}

	return ""
}

type UserActionResponse struct {
	User    database.User
	Success bool
	Error   string
}
