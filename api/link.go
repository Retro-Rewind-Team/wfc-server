package api

import (
	"errors"
	"net/http"
	"wwfc/database"
	"wwfc/gpcm"
)

type LinkRequest struct {
	Secret    string `json:"secret"`
	ProfileID uint32 `json:"pid"`
	DiscordID string `json:"discordID"`
	Action    string `json:"action"`
	Force     bool   `json:"force"`
}

type LinkResponse struct {
	Success bool
	Error   string
	// The overwritten discordID if forcing.
	Replaced string
}

var LinkRoute = MakeRouteSpec[LinkRequest, LinkResponse](
	true,
	"/api/link",
	HandleLink,
	http.MethodPost,
)

var (
	ErrActionMissing       = errors.New("Action missing in request")
	ErrActionDNE           = errors.New("Specified action does not exist")
	ErrDiscordIDMissing    = errors.New("Discord ID missing or invalid")
	ErrDiscordLinked       = errors.New("Discord ID already linked to another profile")
	ErrDiscordWrongStep    = errors.New("Profile is not in the correct step to link Discord ID")
	ErrDiscordCannotUnlink = errors.New("Discord ID cannot be unlinked")
)

// Linking process proceeds as follows:
// 1. "link" action is sent. Set the stage to LS_STARTED. Begin sending
//    "check" intermittently.
// 2. gpcm/friend::handleFriendBot can be used to friend the profile now, and
//    advances the stage to LS_FRIENDED
// 3. "check" action is received, progress the stage to LS_FINISHED, persist
//    the Discord ID permanently.

func HandleLink(req any, _ bool, _ *http.Request) (any, int, error) {
	_req := req.(LinkRequest)
	res := LinkResponse{}

	if _req.ProfileID == 0 {
		return res, http.StatusBadRequest, ErrPIDMissing
	}

	if _req.DiscordID == "" {
		return res, http.StatusBadRequest, ErrDiscordIDMissing
	}

	if _req.Action == "" {
		return res, http.StatusBadRequest, ErrActionMissing
	}

	linkStage, discordID, err := gpcm.GetSessionDiscordInfo(_req.ProfileID)
	// If forcing, then we don't care about the session
	if err != nil && !_req.Force {
		return res, http.StatusInternalServerError, gpcm.ErrNoSession
	}

	switch _req.Action {
	case "link":
		// This is kind of just stuck in here, bits of duplicate code. Should
		// be cleaned up eventually.
		if _req.Force {
			user, err := database.GetProfile(pool, ctx, _req.ProfileID)
			if err != nil {
				return res, http.StatusInternalServerError, ErrUserQuery
			}

			if user.DiscordID != "" {
				res.Replaced = user.DiscordID
			}

			// Ignore any errors. If we can set the session, great, but when
			// forcing a link we don't need the session to exist.
			_ = gpcm.SetSessionDiscordInfo(_req.ProfileID, database.LS_FINISHED, _req.DiscordID)

			// ID is persisted to DB finally
			if user.UpdateDiscordID(pool, ctx, _req.DiscordID) != nil {
				return res, http.StatusInternalServerError, ErrTransaction
			}

			return res, http.StatusOK, nil
		}

		// LinkStage is not persisted in the DB (so if the server resets in the
		// middle of linking, nothing has persisted so it cannot get stuck in
		// an invalid state). Field is inferred to be LS_FINISHED on load from
		// DB if the DiscordID is non-null
		if linkStage == database.LS_FINISHED {
			return res, http.StatusForbidden, ErrDiscordLinked
		}

		if linkStage != database.LS_NONE {
			return res, http.StatusForbidden, ErrDiscordWrongStep
		}

		// Set the stage and the ID on the session upon link request so the
		// in-progress link can't be impacted by anyone else, but it's not
		// persisted yet.
		if gpcm.SetSessionDiscordInfo(_req.ProfileID, database.LS_STARTED, _req.DiscordID) != nil {
			return res, http.StatusInternalServerError, gpcm.ErrNoSession
		}
	case "check":
		// Once the user friends the correct code, the stage progresses from
		// LS_STARTED to LS_FRIENDED. See gpcm/friend::handleFriendBot
		if linkStage != database.LS_FRIENDED {
			return res, http.StatusForbidden, ErrDiscordWrongStep
		}

		user, err := database.GetProfile(pool, ctx, _req.ProfileID)
		if err != nil {
			return res, http.StatusInternalServerError, ErrUserQuery
		}

		if gpcm.SetSessionDiscordInfo(_req.ProfileID, database.LS_FINISHED, _req.DiscordID) != nil {
			return res, http.StatusInternalServerError, gpcm.ErrNoSession
		}

		// ID is persisted to DB finally
		if user.UpdateDiscordID(pool, ctx, _req.DiscordID) != nil {
			return res, http.StatusInternalServerError, ErrTransaction
		}
	case "reset":
		// Only requirement to reset is that the profile has begun linking, and your ID matches
		// Since the ID is applied to the gpcm session on first link, it
		// prevents griefing (if a reset command is ever added), but squatting
		// is prevented by the 10 minute timeout on the bot. I'd prefer to
		// handle the timeout on the server side but for now the temporary
		// solution will likely be permanent...
		if linkStage == database.LS_NONE || _req.DiscordID != discordID {
			return res, http.StatusForbidden, ErrDiscordCannotUnlink
		}

		user, err := database.GetProfile(pool, ctx, _req.ProfileID)
		if err != nil {
			return res, http.StatusInternalServerError, ErrUserQuery
		}

		if user.UpdateDiscordID(pool, ctx, "") != nil {
			return res, http.StatusInternalServerError, ErrTransaction
		}
	default:
		return res, http.StatusBadRequest, ErrActionDNE
	}

	return res, http.StatusOK, nil
}
