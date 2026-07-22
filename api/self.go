package api

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"wwfc/database"
	"wwfc/gpcm"
	"wwfc/qr2"
)

type SelfRequest struct {
	Secret string `json:"secret"`
	// kick or kick_froom
	Command string `json:"command"`
	// Discord ID of the command sender
	DiscordID string `json:"discordID"`
	// pid to kick if using kick_froom
	ProfileID uint32 `json:"pid"`
}

var SelfRoute = MakeRouteSpec[SelfRequest, UserActionResponse](
	true,
	"/api/self",
	func(req any, v bool, _ *http.Request) (any, int, error) {
		return handleUserAction(req.(SelfRequest), v, handleSelfImpl)
	},
	http.MethodPost,
)

var (
	ErrUserNotFoundOnline = errors.New("no linked profile was not found online")
	ErrNotHostingAnyRoom  = errors.New("no linked profiles are hosting any rooms")
)

func handleSelfImpl(req SelfRequest, _ bool) (*database.User, int, error) {
	pids, err := database.GetUsersByDiscordID(pool, ctx, req.DiscordID)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	groups := qr2.GetGroups(nil, nil, false)

	switch req.Command {
	case "kick":
		return handleSelfKick(pids, groups)
	case "kick_froom":
		return handleFroomKick(pids, groups, req.ProfileID)
	default:
		return nil, http.StatusBadRequest, fmt.Errorf("unknown command '%s'", req.Command)
	}
}
func handleSelfKick(pids []uint32, groups []qr2.GroupInfo) (*database.User, int, error) {
	// Attempt to find a matching user that is online. Assume only one user is
	// online at a time which is linked to a specific profile
	for _, group := range groups {
		for _, player := range group.Players {
			pid64, err := strconv.ParseInt(player.ProfileID, 10, 32)
			if err != nil {
				continue
			}

			pid := uint32(pid64)

			if slices.Contains(pids, pid) {
				err := gpcm.KickPlayer(pid, "Self Kick", gpcm.WWFCMsgKickedCustom)
				if err != nil {
					return nil, http.StatusInternalServerError, err
				}

				user, err := database.GetProfile(pool, ctx, pid)
				if err != nil {
					return nil, http.StatusInternalServerError, ErrUserQueryTransaction
				}

				return &user, http.StatusOK, nil
			}
		}
	}

	return nil, http.StatusInternalServerError, ErrUserNotFoundOnline
}

func findHostForPids(pids []uint32, groups []qr2.GroupInfo) (qr2.GroupInfo, error) {
	for _, group := range groups {
		// Only consider private matches
		if group.MatchType == "anybody" {
			continue
		}

		hostIdx := group.ServerIndex
		host := group.Players[hostIdx]

		pid64, err := strconv.ParseInt(host.ProfileID, 10, 32)
		if err != nil {
			return qr2.GroupInfo{}, err
		}

		pid := uint32(pid64)

		if slices.Contains(pids, pid) {
			return group, nil
		}
	}

	return qr2.GroupInfo{}, ErrNotHostingAnyRoom
}

func handleFroomKick(pids []uint32, groups []qr2.GroupInfo, target uint32) (*database.User, int, error) {
	froom, err := findHostForPids(pids, groups)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	targetStr := strconv.FormatUint(uint64(target), 10)
	for _, player := range froom.Players {
		if player.ProfileID == targetStr {
			err := gpcm.KickPlayer(target, "Froom Kick", gpcm.WWFCMsgKickedCustom)
			if err != nil {
				return nil, http.StatusInternalServerError, err
			}

			user, err := database.GetProfile(pool, ctx, target)
			if err != nil {
				return nil, http.StatusInternalServerError, ErrUserQueryTransaction
			}

			return &user, http.StatusOK, nil
		}
	}

	return nil, http.StatusInternalServerError, ErrUserNotFoundOnline
}
