package api

import (
	"fmt"
	"net/http"
	"slices"
	"wwfc/database"
)

type InvestigateRequest struct {
	Secret    string `json:"secret"`
	ProfileID uint32 `json:"pid"`
}

type InvestigateResponse struct {
	MiiNames         []string
	DiscordIDs       []string
	BanReasons       []string
	HiddenBanReasons []string
	UserIDs          []uint64
	ProfileIDs       []uint32
	DeviceIDs        []uint32
	IPs              []string
	Csnums           []string
	Success          bool
	Error            string
}

var InvestigateRoute = MakeRouteSpec[InvestigateRequest, InvestigateResponse](
	true,
	"/api/investigate",
	HandleInvestigate,
	http.MethodPost,
)

func HandleInvestigate(req any, _ bool, _ *http.Request) (any, int, error) {
	_req := req.(InvestigateRequest)

	if _req.ProfileID == 0 {
		return nil, http.StatusBadRequest, ErrPIDMissing
	}

	user, err := database.GetProfile(pool, ctx, _req.ProfileID)

	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("failed to lookup database user '%d': %s", _req.ProfileID, err)
	}

	res := InvestigateResponse{}
	query := makeQueryFromUser(user, QueryRequest{HasBan: 0})

	users, err := database.ScanUsers(pool, ctx, query)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	for _, user := range users {
		if pos, found := slices.BinarySearch(res.MiiNames, user.LastInGameSn); !found {
			res.MiiNames = slices.Insert(res.MiiNames, pos, user.LastInGameSn)
		}

		if pos, found := slices.BinarySearch(res.DiscordIDs, user.DiscordID); !found {
			res.DiscordIDs = slices.Insert(res.DiscordIDs, pos, user.DiscordID)
		}

		if pos, found := slices.BinarySearch(res.BanReasons, user.BanReason); !found {
			res.BanReasons = slices.Insert(res.BanReasons, pos, user.BanReason)
		}

		if pos, found := slices.BinarySearch(res.HiddenBanReasons, user.BanReasonHidden); !found {
			res.HiddenBanReasons = slices.Insert(res.HiddenBanReasons, pos, user.BanReasonHidden)
		}

		if pos, found := slices.BinarySearch(res.UserIDs, user.UserId); !found {
			res.UserIDs = slices.Insert(res.UserIDs, pos, user.UserId)
		}

		if pos, found := slices.BinarySearch(res.ProfileIDs, user.ProfileId); !found {
			res.ProfileIDs = slices.Insert(res.ProfileIDs, pos, user.ProfileId)
		}

		if pos, found := slices.BinarySearch(res.IPs, user.LastIPAddress); !found {
			res.IPs = slices.Insert(res.IPs, pos, user.LastIPAddress)
		}

		for _, csnum := range user.Csnum {
			if pos, found := slices.BinarySearch(res.Csnums, csnum); !found {
				res.Csnums = slices.Insert(res.Csnums, pos, csnum)
			}
		}

		for _, deviceID := range user.NgDeviceId {
			if pos, found := slices.BinarySearch(res.DeviceIDs, deviceID); !found {
				res.DeviceIDs = slices.Insert(res.DeviceIDs, pos, deviceID)
			}
		}
	}

	return res, http.StatusOK, nil
}
