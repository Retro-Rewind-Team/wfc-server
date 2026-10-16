package api

import (
	"net/http"
	"wwfc/database"
)

type MiiRequest struct {
	Secret    string `json:"secret"`
	ProfileID uint32 `json:"pid"`
}

type MiiResponse struct {
	Mii     string
	Success bool
	Error   string
}

var MiiRoute = MakeRouteSpec[MiiRequest, MiiResponse](
	false,
	"/api/mii",
	HandleMii,
	http.MethodPost,
)

func HandleMii(req any, v bool, r *http.Request) (any, int, error) {
	_req := req.(MiiRequest)
	res := MiiResponse{}

	if _req.ProfileID == 0 {
		return res, http.StatusBadRequest, ErrPIDMissing
	}

	var mii string

	mii = database.GetMKWFriendInfo(pool, ctx, _req.ProfileID)

	if mii == "" {
		return res, http.StatusInternalServerError, ErrUserQuery
	}

	res.Mii = mii
	return res, http.StatusOK, nil
}
