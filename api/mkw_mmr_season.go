package api

import (
	"net/http"
	"wwfc/database"
)

type MKWSeasonRequest struct {
	Secret string `json:"secret"`
	Season uint32 `json:"season"`
}

type MKWSeasonResponse struct {
	Season    uint32
	OldSeason uint32
	Success   bool
	Error     string
}

var MKWSeasonRoute = MakeRouteSpec[MKWSeasonRequest, MKWSeasonResponse](
	false,
	"/api/mkw_mmr_season",
	func(req any, v bool, r *http.Request) (any, int, error) {
		res, code, err := handleMKWMMRSeasonImpl(req.(MKWSeasonRequest), v, r)
		if res == nil {
			res = &MKWSeasonResponse{}
		}

		return *res, code, err
	},
	http.MethodGet,
	http.MethodPost,
)

func handleMKWMMRSeasonImpl(req MKWSeasonRequest, v bool, r *http.Request) (*MKWSeasonResponse, int, error) {
	switch r.Method {
	case http.MethodGet:
		return &MKWSeasonResponse{Season: database.GetGlobals().Season}, http.StatusOK, nil
	case http.MethodPost:
		if !v {
			return nil, http.StatusForbidden, ErrInvalidSecret
		}

		oldSeason, err := database.GlobalSetSeason(pool, ctx, req.Season)

		if err != nil {
			return nil, http.StatusInternalServerError, err
		}

		return &MKWSeasonResponse{Season: req.Season, OldSeason: oldSeason}, http.StatusOK, nil
	}

	return nil, http.StatusMethodNotAllowed, nil
}
