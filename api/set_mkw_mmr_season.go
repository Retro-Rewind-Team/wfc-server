package api

import (
	"errors"
	"net/http"
	"wwfc/database"
)

var ErrInvalidMMRSeason = errors.New("MMR season must be a positive number")

type SetMKWMMRSeasonRequest struct {
	Secret string `json:"secret"`
	Season int32  `json:"season"`
}

type SetMKWMMRSeasonResponse struct {
	PreviousSeason int32  `json:"previous_season"`
	Season         int32  `json:"season"`
	Success        bool   `json:"success"`
	Error          string `json:"error"`
}

var SetMKWMMRSeasonRoute = MakeRouteSpec[SetMKWMMRSeasonRequest, SetMKWMMRSeasonResponse](
	true,
	"/api/set_mkw_mmr_season",
	func(req any, _ bool, _ *http.Request) (any, int, error) {
		return handleSetMKWMMRSeasonImpl(req.(SetMKWMMRSeasonRequest))
	},
	http.MethodPost,
)

func handleSetMKWMMRSeasonImpl(req SetMKWMMRSeasonRequest) (SetMKWMMRSeasonResponse, int, error) {
	if req.Season < 1 {
		return SetMKWMMRSeasonResponse{}, http.StatusBadRequest, ErrInvalidMMRSeason
	}

	previous, err := database.GetMKWMMRSeason(pool, ctx)
	if err != nil {
		return SetMKWMMRSeasonResponse{}, http.StatusInternalServerError, ErrTransaction
	}

	if previous != req.Season {
		if err := database.UpdateMKWMMRSeason(pool, ctx, req.Season); err != nil {
			return SetMKWMMRSeasonResponse{}, http.StatusInternalServerError, ErrTransaction
		}
	}

	return SetMKWMMRSeasonResponse{
		PreviousSeason: previous,
		Season:         req.Season,
		Success:        true,
	}, http.StatusOK, nil
}
