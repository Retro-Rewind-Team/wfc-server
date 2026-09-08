package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"wwfc/database"
	"wwfc/logging"
)

type MKWRatingRequest struct {
	Secret    string                 `json:"secret"`
	ProfileID uint32                 `json:"pid"`
	Type      database.MKWRatingType `json:"rating_type"`
	Value     uint32                 `json:"value"`
}

type MKWRatingResponse struct {
	Rating    database.UserMKWRating
	OldRating *database.UserMKWRating
	Success   bool
	Error     string
}

var MKWRatingRoute = MakeRouteSpec[MKWRatingRequest, MKWRatingResponse](
	false,
	"/api/mkw_rating",
	func(req any, v bool, r *http.Request) (any, int, error) {
		var res *MKWRatingResponse
		var code int
		var err error

		switch r.Method {
		case http.MethodGet:
			res, code, err = handleGetMKWRating(r)
		case http.MethodPost:
			res, code, err = handleSetMKWRating(req.(MKWRatingRequest), v, r)
		default:
			res, code, err = &MKWRatingResponse{}, http.StatusMethodNotAllowed, nil
		}

		if res == nil {
			res = &MKWRatingResponse{}
		}

		return *res, code, err
	},
	http.MethodPost,
	http.MethodGet,
)

func handleGetMKWRating(r *http.Request) (*MKWRatingResponse, int, error) {
	query := r.URL.Query()

	pidStr := query.Get("pid")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	if pid == 0 {
		return nil, http.StatusBadRequest, ErrPIDMissing
	}

	rating, err := database.GetMKWRating(pool, ctx, uint32(pid))
	if err != nil {
		return nil, http.StatusInternalServerError, ErrUserQuery
	}

	return &MKWRatingResponse{Rating: rating}, http.StatusOK, nil
}

var (
	ErrInvalidRatingType      = fmt.Errorf("invalid rating type provided < %d", database.RT_LEN)
	ErrRatingQueryTransaction = errors.New("failed to find ratings in the database, but the intended transaction may have gone through")
)

func handleSetMKWRating(req MKWRatingRequest, v bool, _ *http.Request) (*MKWRatingResponse, int, error) {
	if !v {
		return nil, http.StatusForbidden, ErrInvalidSecret
	}

	if req.ProfileID == 0 {
		return nil, http.StatusBadRequest, ErrPIDMissing
	}

	if req.Type >= database.RT_LEN {
		return nil, http.StatusBadRequest, ErrInvalidRatingType
	}

	logging.Error("GUH 1")
	old, err := database.GetMKWRating(pool, ctx, req.ProfileID)
	if err != nil {
		return nil, http.StatusInternalServerError, ErrUserQuery
	}
	logging.Error("GUH")

	err = database.UpdateMKWRating(pool, ctx, req.ProfileID, req.Type, req.Value)
	if err != nil {
		logging.Error("GUH", err)
		return nil, http.StatusInternalServerError, err
	}

	newRating := old
	switch req.Type {
	case database.RT_VR:
		newRating.VR = req.Value
	case database.RT_BR:
		newRating.BR = req.Value
	case database.RT_MMR_RETRO_TRACKS:
		newRating.MMR.RetroTracks = req.Value
	case database.RT_MMR_CUSTOM_TRACKS:
		newRating.MMR.CustomTracks = req.Value
	case database.RT_MMR_VANILLA:
		newRating.MMR.Vanilla = req.Value
	}

	return &MKWRatingResponse{Rating: newRating, OldRating: &old}, http.StatusOK, nil
}
