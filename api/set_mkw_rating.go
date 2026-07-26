package api

import (
	"errors"
	"net/http"
	"strings"
	"wwfc/database"
	"wwfc/gpcm"
)

const (
	defaultMKWManualRating = 5000
	minMKWManualRating     = 100
	maxMKWManualRating     = 1_000_000
)

var (
	ErrRatingType  = errors.New("rating type must be either 'vr' or 'br'")
	ErrRatingValue = errors.New("rating value must be between 100 and 1000000")
)

type SetMKWRatingRequest struct {
	Secret     string `json:"secret"`
	ProfileID  uint32 `json:"pid"`
	RatingType string `json:"rating_type"`
	Reason     string `json:"reason"`
	Value      int32  `json:"value"`
}

type SetMKWRatingResponse struct {
	User          database.User `json:"user"`
	RatingType    string        `json:"rating_type"`
	PreviousValue int32         `json:"previous_value"`
	Value         int32         `json:"value"`
	VR            int32         `json:"vr"`
	BR            int32         `json:"br"`
	Success       bool          `json:"success"`
	Error         string        `json:"error"`
}

var SetMKWRatingRoute = MakeRouteSpec[SetMKWRatingRequest, SetMKWRatingResponse](
	true,
	"/api/set_mkw_rating",
	func(req any, _ bool, _ *http.Request) (any, int, error) {
		return handleSetMKWRatingImpl(req.(SetMKWRatingRequest))
	},
	http.MethodPost,
)

func handleSetMKWRatingImpl(req SetMKWRatingRequest) (SetMKWRatingResponse, int, error) {
	if req.ProfileID == 0 {
		return SetMKWRatingResponse{}, http.StatusBadRequest, ErrPIDMissing
	}

	ratingType := strings.ToLower(strings.TrimSpace(req.RatingType))
	if ratingType != "vr" && ratingType != "br" {
		return SetMKWRatingResponse{}, http.StatusBadRequest, ErrRatingType
	}

	if req.Value < minMKWManualRating || req.Value > maxMKWManualRating {
		return SetMKWRatingResponse{}, http.StatusBadRequest, ErrRatingValue
	}

	vr, br, err := database.GetMKWRawVRBR(pool, ctx, req.ProfileID)
	if err != nil {
		return SetMKWRatingResponse{}, http.StatusNotFound, ErrUserQuery
	}

	currentVR := ratingOrDefault(vr)
	currentBR := ratingOrDefault(br)
	previousValue := currentVR
	if ratingType == "vr" {
		currentVR = req.Value
	} else {
		previousValue = currentBR
		currentBR = req.Value
	}

	if err := database.UpdateMKWVRBR(pool, ctx, req.ProfileID, currentVR, currentBR); err != nil {
		return SetMKWRatingResponse{}, http.StatusInternalServerError, ErrTransaction
	}

	user, err := database.GetProfile(pool, ctx, req.ProfileID)
	if err != nil {
		return SetMKWRatingResponse{}, http.StatusInternalServerError, ErrUserQueryTransaction
	}

	kickReason := "Your VR/BR was updated."
	if reason := strings.TrimSpace(req.Reason); reason != "" {
		kickReason += " - " + reason
	}

	if err := gpcm.KickPlayer(req.ProfileID, kickReason, gpcm.WWFCMsgKickedCustom); err != nil {
		return SetMKWRatingResponse{}, http.StatusInternalServerError, err
	}

	return SetMKWRatingResponse{
		User:          user,
		RatingType:    ratingType,
		PreviousValue: previousValue,
		Value:         req.Value,
		VR:            currentVR,
		BR:            currentBR,
	}, http.StatusOK, nil
}

func ratingOrDefault(rating *int32) int32 {
	if rating == nil {
		return defaultMKWManualRating
	}

	return *rating
}
