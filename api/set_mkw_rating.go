package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"wwfc/database"
	"wwfc/gpcm"
)

const (
	defaultMKWManualRating = 5000
	minMKWManualRating     = 100
	maxMKWManualRating     = 1_000_000
	minMKWMMR              = 100
	maxMKWMMR              = 30_000
)

var (
	ErrRatingType  = errors.New("rating type must be either 'vr', 'br', 'mmr', 'mmr_rt', 'mmr_ct', or 'mmr_vanilla'")
	ErrRatingValue = errors.New("rating value must be between 100 and 1000000")
	ErrMMRValue    = errors.New("MMR value must be between 100 and 30000")
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
	MMRRT         int32         `json:"mmr_rt"`
	MMRCT         int32         `json:"mmr_ct"`
	MMRVanilla    int32         `json:"mmr_vanilla"`
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
	if !isMKWRatingType(ratingType) {
		return SetMKWRatingResponse{}, http.StatusBadRequest, ErrRatingType
	}

	if isMKWMMRType(ratingType) {
		if req.Value < minMKWMMR || req.Value > maxMKWMMR {
			return SetMKWRatingResponse{}, http.StatusBadRequest, ErrMMRValue
		}
	} else if req.Value < minMKWManualRating || req.Value > maxMKWManualRating {
		return SetMKWRatingResponse{}, http.StatusBadRequest, ErrRatingValue
	}

	vr, br, err := database.GetMKWRawVRBR(pool, ctx, req.ProfileID)
	if err != nil {
		return SetMKWRatingResponse{}, http.StatusNotFound, ErrUserQuery
	}

	currentVR := ratingOrDefault(vr)
	currentBR := ratingOrDefault(br)
	currentMMRRT := int32(defaultMKWManualRating)
	currentMMRCT := int32(defaultMKWManualRating)
	currentMMRVanilla := int32(defaultMKWManualRating)
	if storedRT, storedCT, storedVanilla, found := database.GetMKWMMRs(pool, ctx, req.ProfileID); found {
		currentMMRRT = storedRT
		currentMMRCT = storedCT
		currentMMRVanilla = storedVanilla
	}

	previousValue := int32(0)
	switch ratingType {
	case "vr":
		previousValue = currentVR
		currentVR = req.Value
	case "br":
		previousValue = currentBR
		currentBR = req.Value
	case "mmr":
		previousValue = currentMMRRT
		currentMMRRT = req.Value
		currentMMRCT = req.Value
		currentMMRVanilla = req.Value
	case "mmr_rt":
		previousValue = currentMMRRT
		currentMMRRT = req.Value
	case "mmr_ct":
		previousValue = currentMMRCT
		currentMMRCT = req.Value
	case "mmr_vanilla":
		previousValue = currentMMRVanilla
		currentMMRVanilla = req.Value
	}

	var updateErr error
	switch {
	case ratingType == "mmr":
		updateErr = database.UpdateMKWMMR(pool, ctx, req.ProfileID, req.Value)
	case isMKWMMRType(ratingType):
		updateErr = database.UpdateMKWMMRMode(pool, ctx, req.ProfileID, strings.TrimPrefix(ratingType, "mmr_"), req.Value)
	default:
		updateErr = database.UpdateMKWVRBR(pool, ctx, req.ProfileID, currentVR, currentBR)
	}
	if updateErr != nil {
		return SetMKWRatingResponse{}, http.StatusInternalServerError, ErrTransaction
	}

	user, err := database.GetProfile(pool, ctx, req.ProfileID)
	if err != nil {
		return SetMKWRatingResponse{}, http.StatusInternalServerError, ErrUserQueryTransaction
	}

	kickReason := fmt.Sprintf("%s has been changed to %d.", mkwRatingLabel(ratingType), req.Value)

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
		MMRRT:         currentMMRRT,
		MMRCT:         currentMMRCT,
		MMRVanilla:    currentMMRVanilla,
	}, http.StatusOK, nil
}

func isMKWRatingType(ratingType string) bool {
	switch ratingType {
	case "vr", "br", "mmr", "mmr_rt", "mmr_ct", "mmr_vanilla":
		return true
	default:
		return false
	}
}

func isMKWMMRType(ratingType string) bool {
	return ratingType == "mmr" || strings.HasPrefix(ratingType, "mmr_")
}

func mkwRatingLabel(ratingType string) string {
	switch ratingType {
	case "mmr_rt":
		return "MMR RT"
	case "mmr_ct":
		return "MMR CT"
	case "mmr_vanilla":
		return "MMR Vanilla"
	default:
		return strings.ToUpper(ratingType)
	}
}

func ratingOrDefault(rating *int32) int32 {
	if rating == nil {
		return defaultMKWManualRating
	}

	return *rating
}
