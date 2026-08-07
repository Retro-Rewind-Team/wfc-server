package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"wwfc/database"
)

type MKWRatingResponse struct {
	Found      int32 `json:"found"`
	VR         int32 `json:"vr"`
	BR         int32 `json:"br"`
	MMRRT      int32 `json:"mmr_rt"`
	MMRCT      int32 `json:"mmr_ct"`
	MMRVanilla int32 `json:"mmr_vanilla"`
}

func HandleMKWRatings(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	profileID, ok := parseProfileID(query["pid"])
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	vr, br, found := database.GetMKWVRBR(pool, ctx, profileID)
	mmrRT, mmrCT, mmrVanilla, mmrFound := database.GetMKWMMRs(pool, ctx, profileID)
	response := MKWRatingResponse{}
	if found {
		response.Found = 1
	}
	if found {
		response.VR = vr
		response.BR = br
	}
	if mmrFound {
		response.MMRRT = mmrRT
		response.MMRCT = mmrCT
		response.MMRVanilla = mmrVanilla
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
	w.Write(jsonData)
}

func parseProfileID(values []string) (uint32, bool) {
	if len(values) != 1 {
		return 0, false
	}

	profileID, err := strconv.ParseUint(values[0], 10, 32)
	if err != nil || profileID == 0 {
		return 0, false
	}

	return uint32(profileID), true
}
