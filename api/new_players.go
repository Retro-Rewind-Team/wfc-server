package api

import (
	"net/http"
	"wwfc/database"
)

type NewPlayersRequest struct {
	Secret    string `json:"secret"`
	ProfileID uint32 `json:"pid"`
}

type NewPlayersResponse struct {
	Users   []database.User
	Success bool
	Error   string
}

var NewPlayersRoute = MakeRouteSpec[NewPlayersRequest, NewPlayersResponse](
	true,
	"/api/new_players",
	func(_ any, _ bool, _ *http.Request) (any, int, error) {
		res := NewPlayersResponse{}
		res.Users = database.GetNewUsers()

		return res, http.StatusOK, nil
	},
	http.MethodPost,
)
