package api

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"wwfc/database"
)

type QueryRequest struct {
	Secret    string `json:"secret"`
	IP        string `json:"ip"`
	DeviceID  uint32 `json:"deviceID"`
	Csnum     string `json:"csnum"`
	UserID    uint64 `json:"userID"`
	DiscordID string `json:"discordID"`
	ProfileID uint32 `json:"pid"`
	// 0: Either, 1: No Ban, 2: Ban
	HasBan byte `json:"hasban"`
}

type QueryResponse struct {
	Users   []database.User
	Success bool
	Error   string
}

var QueryRoute = MakeRouteSpec[QueryRequest, QueryResponse](
	true,
	"/api/query",
	HandleQuery,
	http.MethodPost,
)

var (
	ErrInvalidIPFormat  = errors.New("invalid ip format. ips must be in the format 'xx.xx.xx.xx'")
	ErrInvalidDeviceID  = errors.New("deviceid cannot be 0")
	ErrInvalidCsnum     = errors.New("csnums must be less than 16 characters long and match the format '^[a-za-z0-9]+$'")
	ErrInvalidDiscordID = errors.New("discord id must be 20 or fewer characters long and all numbers")
	ErrInvalidHasBan    = errors.New("HasBan must be either 0 (Either), 1 (No Ban), 2 (Ban)")
	ErrEmptyParams      = errors.New("at least one of ip, csnum, deviceid, discordid, or pid must be nonzero or nonempty")
	ipRegex             = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	csnumRegex          = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
	numOnlyRegex        = regexp.MustCompile("^[0-9]+$")
)

const QUERYBASE = `SELECT profile_id FROM users WHERE `

func HandleQuery(req any, _ bool, _ *http.Request) (any, int, error) {
	_req := req.(QueryRequest)

	err := validateOptions(_req)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	var query string
	if _req.ProfileID != 0 {
		user, err := database.GetProfile(pool, ctx, _req.ProfileID)

		if err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("failed to lookup database user '%d': %s", _req.ProfileID, err)
		}

		query = makeQueryFromUser(user, _req)
	} else {
		query = makeQuery(_req)
	}

	// TODO: Return a count of the total number of matches, do something
	// about returing 80000 matches if the query is vague enough

	users, err := database.ScanUsers(pool, ctx, query)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	res := QueryResponse{}
	res.Users = users

	return res, http.StatusOK, nil
}

func validateOptions(req QueryRequest) error {
	if req.IP != "" && !ipRegex.MatchString(req.IP) {
		return ErrInvalidIPFormat
	}

	if req.Csnum != "" && (len(req.Csnum) > 16 || !csnumRegex.MatchString(req.Csnum)) {
		return ErrInvalidCsnum
	}

	if req.DiscordID != "" && (len(req.DiscordID) > 20 || !numOnlyRegex.MatchString(req.DiscordID)) {
		return ErrInvalidDiscordID
	}

	if req.HasBan != 0 && req.HasBan != 1 && req.HasBan != 2 {
		return ErrInvalidHasBan
	}

	if req.IP == "" && req.Csnum == "" && req.DeviceID == 0 && req.UserID == 0 && req.DiscordID == "" && req.ProfileID == 0 {
		return ErrEmptyParams
	}

	return nil
}

func makeQuery(req QueryRequest) string {
	queries := []string{}

	if req.IP != "" {
		queries = append(queries, fmt.Sprintf("last_ip_address = '%s'", req.IP))
	}

	if req.DeviceID != 0 {
		queries = append(queries, fmt.Sprintf("%d = ANY(ng_device_id)", req.DeviceID))
	}

	if req.Csnum != "" {
		queries = append(queries, fmt.Sprintf("'%s' = ANY(csnum)", req.Csnum))
	}

	if req.DiscordID != "" {
		queries = append(queries, fmt.Sprintf("discord_id = '%s'", req.DiscordID))
	}

	if req.UserID != 0 {
		queries = append(queries, fmt.Sprintf("user_id = %d", req.UserID))
	}

	switch req.HasBan {
	case 1:
		queries = append(queries, "has_ban = false")
	case 2:
		queries = append(queries, "has_ban = true")
	}

	return QUERYBASE + strings.Join(queries, " AND ") + ";"
}

func makeQueryFromUser(user database.User, req QueryRequest) string {
	queries := []string{}

	if user.LastIPAddress != "" {
		queries = append(queries, fmt.Sprintf("last_ip_address = '%s'", user.LastIPAddress))
	}

	deviceIDs := []string{}

	// Filter default dolphin device id
	for _, id := range user.NgDeviceId {
		if id != 67349608 {
			deviceIDs = append(deviceIDs, fmt.Sprintf("\"%d\"", uint32(id)))
		}
	}

	if len(deviceIDs) > 0 {
		queries = append(queries, fmt.Sprintf("%s && ng_device_id", fmtPSQLArray(deviceIDs)))
	}

	if len(user.Csnum) > 0 {
		queries = append(queries, fmt.Sprintf("%s && csnum", fmtPSQLArray(user.Csnum)))
	}

	queries = append(queries, fmt.Sprintf("user_id = %d", user.UserId))

	if user.DiscordID != "" {
		queries = append(queries, fmt.Sprintf("discord_id = '%s'", user.DiscordID))
	}

	query := strings.Join(queries, " OR ")

	switch req.HasBan {
	case 1:
		query = fmt.Sprintf("(%s) AND has_ban = true", query)
	case 2:
		query = fmt.Sprintf("(%s) AND has_ban = true", query)
	}

	return QUERYBASE + query + ";"
}

func fmtPSQLArray[S any](arr []S) string {
	ret := ""

	if len(arr) == 0 {
		return ret
	}

	for _, e := range arr {
		ret += fmt.Sprintf("%v, ", e)
	}

	ret = ret[0 : len(ret)-2]
	return fmt.Sprintf("'{%s}'", ret)
}
