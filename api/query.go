package api

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"wwfc/database"
	"wwfc/logging"

	"github.com/logrusorgru/aurora/v3"
)

type QueryRequest struct {
	Secret    string `json:"secret"`
	IP        string `json:"ip"`
	DeviceID  uint32 `json:"deviceID"`
	Csnum     string `json:"csnum"`
	UserID    uint64 `json:"userID"`
	DiscordID string `json:"discordID"`
	PID       uint32 `json:"pid"`
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

const QUERYBASE = `SELECT profile_id FROM users WHERE`

func HandleQuery(req any, _ bool, _ *http.Request) (any, int, error) {
	_req := req.(QueryRequest)

	err := validateOptions(_req)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	var query string
	if _req.PID != 0 {
		user, err := database.GetProfile(pool, ctx, _req.PID)

		if err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("failed to lookup database user '%d': %s", _req.PID, err)
		}

		query = makeQueryFromUser(user, _req)
	} else {
		query = makeQuery(_req)
	}

	logging.Info("QUERY", "Executing query", aurora.Cyan(query))

	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	defer rows.Close()

	pids := []uint32{}

	count := 0
	for rows.Next() {
		count++

		var pid uint32
		err := rows.Scan(&pid)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}

		pids = append(pids, pid)

		// TODO: Return a count of the total number of matches, do something
		// about returing 80000 matches if the query is vague enough
	}

	res := QueryResponse{}
	res.Users = []database.User{}

	for _, pid := range pids {
		user, err := database.GetProfile(pool, ctx, pid)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}

		res.Users = append(res.Users, user)
	}

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

	if req.IP == "" && req.Csnum == "" && req.DeviceID == 0 && req.UserID == 0 && req.DiscordID == "" && req.PID == 0 {
		return ErrEmptyParams
	}

	return nil
}

func makeQuery(req QueryRequest) string {
	query := QUERYBASE

	if req.IP != "" {
		query += fmt.Sprintf(" last_ip_address = '%s' AND", req.IP)
	}

	if req.DeviceID != 0 {
		query += fmt.Sprintf(" %d = ANY(ng_device_id) AND", req.DeviceID)
	}

	if req.Csnum != "" {
		query += fmt.Sprintf(" '%s' = ANY(csnum) AND", req.Csnum)
	}

	if req.DiscordID != "" {
		query += fmt.Sprintf(" discord_id = '%s' AND", req.DiscordID)
	}

	if req.UserID != 0 {
		query += fmt.Sprintf(" user_id = %d AND", req.UserID)
	}

	switch req.HasBan {
	case 1:
		query += " has_ban = false AND"
	case 2:
		query += " has_ban = true AND"
	}

	query = query[0 : len(query)-4]
	query += ";"

	return query
}

func makeQueryFromUser(user database.User, rrr QueryRequest) string {
	query := QUERYBASE

	if user.LastIPAddress != "" {
		query += fmt.Sprintf(" last_ip_address = '%s' OR", user.LastIPAddress)
	}

	deviceIDs := []string{}

	// Filter default dolphin device id
	for _, id := range user.NgDeviceId {
		if id != 67349608 {
			deviceIDs = append(deviceIDs, fmt.Sprintf("\"%d\"", uint32(id)))
		}
	}

	if len(deviceIDs) > 0 {
		query += fmt.Sprintf(" %s && ng_device_id OR", fmtPSQLArray(deviceIDs))
	}

	if len(user.Csnum) > 0 {
		query += fmt.Sprintf(" %s && csnum OR", fmtPSQLArray(user.Csnum))
	}

	query += fmt.Sprintf(" user_id = %d OR", user.UserId)

	switch rrr.HasBan {
	case 1:
		query += " has_ban = false OR"
	case 2:
		query += " has_ban = true OR"
	}

	query = query[0 : len(query)-3]
	query += ";"

	return query
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
