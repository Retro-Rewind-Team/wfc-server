package api

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"wwfc/database"
)

type QueryRequest struct {
	Secret    string `json:"secret"`
	IP        string `json:"ip"`
	DeviceID  uint32 `json:"deviceID"`
	Csnum     string `json:"csnum"`
	DiscordID string `json:"discordID"`
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
	ErrInvalidIPFormat  = errors.New("Invalid IP Format. IPs must be in the format 'xx.xx.xx.xx'.")
	ErrInvalidDeviceID  = errors.New("DeviceID cannot be 0.")
	ErrInvalidCsnum     = errors.New("Csnums must be less than 16 characters long and match the format '^[a-zA-Z0-9]+$'.")
	ErrInvalidDiscordID = errors.New("Discord ID must be 18 or fewer characters long and all numbers.")
	ErrInvalidHasBan    = errors.New("HasBan must be either 0 (Either), 1 (No Ban), 2 (Ban)")
	ErrEmptyParams      = errors.New("At least one of IP, Csnum, DeviceID, or DiscordID must be nonzero or nonempty")
	ipRegex             = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	csnumRegex          = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	numOnlyRegex        = regexp.MustCompile("^[0-9]+$")
)

const QUERYBASE = `SELECT profile_id FROM users WHERE`

func HandleQuery(req any, _ bool, _ *http.Request) (any, int, error) {
	_req := req.(QueryRequest)

	if _req.IP != "" && !ipRegex.MatchString(_req.IP) {
		return nil, http.StatusBadRequest, ErrInvalidIPFormat
	}

	if _req.Csnum != "" && (len(_req.Csnum) > 16 || !csnumRegex.MatchString(_req.Csnum)) {
		return nil, http.StatusBadRequest, ErrInvalidCsnum
	}

	if _req.DiscordID != "" && (len(_req.DiscordID) > 18 || !numOnlyRegex.MatchString(_req.DiscordID)) {
		return nil, http.StatusBadRequest, ErrInvalidDiscordID
	}

	if _req.HasBan != 0 && _req.HasBan != 1 && _req.HasBan != 2 {
		return nil, http.StatusBadRequest, ErrInvalidHasBan
	}

	if _req.IP == "" && _req.Csnum == "" && _req.DeviceID == 0 && _req.DiscordID == "" {
		return nil, http.StatusBadRequest, ErrEmptyParams
	}

	query := QUERYBASE

	if _req.IP != "" {
		query += fmt.Sprintf(" last_ip_address = '%s' AND", _req.IP)
	}

	if _req.DeviceID != 0 {
		query += fmt.Sprintf(" %d = ANY(ng_device_id) AND", _req.DeviceID)
	}

	if _req.Csnum != "" {
		query += fmt.Sprintf(" '%s' = ANY(csnum) AND", _req.Csnum)
	}

	if _req.DiscordID != "" {
		query += fmt.Sprintf(" discord_id = '%s' AND", _req.DiscordID)
	}

	if _req.HasBan == 1 {
		query += fmt.Sprintf(" has_ban = false AND")
	} else if _req.HasBan == 2 {
		query += fmt.Sprintf(" has_ban = true AND")
	}

	query = query[0 : len(query)-4]
	query += ";"

	rows, err := pool.Query(ctx, query)
	defer rows.Close()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

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
