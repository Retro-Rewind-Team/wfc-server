package api

import (
	"net/http"
	"wwfc/qr2"
)

type RegionStats struct {
	PlayerCount       int `json:"online"`
	GroupCount        int `json:"groups"`
	PublicPlayerCount int `json:"pub_online"`
	PublicGroupCount  int `json:"pub_groups"`
}

type MKWStatsResponse struct {
	AllRegions Stats                  `json:"global"`
	ByRegion   map[string]RegionStats `json:"by_region"`
	Success    bool
	Error      string
}

var MKWStatsRoute = MakeRouteSpec[struct{}, MKWStatsResponse](
	false,
	"/api/mkw_stats",
	func(a any, b bool, r *http.Request) (any, int, error) {
		res, code, err := HandleMKWStats(a, b, r)
		if res == nil {
			res = &MKWStatsResponse{}
		}

		return *res, code, err
	},
	http.MethodGet,
)

func HandleMKWStats(_ any, _ bool, r *http.Request) (*MKWStatsResponse, int, error) {
	res := MKWStatsResponse{
		AllRegions: Stats{},
		ByRegion:   map[string]RegionStats{},
	}

	servers := qr2.GetSessionServers()
	groups := qr2.GetGroups([]string{"mariokartwii"}, []string{}, false)

	res.AllRegions.OnlinePlayerCount = len(servers)
	res.AllRegions.GroupCount = len(groups)

	for _, group := range groups {
		if len(group.MKWRegion) == 0 {
			continue
		}

		regionStats, exists := res.ByRegion[group.MKWRegion]
		if !exists {
			regionStats = RegionStats{}
		}

		regionStats.GroupCount += 1
		regionStats.PlayerCount += len(group.Players)

		if group.MatchType == "anybody" {
			regionStats.PublicGroupCount += 1
			regionStats.PublicPlayerCount += len(group.Players)
		}

		res.ByRegion[group.MKWRegion] = regionStats
	}

	return &res, http.StatusOK, nil
}
