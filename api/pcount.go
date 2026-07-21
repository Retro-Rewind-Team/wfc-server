package api

import (
	"net/http"
	"time"
	"wwfc/database"
	"wwfc/logging"

	"github.com/linkdata/deadlock"
	"github.com/logrusorgru/aurora/v3"
)

type PCountRequest struct{}

type PCountResponse struct {
	Count   int
	Success bool
	Error   string
}

var PCountRoute = MakeRouteSpec[PCountRequest, PCountResponse](
	false,
	"/api/pcount",
	HandlePCount,
	http.MethodGet,
)

var (
	mu    = deadlock.Mutex{}
	count = -1
)

func HandlePCount(_ any, _ bool, r *http.Request) (any, int, error) {
	res := PCountResponse{}

	mu.Lock()
	res.Count = count
	mu.Unlock()

	return res, http.StatusOK, nil
}

var PCountTickerQuit = make(chan struct{})

func initPCount() {
	err := runPCountUpdate()
	if err != nil {
		logging.Error("API:PCount", "Failed to count total users:", err)
	}

	ticker := time.NewTicker(60 * time.Second)

	go func() {

		for {
			select {
			case <-ticker.C:
				err := runPCountUpdate()
				if err != nil {
					logging.Error("API:PCount", "Failed to count total users:", err)
				}
			case <-PCountTickerQuit:
				logging.Info("API:PCount", "Shutting down PCount ticker.")
				ticker.Stop()
			}
		}
	}()
}

func runPCountUpdate() error {
	logging.Info("API:PCount", "Refreshing user count")
	tmpCount, err := database.CountTotalUsers(pool, ctx)

	if err != nil {
		return err
	}

	mu.Lock()
	count = tmpCount
	mu.Unlock()

	logging.Info("API:PCount", "Refreshed user count:", aurora.Cyan(tmpCount))

	return nil
}
