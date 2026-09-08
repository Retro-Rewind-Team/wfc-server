package database

import (
	"context"
	"errors"
	"strconv"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/linkdata/deadlock"
)

const (
	GetMMRSeason = `SELECT val FROM globals WHERE key = 'season'`
	SetMMRSeason = `UPDATE globals SET val = $1 WHERE key = 'season'`
)

type GlobalData struct {
	Season uint32
}

var (
	globals      GlobalData
	globalsMutex = deadlock.Mutex{}
)

func GlobalsInit(pool *pgxpool.Pool, ctx context.Context) error {
	var seasonStr string

	err := pool.QueryRow(ctx, GetMMRSeason).Scan(&seasonStr)

	globalsMutex.Lock()
	defer globalsMutex.Unlock()

	globals = GlobalData{}

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}

		return err
	}

	season, err := strconv.Atoi(seasonStr)
	if err != nil {
		return err
	}

	globals.Season = uint32(season)

	return nil
}

func GetGlobals() GlobalData {
	globalsMutex.Lock()
	defer globalsMutex.Unlock()

	return globals
}

func GlobalSetSeason(pool *pgxpool.Pool, ctx context.Context, season uint32) (uint32, error) {
	globalsMutex.Lock()
	oldSeason := globals.Season
	globals.Season = season
	globalsMutex.Unlock()

	_, err := pool.Exec(ctx, SetMMRSeason, strconv.Itoa(int(season)))

	return oldSeason, err
}
