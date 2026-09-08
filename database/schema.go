package database

import (
	"context"
	"fmt"
	"wwfc/logging"

	"github.com/jackc/pgx/v4/pgxpool"
)

func UpdateTables(pool *pgxpool.Pool, ctx context.Context) {
	runMigration(pool, ctx, "public.users", `

	ALTER TABLE ONLY public.users
		ADD IF NOT EXISTS last_ip_address character varying DEFAULT ''::character varying,
		ADD IF NOT EXISTS last_ingamesn character varying DEFAULT ''::character varying,
		ADD IF NOT EXISTS has_ban boolean DEFAULT false,
		ADD IF NOT EXISTS ban_issued timestamp without time zone,
		ADD IF NOT EXISTS ban_expires timestamp without time zone,
		ADD IF NOT EXISTS ban_reason character varying,
		ADD IF NOT EXISTS ban_reason_hidden character varying,
		ADD IF NOT EXISTS ban_moderator character varying,
		ADD IF NOT EXISTS ban_tos boolean,
		ADD IF NOT EXISTS open_host boolean DEFAULT false,
		ADD IF NOT EXISTS csnum character varying[],
		ADD IF NOT EXISTS discord_id character varying,
		ADD IF NOT EXISTS mariokartwii_vr integer DEFAULT 5000,
		ADD IF NOT EXISTS mariokartwii_br integer DEFAULT 5000;

	`)

	runMigration(pool, ctx, "ng_device_id bigint", `

	DO $$
	BEGIN
		IF (SELECT data_type FROM information_schema.columns WHERE table_name='users' AND column_name='ng_device_id') != 'ARRAY' THEN
			ALTER TABLE public.users
				ALTER COLUMN ng_device_id TYPE bigint[] using array[ng_device_id];
		END IF;
	END $$;

	`)

	runMigration(pool, ctx, "public.mario_kart_wii_sake", `

	ALTER TABLE ONLY public.mario_kart_wii_sake
		ADD IF NOT EXISTS id serial PRIMARY KEY,
		ADD IF NOT EXISTS upload_time timestamp without time zone;

	`)

	// Create globals index. Used as an arbitrary global key-value store
	runMigration(pool, ctx, "create public.globals", `

	CREATE TABLE IF NOT EXISTS public.globals (
		key character varying NOT NULL,
		val character varying NOT NULL,
		CONSTRAINT unique_key UNIQUE (key)
	);

	ALTER TABLE public.globals OWNER TO wiilink;

	`)

	// Create mmr table. Stores the three mmr types keyed by [profile_id, season]
	runMigration(pool, ctx, "create public.mkw_mmr", `

	CREATE TABLE IF NOT EXISTS public.mkw_mmr (
		season integer NOT NULL,
		profile_id bigint NOT NULL,
		retro_tracks integer NOT NULL DEFAULT 1000,
		custom_tracks integer NOT NULL DEFAULT 1000,
		vanilla integer NOT NULL DEFAULT 1000,
		CONSTRAINT unique_profile_per_season UNIQUE (season, profile_id)
	);

	ALTER TABLE public.mkw_mmr OWNER TO wiilink;

	`)

	runMigration(pool, ctx, "set mmr season to 1", `

	INSERT INTO public.globals (key, val)
	VALUES ('season', '1')
	ON CONFLICT (key) DO NOTHING;

	`)

	// Create indexes to improve performance
	runMigration(pool, ctx, "create public.mkw_mmr season_idx",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS season_idx ON public.mkw_mmr (season);")

	runMigration(pool, ctx, "create public.mkw_mmr profile_idx",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS profile_idx ON public.mkw_mmr (profile_id);")
}

func runMigration(pool *pgxpool.Pool, ctx context.Context, migration string, sql string) {
	_, err := pool.Exec(ctx, sql)
	handleError(migration, err)
}

func handleError(migration string, err error) {
	if err != nil {
		module := fmt.Sprintf("DATABASE:%s", migration)
		logging.Error(module, "Error applying migration:", err)
	}
}
