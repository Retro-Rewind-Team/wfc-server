package database

import (
	"context"

	"github.com/jackc/pgx/v4/pgxpool"
)

func UpdateTables(pool *pgxpool.Pool, ctx context.Context) {
	pool.Exec(ctx, `

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
		ADD IF NOT EXISTS discord_id character varying,
		ADD IF NOT EXISTS mariokartwii_vr integer,
		ADD IF NOT EXISTS mariokartwii_br integer,
		ADD IF NOT EXISTS mariokartwii_mmr integer;

	`)

	pool.Exec(ctx, `

	ALTER TABLE ONLY public.users
		ADD IF NOT EXISTS mariokartwii_mmr_rt integer,
		ADD IF NOT EXISTS mariokartwii_mmr_ct integer,
		ADD IF NOT EXISTS mariokartwii_mmr_vanilla integer;

	`)

	pool.Exec(ctx, `

	UPDATE public.users
	SET mariokartwii_mmr_rt = COALESCE(mariokartwii_mmr_rt, mariokartwii_mmr),
		mariokartwii_mmr_ct = COALESCE(mariokartwii_mmr_ct, mariokartwii_mmr),
		mariokartwii_mmr_vanilla = COALESCE(mariokartwii_mmr_vanilla, mariokartwii_mmr)
	WHERE mariokartwii_mmr IS NOT NULL;

	`)

	pool.Exec(ctx, `

	CREATE TABLE IF NOT EXISTS public.mkw_mmr_seasons (
		profile_id bigint NOT NULL,
		season integer NOT NULL,
		mmr_rt integer NOT NULL,
		mmr_ct integer NOT NULL,
		mmr_vanilla integer NOT NULL,
		PRIMARY KEY (profile_id, season)
	);

	CREATE TABLE IF NOT EXISTS public.mkw_mmr_settings (
		id boolean PRIMARY KEY DEFAULT true CHECK (id),
		current_season integer NOT NULL
	);

	INSERT INTO public.mkw_mmr_settings (id, current_season)
	VALUES (true, 1)
	ON CONFLICT (id) DO NOTHING;

	INSERT INTO public.mkw_mmr_seasons (profile_id, season, mmr_rt, mmr_ct, mmr_vanilla)
	SELECT profile_id, 1,
		COALESCE(mariokartwii_mmr_rt, mariokartwii_mmr, 1000),
		COALESCE(mariokartwii_mmr_ct, mariokartwii_mmr, 1000),
		COALESCE(mariokartwii_mmr_vanilla, mariokartwii_mmr, 1000)
	FROM public.users
	WHERE mariokartwii_mmr IS NOT NULL
		OR mariokartwii_mmr_rt IS NOT NULL
		OR mariokartwii_mmr_ct IS NOT NULL
		OR mariokartwii_mmr_vanilla IS NOT NULL
	ON CONFLICT (profile_id, season) DO NOTHING;

	`)

	pool.Exec(ctx, `

	DO $$ 
	BEGIN
    	IF (SELECT data_type FROM information_schema.columns WHERE table_name='users' AND column_name='ng_device_id') != 'ARRAY' THEN
        	ALTER TABLE public.users
            	ALTER COLUMN ng_device_id TYPE bigint[] using array[ng_device_id];
    	END IF;
	END $$;

	`)

	pool.Exec(ctx, `

	ALTER TABLE ONLY public.mario_kart_wii_sake
        ADD IF NOT EXISTS id serial PRIMARY KEY,
		ADD IF NOT EXISTS upload_time timestamp without time zone;
	
	`)
}
