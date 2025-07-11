package database

import (
	"context"
	"errors"
	"math/rand"
	"time"
	"wwfc/logging"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/logrusorgru/aurora/v3"
)

const (
	InsertUser              = `INSERT INTO users (user_id, gsbrcd, password, ng_device_id, email, unique_nick, csnum) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING profile_id`
	InsertUserWithProfileID = `INSERT INTO users (profile_id, user_id, gsbrcd, password, ng_device_id, email, unique_nick, csnum) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	UpdateUserTable         = `UPDATE users SET firstname = CASE WHEN $3 THEN $2 ELSE firstname END, lastname = CASE WHEN $5 THEN $4 ELSE lastname END, open_host = CASE WHEN $7 THEN $6 ELSE open_host END WHERE profile_id = $1`
	UpdateUserProfileID     = `UPDATE users SET profile_id = $3 WHERE user_id = $1 AND gsbrcd = $2`
	UpdateUserNGDeviceID    = `UPDATE users SET ng_device_id = $2 WHERE profile_id = $1`
	UpdateUserCsnum         = `UPDATE users SET csnum = $2 WHERE profile_id = $1`
	GetUser                 = `SELECT user_id, gsbrcd, ng_device_id, email, unique_nick, firstname, lastname, has_ban, ban_reason, open_host, last_ingamesn, last_ip_address, csnum, discord_id, ban_moderator, ban_reason_hidden, ban_issued, ban_expires FROM users WHERE profile_id = $1`
	ClearProfileQuery       = `DELETE FROM users WHERE profile_id = $1 RETURNING user_id, gsbrcd, email, unique_nick, firstname, lastname, open_host, last_ip_address, last_ingamesn, csnum`
	DoesUserExist           = `SELECT EXISTS(SELECT 1 FROM users WHERE user_id = $1 AND gsbrcd = $2)`
	IsProfileIDInUse        = `SELECT EXISTS(SELECT 1 FROM users WHERE profile_id = $1)`
	DeleteUserSession       = `DELETE FROM sessions WHERE profile_id = $1`
	GetUserProfileID        = `SELECT profile_id, ng_device_id, email, unique_nick, firstname, lastname, open_host, discord_id, last_ip_address, csnum FROM users WHERE user_id = $1 AND gsbrcd = $2`
	UpdateUserLastIPAddress = `UPDATE users SET last_ip_address = $2, last_ingamesn = $3 WHERE profile_id = $1`
	UpdateDiscordID         = `UPDATE users SET discord_id = $2 WHERE profile_id = $1`
	UpdateUserBan           = `UPDATE users SET has_ban = true, ban_issued = $2, ban_expires = $3, ban_reason = $4, ban_reason_hidden = $5, ban_moderator = $6, ban_tos = $7 WHERE profile_id = $1`
	DisableUserBan          = `UPDATE users SET has_ban = false WHERE profile_id = $1`

	GetMKWFriendInfoQuery    = `SELECT mariokartwii_friend_info FROM users WHERE profile_id = $1`
	UpdateMKWFriendInfoQuery = `UPDATE users SET mariokartwii_friend_info = $2 WHERE profile_id = $1`
)

type LinkStage byte

const (
	LS_NONE LinkStage = iota
	LS_STARTED
	LS_FRIENDED
	LS_FINISHED
)

type User struct {
	ProfileId          uint32
	UserId             uint64
	GsbrCode           string
	NgDeviceId         []uint32
	Email              string
	UniqueNick         string
	FirstName          string
	LastName           string
	Restricted         bool
	RestrictedDeviceId uint32
	BanReason          string
	OpenHost           bool
	LastInGameSn       string
	LastIPAddress      string
	Csnum              []string
	DiscordID          string
	// Not stored, set during discord linking and inferred LS_FINISHED from
	// DiscordID != "" on profile load
	LinkStage LinkStage
	// Following fields only used in GetUser query
	BanModerator    string
	BanReasonHidden string
	BanIssued       *time.Time
	BanExpires      *time.Time
}

var (
	ErrProfileIDInUse         = errors.New("profile ID is already in use")
	ErrReservedProfileIDRange = errors.New("profile ID is in reserved range")
)

func (user *User) CreateUser(pool *pgxpool.Pool, ctx context.Context) error {
	if user.ProfileId == 0 {
		return pool.QueryRow(ctx, InsertUser, user.UserId, user.GsbrCode, "", user.NgDeviceId, user.Email, user.UniqueNick, user.Csnum).Scan(&user.ProfileId)
	}

	if user.ProfileId >= 1000000000 {
		return ErrReservedProfileIDRange
	}

	var exists bool
	err := pool.QueryRow(ctx, IsProfileIDInUse, user.ProfileId).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		return ErrProfileIDInUse
	}

	_, err = pool.Exec(ctx, InsertUserWithProfileID, user.ProfileId, user.UserId, user.GsbrCode, "", user.NgDeviceId, user.Email, user.UniqueNick, user.Csnum)
	return err
}

func (user *User) UpdateProfileID(pool *pgxpool.Pool, ctx context.Context, newProfileId uint32) error {
	if newProfileId >= 1000000000 {
		return ErrReservedProfileIDRange
	}

	var exists bool
	err := pool.QueryRow(ctx, IsProfileIDInUse, newProfileId).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		return ErrProfileIDInUse
	}

	_, err = pool.Exec(ctx, UpdateUserProfileID, user.UserId, user.GsbrCode, newProfileId)
	if err == nil {
		user.ProfileId = newProfileId
	}

	return err
}

func (user *User) UpdateDiscordID(pool *pgxpool.Pool, ctx context.Context, discordID string) error {
	_, err := pool.Exec(ctx, UpdateDiscordID, user.ProfileId, discordID)
	if err == nil {
		user.DiscordID = discordID
	} else {
		logging.Error("DB", "Failed to persist DiscordID", aurora.Cyan(discordID), "for profile", aurora.Cyan(user.ProfileId), "error:", aurora.Cyan(err))
	}
	return err
}

func GetUniqueUserID() uint64 {
	// Not guaranteed unique but doesn't matter in practice if multiple people have the same user ID.
	return uint64(rand.Int63n(0x80000000000))
}

func (user *User) UpdateProfile(pool *pgxpool.Pool, ctx context.Context, data map[string]string) {
	firstName, firstNameExists := data["firstname"]
	lastName, lastNameExists := data["lastname"]
	openHost, openHostExists := data["wl:oh"]
	openHostBool := false
	if openHostExists && openHost != "0" {
		openHostBool = true
	}

	_, err := pool.Exec(ctx, UpdateUserTable, user.ProfileId, firstName, firstNameExists, lastName, lastNameExists, openHostBool, openHostExists)
	if err != nil {
		panic(err)
	}

	if firstNameExists {
		user.FirstName = firstName
	}

	if lastNameExists {
		user.LastName = lastName
	}

	if openHostExists {
		user.OpenHost = openHostBool
	}
}

func GetProfile(pool *pgxpool.Pool, ctx context.Context, profileId uint32) (User, error) {
	user := User{}
	row := pool.QueryRow(ctx, GetUser, profileId)

	// May be null
	var firstName *string
	var lastName *string
	var banReason *string
	var lastInGameSn *string
	var lastIPAddress *string
	var banModerator *string
	var banHiddenReason *string
	var discordID *string

	err := row.Scan(&user.UserId, &user.GsbrCode, &user.NgDeviceId, &user.Email, &user.UniqueNick, &firstName, &lastName, &user.Restricted, &banReason, &user.OpenHost, &lastInGameSn, &lastIPAddress, &user.Csnum, &discordID, &banModerator, &banHiddenReason, &user.BanIssued, &user.BanExpires)

	if err != nil {
		return User{}, err
	}

	user.ProfileId = profileId

	if firstName != nil {
		user.FirstName = *firstName
	}

	if lastName != nil {
		user.LastName = *lastName
	}

	if banReason != nil {
		user.BanReason = *banReason
	}

	if lastInGameSn != nil {
		user.LastInGameSn = *lastInGameSn
	}

	if lastIPAddress != nil {
		user.LastIPAddress = *lastIPAddress
	}

	if banModerator != nil {
		user.BanModerator = *banModerator
	}

	if banHiddenReason != nil {
		user.BanReasonHidden = *banHiddenReason
	}

	if discordID != nil {
		user.DiscordID = *discordID
		user.LinkStage = LS_FINISHED
	}

	return user, nil
}

func ClearProfile(pool *pgxpool.Pool, ctx context.Context, profileId uint32) (User, bool) {
	user := User{}
	row := pool.QueryRow(ctx, ClearProfileQuery, profileId)
	err := row.Scan(&user.UserId, &user.GsbrCode, &user.Email, &user.UniqueNick, &user.FirstName, &user.LastName, &user.OpenHost, &user.LastIPAddress, &user.LastInGameSn, &user.Csnum)

	if err != nil {
		return User{}, false
	}

	user.ProfileId = profileId
	return user, true
}

func BanUser(pool *pgxpool.Pool, ctx context.Context, profileId uint32, tos bool, length time.Duration, reason string, reasonHidden string, moderator string) bool {
	_, err := pool.Exec(ctx, UpdateUserBan, profileId, time.Now().UTC(), time.Now().UTC().Add(length), reason, reasonHidden, moderator, tos)
	return err == nil
}

func UnbanUser(pool *pgxpool.Pool, ctx context.Context, profileId uint32) bool {
	_, err := pool.Exec(ctx, DisableUserBan, profileId)
	return err == nil
}

func GetMKWFriendInfo(pool *pgxpool.Pool, ctx context.Context, profileId uint32) string {
	var info string
	err := pool.QueryRow(ctx, GetMKWFriendInfoQuery, profileId).Scan(&info)
	if err != nil {
		return ""
	}

	return info
}

func UpdateMKWFriendInfo(pool *pgxpool.Pool, ctx context.Context, profileId uint32, info string) {
	_, err := pool.Exec(ctx, UpdateMKWFriendInfoQuery, profileId, info)
	if err != nil {
		panic(err)
	}
}
