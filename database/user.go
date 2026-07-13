package database

import (
	"context"
	"encoding/base64"
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
	CountTotalUsersQuery     = `SELECT COUNT(DISTINCT csnum) FROM users`
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
	ErrFailedToGetMKWFriend   = errors.New("failed to get MKW friend info")
	ErrCountHasNoRows         = errors.New("failed to count active users, result has no rows")
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

func sanitizeMKWFriendInfo(mii string, sysID bool) (string, error) {
	miiBytes, err := base64.StdEncoding.DecodeString(mii)

	if err != nil {
		return "", err
	}

	// Zero birth day and birth month
	miiBytes[0x00] &= 0b11000000
	miiBytes[0x01] &= 0b00011111

	if sysID {
		for i := range 4 {
			// Zero sysid
			miiBytes[0x1C+i] = 0
		}
	}

	// Zero creation timestamp
	// Keep top 3 bits of the first byte (special, foreign, regular)
	miiBytes[0x18] = miiBytes[0x18] & 0xE0
	miiBytes[0x19] = 0
	miiBytes[0x1A] = 0
	miiBytes[0x1B] = 0

	// Zero creator name
	for i := 0x36; i < 0x49; i++ {
		miiBytes[i] = 0
	}

	return base64.RawStdEncoding.EncodeToString(miiBytes), nil
}

// GetMKWFriendInfoSanitized Returns the b64 representation of a mii with the birthdate, creation date, creator, and sysid removed
func GetMKWFriendInfoSanitized(pool *pgxpool.Pool, ctx context.Context, profileId uint32) (string, error) {
	mii := GetMKWFriendInfo(pool, ctx, profileId)

	if mii == "" {
		return "", ErrFailedToGetMKWFriend
	}

	return sanitizeMKWFriendInfo(mii, true)
}

func UpdateMKWFriendInfo(pool *pgxpool.Pool, ctx context.Context, profileId uint32, info string) error {
	// We save with sysID for moderator usage. Payload should sanitize
	// everything here but we re-sanitize just in case.
	sanitizedInfo, err := sanitizeMKWFriendInfo(info, false)
	if err != nil {
		return err
	}

	_, err = pool.Exec(ctx, UpdateMKWFriendInfoQuery, profileId, sanitizedInfo)
	return err
}

// ScanUsers takes a query returning pids and collect the matching users
func ScanUsers(pool *pgxpool.Pool, ctx context.Context, query string) ([]User, error) {
	logging.Info("QUERY", "Executing query", aurora.Cyan(query))

	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	pids := []uint32{}

	count := 0
	for rows.Next() {
		count++

		var pid uint32
		err := rows.Scan(&pid)
		if err != nil {
			return nil, err
		}

		pids = append(pids, pid)
	}

	users := []User{}

	for _, pid := range pids {
		user, err := GetProfile(pool, ctx, pid)
		if err != nil {
			return nil, err
		}

		users = append(users, user)
	}

	return users, nil
}

func CountTotalUsers(pool *pgxpool.Pool, ctx context.Context) (int, error) {
	logging.Info("QUERY", "Counting players")

	rows, err := pool.Query(ctx, CountTotalUsersQuery)
	if err != nil {
		return 0, err
	}

	defer rows.Close()
	if !rows.Next() {
		return 0, ErrCountHasNoRows
	}

	var count int
	rows.Scan(&count)

	return count, nil
}
