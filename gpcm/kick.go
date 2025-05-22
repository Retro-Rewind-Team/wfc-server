package gpcm

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"wwfc/common"
	"wwfc/database"
	"wwfc/logging"
	"wwfc/qr2"

	"github.com/logrusorgru/aurora/v3"
)

func resolveWWFCMessage(reason string) WWFCErrorMessage {
	switch reason {
	case "banned":
		return WWFCMsgProfileBannedTOSNow

	case "restricted":
		return WWFCMsgProfileRestrictedNow

	case "restricted_join":
		return WWFCMsgProfileRestricted

	case "moderator_kick":
		return WWFCMsgKickedModerator

	case "room_kick":
		return WWFCMsgKickedRoomHost

	case "invalid_elo":
		return WWFCMsgInvalidELO

	}

	return WWFCMsgKickedGeneric
}

func findMatchingSessions(badSession *GameSpySession) []*GameSpySession {
	ret := []*GameSpySession{}

	badAddrSplit := strings.Split(badSession.RemoteAddr, ":")

	var badAddr string
	// If the bad address cannot be split for some reason just send a blank string
	if len(badAddrSplit) > 0 {
		badAddr = badAddrSplit[0]
	} else {
		badAddr = ""
	}

	for _, session := range sessions {
		if session.ConnIndex == badSession.ConnIndex {
			// We already know to kick this one. Don't try and kick twice.
			continue
		}

		if badSession.DeviceId != 67349608 && badSession.DeviceId == session.DeviceId {
			ret = append(ret, session)
			continue
		}

		if badAddr == "" {
			continue
		}

		// Addresses are in the form of IP:Port
		addrSplit := strings.Split(session.RemoteAddr, ":")

		if len(addrSplit) == 0 {
			continue
		}

		addr := addrSplit[0]

		if addr == badAddr {
			ret = append(ret, session)
		}
	}

	return ret
}

func KickPlayer(profileID uint32, reason string, message WWFCErrorMessage) error {
	mutex.Lock()
	defer mutex.Unlock()

	return kickPlayer(profileID, reason, message)
}

func kickPlayer(profileID uint32, reason string, message WWFCErrorMessage) error {
	var ret error

	// IP Format Functions could panic, so better safe than sorry...
	defer func() {
		if r := recover(); r != nil {
			if nerr, ok := r.(error); ok {
				ret = nerr
			} else {
				ret = errors.New(fmt.Sprintf("%s", r))
			}
		}

		if ret != nil {
			logging.Error("GPCM/Kick", "Error while kicking pid", aurora.Cyan(profileID), ret)
		}
	}()

	kickInfo := []qr2.PIDIPPair{}

	if session, exists := sessions[profileID]; exists {
		// Special exception, I don't really like this but it's behavior left over form wfc server
		if reason == "network_error" {
			common.CloseConnection(ServerName, session.ConnIndex)

			return nil
		}

		ip, _ := common.IPFormatToInt(session.RemoteAddr)
		kickInfo = append(kickInfo, qr2.PIDIPPair{PID: profileID, IP: uint32(ip)})

		gpError := GPError{
			ErrorCode:   ErrConnectionClosed.ErrorCode,
			ErrorString: "The player was kicked from the server. Reason: " + reason,
			Fatal:       true,
			WWFCMessage: message,
			Reason:      reason,
		}

		for _, match := range findMatchingSessions(session) {
			matchIP, _ := common.IPFormatToInt(match.RemoteAddr)
			kickInfo = append(kickInfo, qr2.PIDIPPair{PID: match.User.ProfileId, IP: uint32(matchIP)})

			match.replyError(gpError)
		}

		session.replyError(gpError)
	} else { // If no session is found, get the IP from the Database
		user, err := database.GetProfile(pool, ctx, profileID)

		var ip int32
		if err != nil {
			// Set ret to be returned later, but still kick just off of the PID
			ret = err
		} else {
			ip, _ = common.IPFormatToInt(user.LastIPAddress)
		}

		kickInfo = append(kickInfo, qr2.PIDIPPair{PID: user.ProfileId, IP: uint32(ip)})
	}

	// After 3 seconds, send kick order to all players
	// This is to prevent the restricted player from staying in the group if he ignores the GPCM kick
	go func() {
		time.AfterFunc(3*time.Second, func() {
			qr2.OrderKickFromGroups(kickInfo)
		})
	}()

	return ret
}
