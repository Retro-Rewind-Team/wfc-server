package qr2

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"wwfc/common"
	"wwfc/logging"

	"github.com/logrusorgru/aurora/v3"
)

func heartbeat(moduleName string, conn net.PacketConn, addr net.UDPAddr, buffer []byte) {
	sessionId := binary.BigEndian.Uint32(buffer[1:5])
	values := strings.Split(string(buffer[5:]), "\u0000")

	payload := map[string]string{}
	unknowns := []string{}
	for i := 0; i < len(values); i += 2 {
		if len(values[i]) == 0 || values[i][0] == '+' {
			continue
		}

		if values[i] == "unknown" {
			unknowns = append(unknowns, values[i+1])
			continue
		}

		payload[values[i]] = values[i+1]
	}

	if payload["dwc_mtype"] != "" {
		logging.Info(moduleName, "Match type:", aurora.Cyan(payload["dwc_mtype"]))
	}

	if payload["dwc_hoststate"] != "" {
		logging.Info(moduleName, "Host state:", aurora.Cyan(payload["dwc_hoststate"]))
	}

	realIP, realPort := common.IPFormatToString(addr.String())

	noIP := false
	if ip, ok := payload["publicip"]; !ok || ip == "0" {
		noIP = true
	}

	clientEndianness := common.GetExpectedUnitCode(payload["gamename"])
	if !noIP && clientEndianness == ClientBigEndian {
		if payload["publicip"] != realIP || payload["publicport"] != realPort {
			// Client is mistaken about its public IP
			logging.Error(moduleName, "Public IP mismatch")
			return
		}
	} else if !noIP && clientEndianness == ClientLittleEndian {
		realIPLE, realPortLE := common.IPFormatToStringLE(addr.String())
		if payload["publicip"] != realIPLE || payload["publicport"] != realPortLE {
			// Client is mistaken about its public IP
			logging.Error(moduleName, "Public IP mismatch")
			return
		}
	}
	// Else it's a cross-compatible game and the endianness is ambiguous

	payload["publicip"] = realIP
	payload["publicport"] = realPort

	lookupAddr := makeLookupAddr(addr.String())

	// Check for session shutdown early, outside any mutex
	statechanged, ok := payload["statechanged"]
	if ok && statechanged == "2" {
		logging.Notice(moduleName, "Client session shutdown")
		mutex.Lock()
		removeSession(lookupAddr)
		mutex.Unlock()
		return
	}

	// Validate rating before acquiring any locks
	ratingError := checkValidRating(moduleName, payload)

	// CRITICAL: handleConnection already has the mutex locked, so we should NOT lock it again
	// Create or update the session without locking the mutex again
	session, ok := setSessionData(moduleName, &addr, sessionId, payload)
	if !ok {
		return
	}

	// No mutex needed - we're just checking a local variable
	if ratingError != "ok" {
		// Only check at this point, after setSessionData, so we have a valid session with login
		if session.login != nil {
			profileId := session.login.ProfileID
			gpErrorCallback(profileId, ratingError)
			return
		}
	}

	// Process unknowns without acquiring mutex recursively
	if len(unknowns) > 0 && session.login == nil {
		profileId := unknowns[0]
		logging.Info(moduleName, "Attempting to use unknown as profile ID", aurora.Cyan(profileId))
		
		// We already have the mutex from handleConnection, just use it directly
		sessionPtr := sessions[lookupAddr]
		if sessionPtr != nil && sessionPtr.login == nil {
			sessionPtr.setProfileID(moduleName, profileId, "")
		}
	}

	if !session.Authenticated || noIP {
		sendChallenge(conn, addr, session, lookupAddr)
	}

	// Work with exploit sending without acquiring mutex recursively
	currentSession := sessions[lookupAddr]
	if currentSession != nil {
		if !currentSession.ExploitReceived && currentSession.login != nil && currentSession.login.NeedsExploit {
			// The version of DWC in Mario Kart DS doesn't check matching status
			if (!noIP && statechanged == "1") || 
			   currentSession.login.GameCode == "AMCE" || 
			   currentSession.login.GameCode == "AMCP" || 
			   currentSession.login.GameCode == "AMCJ" {
				sessionCopy := *currentSession
				
				// Temporarily release mutex during the exploit send
				mutex.Unlock()
				logging.Notice(moduleName, "Sending SBCM exploit to DNS patcher client")
				sendClientExploit(moduleName, sessionCopy)
				mutex.Lock()
			}
		} else if currentSession.groupPointer != nil {
			// Update the group server if needed
			if currentSession.groupPointer.server == nil {
				currentSession.groupPointer.findNewServer()
			} else {
				// Update the match type if needed
				currentSession.groupPointer.updateMatchType()
			}
		}
	}
}

func checkValidRating(moduleName string, payload map[string]string) string {
	if payload["gamename"] == "mariokartwii" {
		// ev and eb values must be in range 1 to 9999
		if ev := payload["ev"]; ev != "" {
			evInt, err := strconv.ParseInt(ev, 10, 16)
			if err != nil || evInt < 1 || evInt > 30000 {
				logging.Error(moduleName, "Invalid ev value:", aurora.Cyan(ev))
				return "invalid_elo"
			}
		}

		if eb := payload["eb"]; eb != "" {
			ebInt, err := strconv.ParseInt(eb, 10, 16)
			if err != nil || ebInt < 1 || ebInt > 30000 {
				logging.Error(moduleName, "Invalid eb value:", aurora.Cyan(eb))
				return "invalid_elo"
			}
		}
	}

	return "ok"
}