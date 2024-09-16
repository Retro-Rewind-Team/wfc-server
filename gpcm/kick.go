package gpcm

import "wwfc/common"

func kickPlayer(profileID uint32, reason string) {
	if session, exists := sessions[profileID]; exists {
		errorMessage := WWFCMsgKickedGeneric

		switch reason {
		case "banned":
			errorMessage = WWFCMsgProfileBannedTOSNow

		case "restricted":
			errorMessage = WWFCMsgProfileRestrictedNow

		case "restricted_join":
			errorMessage = WWFCMsgProfileRestricted

		case "moderator_kick":
			errorMessage = WWFCMsgKickedModerator

		case "room_kick":
			errorMessage = WWFCMsgKickedRoomHost

		case "invalid_elo":
			errorMessage = WWFCMsgInvalidELO

		case "too_many_frames_dropped":
			errorMessage = WWFCMsgTooManyFramesDropped

		case "network_error":
			// No error message
			common.CloseConnection(ServerName, session.ConnIndex)
			return
		}

		session.replyError(GPError{
			ErrorCode:   ErrConnectionClosed.ErrorCode,
			ErrorString: "The player was kicked from the server. Reason: " + reason,
			Fatal:       true,
			WWFCMessage: errorMessage,
		})
	}
}

func KickPlayer(profileID uint32, reason string) {
	mutex.Lock()
	defer mutex.Unlock()

	kickPlayer(profileID, reason)
}

// Exists because the above function is used in too many places to be updated easily
func KickPlayerCustomMessage(profileID uint32, reason string, message WWFCErrorMessage) {
	mutex.Lock()
	defer mutex.Unlock()

	if session, exists := sessions[profileID]; exists {
		session.replyError(GPError{
			ErrorCode:   ErrConnectionClosed.ErrorCode,
			ErrorString: "The player was kicked from the server. Reason: " + reason,
			Fatal:       true,
			WWFCMessage: message,
		})
	}
}
