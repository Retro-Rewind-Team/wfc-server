package qr2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"wwfc/common"
	"wwfc/logging"

	"github.com/logrusorgru/aurora/v3"
	"gvisor.dev/gvisor/pkg/sleep"
)

func printHex(data []byte) string {
	logMsg := ""
	for i := 0; i < len(data); i++ {
		if (i % 32) == 0 {
			logMsg += "\n"
		}
		logMsg += fmt.Sprintf("%02x ", data[i])
	}

	return logMsg
}

func SendClientMessage(senderIP string, destSearchID uint64, message []byte) {
	moduleName := "QR2/MSG"

	var matchData common.MatchCommandData
	var sender *Session
	var receiver *Session

	useSearchID := destSearchID < (1 << 24)
	if useSearchID {
		receiver = sessionBySearchID[destSearchID]
	} else {
		// It's an IP address, used in some circumstances
		receiver = sessions[destSearchID]
	}

	if receiver == nil || !receiver.Authenticated {
		logging.Error(moduleName, "Destination", aurora.Cyan(destSearchID), "does not exist")
		return
	}

	if destPid, ok := receiver.Data["dwc_pid"]; !ok || destPid == "" {
		logging.Error(moduleName, "Destination", aurora.Cyan(destSearchID), "has no profile ID")
		return
	}

	if receiver.login == nil || !receiver.login.DeviceAuthenticated {
		logging.Error(moduleName, "Destination", aurora.Cyan(destSearchID), "is not device authenticated")
	}

	// Decode and validate the message
	isNatnegPacket := false
	if bytes.Equal(message[:2], []byte{0xfd, 0xfc}) {
		// Sending natneg cookie
		isNatnegPacket = true
		if len(message) != 0xA {
			logging.Error(moduleName, "Received invalid length NATNEG packet")
			return
		}

		natnegID := binary.LittleEndian.Uint32(message[0x6:0xA])
		moduleName = "QR2/MSG:s" + strconv.FormatUint(uint64(natnegID), 10)
	} else if bytes.Equal(message[:4], []byte{0xbb, 0x49, 0xcc, 0x4d}) || bytes.Equal(message[:4], []byte("SBCM")) {
		// DWC match command
		if len(message) < 0x14 || len(message) > 0x94 {
			logging.Error(moduleName, "Received invalid length match command packet")
			return
		}

		version := int(binary.LittleEndian.Uint32(message[0x04:0x08]))
		if version != 3 && version != 11 && version != 90 {
			logging.Error(moduleName, "Received invalid match version")
			return
		}

		senderProfileID := binary.LittleEndian.Uint32(message[0x10:0x14])
		moduleName = "QR2/MSG:p" + strconv.FormatUint(uint64(senderProfileID), 10)

		if (int(message[9]) + 0x14) != len(message) {
			logging.Error(moduleName, "Received invalid match command packet header")
			return
		}

		qr2IP := binary.BigEndian.Uint32(message[0x0C:0x10])
		qr2Port := binary.LittleEndian.Uint16(message[0x0A:0x0C])

		sender = sessions[(uint64(qr2Port)<<32)|uint64(qr2IP)]
		if sender == nil || !sender.Authenticated {
			logging.Error(moduleName, "Session does not exist with QR2 IP and port")
			return
		}

		if !sender.setProfileID(moduleName, strconv.FormatUint(uint64(senderProfileID), 10), strings.Split(senderIP, ":")[0]) {
			// Error already logged
			return
		}

		if sender.login == nil || !sender.login.DeviceAuthenticated {
			logging.Error(moduleName, "Sender is not device authenticated")
			return
		}

		mutex.Lock()
		if sender.Data["gamename"] != receiver.Data["gamename"] {
			mutex.Unlock()
			logging.Error(moduleName, "Sender and receiver are not playing the same game")
			return
		}
		mutex.Unlock()

		var ok bool
		matchData, ok = common.DecodeMatchCommand(message[8], message[0x14:], version)
		if !ok {
			logging.Error(moduleName, "Received invalid match command:", aurora.Cyan(printHex(message)))
			return
		}

		if message[8] == common.MatchReservation {
			if matchData.Reservation.HasPublicIP {
				if qr2IP != matchData.Reservation.PublicIP {
					logging.Error(moduleName, "RESERVATION: Public IP mismatch in header and command")
					return
				}

				if qr2Port != matchData.Reservation.PublicPort {
					logging.Error(moduleName, "RESERVATION: Public port mismatch in header and command")
					return
				}
			}

			if version == 90 {
				if matchData.Reservation.LocalPort < 1024 {
					logging.Error(moduleName, "RESERVATION: Local port is reserved")
					return
				}
			}

			if useSearchID {
				matchData.Reservation.PublicIP = uint32(sender.SearchID & 0xffffffff)
				matchData.Reservation.PublicPort = uint16((sender.SearchID >> 32) & 0xffff)
				matchData.Reservation.LocalIP = 0
				matchData.Reservation.LocalPort = 0
			}
		}

		if message[8] == common.MatchResvOK {
			if qr2IP != matchData.ResvOK.PublicIP {
				logging.Error(moduleName, "RESERVATION: Public IP mismatch in header and command")
				return
			}

			if qr2Port != matchData.ResvOK.PublicPort {
				logging.Error(moduleName, "RESERVATION: Public port mismatch in header and command")
				return
			}

			if version == 90 {
				if matchData.ResvOK.LocalPort < 1024 {
					logging.Error(moduleName, "RESV_OK: Local port is reserved")
					return
				}

				if matchData.ResvOK.ProfileID != senderProfileID {
					logging.Error(moduleName, "RESV_OK: Profile ID mismatch in header")
					return
				}
			}

			if useSearchID {
				matchData.ResvOK.PublicIP = uint32(sender.SearchID & 0xffffffff)
				matchData.ResvOK.PublicPort = uint16((sender.SearchID >> 32) & 0xffff)
				matchData.ResvOK.LocalIP = 0
				matchData.ResvOK.LocalPort = 0
			}
		}

		if message[8] == common.MatchTellAddr {
			mutex.Lock()
			if sender.Data["publicip"] != receiver.Data["publicip"] {
				mutex.Unlock()
				logging.Error(moduleName, "TELL_ADDR: Public IP does not match receiver")
				return
			}
			mutex.Unlock()

			if matchData.TellAddr.LocalPort < 1024 {
				logging.Error(moduleName, "TELL_ADDR: Local port is reserved")
				return
			}
		}

		if useSearchID {
			// Convert public IP to search ID
			qr2SearchID := binary.LittleEndian.AppendUint16([]byte{}, uint16((sender.SearchID>>32)&0xffff))
			qr2SearchID = binary.BigEndian.AppendUint32(qr2SearchID, uint32(sender.SearchID&0xffffffff))
			message = append(message[:0x0A], append(qr2SearchID, message[0x10:0x14]...)...)
		} else {
			message = message[:0x14]
		}

		var matchMessage []byte
		matchMessage, ok = common.EncodeMatchCommand(message[8], matchData)
		if !ok || len(matchMessage) > 0x80 {
			logging.Error(moduleName, "Failed to reencode match command:", aurora.Cyan(printHex(message)))
			return
		}

		if len(matchMessage) != 0 {
			message = append(message, matchMessage...)
		}
	} else {
		logging.Error(moduleName, "Invalid message:", aurora.Cyan(printHex(message)))
	}

	destSessionID, packetCount, destAddr := processClientMessage(moduleName, sender, receiver, message, isNatnegPacket, matchData)

	payload := createResponseHeader(ClientMessageRequest, destSessionID)

	payload = append(payload, []byte{0, 0, 0, 0}...)
	binary.BigEndian.PutUint32(payload[len(payload)-4:], packetCount)
	payload = append(payload, message...)

	receiver.messageMutex.Lock()
	if receiver.login == nil {
		receiver.messageMutex.Unlock()
		return
	}
	// Store the profile ID for later use if needed
	profileID := receiver.login.ProfileID
	// Clear the waker while holding the lock
	receiver.messageAckWaker.Clear()
	receiver.messageMutex.Unlock()

	// Set up sleep management outside of lock
	s := sleep.Sleeper{}
	defer s.Done()

	// Brief lock to add the waker
	receiver.messageMutex.Lock()
	s.AddWaker(receiver.messageAckWaker)
	receiver.messageMutex.Unlock()

	timeWaker := sleep.Waker{}
	s.AddWaker(&timeWaker)

	timeOutCount := 0
	for {
		time.AfterFunc(1*time.Second, func() {
			timeWaker.Assert()
		})

		// Network I/O without holding any locks
		_, err := masterConn.WriteTo(payload, &destAddr)
		if err != nil {
			logging.Error(moduleName, "Error sending message:", err.Error())
		}

		// Wait for an ack or timeout (no locks held)
		switch s.Fetch(true) {
		case &timeWaker:
			timeOutCount++

			// Enforce a 10s  timeout
			if timeOutCount <= 10 {
				break
			}

			logging.Error(moduleName, "Timed out waiting for ack")

			receiver.messageMutex.Lock()

			if receiver.login != nil && receiver.login.ProfileID == profileID {
				gpErrorCallback(profileID, "network_error")
				receiver.login = nil
			}
			receiver.messageMutex.Unlock()
			return

		default:
			return
		}
	}
}

func processClientMessage(moduleName string, sender, receiver *Session, message []byte, isNatnegPacket bool, matchData common.MatchCommandData) (destSessionID uint32, packetCount uint32, destAddr net.UDPAddr) {
	mutex.Lock()

	destPid, ok := receiver.Data["dwc_pid"]
	if !ok || destPid == "" {
		destPid = "<UNKNOWN>"
	}

	destSessionID = receiver.SessionID
	packetCount = receiver.PacketCount + 1
	receiver.PacketCount = packetCount
	destAddr = receiver.Addr

	if isNatnegPacket {
		mutex.Unlock()
		cookie := binary.BigEndian.Uint32(message[0x6:0xA])
		logging.Notice(moduleName, "Send NN cookie", aurora.Cyan(strconv.FormatUint(uint64(cookie), 16)), "to", aurora.BrightCyan(destPid))
		return
	}
	defer mutex.Unlock()

	cmd := message[8]
	common.LogMatchCommand(moduleName, destPid, cmd, matchData)

	if cmd == common.MatchReservation {
		resvError := checkReservationAllowed(moduleName, sender, receiver, matchData.Reservation.MatchType)
		if resvError != "ok" {
			if resvError == "restricted" || resvError == "restricted_join" {
				logging.Error(moduleName, "RESERVATION: Restricted player attempted to join a public match")

				if sender.login != nil && sender.login.Restricted {
					profileId := sender.login.ProfileID

					mutex.Unlock()
					gpErrorCallback(profileId, resvError)
					mutex.Lock()
				}
				if receiver.login != nil && receiver.login.Restricted {
					profileId := receiver.login.ProfileID

					mutex.Unlock()
					gpErrorCallback(profileId, resvError)
					mutex.Lock()
				}
			}
			return
		}

		sender.Reservation = matchData
		sender.ReservationID = receiver.SearchID
	} else if cmd == common.MatchResvOK || cmd == common.MatchResvDeny || cmd == common.MatchResvWait {
		if receiver.ReservationID != sender.SearchID || receiver.Reservation.Reservation == nil {
			logging.Warn(moduleName, "Destination has no reservation with the sender")
			if receiver.groupPointer == nil || receiver.groupPointer != sender.groupPointer {
				return
			}
			// Allow the message through anyway to avoid a room deadlock
		}

		if receiver.Reservation.Version != matchData.Version {
			logging.Error(moduleName, "Reservation version mismatch")
			return
		}

		if cmd == common.MatchResvOK {
			if !processResvOK(moduleName, matchData.Version, *receiver.Reservation.Reservation, *matchData.ResvOK, sender, receiver) {
				return
			}
		} else if receiver.ReservationID == sender.SearchID {
			receiver.ReservationID = 0
		}
	} else if cmd == common.MatchTellAddr {
		processTellAddr(moduleName, sender, receiver)
	}

	return
}

func sendClientExploit(moduleName string, sessionCopy Session) {
	if len(sessionCopy.login.GameCode) != 4 || !common.IsUppercaseAlphanumeric(sessionCopy.login.GameCode) {
		logging.Error(moduleName, "Invalid game code:", aurora.Cyan(sessionCopy.login.GameCode))
		return
	}

	exploit, err := os.ReadFile("payload/sbcm/" + "payload." + sessionCopy.login.GameCode + ".bin")
	if err != nil {
		logging.Error(moduleName, "Error reading exploit file", aurora.Cyan(sessionCopy.login.GameCode), "-", err.Error())
		return
	}

	mutex.Lock()
	session, sessionExists := sessions[makeLookupAddr(sessionCopy.Addr.String())]
	if !sessionExists {
		mutex.Unlock()
		logging.Error(moduleName, "Session not found")
		return
	}

	packetCount := session.PacketCount + 1
	session.PacketCount = packetCount
	mutex.Unlock()

	// Now send the exploit
	payload := createResponseHeader(ClientMessageRequest, sessionCopy.SessionID)
	payload = append(payload, []byte{0, 0, 0, 0}...)
	binary.BigEndian.PutUint32(payload[len(payload)-4:], packetCount)
	payload = append(payload, exploit[0xB:]...)

	go func() {
		for {
			_, err = masterConn.WriteTo(payload, &sessionCopy.Addr)
			if err != nil {
				logging.Error(moduleName, "Error sending message:", err.Error())
			}

			// Resend the message if no ack after 2 seconds
			time.Sleep(2 * time.Second)

			mutex.Lock()
			session, sessionExists := sessions[makeLookupAddr(sessionCopy.Addr.String())]
			if !sessionExists || session.ExploitReceived || session.login == nil || !session.login.NeedsExploit {
				mutex.Unlock()
				return
			}

			mutex.Unlock()
			logging.Notice(moduleName, "Resending SBCM exploit to DNS patcher client")
		}
	}()
}
