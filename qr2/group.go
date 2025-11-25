package qr2

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"wwfc/common"
	"wwfc/logging"

	"github.com/logrusorgru/aurora/v3"
)

type RacePlayer struct {
	TeamID              int
	RaceStage           uint32
	LastRaceStageUpdate time.Time
}

type RaceResult struct {
	ProfileID     uint32
	PlayerID      int
	FinishTime    uint32
	CharacterID   uint32
	VehicleID     uint32
	PlayerCount   uint32
	FinishPos     int
	FramesIn1st   uint32
	CourseID      int
	EngineClassID int
}

var racePlayers = map[string]map[uint32][]RacePlayer{} // GroupName -> ProfileID -> []RacePlayer
var raceResults = map[string]map[int][]RaceResult{}    // GroupName -> RaceNumber -> []RaceResult

type Group struct {
	GroupID       uint32
	GroupName     string
	CreateTime    time.Time
	GameName      string
	MatchType     string
	MKWRegion     string
	LastJoinIndex int
	server        *Session
	players       map[*Session]bool

	MKWRaceNumber    int
	MKWCourseID      int
	MKWEngineClassID int
}

var groups = map[string]*Group{}

func normalizeMKWRegion(rk string) string {
	// Check and remove regional searches due to the limited player count
	// China (ID 6) gets a pass because it was never released
	if len(rk) == 4 && (strings.HasPrefix(rk, "vs_") || strings.HasPrefix(rk, "bt_")) && rk[3] >= '0' && rk[3] < '6' {
		return rk[:2]
	}

	return rk
}

func processResvOK(moduleName string, matchVersion int, reservation common.MatchCommandDataReservation, resvOK common.MatchCommandDataResvOK, sender, destination *Session) bool {
	if len(groups) >= 100000 {
		logging.Error(moduleName, "Hit arbitrary global maximum group count (somehow)")
		return false
	}

	group := sender.groupPointer
	if group == nil {
		group = &Group{
			GroupID:       resvOK.GroupID,
			GroupName:     "",
			CreateTime:    time.Now().UTC(),
			GameName:      sender.Data["gamename"],
			MatchType:     sender.Data["dwc_mtype"],
			MKWRegion:     "",
			LastJoinIndex: 0,
			server:        sender,
			players:       map[*Session]bool{sender: true},
		}

		for {
			groupName := common.RandomString(6)
			if groups[groupName] != nil {
				continue
			}

			group.GroupName = groupName
			break
		}

		if group.GameName == "mariokartwii" {
			group.MKWRegion = normalizeMKWRegion(sender.Data["rk"])
		}

		sender.Data["+joinindex"] = "0"
		if matchVersion == 90 {
			sender.Data["+localplayers"] = strconv.FormatUint(uint64(resvOK.LocalPlayerCount), 10)
		}

		sender.groupPointer = group
		sender.GroupName = group.GroupName
		groups[group.GroupName] = group

		logging.Notice(moduleName, "Created new group", aurora.Cyan(group.GroupName))
	}

	// Keep group ID updated
	group.GroupID = resvOK.GroupID

	// Set connecting
	sender.Data["+conn_"+destination.Data["+joinindex"]] = "1"
	destination.Data["+conn_"+sender.Data["+joinindex"]] = "1"

	if group.players[destination] {
		// Player is already in the group
		return true
	}

	logging.Notice(moduleName, "New player", aurora.BrightCyan(destination.Data["dwc_pid"]), "in group", aurora.Cyan(group.GroupName))

	group.LastJoinIndex++
	destination.Data["+joinindex"] = strconv.Itoa(group.LastJoinIndex)
	if matchVersion == 90 {
		destination.Data["+localplayers"] = strconv.FormatUint(uint64(reservation.LocalPlayerCount), 10)
	}

	if destination.groupPointer != nil && destination.groupPointer != group {
		destination.removeFromGroup()
	}

	group.players[destination] = true
	destination.groupPointer = group
	destination.GroupName = group.GroupName

	return true
}

func processTellAddr(moduleName string, sender *Session, destination *Session) {
	if sender.groupPointer != nil && sender.groupPointer == destination.groupPointer {
		// Just assume the connection is successful if TELL_ADDR is used
		sender.Data["+conn_"+destination.Data["+joinindex"]] = "2"
		destination.Data["+conn_"+sender.Data["+joinindex"]] = "2"
	}
}

func ProcessGPResvOK(matchVersion int, reservation common.MatchCommandDataReservation, resvOK common.MatchCommandDataResvOK, senderIP uint64, senderPid uint32, destIP uint64, destPid uint32) bool {
	senderPidStr := strconv.FormatUint(uint64(senderPid), 10)
	destPidStr := strconv.FormatUint(uint64(destPid), 10)

	moduleName := "QR2:GPMsg:" + senderPidStr + "->" + destPidStr

	mutex.Lock()
	defer mutex.Unlock()

	from := sessions[senderIP]
	if from == nil {
		logging.Error(moduleName, "Sender IP does not exist:", aurora.Cyan(fmt.Sprintf("%012x", senderIP)))
		return false
	}

	to := sessions[destIP]
	if to == nil {
		logging.Error(moduleName, "Destination IP does not exist:", aurora.Cyan(fmt.Sprintf("%012x", destIP)))
		return false
	}

	// Validate dwc_pid values
	if !from.setProfileID(moduleName, senderPidStr, "") {
		return false
	}

	if !to.setProfileID(moduleName, destPidStr, "") {
		return false
	}

	return processResvOK(moduleName, matchVersion, reservation, resvOK, from, to)
}

func ProcessGPTellAddr(senderPid uint32, senderIP uint64, destPid uint32, destIP uint64) {
	senderPidStr := strconv.FormatUint(uint64(senderPid), 10)
	destPidStr := strconv.FormatUint(uint64(destPid), 10)

	moduleName := "QR2:GPMsg:" + senderPidStr + "->" + destPidStr

	mutex.Lock()
	defer mutex.Unlock()

	from := sessions[senderIP]
	if from == nil {
		logging.Error(moduleName, "Sender IP does not exist:", aurora.Cyan(fmt.Sprintf("%012x", senderIP)))
		return
	}

	to := sessions[destIP]
	if to == nil {
		logging.Error(moduleName, "Destination IP does not exist:", aurora.Cyan(fmt.Sprintf("%012x", destIP)))
		return
	}

	// Validate dwc_pid values
	if !from.setProfileID(moduleName, senderPidStr, "") {
		return
	}

	if !to.setProfileID(moduleName, destPidStr, "") {
		return
	}

	processTellAddr(moduleName, from, to)
}

func ProcessGPStatusUpdate(profileID uint32, senderIP uint64, status string) {
	moduleName := "QR2/GPStatus:" + strconv.FormatUint(uint64(profileID), 10)

	mutex.Lock()
	defer mutex.Unlock()

	login, exists := logins[profileID]
	if !exists || login == nil {
		logging.Info(moduleName, "Received status update for non-existent profile ID", aurora.Cyan(profileID))
		return
	}

	session := login.session
	if session == nil {
		if senderIP == 0 {
			logging.Info(moduleName, "Received status update for profile ID", aurora.Cyan(profileID), "but no session exists")
			return
		}

		// Login with this profile ID
		session, exists = sessions[senderIP]
		if !exists || session == nil {
			logging.Info(moduleName, "Received status update for profile ID", aurora.Cyan(profileID), "but no session exists")
			return
		}

		if !session.setProfileID(moduleName, strconv.FormatUint(uint64(profileID), 10), "") {
			return
		}
	}

	// Send the client message exploit if not received yet
	if status != "0" && status != "1" && !session.ExploitReceived && session.login != nil && session.login.NeedsExploit {
		sessionCopy := *session

		mutex.Unlock()
		logging.Notice(moduleName, "Sending SBCM exploit to DNS patcher client")
		sendClientExploit(moduleName, sessionCopy)
		mutex.Lock()
	}

	if status == "0" || status == "1" || status == "3" || status == "4" {
		session := sessions[senderIP]
		if session == nil || session.groupPointer == nil {
			return
		}

		session.removeFromGroup()
	}
}

func checkReservationAllowed(moduleName string, sender, destination *Session, joinType byte) string {
	if sender.login == nil || destination.login == nil {
		return ""
	}

	if !sender.login.Restricted && !destination.login.Restricted {
		return "ok"
	}

	if joinType != 2 && joinType != 3 {
		return "restricted_join"
	}

	// TODO: Once OpenHost is implemented, disallow joining public rooms

	if destination.groupPointer == nil {
		// Destination is not in a group, check their dwc_mtype instead
		if destination.Data["dwc_mtype"] != "2" && destination.Data["dwc_mtype"] != "3" {
			return "restricted_join"
		}

		// This is fine
		return "ok"
	}

	if destination.groupPointer.MatchType != "private" {
		return "restricted_join"
	}

	return "ok"
}

func CheckGPReservationAllowed(senderIP uint64, senderPid uint32, destPid uint32, joinType byte) string {
	senderPidStr := strconv.FormatUint(uint64(senderPid), 10)
	destPidStr := strconv.FormatUint(uint64(destPid), 10)

	moduleName := "QR2:CheckReservation:" + senderPidStr + "->" + destPidStr

	mutex.Lock()
	defer mutex.Unlock()

	from := sessions[senderIP]
	if from == nil {
		logging.Error(moduleName, "Sender IP does not exist:", aurora.Cyan(fmt.Sprintf("%012x", senderIP)))
		return ""
	}

	toLogin := logins[destPid]
	if toLogin == nil {
		logging.Error(moduleName, "Destination profile ID does not exist:", aurora.Cyan(destPid))
		return ""
	}

	to := toLogin.session
	if to == nil {
		logging.Error(moduleName, "Destination profile ID does not have a session")
		return ""
	}

	// Validate dwc_pid value
	if !from.setProfileID(moduleName, senderPidStr, "") || from.login == nil {
		return ""
	}

	return checkReservationAllowed(moduleName, from, to, joinType)
}

func ProcessNATNEGReport(result byte, ip1 string, ip2 string) {
	moduleName := "QR2:NATNEGReport"

	ip1Lookup := makeLookupAddr(ip1)
	ip2Lookup := makeLookupAddr(ip2)

	mutex.Lock()
	defer mutex.Unlock()

	session1 := sessions[ip1Lookup]
	if session1 == nil {
		logging.Warn(moduleName, "Received NATNEG report for non-existent IP", aurora.Cyan(ip1))
		return
	}

	session2 := sessions[ip2Lookup]
	if session2 == nil {
		logging.Warn(moduleName, "Received NATNEG report for non-existent IP", aurora.Cyan(ip2))
		return
	}

	if session1.groupPointer == nil || session1.groupPointer != session2.groupPointer {
		logging.Warn(moduleName, "Received NATNEG report for two IPs in different groups")
		return
	}

	resultString := "3"
	if result == 1 {
		// Success
		resultString = "2"
	}

	session1.Data["+conn_"+session2.Data["+joinindex"]] = resultString
	session2.Data["+conn_"+session1.Data["+joinindex"]] = resultString

	if result != 1 {
		// Increment +conn_fail
		connFail1, _ := strconv.Atoi(session1.Data["+conn_fail"])
		connFail2, _ := strconv.Atoi(session2.Data["+conn_fail"])
		connFail1++
		connFail2++
		session1.Data["+conn_fail"] = strconv.Itoa(connFail1)
		session2.Data["+conn_fail"] = strconv.Itoa(connFail2)
	}
}

func ProcessUSER(senderPid uint32, senderIP uint64, packet []byte) {
	moduleName := "QR2:ProcessUSER/" + strconv.FormatUint(uint64(senderPid), 10)

	mutex.Lock()
	login := logins[senderPid]
	if login == nil {
		mutex.Unlock()
		logging.Warn(moduleName, "Received USER packet from non-existent profile ID", aurora.Cyan(senderPid))
		return
	}

	session := login.session
	if session == nil {
		mutex.Unlock()
		logging.Warn(moduleName, "Received USER packet from profile ID", aurora.Cyan(senderPid), "but no session exists")
		return
	}
	mutex.Unlock()

	miiGroupCount := binary.BigEndian.Uint16(packet[0x04:0x06])
	if miiGroupCount != 2 {
		logging.Error(moduleName, "Received USER packet with unexpected Mii group count", aurora.Cyan(miiGroupCount))
		// Kick the client
		gpErrorCallback(senderPid, "bad_packet")
		return
	}

	miiGroupBitflags := binary.BigEndian.Uint32(packet[0x00:0x04])

	var miiData []string
	var miiName []string
	for i := 0; i < int(miiGroupCount); i++ {
		if miiGroupBitflags&(1<<uint(i)) == 0 {
			continue
		}

		index := 0x08 + i*0x4C
		mii := common.Mii(packet[index : index+0x4C])
		if mii.RFLCalculateCRC() != 0x0000 {
			logging.Error(moduleName, "Received USER packet with invalid Mii data CRC")
			gpErrorCallback(senderPid, "bad_packet")
			return
		}

		createId := binary.BigEndian.Uint64(packet[index+0x18 : index+0x20])
		official, _ := common.RFLSearchOfficialData(createId)
		if official {
			miiName = append(miiName, "Player")
		} else {
			decodedName, err := common.GetWideString(packet[index+0x2:index+0x2+20], binary.BigEndian)
			if err != nil {
				logging.Error(moduleName, "Failed to parse Mii name:", err)
				gpErrorCallback(senderPid, "bad_packet")
				return
			}

			miiName = append(miiName, decodedName)
		}

		miiData = append(miiData, base64.StdEncoding.EncodeToString(packet[index:index+0x4A]))
	}

	mutex.Lock()
	defer mutex.Unlock()

	for i, name := range miiName {
		session.Data["+mii"+strconv.Itoa(i)] = miiData[i]
		session.Data["+mii_name"+strconv.Itoa(i)] = name
	}
}

// findNewServer attempts to find the new server/host in the group when the current server goes down.
// If no server is found, the group's server pointer is set to nil.
// Expects the mutex to be locked.
func (g *Group) findNewServer() {
	server := (*Session)(nil)
	serverJoinIndex := -1
	for session := range g.players {
		if session.Data["dwc_hoststate"] != "2" {
			continue
		}

		joinIndex, err := strconv.Atoi(session.Data["+joinindex"])
		if err != nil {
			continue
		}

		if server == nil || joinIndex < serverJoinIndex {
			server = session
			serverJoinIndex = joinIndex
		}
	}

	g.server = server
	g.updateMatchType()
}

// updateMatchType updates the match type of the group based on the host's dwc_mtype value.
// Expects the mutex to be locked.
func (g *Group) updateMatchType() {
	if g.server == nil || g.server.Data["dwc_mtype"] == "" {
		return
	}

	g.MatchType = g.server.Data["dwc_mtype"]
}

func ProcessMKWSelectRecord(profileId uint32, key string, value string) {
	moduleName := "QR2:MKWSelectRecord:" + strconv.FormatUint(uint64(profileId), 10)

	mutex.Lock()
	login := logins[profileId]
	if login == nil {
		mutex.Unlock()
		logging.Warn(moduleName, "Received SELECT record from non-existent profile ID", aurora.Cyan(profileId))
		return
	}

	session := login.session
	if session == nil {
		mutex.Unlock()
		logging.Warn(moduleName, "Received SELECT record  from profile ID", aurora.Cyan(profileId), "but no session exists")
		return
	}
	mutex.Unlock()

	group := session.groupPointer
	if group == nil {
		return
	}

	keyColored := aurora.BrightCyan(key).String()

	switch key {
	case "wl:mkw_select_course":
		courseId, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			logging.Error(moduleName, "Error decoding", keyColored+":", err.Error())
			return
		}

		logging.Info(moduleName, "Selected course", aurora.BrightCyan(strconv.FormatUint(courseId, 10)))

		mutex.Lock()
		defer mutex.Unlock()

		group.MKWRaceNumber++
		group.MKWCourseID = int(courseId)
		group.MKWEngineClassID = -1
		return

	case "wl:mkw_select_cc":
		ccId, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			logging.Error(moduleName, "Error decoding", keyColored+":", err.Error())
			return
		}

		logging.Info(moduleName, "Selected CC", aurora.BrightCyan(strconv.FormatUint(ccId, 10)))

		mutex.Lock()
		defer mutex.Unlock()

		group.MKWEngineClassID = int(ccId)
		return
	}

}

// parse message like "key1=val1|key2=val2|key3=val3" into a map of key to uint32 value
func GetMessageParts(message string) map[string]uint32 {
	parts := strings.Split(message, "|")
	result := make(map[string]uint32)

	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := kv[0]
		value, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			continue
		}

		result[key] = uint32(value)
	}

	return result
}

func ProcessMKWExtendedTeams(profileId uint32, value string) {
	moduleName := "QR2:MKWExtendedTeams:" + strconv.FormatUint(uint64(profileId), 10)

	mutex.Lock()
	login := logins[profileId]
	if login == nil {
		mutex.Unlock()
		logging.Warn(moduleName, "Received Extended Teams record from non-existent profile ID", aurora.Cyan(profileId))
		return
	}

	session := login.session
	if session == nil {
		mutex.Unlock()
		logging.Warn(moduleName, "Received Extended Teams record from profile ID", aurora.Cyan(profileId), "but no session exists")
		return
	}
	mutex.Unlock()

	group := session.groupPointer
	if group == nil {
		return
	}

	// Example value: hi=0|tm=2
	// It would mean the first player (hi) of sending console is on team 2 (tm).
	teamId := -1
	hudId := -1
	parts := GetMessageParts(value)
	if len(parts) != 2 {
		logging.Error(moduleName, "Invalid Extended Teams record format:", aurora.Cyan(value))
		return
	}

	val, ok := parts["tm"]
	if !ok {
		logging.Error(moduleName, "Missing team ID in Extended Teams record:", aurora.Cyan(value))
		return
	}
	teamId = int(val)

	val, ok = parts["hi"]
	if !ok {
		logging.Error(moduleName, "Missing player ID in Extended Teams record:", aurora.Cyan(value))
		return
	}

	hudId = int(val)

	if hudId < 0 || hudId > 1 {
		logging.Error(moduleName, "Invalid player ID:", aurora.Cyan(hudId))
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	_, ok = racePlayers[group.GroupName]
	if !ok {
		racePlayers[group.GroupName] = map[uint32][]RacePlayer{}
	}

	player, ok := racePlayers[group.GroupName][profileId]
	if !ok {
		racePlayers[group.GroupName][profileId] = make([]RacePlayer, 2)
		player = racePlayers[group.GroupName][profileId]
	}

	player[hudId].TeamID = teamId
}

func ProcessMKWRaceStage(profileId uint32, value string) {
	moduleName := "QR2:MKWRaceStage:" + strconv.FormatUint(uint64(profileId), 10)

	mutex.Lock()
	login := logins[profileId]
	if login == nil {
		mutex.Unlock()
		logging.Warn(moduleName, "Received MKW Race Stage record from non-existent profile ID", aurora.Cyan(profileId))
		return
	}

	session := login.session
	if session == nil {
		mutex.Unlock()
		logging.Warn(moduleName, "Received MKW Race Stage record from profile ID", aurora.Cyan(profileId), "but no session exists")
		return
	}
	mutex.Unlock()

	group := session.groupPointer
	if group == nil {
		return
	}

	raceStage, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		logging.Error(moduleName, "Error decoding race stage:", err.Error())
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	_, ok := racePlayers[group.GroupName]
	if !ok {
		racePlayers[group.GroupName] = map[uint32][]RacePlayer{}
	}

	player, ok := racePlayers[group.GroupName][profileId]
	if !ok {
		racePlayers[group.GroupName][profileId] = make([]RacePlayer, 2)
		player = racePlayers[group.GroupName][profileId]
	}

	player[0].RaceStage = uint32(raceStage)
	player[0].LastRaceStageUpdate = time.Now().UTC()

	player[1].RaceStage = uint32(raceStage)
	player[1].LastRaceStageUpdate = time.Now().UTC()
}

func ProcessMKWRaceResult(profileId uint32, value string) {
	moduleName := "QR2:MKWRaceResult:" + strconv.FormatUint(uint64(profileId), 10)

	mutex.Lock()
	login := logins[profileId]
	if login == nil {
		mutex.Unlock()
		logging.Warn(moduleName, "Received MKW Race Result record from non-existent profile ID", aurora.Cyan(profileId))
		return
	}

	session := login.session
	if session == nil {
		mutex.Unlock()
		logging.Warn(moduleName, "Received MKW Race Result record from profile ID", aurora.Cyan(profileId), "but no session exists")
		return
	}
	mutex.Unlock()

	group := session.groupPointer
	if group == nil {
		return
	}

	// Message format: hi=%d|ch=%d|ve=%d|ft=%u|fp=%d|f1=%u|pc=%d
	// hi = HUD ID (0 or 1)
	// ch = Character ID
	// ve = Vehicle ID
	// ft = Finish Time (float encoded as uint32)
	// fp = Finish Position (1-12 ?)
	// f1 = Frames in 1st position (uint32)
	// pc = Player count (1-12)
	parts := GetMessageParts(value)
	if len(parts) != 7 {
		logging.Error(moduleName, "Invalid MKW Race Result record format:", aurora.Cyan(value))
		return
	}

	hudId := -1
	characterId := uint32(0)
	vehicleId := uint32(0)
	finishTime := uint32(0)
	finishPosition := -1
	framesIn1st := uint32(0)
	playerCount := -1

	val, ok := parts["hi"]
	if !ok {
		logging.Error(moduleName, "Missing HUD ID in MKW Race Result record:", aurora.Cyan(value))
		return
	}

	hudId = int(val)

	val, ok = parts["ch"]
	if !ok {
		logging.Error(moduleName, "Missing Character ID in MKW Race Result record:", aurora.Cyan(value))
		return
	}

	characterId = val

	val, ok = parts["ve"]
	if !ok {
		logging.Error(moduleName, "Missing Vehicle ID in MKW Race Result record:", aurora.Cyan(value))
		return
	}

	vehicleId = val

	val, ok = parts["ft"]
	if !ok {
		logging.Error(moduleName, "Missing Finish Time in MKW Race Result record:", aurora.Cyan(value))
		return
	}

	finishTime = val

	val, ok = parts["fp"]
	if !ok {
		logging.Error(moduleName, "Missing Finish Position in MKW Race Result record:", aurora.Cyan(value))
		return
	}

	finishPosition = int(val)
	val, ok = parts["f1"]
	if !ok {
		logging.Error(moduleName, "Missing Frames in 1st in MKW Race Result record:", aurora.Cyan(value))
		return
	}

	framesIn1st = val

	val, ok = parts["pc"]
	if !ok {
		logging.Error(moduleName, "Missing Player Count in MKW Race Result record:", aurora.Cyan(value))
		return
	}

	playerCount = int(val)

	mutex.Lock()
	defer mutex.Unlock()

	if group.MKWRaceNumber == 0 {
		logging.Error(moduleName, "Received MKW Race Result record but no races have been started")
		return
	}

	if raceResults[group.GroupName] == nil {
		raceResults[group.GroupName] = map[int][]RaceResult{}

	}

	raceResults[group.GroupName][group.MKWRaceNumber] = append(raceResults[group.GroupName][group.MKWRaceNumber], RaceResult{
		ProfileID:   profileId,
		PlayerID:    hudId,
		FinishTime:  finishTime,
		CharacterID: characterId,
		VehicleID:   vehicleId,
		PlayerCount: uint32(playerCount),
		FinishPos:   finishPosition,
		FramesIn1st: framesIn1st,
		// Redundant but efficient to store these here
		CourseID:      group.MKWCourseID,
		EngineClassID: group.MKWEngineClassID,
	})
}

func GetRaceResultsForGroup(groupName string) (map[int][]RaceResult, map[uint32][]RacePlayer) {
	mutex.Lock()
	defer mutex.Unlock()

	groupPlayers, ok := racePlayers[groupName]
	if !ok {
		return nil, nil
	}

	groupResults, ok := raceResults[groupName]
	if !ok {
		return nil, groupPlayers
	}

	// Return copies
	copiedRaceResults := make(map[int][]RaceResult)
	for raceNumber, results := range groupResults {
		copiedRaceResults[raceNumber] = make([]RaceResult, len(results))
		copy(copiedRaceResults[raceNumber], results)
	}

	copiedGroupPlayers := make(map[uint32][]RacePlayer)
	for playerID, playerResults := range groupPlayers {
		copiedGroupPlayers[playerID] = make([]RacePlayer, len(playerResults))
		copy(copiedGroupPlayers[playerID], playerResults)
	}

	return copiedRaceResults, copiedGroupPlayers
}

// saveGroups saves the current groups state to disk.
// Expects the mutex to be locked.
func saveGroups() error {
	file, err := os.OpenFile("state/qr2_groups.gob", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	encoder := gob.NewEncoder(file)
	err = encoder.Encode(groups)
	file.Close()
	return err
}

// loadGroups loads the groups state from disk.
// Expects the mutex to be locked, and the sessions to already be loaded.
func loadGroups() error {
	file, err := os.Open("state/qr2_groups.gob")
	if err != nil {
		return err
	}

	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&groups)
	file.Close()
	if err != nil {
		return err
	}

	for _, session := range sessions {
		if session.groupPointer != nil || session.GroupName == "" {
			continue
		}

		group := groups[session.GroupName]
		if group == nil {
			logging.Warn("QR2", "Session", aurora.BrightCyan(session.Addr.String()), "has a group name but the group does not exist")
			continue
		}

		if group.players == nil {
			group.players = map[*Session]bool{}
		}

		group.players[session] = true
		session.groupPointer = group
	}

	for _, group := range groups {
		if group.players == nil {
			group.players = map[*Session]bool{}
		}

		group.findNewServer()
	}

	return nil
}

type PIDIPPair struct {
	PID uint32
	IP  uint32
}

// Send kick order to all QR2-authenticated session to kick a player from their group
func OrderKickFromGroups(playersToKick []PIDIPPair) {
	// QR2 messages are limited at 0x80 in length. With a 7-byte header and a
	// byte for length, that leaves 120 bytes worth of pids, thus 30 4-byte
	// integers. Surely more than 15 online players won't match at once :)

	moduleName := "QR2:OrderKickFromGroup/"

	iterMax := min(len(playersToKick), 15)
	for i := range iterMax {
		moduleName += strconv.FormatUint(uint64(playersToKick[i].PID), 10)

		if i+1 != iterMax {
			moduleName += ", "
		}
	}

	mutex.Lock()
	defer mutex.Unlock()

	var numSent int = 0
	for _, session := range sessions {
		message := createResponseHeader(ClientKickPeerOrder, session.SessionID) // 7 byte header
		message = append(message, byte(iterMax))                                // 1 byte len

		for i := range iterMax {
			// All 4 bytes, preserves alignment
			message = binary.BigEndian.AppendUint32(message, playersToKick[i].PID)
			message = binary.BigEndian.AppendUint32(message, playersToKick[i].IP)
		}

		_, err := masterConn.WriteTo(message, &session.Addr)
		if err != nil {
			logging.Error(moduleName, "Error sending message:", err.Error())
		}

		numSent++
	}

	logging.Notice(moduleName, "Sent kick order message to", aurora.Cyan(numSent), "player(s)")
}
