package gpcm

import (
	"strconv"
	"strings"
	"wwfc/common"
	"wwfc/database"
	"wwfc/logging"
	"wwfc/qr2"

	"github.com/logrusorgru/aurora/v3"
)

const (
	minMKWVRBR = 1
	maxMKWVRBR = 1_000_000
)

func parseMKWVRBRRecord(value string) (int32, int32, bool) {
	var vr int32
	var br int32
	var hasVR bool
	var hasBR bool

	for _, part := range strings.Split(value, "|") {
		key, rawValue, ok := strings.Cut(part, "=")
		if !ok || key == "" || rawValue == "" {
			return 0, 0, false
		}

		parsed, err := strconv.ParseInt(rawValue, 10, 32)
		if err != nil || parsed < minMKWVRBR || parsed > maxMKWVRBR {
			return 0, 0, false
		}

		switch key {
		case "vr":
			if hasVR {
				return 0, 0, false
			}
			vr = int32(parsed)
			hasVR = true
		case "br":
			if hasBR {
				return 0, 0, false
			}
			br = int32(parsed)
			hasBR = true
		default:
			return 0, 0, false
		}
	}

	return vr, br, hasVR && hasBR
}

func (g *GameSpySession) handleWWFCReport(command common.GameSpyCommand) {
	for key, value := range command.OtherValues {
		logging.Info(g.ModuleName, "WiiLink Report:", aurora.Yellow(key))

		keyColored := aurora.BrightCyan(key).String()

		switch key {
		default:
			logging.Error(g.ModuleName, "Unknown record", aurora.Cyan(key).String()+":", aurora.Cyan(value))

		case "wl:bad_packet":
			profileId, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				logging.Error(g.ModuleName, "Error decoding", keyColored+":", err.Error())
				continue
			}

			logging.Warn(g.ModuleName, "Report bad packet from", aurora.BrightCyan(strconv.FormatUint(profileId, 10)))

		case "wl:stall":
			profileId, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				logging.Error(g.ModuleName, "Error decoding", keyColored+":", err.Error())
				continue
			}

			logging.Warn(g.ModuleName, "Room stall caused by", aurora.BrightCyan(strconv.FormatUint(profileId, 10)))

		case "wl:mkw_user":
			if g.GameName != "mariokartwii" {
				logging.Warn(g.ModuleName, "Ignoring", keyColored+":", "from wrong game")
				continue
			}

			packet, err := common.Base64DwcEncoding.DecodeString(value)
			if err != nil {
				logging.Error(g.ModuleName, "Error decoding", keyColored+":", err.Error())
				continue
			}

			if len(packet) != 0xC0 {
				logging.Error(g.ModuleName, "Invalid", keyColored, "record length:", len(packet))
				continue
			}

			qr2.ProcessUSER(g.User.ProfileId, g.QR2IP, packet)

		case "wl:mkw_select_course", "wl:mkw_select_cc":
			if g.GameName != "mariokartwii" {
				logging.Warn(g.ModuleName, "Ignoring", keyColored, "from wrong game")
				continue
			}

			qr2.ProcessMKWSelectRecord(g.User.ProfileId, key, value)

		case "wl:mkw_extended_teams":
			if g.GameName != "mariokartwii" {
				logging.Warn(g.ModuleName, "Ignoring", keyColored, "from wrong game")
				continue
			}

			qr2.ProcessMKWExtendedTeams(g.User.ProfileId, value)

		case "wl:mkw_race_stage":
			if g.GameName != "mariokartwii" {
				logging.Warn(g.ModuleName, "Ignoring", keyColored, "from wrong game")
				continue
			}

			qr2.ProcessMKWRaceStage(g.User.ProfileId, value)

		case "wl:mkw_race_result":
			if g.GameName != "mariokartwii" {
				logging.Warn(g.ModuleName, "Ignoring", keyColored, "from wrong game")
				continue
			}

			qr2.ProcessMKWRaceResult(g.User.ProfileId, value)

		case "wl:mkw_vrbr":
			if g.GameName != "mariokartwii" {
				logging.Warn(g.ModuleName, "Ignoring", keyColored, "from wrong game")
				continue
			}

			vr, br, ok := parseMKWVRBRRecord(value)
			if !ok {
				logging.Error(g.ModuleName, "Invalid", keyColored, "record:", aurora.Cyan(value))
				continue
			}

			if err := database.UpdateMKWVRBR(pool, ctx, g.User.ProfileId, vr, br); err != nil {
				logging.Error(g.ModuleName, "Failed to persist", keyColored, "for", aurora.Cyan(g.User.ProfileId), ":", err)
				continue
			}

			logging.Info(g.ModuleName, "Persisted", keyColored, "for", aurora.Cyan(g.User.ProfileId), "vr=", aurora.Cyan(vr), "br=", aurora.Cyan(br))
		}
	}
}
