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

func parseMKWVRBRRecord(value string) (int32, int32, bool) {
	parts := strings.Split(value, "|")
	var vr int64 = -1
	var br int64 = -1

	for _, part := range parts {
		keyValue := strings.SplitN(part, "=", 2)
		if len(keyValue) != 2 {
			return 0, 0, false
		}

		parsed, err := strconv.ParseInt(keyValue[1], 10, 32)
		if err != nil || parsed < 1 || parsed > 1000000 {
			return 0, 0, false
		}

		switch keyValue[0] {
		case "vr":
			vr = parsed
		case "br":
			br = parsed
		default:
			return 0, 0, false
		}
	}

	if vr < 0 || br < 0 {
		return 0, 0, false
	}

	return int32(vr), int32(br), true
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

			err := database.UpdateMKWVRBR(pool, ctx, g.User.ProfileId, vr, br)
			if err != nil {
				logging.Error(g.ModuleName, "Failed to persist", keyColored, "for", aurora.Cyan(g.User.ProfileId), ":", err)
			}
		}
	}
}
