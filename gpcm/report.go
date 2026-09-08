package gpcm

import (
	"errors"
	"strconv"
	"strings"
	"wwfc/common"
	"wwfc/database"
	"wwfc/logging"
	"wwfc/qr2"

	"github.com/logrusorgru/aurora/v3"
)

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

			vr, br, err := parseMKWVRBRRecord(value)
			if err != nil {
				logging.Error(g.ModuleName, "Invalid", keyColored, "record:", aurora.Cyan(value), ":", err)
				continue
			}

			err = database.UpdateMKWVRBR(pool, ctx, g.User.ProfileId, vr, br)
			if err != nil {
				logging.Error(g.ModuleName,
					"Failed to persist", keyColored, "for",
					aurora.Cyan(g.User.ProfileId),
					":", err,
				)
				continue
			}

			logging.Info(g.ModuleName,
				"Persisted", keyColored, "for",
				aurora.Cyan(g.User.ProfileId),
				"vr=", vr,
				"br=", br,
			)
		case "mkw_mmr":
		}
	}
}

var (
	ErrMalformedEntry = errors.New("entry is malformed")
	ErrUnknownKey     = errors.New("the provided key must be one of 'vr' or 'br'")
	ErrMissingVR      = errors.New("record is missing vr entry")
	ErrMissingBR      = errors.New("record is missing br entry")
	ErrUnknownMode    = errors.New("the provided mode must be one of 'rt', 'ct', or 'vanilla'")
	ErrMissingMode    = errors.New("record is missing mode entry")
	ErrMissingMMR     = errors.New("record is missing mmr entry")
)

func parseMKWVRBRRecord(value string) (uint32, uint32, error) {
	var vr uint32
	vrMatched := false
	var br uint32
	brMatched := false

	for split := range strings.SplitSeq(value, "|") {
		key, raw, ok := strings.Cut(split, "=")
		if !ok || len(key) == 0 || len(raw) == 0 {
			return 0, 0, ErrMalformedEntry
		}

		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return 0, 0, err
		}

		switch key {
		case "vr":
			vr = uint32(parsed)
			vrMatched = true
		case "br":
			br = uint32(parsed)
			brMatched = true
		default:
			return 0, 0, ErrUnknownKey
		}
	}

	if !vrMatched {
		return 0, 0, ErrMissingVR
	}

	if !brMatched {
		return 0, 0, ErrMissingBR
	}

	return vr, br, nil
}

func parseMMRMode(mode string) (database.MKWRatingType, error) {
	switch mode {
	case "rt":
		return database.RT_MMR_RETRO_TRACKS, nil
	case "ct":
		return database.RT_MMR_CUSTOM_TRACKS, nil
	case "vanilla":
		return database.RT_MMR_VANILLA, nil
	default:
		return 0, ErrUnknownMode
	}
}

func parseMKWMMRRecord(value string) (database.MKWRatingType, uint32, error) {
	var ratingType database.MKWRatingType
	ratingTypeMatched := false
	var mmr uint32
	mmrMatched := false

	for split := range strings.SplitSeq(value, "|") {
		key, raw, ok := strings.Cut(split, "=")
		if !ok || len(key) == 0 || len(raw) == 0 {
			return 0, 0, ErrMalformedEntry
		}

		switch key {
		case "mode":
			parsed, err := parseMMRMode(raw)
			if err != nil {
				return 0, 0, err
			}

			ratingType = parsed
			ratingTypeMatched = true
		case "mmr":
			parsed, err := strconv.Atoi(raw)
			if err != nil {
				return 0, 0, err
			}

			mmr = uint32(parsed)
			mmrMatched = true
		}
	}

	if !ratingTypeMatched {
		return 0, 0, ErrMissingMode
	}

	if !mmrMatched {
		return 0, 0, ErrMissingMMR
	}

	return ratingType, mmr, nil
}
