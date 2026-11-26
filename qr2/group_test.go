package qr2

import (
	"fmt"
	"math"
	"testing"
	"time"
)

const regularRoomPlayersCount = 6

func newTestGroup(t *testing.T, groupName string, profileID uint32) *Group {
	t.Helper()

	newGroup := &Group{
		GroupName: groupName,
	}

	newLogin := &LoginInfo{
		ProfileID: profileID,
		session: &Session{
			groupPointer: newGroup,
		},
	}

	logins[profileID] = newLogin

	t.Cleanup(func() {
		delete(logins, profileID)
		delete(raceResults, groupName)
	})

	return newGroup
}

func buildResultMessage(finishTimeSeconds float32, playerCount int) string {
	return fmt.Sprintf("hi=0|ch=1|ve=2|ft=%d|fp=1|f1=0|pc=%d", math.Float32bits(finishTimeSeconds), playerCount)
}

func selectTrackAndSleep(profileID uint32, courseID string, sleepDuration time.Duration) {
	ProcessMKWSelectRecord(profileID, "wl:mkw_select_course", courseID)
	time.Sleep(sleepDuration)
}

func selectEngineClassAndSleep(profileID uint32, engineClassID string, sleepDuration time.Duration) {
	ProcessMKWSelectRecord(profileID, "wl:mkw_select_cc", engineClassID)
	time.Sleep(sleepDuration)
}

func expectRaceResultsLength(t *testing.T, groupRaces map[int][]RaceResult, raceNumber int, expectedCount int) bool {
	t.Helper()
	results := groupRaces[raceNumber]
	if len(results) != expectedCount {
		t.Errorf("MKWRaceNumber %d results must have %d result(s) (len=%d)", raceNumber, expectedCount, len(results))
		return false
	}
	return true
}

func expectCourseIDInRaceResult(t *testing.T, groupRaces map[int][]RaceResult, raceNumber int, expectedCourseID int) bool {
	t.Helper()
	results := groupRaces[raceNumber]
	if len(results) != 1 {
		t.Errorf("MKWRaceNumber %d results must have 1 result (len=%d)", raceNumber, len(results))
		return false
	} else if results[0].CourseID != expectedCourseID {
		t.Errorf("MKWRaceNumber %d result should be filed under CourseID %d (CourseID=%d)", raceNumber, expectedCourseID, results[0].CourseID)
		return false
	}
	return true
}

func expectEngineClassIDInRaceResult(t *testing.T, groupRaces map[int][]RaceResult, raceNumber int, expectedEngineClassID int) bool {
	t.Helper()
	results := groupRaces[raceNumber]
	if len(results) != 1 {
		t.Errorf("MKWRaceNumber %d results must have 1 result (len=%d)", raceNumber, len(results))
		return false
	} else if results[0].EngineClassID != expectedEngineClassID {
		t.Errorf("MKWRaceNumber %d result should have EngineClassID %d (EngineClassID=%d)", raceNumber, expectedEngineClassID, results[0].EngineClassID)
		return false
	}
	return true
}

func TestLateResultIsFiledUnderPreviousRace(t *testing.T) {
	profileID := uint32(900001)
	groupName := "TEST01"

	newTestGroup(t, groupName, profileID)

	selectTrackAndSleep(profileID, "100", 500*time.Millisecond)
	selectTrackAndSleep(profileID, "200", 0)

	ProcessMKWRaceResult(profileID, buildResultMessage(0.4, regularRoomPlayersCount))

	expectCourseIDInRaceResult(t, raceResults[groupName], 1, 100)

	expectRaceResultsLength(t, raceResults[groupName], 2, 0)
}

func TestOnTimeResultIsFiledUnderCurrentRace(t *testing.T) {
	profileID := uint32(900002)
	groupName := "TEST02"

	newTestGroup(t, groupName, profileID)

	selectTrackAndSleep(profileID, "100", 300*time.Millisecond)
	selectTrackAndSleep(profileID, "200", 300*time.Millisecond)

	ProcessMKWRaceResult(profileID, buildResultMessage(0.1, regularRoomPlayersCount))

	expectRaceResultsLength(t, raceResults[groupName], 1, 0)

	expectCourseIDInRaceResult(t, raceResults[groupName], 2, 200)
}

func TestRaceNumberIsNotRewoundOnLateResult(t *testing.T) {
	profileID := uint32(900003)
	groupName := "TEST03"

	group := newTestGroup(t, groupName, profileID)

	selectTrackAndSleep(profileID, "100", 500*time.Millisecond)
	selectTrackAndSleep(profileID, "200", 0)

	ProcessMKWRaceResult(profileID, buildResultMessage(0.4, regularRoomPlayersCount))

	expectCourseIDInRaceResult(t, raceResults[groupName], 1, 100)

	if group.MKWRaceNumber != 2 || group.MKWCourseID != 200 {
		t.Fatalf("Group's current MKWRaceNumber should be 2 with courseID 200 (MKWRaceNumber=%d, MKWCourseID=%d)", group.MKWRaceNumber, group.MKWCourseID)
	}

	selectTrackAndSleep(profileID, "300", 0)

	if group.MKWRaceNumber != 3 || group.MKWCourseID != 300 {
		t.Fatalf("Group's current MKWRaceNumber should be 3 with courseID 300 (MKWRaceNumber=%d, MKWCourseID=%d)", group.MKWRaceNumber, group.MKWCourseID)
	}
}

func TestEngineClassGoesToPreviousRaceResult(t *testing.T) {
	profileID := uint32(900004)
	groupName := "TEST04"

	newTestGroup(t, groupName, profileID)

	selectTrackAndSleep(profileID, "100", 0)
	selectEngineClassAndSleep(profileID, "5", 500*time.Millisecond)

	selectTrackAndSleep(profileID, "200", 0)
	selectEngineClassAndSleep(profileID, "10", 0)

	ProcessMKWRaceResult(profileID, buildResultMessage(0.4, regularRoomPlayersCount))

	if expectCourseIDInRaceResult(t, raceResults[groupName], 1, 100) {
		// prevent error warning printing twice for MKWRaceNumber 1 results being empty
		expectEngineClassIDInRaceResult(t, raceResults[groupName], 1, 5)
	}

	expectRaceResultsLength(t, raceResults[groupName], 2, 0)
}

func TestMaxTrackPickHistory(t *testing.T) {
	profileID := uint32(900005)
	groupName := "TEST05"

	group := newTestGroup(t, groupName, profileID)

	for i := 0; i < 10; i++ {
		selectTrackAndSleep(profileID, fmt.Sprintf("10%d", i), 0)
	}

	if len(group.trackPickHistory) != maxTrackPickHistory {
		t.Fatalf("group.trackPickHistory should have been truncated to length %d (len=%d)", maxTrackPickHistory, len(group.trackPickHistory))
	} else if group.trackPickHistory[0].raceNumber != 3 {
		t.Fatalf("First entry in track history should be raceNumber 3 (raceNumber=%d)", group.trackPickHistory[0].raceNumber)
	}
}

func TestCutOffPlayerResultGoesToCurrentRace(t *testing.T) {
	profileID := uint32(900006)
	groupName := "TEST06"

	newTestGroup(t, groupName, profileID)

	selectTrackAndSleep(profileID, "100", 500*time.Millisecond)
	selectTrackAndSleep(profileID, "200", 300*time.Millisecond)

	ProcessMKWRaceResult(profileID, buildResultMessage(0.1, regularRoomPlayersCount))
	ProcessMKWRaceResult(profileID, buildResultMessage(0.6, regularRoomPlayersCount))

	expectRaceResultsLength(t, raceResults[groupName], 1, 0)
	expectRaceResultsLength(t, raceResults[groupName], 2, 2)
}

func TestTwoPlayerRaceResultsAreNotMoved(t *testing.T) {
	profileID := uint32(900007)
	groupName := "TEST07"

	newTestGroup(t, groupName, profileID)

	selectTrackAndSleep(profileID, "100", 500*time.Millisecond)
	selectTrackAndSleep(profileID, "200", 0)

	ProcessMKWRaceResult(profileID, buildResultMessage(0.4, minRacersForResultAdjustment-1))

	expectRaceResultsLength(t, raceResults[groupName], 1, 0)
	expectCourseIDInRaceResult(t, raceResults[groupName], 2, 200)
}

func TestUnbelievableRaceTimesFallBackToDefaultFiling(t *testing.T) {
	cases := []struct {
		testName string
		raceTime float32
	}{
		{"zero", 0},
		{"negative", -5.7},
		{"nan", float32(math.NaN())},
		{"-inf", float32(math.Inf(-1))},
		{"+inf", float32(math.Inf(1))},
		{"overRaceTimeLimit", 300.001},
		{"penaltyLimit", 1203.6},
	}

	for i, c := range cases {
		t.Run(c.testName, func(t *testing.T) {
			groupName := c.testName
			profileID := uint32(900010 + i)

			newTestGroup(t, groupName, profileID)
			selectTrackAndSleep(profileID, "100", 500*time.Millisecond)
			selectTrackAndSleep(profileID, "200", 0)
			ProcessMKWRaceResult(profileID, buildResultMessage(c.raceTime, regularRoomPlayersCount))

			expectRaceResultsLength(t, raceResults[groupName], 1, 0)

			if expectCourseIDInRaceResult(t, raceResults[groupName], 2, 200) {
				if raceResults[groupName][2][0].FinishTime != math.Float32bits(c.raceTime) {
					t.Fatalf("Group %s race 2 result finish time should be %d (FinishTime=%d)", c.testName, math.Float32bits(c.raceTime), raceResults[groupName][2][0].FinishTime)
				}
			}
		})
	}
}

func TestRaceLookupReturnsCorrectRace(t *testing.T) {
	base := time.Date(2026, 01, 01, 16, 0, 0, 0, time.UTC)
	trackHistory := []trackPick{
		{
			pickTime:      base,
			raceNumber:    1,
			courseID:      100,
			engineClassID: 1000,
		},
		{
			pickTime:      base.Add(200 * time.Second),
			raceNumber:    2,
			courseID:      200,
			engineClassID: 2000,
		},
		{
			pickTime:      base.Add(400 * time.Second),
			raceNumber:    3,
			courseID:      300,
			engineClassID: 3000,
		},
	}

	splitRoomTrackHistory := []trackPick{
		{
			pickTime:      base,
			raceNumber:    4,
			courseID:      400,
			engineClassID: 4000,
		},
		{
			pickTime:      base.Add(40 * time.Second),
			raceNumber:    5,
			courseID:      500,
			engineClassID: 5000,
		},
		{
			pickTime:      base.Add(190 * time.Second),
			raceNumber:    6,
			courseID:      600,
			engineClassID: 6000,
		},
		{
			pickTime:      base.Add(200 * time.Second),
			raceNumber:    7,
			courseID:      700,
			engineClassID: 7000,
		},
	}

	cases := []struct {
		name      string
		history   []trackPick
		arrival   time.Time
		raceTime  float32
		wantFound bool
		wantRace  int
	}{
		{"onTime", trackHistory, base.Add(570 * time.Second), 150, true, 3},
		{"late", trackHistory, base.Add(450 * time.Second), 150, true, 2},
		{"veryLate", trackHistory, base.Add(450 * time.Second), 300, true, 1},
		{"exactlyOnPick", trackHistory, base.Add(350 * time.Second), 150, true, 2},
		{"justBeforePick", trackHistory, base.Add(350*time.Second - time.Millisecond), 150, true, 1},
		{"exactlyLimit", trackHistory, base.Add(700 * time.Second), 300, true, 3},
		{"olderThanHistory", trackHistory, base.Add(100 * time.Second), 150, false, 0},
		{"emptyHistory", nil, base.Add(570 * time.Second), 150, false, 0},
		{"zero", trackHistory, base.Add(570 * time.Second), 0, false, 0},
		{"negative", trackHistory, base.Add(570 * time.Second), -5, false, 0},
		{"nan", trackHistory, base.Add(570 * time.Second), float32(math.NaN()), false, 0},
		{"-inf", trackHistory, base.Add(570 * time.Second), float32(math.Inf(-1)), false, 0},
		{"+inf", trackHistory, base.Add(570 * time.Second), float32(math.Inf(1)), false, 0},
		{"justOverLimit", trackHistory, base.Add(700 * time.Second), 300.001, false, 0},
		{"penalty", trackHistory, base.Add(1300 * time.Second), 1203.6, false, 0},
		{"splitFixed", splitRoomTrackHistory, base.Add(155 * time.Second), 130, true, 4},
		// In a split room, A's host picks race 6 at 190s
		// Race starts at 220s (30s roulette, loading, countdown)
		// Racer's finish time is 130s
		// 350s - 130s = 220s (estimated race start time)
		// However latest pick at or before 220s is B's race 7 at 200s
		// Server doesn't know which group made the pick
		// This is the known case where it will be misfiled but no worse than current behaviour
		{"splitKnownLimit", splitRoomTrackHistory, base.Add(350 * time.Second), 130, true, 7},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pick, found := findTrackPick(c.history, c.arrival, math.Float32bits(c.raceTime))

			if found != c.wantFound {
				t.Fatalf("Expected found to be %v (found=%v)", c.wantFound, found)
			}

			if pick.raceNumber != c.wantRace {
				t.Errorf("Expected raceNumber to be %d (raceNumber=%d)", c.wantRace, pick.raceNumber)
			}
		})
	}
}
