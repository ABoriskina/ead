package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const npmBaselineExpectedEvents = 7

type npmBaselineEvaluationState struct {
	detected       map[string]bool
	correctLinks   map[string]bool
	incorrectLinks map[string]bool
	phasePIDs      map[uint32]bool
	unexpected     uint64
}

var npmBaselineEvaluation = npmBaselineEvaluationState{
	detected:       make(map[string]bool),
	correctLinks:   make(map[string]bool),
	incorrectLinks: make(map[string]bool),
	phasePIDs:      make(map[uint32]bool),
}

func executionHasArgument(event *executionEvent, expected string) bool {
	for _, argument := range event.Argv {
		if cString(argument[:]) == expected {
			return true
		}
	}

	return false
}

func npmBaselineFileExpectation(pathname string, flags uint32) string {
	isRead := flags&uint32(unix.O_ACCMODE) == uint32(unix.O_RDONLY)
	isCreate := flags&uint32(unix.O_CREAT) != 0
	inRun := strings.Contains(pathname, "/npm-baseline/runs/N0-")

	switch {
	case inRun && strings.HasSuffix(pathname, "/package.json") &&
		!strings.Contains(pathname, "/node_modules/") && isCreate:
		return "create_root_package_json"
	case inRun && strings.HasSuffix(pathname, "/package.json") &&
		!strings.Contains(pathname, "/node_modules/") && isRead:
		return "read_root_package_json"
	case strings.Contains(pathname, "/npm-baseline/artifacts/") &&
		strings.HasSuffix(pathname, ".tgz") && isRead:
		return "read_package_archive"
	case inRun && strings.HasSuffix(pathname, "/node_modules/ead-lab-n0-no-scripts/index.js") && isCreate:
		return "create_installed_index"
	case inRun && strings.HasSuffix(pathname, "/node_modules/ead-lab-n0-no-scripts/package.json") && isCreate:
		return "create_installed_package_json"
	default:
		return ""
	}
}

func recordNpmBaselineEvent(data interface{}, kind eventType) {
	expectation := ""
	pid := uint32(0)
	linkIsCorrect := false

	switch kind {
	case eventExecveExit:
		event, ok := data.(*executionEvent)
		if !ok || event.Header.Res < 0 {
			break
		}

		if executionHasArgument(event, "init") {
			expectation = "execute_npm_init"
		} else if executionHasArgument(event, "install") {
			expectation = "execute_npm_install"
		}

		if expectation != "" {
			pid = event.Header.Pid
			npmBaselineEvaluation.phasePIDs[pid] = true
			linkIsCorrect = pid != 0 && filepath.Base(cString(event.Pathname[:])) != ""
		}

	case eventOpenatExit:
		event, ok := data.(*openingEvent)
		if !ok || event.Header.Res < 0 {
			break
		}
		pid = event.Header.Pid
		expectation = npmBaselineFileExpectation(cString(event.Pathname[:]), event.Flags)
		linkIsCorrect = npmBaselineEvaluation.phasePIDs[pid]

	case eventFileOpen:
		event, ok := data.(*fileOpenEvent)
		if !ok {
			break
		}
		pid = event.Header.Pid
		expectation = npmBaselineFileExpectation(cString(event.Pathname[:]), event.Flags)
		linkIsCorrect = npmBaselineEvaluation.phasePIDs[pid]
	}

	if expectation == "" {
		npmBaselineEvaluation.unexpected++
		return
	}

	npmBaselineEvaluation.detected[expectation] = true
	if linkIsCorrect {
		npmBaselineEvaluation.correctLinks[expectation] = true
		delete(npmBaselineEvaluation.incorrectLinks, expectation)
	} else if !npmBaselineEvaluation.correctLinks[expectation] {
		npmBaselineEvaluation.incorrectLinks[expectation] = true
	}
}

func printNpmBaselineEvaluation() {
	detected := len(npmBaselineEvaluation.detected)
	correctLinks := len(npmBaselineEvaluation.correctLinks)

	fmt.Printf(
		"[NPM_BASELINE_EVALUATION] expected_events=%d detected_expected_events=%d missed_expected_events=%d unexpected_events=%d correct_links=%d incorrect_links=%d missed_links=%d\n",
		npmBaselineExpectedEvents,
		detected,
		npmBaselineExpectedEvents-detected,
		npmBaselineEvaluation.unexpected,
		correctLinks,
		len(npmBaselineEvaluation.incorrectLinks),
		npmBaselineExpectedEvents-correctLinks,
	)
}
