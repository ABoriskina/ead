package main

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var npmBaselineExpectedByScenario = map[string][]string{
	"N0": {
		"execute_npm_init", "create_root_package_json", "execute_npm_install",
		"read_root_package_json", "read_package_archive", "create_installed_index",
		"create_installed_package_json",
	},
	"N1": postinstallExpectations("write_postinstall_result"),
	"N2": postinstallExpectations("read_fake_token"),
	"N3": postinstallExpectations("execute_id"),
	"N4": postinstallExpectations("connect_local_test_server"),
}

func postinstallExpectations(scenarioAction string) []string {
	return []string{
		"execute_npm_init", "create_root_package_json", "execute_npm_install",
		"read_root_package_json", "create_installed_index", "create_installed_package_json",
		"execute_postinstall", scenarioAction,
	}
}

type npmBaselineEvaluationState struct {
	detected       map[string]bool
	correctLinks   map[string]bool
	incorrectLinks map[string]bool
	phasePIDs      map[uint32]bool
	scenario       string
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

func executionArgumentContains(event *executionEvent, expected string) bool {
	for _, argument := range event.Argv {
		if strings.Contains(cString(argument[:]), expected) {
			return true
		}
	}
	return false
}

func npmBaselineScenario(pathname string) string {
	for scenario := range npmBaselineExpectedByScenario {
		if strings.Contains(pathname, "/npm-baseline/runs/"+scenario+"-") {
			return scenario
		}
	}
	return ""
}

func observeNpmBaselineScenario(pathname string, flags uint32) {
	scenario := npmBaselineScenario(pathname)
	isRootManifest := strings.HasSuffix(pathname, "/package.json") &&
		!strings.Contains(pathname, "/node_modules/")
	isCreate := flags&uint32(unix.O_CREAT) != 0
	if scenario != "" && isRootManifest && isCreate {
		npmBaselineEvaluation.scenario = scenario
	}
}

func npmBaselineFileExpectation(pathname string, flags uint32) string {
	observeNpmBaselineScenario(pathname, flags)
	isRead := flags&uint32(unix.O_ACCMODE) == uint32(unix.O_RDONLY)
	isWrite := flags&uint32(unix.O_ACCMODE) != uint32(unix.O_RDONLY)
	isCreate := flags&uint32(unix.O_CREAT) != 0
	inRun := npmBaselineScenario(pathname) != ""

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
	case inRun && strings.Contains(pathname, "/node_modules/") &&
		strings.HasSuffix(pathname, "/index.js") && isCreate:
		return "create_installed_index"
	case inRun && strings.Contains(pathname, "/node_modules/") &&
		strings.HasSuffix(pathname, "/package.json") && isCreate:
		return "create_installed_package_json"
	case inRun && strings.HasSuffix(pathname, "/postinstall-result.json") && isWrite:
		return "write_postinstall_result"
	case inRun && strings.HasSuffix(pathname, "/fixtures/fake-token.txt") && isRead:
		return "read_fake_token"
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
		pid = event.Header.Pid
		pathname := cString(event.Pathname[:])
		switch {
		case executionHasArgument(event, "init"):
			expectation = "execute_npm_init"
		case executionHasArgument(event, "install"):
			expectation = "execute_npm_install"
		case filepath.Base(pathname) == "id":
			expectation = "execute_id"
		case executionArgumentContains(event, "postinstall.js"):
			expectation = "execute_postinstall"
		}
		if expectation == "execute_npm_init" || expectation == "execute_npm_install" {
			npmBaselineEvaluation.phasePIDs[pid] = true
		}
		linkIsCorrect = npmBaselineEvaluation.phasePIDs[pid]

	case eventCloneExit:
		event, ok := data.(*cloningEvent)
		if !ok || event.Header.Res < 0 {
			break
		}
		if npmBaselineEvaluation.phasePIDs[event.Header.Pid] && event.CreatedTaskID > 0 {
			npmBaselineEvaluation.phasePIDs[uint32(event.CreatedTaskID)] = true
		}
		return

	case eventConnect:
		event, ok := data.(*tcpConnectionEvent)
		if !ok || event.Header.Res < 0 {
			break
		}
		pid = event.Header.Pid
		if uint32ToIPv4(event.Daddr).Equal(net.IPv4(127, 0, 0, 1)) && event.Dport == 18080 {
			expectation = "connect_local_test_server"
		}
		linkIsCorrect = npmBaselineEvaluation.phasePIDs[pid]

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
	scenario := npmBaselineEvaluation.scenario
	if scenario == "" {
		scenario = "N0"
	}
	expectedNames := npmBaselineExpectedByScenario[scenario]
	expected := make(map[string]bool, len(expectedNames))
	for _, name := range expectedNames {
		expected[name] = true
	}

	detected, correctLinks, incorrectLinks := 0, 0, 0
	for name := range expected {
		if npmBaselineEvaluation.detected[name] {
			detected++
		}
		if npmBaselineEvaluation.correctLinks[name] {
			correctLinks++
		} else if npmBaselineEvaluation.incorrectLinks[name] {
			incorrectLinks++
		}
	}

	fmt.Printf(
		"[NPM_BASELINE_EVALUATION] scenario=%s expected_events=%d detected_expected_events=%d missed_expected_events=%d unexpected_events=%d correct_links=%d incorrect_links=%d missed_links=%d\n",
		scenario, len(expected), detected, len(expected)-detected, npmBaselineEvaluation.unexpected,
		correctLinks, incorrectLinks, len(expected)-correctLinks,
	)
}
