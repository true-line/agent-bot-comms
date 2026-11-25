package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// This is the exact candidate-2 local_test field set signed into both the
// Machine B policy and B FD3. The independent FD3 verifier must compare the
// two canonical values and bind this record to the selected lead member.
type observedLocalTest struct {
	SelectedMemberID          string                  `json:"selected_member_id"`
	SelectedLaunchID          string                  `json:"selected_launch_id"`
	SelectedMemberSelector    string                  `json:"selected_member_selector"`
	RunnerAccount             string                  `json:"runner_account"`
	ExpectedChildCWDLexical   string                  `json:"expected_child_cwd_lexical"`
	ExpectedChildCWDEmitted   string                  `json:"expected_child_cwd_emitted"`
	ExpectedChildHomeLexical  string                  `json:"expected_child_home_lexical"`
	ExpectedMemoryPathLexical string                  `json:"expected_memory_path_lexical"`
	BodyProfile               string                  `json:"body_profile"`
	StaticProjectionSHA256    string                  `json:"static_projection_sha256"`
	OwnerPromptSHA256         string                  `json:"owner_prompt_sha256"`
	FirstBriefSHA256          string                  `json:"r_first_brief_sha256"`
	HeaderShape               observedHeaderShape     `json:"header_shape"`
	HeaderShapeSHA256         string                  `json:"header_shape_sha256"`
	ClientKeySHA256           string                  `json:"client_key_sha256"`
	Model                     string                  `json:"model"`
	HTTPHost                  string                  `json:"http_host"`
	MessagesQuery             string                  `json:"messages_query"`
	FixtureConfigSHA256       string                  `json:"fixture_config_sha256"`
	AncillaryProfile          observedAncillaryPolicy `json:"ancillary_profile"`
	AncillaryProfileSHA256    string                  `json:"ancillary_profile_sha256"`
}

func observedRunnerAccount(installationID string) string {
	hash := sha256.Sum256([]byte(installationID))
	return "_abm-sr-" + hex.EncodeToString(hash[:10])
}

func observedMemorySlug(emittedCWD string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, emittedCWD)
}

func observedStartSlot(installationID, startID string) string {
	hash := sha256.Sum256([]byte("agent-bot-soul-endpoint-start/v1\x00" +
		installationID + "\x00" + startID))
	return hex.EncodeToString(hash[:10])
}

func (lt observedLocalTest) validate(installationID, startID string) error {
	if !idPattern.MatchString(installationID) || !startPattern.MatchString(startID) ||
		!idPattern.MatchString(lt.SelectedMemberID) ||
		!launchPattern.MatchString(lt.SelectedLaunchID) ||
		!selectorPattern.MatchString(lt.SelectedMemberSelector) ||
		lt.RunnerAccount != observedRunnerAccount(installationID) ||
		lt.BodyProfile != "stage2a-stock-observed-local-test/v1" ||
		!validDigest(lt.StaticProjectionSHA256) || !validDigest(lt.OwnerPromptSHA256) ||
		!validDigest(lt.FirstBriefSHA256) || !validDigest(lt.ClientKeySHA256) ||
		!validDigest(lt.FixtureConfigSHA256) || !idPattern.MatchString(lt.Model) ||
		!idPattern.MatchString(lt.HTTPHost) || !queryPattern.MatchString(lt.MessagesQuery) ||
		lt.MessagesQuery == "" ||
		lt.HeaderShape.validateSigned(lt.HeaderShapeSHA256,
			"stage2a-observed-body-header-shape/v1", lt.HTTPHost) != nil ||
		lt.AncillaryProfile.validate(lt.AncillaryProfileSHA256, lt.HTTPHost) != nil ||
		observedFixedHeadersDigest(lt.HeaderShape.RequiredFixed) == lt.AncillaryProfile.FirstHeadersSHA256 ||
		observedFixedHeadersDigest(lt.HeaderShape.RequiredFixed) == lt.AncillaryProfile.SecondHeadersSHA256 {
		return invalid
	}
	root := "/var/agent-bot-soul-runner-" + lt.RunnerAccount +
		"/state/child-" + observedStartSlot(installationID, startID)
	wantLexical := root + "/work"
	wantEmitted := "/private" + wantLexical
	wantHome := root + "/home"
	wantMemory := wantHome + "/.claude/projects/" +
		observedMemorySlug(wantEmitted) + "/memory/"
	if lt.ExpectedChildCWDLexical != wantLexical ||
		lt.ExpectedChildCWDEmitted != wantEmitted ||
		lt.ExpectedChildHomeLexical != wantHome ||
		lt.ExpectedMemoryPathLexical != wantMemory {
		return invalid
	}
	return nil
}
