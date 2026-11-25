package main

import "testing"

func observedLocalTestFixture(t *testing.T) observedLocalTest {
	t.Helper()
	ancillary, ancillarySHA := observedAncillaryPolicyFixture(t)
	header := ancillary.FirstHeaderShape
	header.Schema = "stage2a-observed-body-header-shape/v1"
	header.RequiredFixed = make(map[string]string, len(ancillary.FirstHeaderShape.RequiredFixed))
	for name, value := range ancillary.FirstHeaderShape.RequiredFixed {
		header.RequiredFixed[name] = value
	}
	header.RequiredFixed["anthropic-beta"] = "target-value"
	headerBytes, err := canonicalJSONValue(header)
	if err != nil {
		t.Fatal(err)
	}
	account := observedRunnerAccount("fixture.installation")
	root := "/var/agent-bot-soul-runner-" + account +
		"/state/child-" + observedStartSlot("fixture.installation", "st_111111111111111111111111")
	cwd := root + "/work"
	emitted := "/private" + cwd
	home := root + "/home"
	return observedLocalTest{
		SelectedMemberID: "m_lead", SelectedLaunchID: "ln_111111111111111111111111",
		SelectedMemberSelector: "mb_" + "1111111111111111111111111111111111111111111111111111111111111111",
		RunnerAccount:          account, ExpectedChildCWDLexical: cwd,
		ExpectedChildCWDEmitted: emitted, ExpectedChildHomeLexical: home,
		ExpectedMemoryPathLexical: home + "/.claude/projects/" + observedMemorySlug(emitted) + "/memory/",
		BodyProfile:               "stage2a-stock-observed-local-test/v1",
		StaticProjectionSHA256:    digest([]byte("static profile")),
		OwnerPromptSHA256:         digest([]byte("owner prompt")),
		FirstBriefSHA256:          digest([]byte("no-notes brief")),
		HeaderShape:               header, HeaderShapeSHA256: digest(headerBytes),
		ClientKeySHA256: digest([]byte("client key")), Model: "fixture-model",
		HTTPHost: "fixture.invalid", MessagesQuery: "beta=true",
		FixtureConfigSHA256: digest([]byte("fixture config")),
		AncillaryProfile:    ancillary, AncillaryProfileSHA256: ancillarySHA,
	}
}

func TestObservedLocalTestDerivesThreeSignedPaths(t *testing.T) {
	lt := observedLocalTestFixture(t)
	if err := lt.validate("fixture.installation", "st_111111111111111111111111"); err != nil {
		t.Fatalf("derived local-test profile refused: %v", err)
	}
	for name, change := range map[string]func(*observedLocalTest){
		"stale_runner_root": func(lt *observedLocalTest) {
			lt.ExpectedChildCWDLexical = "/var/agent-bot-soul-runner-" + lt.RunnerAccount + "/work"
		},
		"other_installation":    func(lt *observedLocalTest) { lt.RunnerAccount = observedRunnerAccount("other.installation") },
		"physical_cwd_alias":    func(lt *observedLocalTest) { lt.ExpectedChildCWDEmitted = lt.ExpectedChildCWDLexical },
		"lexical_cwd_alias":     func(lt *observedLocalTest) { lt.ExpectedChildCWDLexical = lt.ExpectedChildCWDEmitted },
		"physical_home_alias":   func(lt *observedLocalTest) { lt.ExpectedChildHomeLexical = "/private" + lt.ExpectedChildHomeLexical },
		"physical_memory_alias": func(lt *observedLocalTest) { lt.ExpectedMemoryPathLexical = "/private" + lt.ExpectedMemoryPathLexical },
		"wrong_memory_slug":     func(lt *observedLocalTest) { lt.ExpectedMemoryPathLexical += "other" },
		"unsigned_header_shape": func(lt *observedLocalTest) { lt.HeaderShape.RequiredFixed["anthropic-beta"] = "changed" },
		"unsigned_ancillary":    func(lt *observedLocalTest) { lt.AncillaryProfile.MaxAncillary = 3 },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := observedLocalTestFixture(t)
			change(&mutated)
			if err := mutated.validate("fixture.installation", "st_111111111111111111111111"); err == nil {
				t.Fatal("changed signed local-test path or profile accepted")
			}
		})
	}
	if lt.validate("fixture.installation", "st_222222222222222222222222") == nil {
		t.Fatal("signed paths reused for another start")
	}
	if observedStartSlot("inst.fixture", "st_111111111111111111111111") != "70799e6441e7d13e10b2" {
		t.Fatal("Machine start-slot derivation changed")
	}
}
