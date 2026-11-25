package main

import "net/http"

type observedInspectedRequest struct {
	Class         observedRequestClass
	Body          observedBodyResult
	HeadersSHA256 string
}

// Class comes from the A-signed local-test header shape, never from a client
// supplied tag. This inspection runs on buffered bytes before any H ingress
// or provider call. Ancillary requests can only receive a local 422.
func classifyObservedRequest(req *http.Request, data []byte,
	authority observedAuthority) (observedInspectedRequest, error) {
	lt := authority.FD3.LocalTest
	if lt.validate(authority.FD3.Selectors.InstallationID,
		authority.FD3.Selectors.StartID) != nil || req == nil ||
		len(data) == 0 || len(data) > maxBody {
		return observedInspectedRequest{}, invalid
	}
	profiles := []struct {
		class observedRequestClass
		fixed map[string]string
		want  string
	}{
		{observedAncillaryA, lt.AncillaryProfile.FirstHeaderShape.RequiredFixed,
			lt.AncillaryProfile.FirstHeadersSHA256},
		{observedAncillaryB, lt.AncillaryProfile.SecondHeaderShape.RequiredFixed,
			lt.AncillaryProfile.SecondHeadersSHA256},
		{observedTarget, lt.HeaderShape.RequiredFixed,
			observedFixedHeadersDigest(lt.HeaderShape.RequiredFixed)},
	}
	for _, profile := range profiles {
		headerSHA, err := inspectObservedHeaders(req, len(data), observedHeaderProfile{
			Host: lt.HTTPHost, MessagesQuery: lt.MessagesQuery,
			ClientKeySHA256: lt.ClientKeySHA256, RequiredFixed: profile.fixed,
		})
		if err != nil || headerSHA != profile.want {
			continue
		}
		if profile.class != observedTarget {
			if inspectObservedAncillary(data, lt.Model,
				lt.AncillaryProfile.NormalizedBodySHA256) != nil {
				return observedInspectedRequest{}, invalid
			}
			return observedInspectedRequest{Class: profile.class,
				HeadersSHA256: headerSHA}, nil
		}
		body, err := inspectObservedBody(data, observedBodyProfile{
			Model: lt.Model, OwnerPromptSHA256: lt.OwnerPromptSHA256,
			ProjectionSHA256:    lt.StaticProjectionSHA256,
			ChildCWD:            lt.ExpectedChildCWDEmitted,
			ChildCWDLexical:     lt.ExpectedChildCWDLexical,
			MemoryPath:          lt.ExpectedMemoryPathLexical,
			ExpectedBriefSHA256: lt.FirstBriefSHA256,
			MaxBriefBytes:       258,
		})
		if err != nil {
			return observedInspectedRequest{}, invalid
		}
		return observedInspectedRequest{Class: profile.class, Body: body,
			HeadersSHA256: headerSHA}, nil
	}
	return observedInspectedRequest{}, invalid
}
