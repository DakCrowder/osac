/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bmcdiscovery

import (
	"errors"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck
)

var _ = Describe("ValidateBMCAddress", func() {
	Context("valid addresses", func() {
		DescribeTable("should accept",
			func(address string) {
				Expect(ValidateBMCAddress(address)).To(Succeed())
			},
			Entry("redfish-virtualmedia",
				"redfish-virtualmedia+https://10.141.0.1/redfish/v1/Systems/1"),
			Entry("idrac-virtualmedia",
				"idrac-virtualmedia+https://10.141.0.5/redfish/v1/Systems/System.Embedded.1"),
			Entry("ilo5-virtualmedia",
				"ilo5-virtualmedia+https://10.141.0.9/redfish/v1/Systems/1"),
			Entry("redfish-virtualmedia over http",
				"redfish-virtualmedia+http://192.168.150.1:8000/redfish/v1/Systems/1"),
			Entry("idrac-virtualmedia over http",
				"idrac-virtualmedia+http://10.141.0.5/redfish/v1/Systems/System.Embedded.1"),
			Entry("ilo5-virtualmedia over http",
				"ilo5-virtualmedia+http://10.141.0.9/redfish/v1/Systems/1"),
			Entry("ipmi",
				"ipmi://10.141.0.1"),
			Entry("ipmi with port",
				"ipmi://10.141.0.1:6230"),
			Entry("redfish with non-standard port",
				"redfish-virtualmedia+https://10.141.0.1:8443/redfish/v1/Systems/1"),
			Entry("ipmi with bracketed IPv6",
				"ipmi://[2001:db8::1]"),
			Entry("redfish with bracketed IPv6",
				"redfish-virtualmedia+https://[2001:db8::1]/redfish/v1/Systems/1"),
			Entry("https for Redfish discovery",
				"https://10.141.0.1/redfish/v1/Systems/1"),
		)
	})

	Context("invalid schemes", func() {
		DescribeTable("should reject",
			func(address string, expectedSubstring string) {
				err := ValidateBMCAddress(address)
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, ErrInvalidBMCTarget)).To(BeTrue())
				Expect(err.Error()).To(ContainSubstring(expectedSubstring))
			},
			Entry("http scheme", "http://10.141.0.1/redfish/v1/Systems/1", "disallowed scheme"),
			Entry("ftp scheme", "ftp://10.141.0.1/redfish/v1/Systems/1", "disallowed scheme"),
			Entry("ssh scheme", "ssh://10.141.0.1", "disallowed scheme"),
			Entry("missing scheme entirely", "10.141.0.1/redfish/v1/Systems/1", "missing scheme"),
		)
	})
})
