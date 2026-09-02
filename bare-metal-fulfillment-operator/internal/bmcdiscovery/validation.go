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
	"fmt"
	"strings"
)

var allowedSchemes = map[string]bool{
	"https":                      true,
	"ipmi":                       true,
	"redfish-virtualmedia+https": true,
	"idrac-virtualmedia+https":   true,
	"ilo5-virtualmedia+https":    true,
	// Metal3/BMO also supports the plaintext-HTTP virtualmedia variants
	// (e.g. sushy-tools dev BMCs). Plain "http" remains disallowed.
	"redfish-virtualmedia+http": true,
	"idrac-virtualmedia+http":   true,
	"ilo5-virtualmedia+http":    true,
}

// ValidateBMCAddress validates a fully-formed BMC URL by checking the
// scheme against the set of protocols Metal3/BMO supports.
func ValidateBMCAddress(address string) error {
	if strings.HasPrefix(address, "ipmi://") {
		return nil
	}

	schemeEnd := strings.Index(address, "://")
	if schemeEnd < 0 {
		return fmt.Errorf("%w: missing scheme in %q", ErrInvalidBMCTarget, address)
	}

	scheme := address[:schemeEnd]
	if !allowedSchemes[scheme] {
		return fmt.Errorf("%w: disallowed scheme %q", ErrInvalidBMCTarget, scheme)
	}

	return nil
}
