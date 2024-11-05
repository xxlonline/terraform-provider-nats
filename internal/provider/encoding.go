// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/base32"
	"encoding/base64"
)

var b32Enc = base32.StdEncoding.WithPadding(base32.NoPadding)
var b64Enc = base64.StdEncoding.WithPadding(base64.NoPadding)
