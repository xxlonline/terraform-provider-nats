// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/base64"
)

var b64Enc = base64.StdEncoding.WithPadding(base64.NoPadding)
