// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/function"

	"github.com/nats-io/nkeys"
)

var (
	_ function.Function = PkeyFunction{}
)

func NewPkeyFunction() function.Function {
	return PkeyFunction{}
}

type PkeyFunction struct{}

func (r PkeyFunction) Metadata(_ context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "pkey"
}

func (r PkeyFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:             "Pkey function",
		MarkdownDescription: "获取NKey的公钥",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:                "value",
				MarkdownDescription: "值",
				AllowNullValue:      false,
				AllowUnknownValues:  false,
			},
		},
		Return: function.StringReturn{},
	}
}

func (r PkeyFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var seed string
	resp.Error = function.ConcatFuncErrors(req.Arguments.Get(ctx, &seed))

	nkey, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		resp.Error = function.NewArgumentFuncError(0, "seed 错误")
		return
	}
	pkey, err := nkey.PublicKey()
	if err != nil {
		resp.Error = function.NewArgumentFuncError(0, "seed 错误")
		return
	}

	if resp.Error != nil {
		return
	}

	resp.Error = function.ConcatFuncErrors(resp.Result.Set(ctx, pkey))
}
