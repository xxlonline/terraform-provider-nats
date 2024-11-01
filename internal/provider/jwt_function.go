// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

var (
	_ function.Function = JwtFunction{}
)

func NewJwtFunction() function.Function {
	return JwtFunction{}
}

type JwtFunction struct{}

func (r JwtFunction) Metadata(_ context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "jwt"
}

func (r JwtFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:             "Jwt function",
		MarkdownDescription: "Echoes given argument as result",
		Parameters: []function.Parameter{
			function.ObjectParameter{
				AttributeTypes: map[string]attr.Type{
					"sub":  basetypes.StringType{},
					"iss":  basetypes.StringType{},
					"name": basetypes.StringType{},
					"aud":  basetypes.StringType{},
					"exp":  basetypes.StringType{},
					"nbf":  basetypes.StringType{},
					"nats": basetypes.StringType{},
				},
				Name:                "value",
				MarkdownDescription: "值",
				AllowNullValue:      false,
				AllowUnknownValues:  false,
			},
		},
		Return: function.StringReturn{},
	}
}

func decodeNKey(seed string) (nkeys.PrefixByte, string, error) {
	prefix, _, err := nkeys.DecodeSeed([]byte(seed))
	if err != nil {
		return nkeys.PrefixByteUnknown, "", err
	}
	nkey, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return nkeys.PrefixByteUnknown, "", err
	}
	pkey, err := nkey.PublicKey()
	if err != nil {
		return nkeys.PrefixByteUnknown, "", err
	}
	return prefix, pkey, nil
}

func (r JwtFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var data struct {
		Issuer    *string `tfsdk:"iss"`
		Subject   *string `tfsdk:"sub"`
		Name      *string `tfsdk:"name"`
		Audience  *string `tfsdk:"aud"`
		Expires   *int64  `tfsdk:"exp"`
		NotBefore *int64  `tfsdk:"nbf"`
		Nats      *string `tfsdk:"nats"`
	}

	resp.Error = function.ConcatFuncErrors(req.Arguments.Get(ctx, &data))

	if data.Issuer == nil {
		resp.Error = function.NewArgumentFuncError(0, "iss 不能为空")
		return
	}
	if data.Subject == nil {
		resp.Error = function.NewArgumentFuncError(0, "sub 不能为空")
		return
	}
	if data.Name == nil {
		resp.Error = function.NewArgumentFuncError(0, "name 不能为空")
		return
	}

	subject, err := nkeys.FromSeed([]byte(*data.Subject))
	if err != nil {
		resp.Error = function.NewFuncError("sub 错误")
		return
	}
	subjectPublicKey, err := subject.PublicKey()
	if err != nil {
		resp.Error = function.NewFuncError("sub 错误")
		return
	}
	prefix, _, err := nkeys.DecodeSeed([]byte(*data.Subject))
	if err != nil {
		resp.Error = function.NewFuncError("sub 错误")
		return
	}

	issuer, err := nkeys.FromSeed([]byte(*data.Issuer))
	if err != nil {
		resp.Error = function.NewFuncError("iss 错误")
	}

	var token string
	if prefix == nkeys.PrefixByteOperator {
		cliams := jwt.NewOperatorClaims(subjectPublicKey)
		cliams.Subject = subjectPublicKey
		cliams.Name = *data.Name
		if data.Audience != nil {
			cliams.Audience = *data.Audience
		}
		if data.Expires != nil {
			cliams.Expires = *data.Expires
		}
		if data.NotBefore != nil {
			cliams.NotBefore = *data.NotBefore
		}
		if data.Nats != nil {
			err := json.Unmarshal([]byte(*data.Nats), &cliams.Operator)
			if err != nil {
				resp.Error = function.NewFuncError("nats 错误")
				return
			}
			for index, signingKey := range cliams.Operator.SigningKeys {
				prefix, publicKey, err := decodeNKey(signingKey)
				if err != nil {
					resp.Error = function.NewFuncError("signing_key 接码错误")
					return
				}
				if prefix != nkeys.PrefixByteOperator {
					resp.Error = function.NewFuncError("signing_key 类型错误")
					return
				}
				cliams.Operator.SigningKeys[index] = publicKey
			}
		}
		token, err = cliams.Encode(issuer)
		if err != nil {
			resp.Error = function.NewFuncError("编码JWT错误")
			return
		}
	} else if prefix == nkeys.PrefixByteAccount {
		cliams := jwt.NewAccountClaims(subjectPublicKey)
		cliams.Subject = subjectPublicKey
		cliams.Name = *data.Name
		if data.Audience != nil {
			cliams.Audience = *data.Audience
		}
		if data.Expires != nil {
			cliams.Expires = *data.Expires
		}
		if data.NotBefore != nil {
			cliams.NotBefore = *data.NotBefore
		}

		if data.Nats != nil {
			err := json.Unmarshal([]byte(*data.Nats), &cliams.Account)
			if err != nil {
				resp.Error = function.NewFuncError("nats 错误")
				return
			}
			signingKeys := jwt.SigningKeys{}
			for signingKey, scope := range cliams.Account.SigningKeys {

				prefix, publicKey, err := decodeNKey(signingKey)
				if err != nil {
					resp.Error = function.NewFuncError("signing_key 接码错误")
					return
				}
				if prefix != nkeys.PrefixByteAccount {
					resp.Error = function.NewFuncError("signing_key 类型错误")
					return
				}
				signingKeys[publicKey] = scope
			}
			cliams.Account.SigningKeys = signingKeys
		}

		token, err = cliams.Encode(issuer)
		if err != nil {
			resp.Error = function.NewFuncError("编码JWT错误")
			return
		}
	} else if prefix == nkeys.PrefixByteUser {
		cliams := jwt.NewUserClaims(subjectPublicKey)
		cliams.Subject = subjectPublicKey
		cliams.Name = *data.Name
		if data.Audience != nil {
			cliams.Audience = *data.Audience
		}
		if data.Expires != nil {
			cliams.Expires = *data.Expires
		}
		if data.NotBefore != nil {
			cliams.NotBefore = *data.NotBefore
		}
		if data.Nats != nil {
			err := json.Unmarshal([]byte(*data.Nats), &cliams.User)
			if err != nil {
				resp.Error = function.NewFuncError("nats 错误")
				return
			}
		}

		token, err = cliams.Encode(issuer)
		if err != nil {
			resp.Error = function.NewFuncError("编码JWT错误")
			return
		}
	} else {
		resp.Error = function.NewFuncError("sub 类型错误")
		return
	}

	if resp.Error != nil {
		return
	}

	resp.Error = function.ConcatFuncErrors(resp.Result.Set(ctx, token))
}
