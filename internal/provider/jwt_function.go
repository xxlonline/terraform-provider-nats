// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/sha512"
	"fmt"
	"strconv"

	"context"
	"encoding/base64"
	"encoding/json"

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
		MarkdownDescription: "生成JWT",
		Parameters: []function.Parameter{
			function.MapParameter{
				ElementType:         basetypes.StringType{},
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
	data := map[string]string{}

	resp.Error = function.ConcatFuncErrors(req.Arguments.Get(ctx, &data))
	if resp.Error != nil {
		return
	}

	iss, ok := data["iss"]
	if !ok {
		resp.Error = function.NewArgumentFuncError(0, "iss 不能为空")
		return
	}
	sub, ok := data["sub"]
	if !ok {
		resp.Error = function.NewArgumentFuncError(0, "sub 不能为空")
		return
	}
	name, ok := data["name"]
	if !ok {
		resp.Error = function.NewArgumentFuncError(0, "name 不能为空")
		return
	}

	subject, err := nkeys.FromSeed([]byte(sub))
	if err != nil {
		resp.Error = function.NewFuncError("sub 错误")
		return
	}
	subjectPublicKey, err := subject.PublicKey()
	if err != nil {
		resp.Error = function.NewFuncError("sub 错误")
		return
	}
	prefix, _, err := nkeys.DecodeSeed([]byte(sub))
	if err != nil {
		resp.Error = function.NewFuncError("sub 错误")
		return
	}

	issuer, err := nkeys.FromSeed([]byte(iss))
	if err != nil {
		resp.Error = function.NewFuncError("iss 错误")
	}
	issuerPublicKey, err := issuer.PublicKey()
	if err != nil {
		resp.Error = function.NewFuncError("sub 错误")
		return
	}
	issuerPrefix, _, err := nkeys.DecodeSeed([]byte(iss))
	if err != nil {
		resp.Error = function.NewFuncError("sub 错误")
		return
	}

	var cliams jwt.Claims
	if prefix == nkeys.PrefixByteOperator {
		if issuerPrefix != nkeys.PrefixByteOperator {
			resp.Error = function.NewFuncError("iss 错误")
			return
		}

		ocliams := jwt.NewOperatorClaims(subjectPublicKey)
		nats, ok := data["nats"]
		if ok {
			err := json.Unmarshal([]byte(nats), &ocliams.Operator)
			if err != nil {
				resp.Error = function.NewFuncError("nats 错误")
				return
			}
			for index, signingKey := range ocliams.Operator.SigningKeys {
				prefix, publicKey, err := decodeNKey(signingKey)
				if err != nil {
					resp.Error = function.NewFuncError("signing_key 错误")
					return
				}
				if prefix != nkeys.PrefixByteOperator {
					resp.Error = function.NewFuncError("signing_key 类型错误")
					return
				}
				ocliams.Operator.SigningKeys[index] = publicKey
			}
		}

		cliams = ocliams
	} else if prefix == nkeys.PrefixByteAccount {
		if issuerPrefix != nkeys.PrefixByteOperator {
			resp.Error = function.NewFuncError("iss 错误")
			return
		}

		ocliams := jwt.NewAccountClaims(subjectPublicKey)
		nats, ok := data["nats"]
		if ok {
			err := json.Unmarshal([]byte(nats), &ocliams.Account)
			if err != nil {
				resp.Error = function.NewFuncError("nats 错误")
				return
			}
			signingKeys := jwt.SigningKeys{}
			for signingKey, scope := range ocliams.Account.SigningKeys {

				prefix, publicKey, err := decodeNKey(signingKey)
				if err != nil {
					resp.Error = function.NewFuncError("signing_key 错误")
					return
				}
				if prefix != nkeys.PrefixByteAccount {
					resp.Error = function.NewFuncError("signing_key 类型错误")
					return
				}
				signingKeys[publicKey] = scope
			}
			ocliams.Account.SigningKeys = signingKeys
		}

		cliams = ocliams
	} else if prefix == nkeys.PrefixByteUser {
		if issuerPrefix != nkeys.PrefixByteAccount {
			resp.Error = function.NewFuncError("iss 错误")
			return
		}

		ocliams := jwt.NewUserClaims(subjectPublicKey)
		nats, ok := data["nats"]
		if ok {
			err := json.Unmarshal([]byte(nats), &ocliams.User)
			if err != nil {
				resp.Error = function.NewFuncError("nats 错误")
				return
			}
		}

		cliams = ocliams

	} else {
		resp.Error = function.NewFuncError("sub 类型错误")
		return
	}

	// 颁发者
	cliams.Claims().Issuer = issuerPublicKey
	// 主体
	cliams.Claims().Subject = subjectPublicKey
	// 名称
	cliams.Claims().Name = name

	// aud
	aud, ok := data["aud"]
	if ok {
		cliams.Claims().Audience = aud
	}

	// 有效期
	exp, ok := data["exp"]
	if ok {
		cliams.Claims().Expires, err = strconv.ParseInt(exp, 10, 64)
		if err != nil {
			resp.Error = function.NewFuncError("exp 错误")
			return
		}
	}

	// 生效时间
	nbf, ok := data["nbf"]
	if ok {
		cliams.Claims().NotBefore, _ = strconv.ParseInt(nbf, 10, 64)
		if err != nil {
			resp.Error = function.NewFuncError("nbf 错误")
			return
		}
	}

	// 编码
	_, err = cliams.Encode(issuer)
	if err != nil {
		resp.Error = function.NewFuncError("编码错误")
		return
	}

	// 颁发时间
	iat, ok := data["iat"]
	if ok {
		cliams.Claims().IssuedAt, err = strconv.ParseInt(iat, 10, 64)
		if err != nil {
			resp.Error = function.NewFuncError("iat 错误")
			return
		}
	}

	// ID
	cliams.Claims().ID = ""
	cliams.Claims().ID, err = hash(*cliams.Claims())
	if err != nil {
		resp.Error = function.NewFuncError("iat 错误")
		return
	}

	// 头
	header, err := serialize(&jwt.Header{Type: jwt.TokenTypeJwt, Algorithm: jwt.AlgorithmNkey})
	if err != nil {
		resp.Error = function.NewFuncError("序列化错误")
		return
	}

	// 体
	payload, err := serialize(cliams)
	if err != nil {
		resp.Error = function.NewFuncError("序列化错误")
		return
	}

	toSign := fmt.Sprintf("%s.%s", header, payload)
	sig, err := issuer.Sign([]byte(toSign))
	if err != nil {
		resp.Error = function.NewFuncError("签名错误")
		return
	}
	eSig := encodeToString(sig)

	token := fmt.Sprintf("%s.%s", toSign, eSig)

	resp.Error = function.ConcatFuncErrors(resp.Result.Set(ctx, token))
}

func hash(c interface{}) (string, error) {
	j, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	h := sha512.New512_256()
	h.Write(j)
	return b32Enc.EncodeToString(h.Sum(nil)), nil
}

func encodeToString(d []byte) string {
	return base64.RawURLEncoding.EncodeToString(d)
}

func serialize(v interface{}) (string, error) {
	j, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return encodeToString(j), nil
}
