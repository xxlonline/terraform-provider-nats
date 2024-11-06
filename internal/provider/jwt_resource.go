// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &JwtResource{}
var _ resource.ResourceWithImportState = &JwtResource{}

func NewJwtResource() resource.Resource {
	return &JwtResource{}
}

// JwtResource defines the resource implementation.
type JwtResource struct {
}

// JwtResourceModel describes the resource data model.
type JwtResourceModel struct {
	ID        types.String `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	Subject   types.String `tfsdk:"sub"`
	Issuer    types.String `tfsdk:"iss"`
	IssuedAt  types.Int64  `tfsdk:"iat"`
	Expires   types.Int64  `tfsdk:"exp"`
	NotBefore types.Int64  `tfsdk:"nbf"`
	Audience  types.String `tfsdk:"aud"`
	Nats      types.String `tfsdk:"nats"`
	Token     types.String `tfsdk:"token"`
}

func (r *JwtResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_jwt"
}

func (r *JwtResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "NATS JWT",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ID",
			},
			"name": schema.StringAttribute{
				Computed:            false,
				MarkdownDescription: "Name",
				Required:            true,
			},
			"sub": schema.StringAttribute{
				Computed:            false,
				MarkdownDescription: "Subject",
				Required:            true,
			},
			"iss": schema.StringAttribute{
				Computed:            false,
				MarkdownDescription: "Issuer",
				Required:            true,
			},
			"iat": schema.Int64Attribute{
				MarkdownDescription: "IssuedAt",
				Optional:            true,
			},
			"exp": schema.Int64Attribute{
				MarkdownDescription: "Expires",
				Optional:            true,
			},
			"nbf": schema.Int64Attribute{
				MarkdownDescription: "NotBefore",
				Optional:            true,
			},
			"aud": schema.StringAttribute{
				MarkdownDescription: "Audience",
				Optional:            true,
			},
			"nats": schema.StringAttribute{
				MarkdownDescription: "Nats",
				Optional:            true,
			},
			"token": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Token",
			},
		},
	}
}

func (r *JwtResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
}

func UpdateJWT(data *JwtResourceModel) error {
	// 获取主体类型
	var subType nkeys.PrefixByte
	if nkeys.IsValidPublicOperatorKey(data.Subject.ValueString()) {
		subType = nkeys.PrefixByteOperator
	} else if nkeys.IsValidPublicAccountKey(data.Subject.ValueString()) {
		subType = nkeys.PrefixByteAccount
	} else if nkeys.IsValidPublicUserKey(data.Subject.ValueString()) {
		subType = nkeys.PrefixByteUser
	} else {
		return function.NewFuncError("sub invalid")
	}

	// 获取签发机构
	issuer, err := nkeys.FromSeed([]byte(data.Issuer.ValueString()))
	if err != nil {
		return err
	}
	issuerPublicKey, err := issuer.PublicKey()
	if err != nil {
		return err
	}
	issuerPrefix, _, err := nkeys.DecodeSeed([]byte(data.Issuer.ValueString()))
	if err != nil {
		return err
	}

	var ccliams jwt.Claims
	if subType == nkeys.PrefixByteOperator {
		if issuerPrefix != nkeys.PrefixByteOperator {
			return function.NewFuncError("isser invalid")
		}

		ocliams := jwt.NewOperatorClaims(data.Subject.ValueString())

		if !data.Nats.IsNull() {
			err = json.Unmarshal([]byte(data.Nats.ValueString()), &ocliams.Operator)
			if err != nil {
				return err
			}
		}

		ocliams.Type = jwt.OperatorClaim
		ocliams.Version = 2
		ccliams = ocliams
	} else if subType == nkeys.PrefixByteAccount {
		if issuerPrefix != nkeys.PrefixByteOperator {
			return function.NewFuncError("isser invalid")
		}

		ocliams := jwt.NewAccountClaims(data.Subject.ValueString())

		if !data.Nats.IsNull() {
			err = json.Unmarshal([]byte(data.Nats.ValueString()), &ocliams.Account)
			if err != nil {
				return err
			}
		}

		ocliams.Type = jwt.OperatorClaim
		ocliams.Version = 2
		ccliams = ocliams
	} else if subType == nkeys.PrefixByteUser {
		if issuerPrefix != nkeys.PrefixByteOperator {
			return function.NewFuncError("isser invalid")
		}

		ocliams := jwt.NewUserClaims(data.Subject.ValueString())

		if !data.Nats.IsNull() {
			err = json.Unmarshal([]byte(data.Nats.ValueString()), &ocliams.User)
			if err != nil {
				return err
			}
		}

		ocliams.Type = jwt.OperatorClaim
		ocliams.Version = 2
		ccliams = ocliams
	} else {
		return function.NewFuncError("sub invalid")
	}

	// 名称
	ccliams.Claims().Name = data.Name.ValueString()

	// 签发者
	ccliams.Claims().Issuer = issuerPublicKey

	// 签发时间
	if data.Expires.IsNull() {
		ccliams.Claims().IssuedAt = time.Now().UTC().Unix()
	} else {
		ccliams.Claims().IssuedAt = data.IssuedAt.ValueInt64()
	}

	// 有效时间
	if !data.Expires.IsNull() {
		ccliams.Claims().Expires = data.Expires.ValueInt64()
	}

	// 生效时间
	if !data.NotBefore.IsNull() {
		ccliams.Claims().NotBefore = data.NotBefore.ValueInt64()
	}

	// 接收者
	if !data.Audience.IsNull() {
		ccliams.Claims().Audience = data.Audience.ValueString()
	}

	// ID
	ccliams.Claims().ID = ""
	ccliams.Claims().ID, err = hash(*ccliams.Claims())
	if err != nil {
		return err
	}
	data.ID = types.StringValue(ccliams.Claims().ID)

	// 头
	header, err := serialize(&jwt.Header{Type: jwt.TokenTypeJwt, Algorithm: jwt.AlgorithmNkey})
	if err != nil {
		return err
	}

	// 体
	payload, err := serialize(ccliams)
	if err != nil {
		return err
	}

	toSign := fmt.Sprintf("%s.%s", header, payload)
	sig, err := issuer.Sign([]byte(toSign))
	if err != nil {
		return err
	}
	eSig := encodeToString(sig)

	data.Token = types.StringValue(fmt.Sprintf("%s.%s", toSign, eSig))

	return nil
}

func (r *JwtResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data JwtResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := UpdateJWT(&data)
	if err != nil {
		resp.Diagnostics.AddError("create JWT error", err.Error())
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *JwtResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data JwtResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := UpdateJWT(&data)
	if err != nil {
		resp.Diagnostics.AddError("read JWT error", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *JwtResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data JwtResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := UpdateJWT(&data)
	if err != nil {
		resp.Diagnostics.AddError("update JWT error", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *JwtResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data JwtResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *JwtResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
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
