// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"context"
	"crypto/ed25519"

	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nats-io/nkeys"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &NkeyResource{}
var _ resource.ResourceWithImportState = &NkeyResource{}

func NewNkeyResource() resource.Resource {
	return &NkeyResource{}
}

// NkeyResource defines the resource implementation.
type NkeyResource struct {
}

// NkeyResourceModel describes the resource data model.
type NkeyResourceModel struct {
	Type    types.String `tfsdk:"type"`
	ID      types.String `tfsdk:"id"`
	Subject types.String `tfsdk:"subject"`
	Private types.String `tfsdk:"private"`
	Public  types.String `tfsdk:"public"`
}

func (r *NkeyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_nkey"
}

func (r *NkeyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "NATS NKey",

		Attributes: map[string]schema.Attribute{
			"type": schema.StringAttribute{
				Computed:            false,
				MarkdownDescription: "类型(Operator, Account, User)",
				Required:            true,
			},
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ID",
			},
			"subject": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Subject",
			},
			"private": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Private",
			},
			"public": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Public",
			},
		},
	}
}

func (r *NkeyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
}

func UpdateNKey(data *NkeyResourceModel) error {
	if data.ID.IsUnknown() {
		return function.NewFuncError("读取 NKey 错误")
	}

	prefix, rawSeed, err := nkeys.DecodeSeed([]byte(data.ID.ValueString()))
	if err != nil {
		return err
	}

	if prefix == nkeys.PrefixByteOperator {
		data.Type = types.StringValue("Operator")
	} else if prefix == nkeys.PrefixByteAccount {
		data.Type = types.StringValue("Operator")
	} else if prefix == nkeys.PrefixByteUser {
		data.Type = types.StringValue("User")
	} else {
		return function.NewFuncError("读取 NKey 错误")
	}

	keys, err := nkeys.FromSeed([]byte(data.ID.ValueString()))
	if err != nil {
		return function.NewFuncError("读取 NKey 错误")
	}

	subject, err := keys.PublicKey()
	if err != nil {
		return function.NewFuncError("读取 NKey 错误")
	}
	data.Subject = types.StringValue(subject)

	pub, priv, err := ed25519.GenerateKey(bytes.NewReader(rawSeed))
	if err != nil {
		return function.NewFuncError("读取 NKey 错误")
	}
	data.Public = types.StringValue(b64Enc.EncodeToString(pub))
	data.Private = types.StringValue(b64Enc.EncodeToString(priv))

	return nil
}

func (r *NkeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data NkeyResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var keys nkeys.KeyPair
	var err error
	if data.Type.ValueString() == "Operator" {
		keys, err = nkeys.CreateOperator()
	} else if data.Type.ValueString() == "Account" {
		keys, err = nkeys.CreateAccount()
	} else if data.Type.ValueString() == "User" {
		keys, err = nkeys.CreateUser()
	} else {
		resp.Diagnostics.AddError("生成 NKey", "类型错误")
		return
	}

	if err != nil {
		resp.Diagnostics.AddError("生成 NKey", err.Error())
		return
	}

	seed, err := keys.Seed()
	if err != nil {
		resp.Diagnostics.AddError("访问 NKey", err.Error())
		return
	}
	data.ID = types.StringValue(string(seed))

	err = UpdateNKey(&data)
	if err != nil {
		resp.Diagnostics.AddError("读取 NKey 错误", err.Error())
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *NkeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data NkeyResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := UpdateNKey(&data)
	if err != nil {
		resp.Diagnostics.AddError("读取 NKey 错误", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *NkeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data NkeyResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := UpdateNKey(&data)
	if err != nil {
		resp.Diagnostics.AddError("读取 NKey 错误", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *NkeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data NkeyResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *NkeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
