// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

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
	Type types.String `tfsdk:"type"`
	ID   types.String `tfsdk:"od"`
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
		},
	}
}

func (r *NkeyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
}

func (r *NkeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data NkeyResourceModel

	// Read Terraform plan data into the model
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

	// Write logs using the tflog package
	// Documentation: https://terraform.io/plugin/log
	tflog.Trace(ctx, "created a resource")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *NkeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data NkeyResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if data.ID.IsUnknown() {
		resp.Diagnostics.AddError(
			"读取 NKey",
			"Cannot read NATS NKey with unknown ID",
		)
		return
	}

	prefix, _, err := nkeys.DecodeSeed([]byte(data.ID.String()))
	if err != nil {
		resp.Diagnostics.AddError("读取 NKey", err.Error())
		return
	}

	if prefix == nkeys.PrefixByteOperator {
		data.Type = types.StringValue("Operator")
	} else if prefix == nkeys.PrefixByteAccount {
		data.Type = types.StringValue("Operator")
	} else if prefix == nkeys.PrefixByteUser {
		data.Type = types.StringValue("User")
	} else {
		resp.Diagnostics.AddError("读取 NKey", "未知类型")
		return
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// If applicable, this is a great opportunity to initialize any necessary
	// provider client data and make a call using it.
	// httpResp, err := r.client.Do(httpReq)
	// if err != nil {
	//     resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read example, got error: %s", err))
	//     return
	// }

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *NkeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data NkeyResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// If applicable, this is a great opportunity to initialize any necessary
	// provider client data and make a call using it.
	// httpResp, err := r.client.Do(httpReq)
	// if err != nil {
	//     resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to update example, got error: %s", err))
	//     return
	// }

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *NkeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data NkeyResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// If applicable, this is a great opportunity to initialize any necessary
	// provider client data and make a call using it.
	// httpResp, err := r.client.Do(httpReq)
	// if err != nil {
	//     resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete example, got error: %s", err))
	//     return
	// }
}

func (r *NkeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
