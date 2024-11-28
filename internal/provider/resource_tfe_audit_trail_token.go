// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// NOTE: This is a legacy resource and should be migrated to the Plugin
// Framework if substantial modifications are planned. See
// docs/new-resources.md if planning to use this code as boilerplate for
// a new resource.

package provider

import (
	"context"
	"errors"
	"fmt"
	"time"

	//"strings"

	tfe "github.com/hashicorp/go-tfe"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type resourceAuditTrailToken struct {
	config ConfiguredClient
}

var _ resource.Resource = &resourceAuditTrailToken{}
var _ resource.ResourceWithConfigure = &resourceAuditTrailToken{}

//var _ resource.ResourceWithImportState = &resourceOrgRunTask{}
//var _ resource.ResourceWithModifyPlan = &resourceOrgRunTask{}

func NewAuditTrailTokenResource() resource.Resource {
	return &resourceAuditTrailToken{}
}

type modelTFEAuditTrailTokenV0 struct {
	ID           types.String `tfsdk:"id"`
	Organization types.String `tfsdk:"organization"`
	Token        types.String `tfsdk:"token"`
	ExpiredAt    types.String `tfsdk:"expired_at"` // TODO: What about no expiry?

	// Category     types.String `tfsdk:"category"`
	// Description  types.String `tfsdk:"description"`
	// Enabled      types.Bool   `tfsdk:"enabled"`
	// HMACKey      types.String `tfsdk:"hmac_key"`
	// ID           types.String `tfsdk:"id"`
	// Name         types.String `tfsdk:"name"`
	// URL          types.String `tfsdk:"url"`
}

func modelFromTFEOrganizationToken(v *tfe.OrganizationToken, organization, tokenValue string) modelTFEAuditTrailTokenV0 {
	result := modelTFEAuditTrailTokenV0{
		Organization: types.StringValue(organization),
		ID:           types.StringValue(v.ID),
		//ExpiredAt:    types.StringValue(v.ExpiredAt.String()),
		Token: types.StringValue(""), // This value is only emitted by the API at create time so we inject it later

		// Category:     types.StringValue(v.Category),
		// Description:  types.StringValue(v.Description),
		// Enabled:      types.BoolValue(v.Enabled),
		// ID:           types.StringValue(v.ID),
		// Name:         types.StringValue(v.Name),
		// URL:          types.StringValue(v.URL),
	}

	if !v.ExpiredAt.IsZero() {
		result.ExpiredAt = types.StringValue(v.ExpiredAt.Format(time.RFC3339))
	}

	if len(tokenValue) > 0 {
		result.Token = types.StringValue(tokenValue)
	}

	return result
}

func (r *resourceAuditTrailToken) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_audit_trail_token"
}

// Configure implements resource.ResourceWithConfigure
func (r *resourceAuditTrailToken) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(ConfiguredClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected resource Configure type",
			fmt.Sprintf("Expected tfe.ConfiguredClient, got %T. This is a bug in the tfe provider, so please report it on GitHub.", req.ProviderData),
		)
	}
	r.config = client
}

func (r *resourceAuditTrailToken) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version: 0,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Service-generated identifier for the token",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"organization": schema.StringAttribute{
				Description: "Name of the organization. If omitted, organization must be defined in the provider config.",
				Optional:    true,
				Computed:    true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				// From ForceNew: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},

			// expired at
			"expired_at": schema.StringAttribute{
				//Description: "The time when the GPG key was created.",
				Optional: true,
				// From ForceNew: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},

			"token": schema.StringAttribute{
				Sensitive: true,
				Optional:  true,
				Computed:  true,
				Default:   stringdefault.StaticString(""),
			},

			// "name": schema.StringAttribute{
			// 	Required: true,
			// },

			// "url": schema.StringAttribute{
			// 	Required: true,
			// 	Validators: []validator.String{
			// 		customValidators.IsURLWithHTTPorHTTPS(),
			// 	},
			// },
			// "category": schema.StringAttribute{
			// 	Optional: true,
			// 	Computed: true,
			// 	Default:  stringdefault.StaticString("task"),
			// },
			// "hmac_key": schema.StringAttribute{
			// 	Sensitive: true,
			// 	Optional:  true,
			// 	Computed:  true,
			// 	Default:   stringdefault.StaticString(""),
			// },
			// "enabled": schema.BoolAttribute{
			// 	Optional: true,
			// 	Computed: true,
			// 	Default:  booldefault.StaticBool(true),
			// },
			// "description": schema.StringAttribute{
			// 	Optional: true,
			// 	Computed: true,
			// 	Default:  stringdefault.StaticString(""),
			// },
		},
	}
}

func (r *resourceAuditTrailToken) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state modelTFEAuditTrailTokenV0

	// Read Terraform current state into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var organization string
	resp.Diagnostics.Append(r.config.dataOrDefaultOrganization(ctx, req.State, &organization)...)
	if resp.Diagnostics.HasError() {
		return
	}

	//tokenID := state.ID.ValueString()
	//organization := state.Organization.ValueString()
	tokenType := tfe.AuditTrailToken

	tflog.Debug(ctx, "Reading audit trail token")
	token, err := r.config.Client.OrganizationTokens.ReadWithOptions(ctx, organization, tfe.OrganizationTokenReadOptions{TokenType: &tokenType})
	if err != nil {
		if errors.Is(err, tfe.ErrResourceNotFound) {
			resp.State.RemoveResource(ctx)
		} else {
			resp.Diagnostics.AddError("Error reading Organization Audit Trail Token", "Could not read Organization Audit Trail Token, unexpected error: "+err.Error())
		}
		return
	}

	result := modelFromTFEOrganizationToken(token, organization, state.Token.ValueString())

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &result)...)
}

func (r *resourceAuditTrailToken) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	//panic("Not implemented")
	var plan modelTFEAuditTrailTokenV0

	// Read Terraform planned changes into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var organization string
	resp.Diagnostics.Append(r.config.dataOrDefaultOrganization(ctx, req.Plan, &organization)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tokenType := tfe.AuditTrailToken
	options := tfe.OrganizationTokenCreateOptions{
		TokenType: &tokenType,
	}

	// Optional ExpiryAt
	if !plan.ExpiredAt.IsNull() {
		expire_string := plan.ExpiredAt.ValueString()
		expiry, err := time.Parse(time.RFC3339, expire_string)

		if err != nil {
			resp.Diagnostics.AddError("Invalid date", fmt.Sprintf("%s must be a valid date or time, provided in iso8601 format", expire_string))
			return
		}
		options.ExpiredAt = &expiry
	}

	tflog.Debug(ctx, fmt.Sprintf("Create audit trail token for organization %s", organization))
	token, err := r.config.Client.OrganizationTokens.CreateWithOptions(ctx, organization, options)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create organization audit trail token", err.Error())
		return
	}

	tflog.Error(ctx, "!!!!!!!!!!!!!!!!\n\n"+token.Token+"\n\n")

	result := modelFromTFEOrganizationToken(token, organization, token.Token) //, plan.HMACKey)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &result)...)
}

func (r *resourceAuditTrailToken) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	panic("Not implemented")
	// var plan modelTFEOrganizationRunTaskV0

	// // Read Terraform planned changes into the model
	// resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	// if resp.Diagnostics.HasError() {
	// 	return
	// }

	// var state modelTFEOrganizationRunTaskV0
	// // Read Terraform state into the model
	// resp.Diagnostics.Append(req.Plan.Get(ctx, &state)...)
	// if resp.Diagnostics.HasError() {
	// 	return
	// }

	// options := tfe.RunTaskUpdateOptions{
	// 	Name:        plan.Name.ValueStringPointer(),
	// 	URL:         plan.URL.ValueStringPointer(),
	// 	Category:    plan.Category.ValueStringPointer(),
	// 	Enabled:     plan.Enabled.ValueBoolPointer(),
	// 	Description: plan.Description.ValueStringPointer(),
	// }

	// // HMAC Key is a write-only value so we should only send it if
	// // it really has changed.
	// if plan.HMACKey.ValueString() != state.HMACKey.ValueString() {
	// 	options.HMACKey = plan.HMACKey.ValueStringPointer()
	// }

	// taskID := plan.ID.ValueString()

	// tflog.Debug(ctx, fmt.Sprintf("Update task %s", taskID))
	// task, err := r.config.Client.RunTasks.Update(ctx, taskID, options)
	// if err != nil {
	// 	resp.Diagnostics.AddError("Unable to update organization task", err.Error())
	// 	return
	// }

	// result := modelFromTFEOrganizationRunTask(task, plan.HMACKey)

	// // Save data into Terraform state
	// resp.Diagnostics.Append(resp.State.Set(ctx, &result)...)
}

func (r *resourceAuditTrailToken) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state modelTFEAuditTrailTokenV0
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var organization string
	resp.Diagnostics.Append(r.config.dataOrDefaultOrganization(ctx, req.State, &organization)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tokenType := tfe.AuditTrailToken

	options := tfe.OrganizationTokenDeleteOptions{
		TokenType: &tokenType,
	}

	tflog.Debug(ctx, fmt.Sprintf("Delete organization audit trail token %s", organization))
	err := r.config.Client.OrganizationTokens.DeleteWithOptions(ctx, organization, options)
	// Ignore 404s for delete
	if err != nil && !errors.Is(err, tfe.ErrResourceNotFound) {
		resp.Diagnostics.AddError(
			"Error deleting organization audit trail token",
			fmt.Sprintf("Couldn't delete organization audit trail token %s: %s", organization, err.Error()),
		)
	}
	// Resource is implicitly deleted from resp.State if diagnostics have no errors.
}

func (r *resourceAuditTrailToken) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	panic("Not implemented")
	// s := strings.SplitN(req.ID, "/", 2)
	// if len(s) != 2 {
	// 	resp.Diagnostics.AddError(
	// 		"Error importing organization run task",
	// 		fmt.Sprintf("Invalid task input format: %s (expected <ORGANIZATION>/<TASK NAME>)", req.ID),
	// 	)
	// 	return
	// }

	// taskName := s[1]
	// orgName := s[0]

	// if task, err := fetchOrganizationRunTask(taskName, orgName, r.config.Client); err != nil {
	// 	resp.Diagnostics.AddError(
	// 		"Error importing organization run task",
	// 		err.Error(),
	// 	)
	// } else if task == nil {
	// 	resp.Diagnostics.AddError(
	// 		"Error importing organization run task",
	// 		"Task does not exist or has no details",
	// 	)
	// } else {
	// 	// We can never import the HMACkey (Write-only) so assume it's the default (empty)
	// 	result := modelFromTFEOrganizationRunTask(task, types.StringValue(""))
	// 	resp.Diagnostics.Append(resp.State.Set(ctx, &result)...)
	// }
}

//----

// import (
// 	"context"
// 	"errors"
// 	"fmt"
// 	"log"
// 	"time"

// 	tfe "github.com/hashicorp/go-tfe"
// 	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
// )

// func resourceTFEAuditTrailToken() *schema.Resource {
// 	return &schema.Resource{
// 		Create: resourceTFEAuditTrailTokenCreate,
// 		Read:   resourceTFEAuditTrailTokenRead,
// 		Delete: resourceTFEAuditTrailTokenDelete,
// 		Importer: &schema.ResourceImporter{
// 			StateContext: resourceTFEAuditTrailTokenImporter,
// 		},

// 		CustomizeDiff: customizeDiffIfProviderDefaultOrganizationChanged,

// 		Schema: map[string]*schema.Schema{
// 			"organization": {
// 				Type:     schema.TypeString,
// 				Optional: true,
// 				Computed: true,
// 				ForceNew: true,
// 			},

// 			"force_regenerate": {
// 				Type:     schema.TypeBool,
// 				Optional: true,
// 				ForceNew: true,
// 			},

// 			"token": {
// 				Type:      schema.TypeString,
// 				Computed:  true,
// 				Sensitive: true,
// 			},

// 			"expired_at": {
// 				Type:     schema.TypeString,
// 				Optional: true,
// 				ForceNew: true,
// 			},
// 		},
// 	}
// }

// func resourceTFEAuditTrailTokenCreate(d *schema.ResourceData, meta interface{}) error {
// 	config := meta.(ConfiguredClient)
// 	auditTrailTokenType := tfe.AuditTrailToken

// 	// Get the organization name.
// 	organization, err := config.schemaOrDefaultOrganization(d)
// 	if err != nil {
// 		return err
// 	}

// 	readOptions := tfe.OrganizationTokenReadOptions{
// 		TokenType: &auditTrailTokenType,
// 	}
// 	log.Printf("[DEBUG] Check if an audit trail token already exists for organization: %s", organization)
// 	_, err = config.Client.OrganizationTokens.ReadWithOptions(ctx, organization, readOptions)
// 	if err != nil && !errors.Is(err, tfe.ErrResourceNotFound) {
// 		return fmt.Errorf("error checking if an audit token exists for organization %s: %w", organization, err)
// 	}

// 	// If error is nil, the token already exists.
// 	if err == nil {
// 		if !d.Get("force_regenerate").(bool) {
// 			return fmt.Errorf("an audit trail token already exists for organization: %s", organization)
// 		}
// 		log.Printf("[DEBUG] Regenerating existing audit trail token for organization: %s", organization)
// 	}

// 	// Get the token create options.
// 	createOptions := tfe.OrganizationTokenCreateOptions{
// 		TokenType: &auditTrailTokenType,
// 	}

// 	// Check whether the optional expiry was provided.
// 	expiredAt, expiredAtProvided := d.GetOk("expired_at")

// 	// If an expiry was provided, parse it and update the options struct.
// 	if expiredAtProvided {
// 		expiry, err := time.Parse(time.RFC3339, expiredAt.(string))

// 		createOptions.ExpiredAt = &expiry

// 		if err != nil {
// 			return fmt.Errorf("%s must be a valid date or time, provided in iso8601 format", expiredAt)
// 		}
// 	}

// 	token, err := config.Client.OrganizationTokens.CreateWithOptions(ctx, organization, createOptions)
// 	if err != nil {
// 		return fmt.Errorf(
// 			"error creating new audit trail token for organization %s: %w", organization, err)
// 	}

// 	d.SetId(organization)

// 	// We need to set this here in the create function as this value will
// 	// only be returned once during the creation of the token.
// 	d.Set("token", token.Token)

// 	return resourceTFEAuditTrailTokenRead(d, meta)
// }

// func resourceTFEAuditTrailTokenRead(d *schema.ResourceData, meta interface{}) error {
// 	config := meta.(ConfiguredClient)

// 	auditTrailTokenType := tfe.AuditTrailToken
// 	readOptions := tfe.OrganizationTokenReadOptions{
// 		TokenType: &auditTrailTokenType,
// 	}
// 	log.Printf("[DEBUG] Read the audit trail token from organization: %s", d.Id())
// 	_, err := config.Client.OrganizationTokens.ReadWithOptions(ctx, d.Id(), readOptions)
// 	if err != nil {
// 		if err == tfe.ErrResourceNotFound {
// 			log.Printf("[DEBUG] Audit trail token for organization %s no longer exists", d.Id())
// 			d.SetId("")
// 			return nil
// 		}
// 		return fmt.Errorf("error reading audit trail token from organization %s: %w", d.Id(), err)
// 	}

// 	return nil
// }

// func resourceTFEAuditTrailTokenDelete(d *schema.ResourceData, meta interface{}) error {
// 	config := meta.(ConfiguredClient)

// 	organization, err := config.schemaOrDefaultOrganization(d)
// 	if err != nil {
// 		return err
// 	}
// 	auditTrailTokenType := tfe.AuditTrailToken
// 	deleteOptions := tfe.OrganizationTokenDeleteOptions{
// 		TokenType: &auditTrailTokenType,
// 	}
// 	log.Printf("[DEBUG] Delete token from organization: %s", organization)
// 	err = config.Client.OrganizationTokens.DeleteWithOptions(ctx, organization, deleteOptions)
// 	if err != nil {
// 		if err == tfe.ErrResourceNotFound {
// 			return nil
// 		}
// 		return fmt.Errorf("error deleting audit trail token from organization %s: %w", d.Id(), err)
// 	}

// 	return nil
// }

// func resourceTFEAuditTrailTokenImporter(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
// 	// Set the organization field.
// 	d.Set("organization", d.Id())

// 	return []*schema.ResourceData{d}, nil
// }
