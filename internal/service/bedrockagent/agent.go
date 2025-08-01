// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bedrockagent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/YakDriver/regexache"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	awstypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/id"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-provider-aws/internal/enum"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/fwdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/framework"
	fwflex "github.com/hashicorp/terraform-provider-aws/internal/framework/flex"
	fwtypes "github.com/hashicorp/terraform-provider-aws/internal/framework/types"
	tfslices "github.com/hashicorp/terraform-provider-aws/internal/slices"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @FrameworkResource("aws_bedrockagent_agent", name="Agent")
// @Tags(identifierAttribute="agent_arn")
func newAgentResource(context.Context) (resource.ResourceWithConfigure, error) {
	r := &agentResource{}

	r.SetDefaultCreateTimeout(5 * time.Minute)
	r.SetDefaultUpdateTimeout(5 * time.Minute)
	r.SetDefaultDeleteTimeout(5 * time.Minute)

	return r, nil
}

type agentResource struct {
	framework.ResourceWithModel[agentResourceModel]
	framework.WithTimeouts
}

func (r *agentResource) Schema(ctx context.Context, request resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"agent_arn": framework.ARNAttributeComputedOnly(),
			"agent_id":  framework.IDAttribute(),
			"agent_collaboration": schema.StringAttribute{
				CustomType: fwtypes.StringEnumType[awstypes.AgentCollaboration](),
				Optional:   true,
				Computed:   true,
			},
			"agent_name": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexache.MustCompile(`^([0-9a-zA-Z][_-]?){1,100}$`), "valid characters are a-z, A-Z, 0-9, _ (underscore) and - (hyphen). The name can have up to 100 characters"),
				},
			},
			"agent_resource_role_arn": schema.StringAttribute{
				CustomType: fwtypes.ARNType,
				Required:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"agent_version": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"customer_encryption_key_arn": schema.StringAttribute{
				CustomType: fwtypes.ARNType,
				Optional:   true,
			},
			names.AttrDescription: schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 200),
				},
			},
			"foundation_model": schema.StringAttribute{
				Required: true,
			},
			"guardrail_configuration": schema.ListAttribute{
				CustomType: fwtypes.NewListNestedObjectTypeOf[guardrailConfigurationModel](ctx),
				Optional:   true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				ElementType: types.ObjectType{
					AttrTypes: fwtypes.AttributeTypesMust[guardrailConfigurationModel](ctx),
				},
			},
			names.AttrID: framework.IDAttribute(),
			"idle_session_ttl_in_seconds": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
				Validators: []validator.Int64{
					int64validator.Between(60, 3600),
				},
			},
			"instruction": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.UTF8LengthBetween(40, 20000),
				},
			},
			"memory_configuration":          framework.ResourceOptionalComputedListOfObjectsAttribute[memoryConfigurationModel](ctx, 1, nil, listplanmodifier.UseStateForUnknown()),
			"prompt_override_configuration": framework.ResourceOptionalComputedListOfObjectsAttribute[promptOverrideConfigurationModel](ctx, 1, nil, listplanmodifier.UseStateForUnknown()),
			"prepared_at": schema.StringAttribute{
				CustomType: timetypes.RFC3339Type{},
				Computed:   true,
			},
			"prepare_agent": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"skip_resource_in_use_check": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			names.AttrTags:    tftags.TagsAttribute(),
			names.AttrTagsAll: tftags.TagsAttributeComputedOnly(),
		},
		Blocks: map[string]schema.Block{
			names.AttrTimeouts: timeouts.Block(ctx, timeouts.Opts{
				Create: true,
				Update: true,
				Delete: true,
			}),
		},
	}
}

func (r *agentResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var data agentResourceModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &data)...)
	if response.Diagnostics.HasError() {
		return
	}

	conn := r.Meta().BedrockAgentClient(ctx)

	input := bedrockagent.CreateAgentInput{}
	response.Diagnostics.Append(fwflex.Expand(ctx, data, &input)...)
	if response.Diagnostics.HasError() {
		return
	}

	input.ClientToken = aws.String(id.UniqueId())
	input.Tags = getTagsIn(ctx)

	output, err := conn.CreateAgent(ctx, &input)

	if err != nil {
		response.Diagnostics.AddError("creating Bedrock Agent", err.Error())
		return
	}

	// Set values for unknowns.
	data.AgentID = fwflex.StringToFramework(ctx, output.Agent.AgentId)
	data.setID()

	timeout := r.CreateTimeout(ctx, data.Timeouts)
	agent, err := waitAgentCreated(ctx, conn, data.ID.ValueString(), timeout)

	if err != nil {
		response.Diagnostics.AddError(fmt.Sprintf("waiting for Bedrock Agent (%s) create", data.ID.ValueString()), err.Error())
		return
	}

	if data.PrepareAgent.ValueBool() {
		agent, err = prepareAgent(ctx, conn, data.ID.ValueString(), timeout)

		if err != nil {
			response.Diagnostics.AddError("creating Agent", err.Error())
			return
		}
	}

	removeDefaultPrompts(agent)

	// Set values for unknowns.
	response.Diagnostics.Append(fwflex.Flatten(ctx, agent, &data)...)
	if response.Diagnostics.HasError() {
		return
	}

	response.Diagnostics.Append(response.State.Set(ctx, &data)...)
}

func (r *agentResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var data agentResourceModel
	response.Diagnostics.Append(request.State.Get(ctx, &data)...)
	if response.Diagnostics.HasError() {
		return
	}

	if err := data.InitFromID(); err != nil {
		response.Diagnostics.AddError("parsing resource ID", err.Error())
		return
	}

	conn := r.Meta().BedrockAgentClient(ctx)

	agentID := data.ID.ValueString()
	agent, err := findAgentByID(ctx, conn, agentID)

	if tfresource.NotFound(err) {
		response.Diagnostics.Append(fwdiag.NewResourceNotFoundWarningDiagnostic(err))
		response.State.RemoveResource(ctx)
		return
	}

	if err != nil {
		response.Diagnostics.AddError(fmt.Sprintf("reading Bedrock Agent (%s)", agentID), err.Error())
		return
	}

	removeDefaultPrompts(agent)

	response.Diagnostics.Append(fwflex.Flatten(ctx, agent, &data)...)
	if response.Diagnostics.HasError() {
		return
	}

	response.Diagnostics.Append(response.State.Set(ctx, &data)...)
}

func (r *agentResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var old, new agentResourceModel
	response.Diagnostics.Append(request.State.Get(ctx, &old)...)
	if response.Diagnostics.HasError() {
		return
	}
	response.Diagnostics.Append(request.Plan.Get(ctx, &new)...)
	if response.Diagnostics.HasError() {
		return
	}
	conn := r.Meta().BedrockAgentClient(ctx)

	if !new.AgentCollaboration.Equal(old.AgentCollaboration) ||
		!new.AgentName.Equal(old.AgentName) ||
		!new.AgentResourceRoleARN.Equal(old.AgentResourceRoleARN) ||
		!new.CustomerEncryptionKeyARN.Equal(old.CustomerEncryptionKeyARN) ||
		!new.Description.Equal(old.Description) ||
		!new.Instruction.Equal(old.Instruction) ||
		!new.IdleSessionTTLInSeconds.Equal(old.IdleSessionTTLInSeconds) ||
		!new.FoundationModel.Equal(old.FoundationModel) ||
		!new.GuardrailConfiguration.Equal(old.GuardrailConfiguration) ||
		!new.MemoryConfiguration.Equal(old.MemoryConfiguration) ||
		!new.PromptOverrideConfiguration.Equal(old.PromptOverrideConfiguration) {
		var input bedrockagent.UpdateAgentInput
		response.Diagnostics.Append(flexExpandForUpdate(ctx, new, &input)...)
		if response.Diagnostics.HasError() {
			return
		}

		if !new.CustomerEncryptionKeyARN.Equal(old.CustomerEncryptionKeyARN) {
			input.CustomerEncryptionKeyArn = fwflex.StringFromFramework(ctx, new.CustomerEncryptionKeyARN)
		}

		if !new.GuardrailConfiguration.Equal(old.GuardrailConfiguration) && !new.GuardrailConfiguration.IsNull() {
			guardrailConfiguration := &awstypes.GuardrailConfiguration{}
			response.Diagnostics.Append(fwflex.Expand(ctx, new.GuardrailConfiguration, guardrailConfiguration)...)
			if response.Diagnostics.HasError() {
				return
			}

			input.GuardrailConfiguration = guardrailConfiguration
		}

		if !new.MemoryConfiguration.Equal(old.MemoryConfiguration) {
			memoryConfiguration := &awstypes.MemoryConfiguration{}
			response.Diagnostics.Append(fwflex.Expand(ctx, new.MemoryConfiguration, memoryConfiguration)...)
			if response.Diagnostics.HasError() {
				return
			}

			if len(memoryConfiguration.EnabledMemoryTypes) > 0 {
				input.MemoryConfiguration = memoryConfiguration
			}
		}

		if !new.PromptOverrideConfiguration.IsNull() {
			promptOverrideConfiguration := &awstypes.PromptOverrideConfiguration{}
			response.Diagnostics.Append(fwflex.Expand(ctx, new.PromptOverrideConfiguration, promptOverrideConfiguration)...)
			if response.Diagnostics.HasError() {
				return
			}

			if len(promptOverrideConfiguration.PromptConfigurations) > 0 {
				input.PromptOverrideConfiguration = promptOverrideConfiguration
			}
		}

		timeout := r.UpdateTimeout(ctx, new.Timeouts)
		_, err := updateAgentWithRetry(ctx, conn, input, timeout)

		if err != nil {
			response.Diagnostics.AddError(fmt.Sprintf("updating Bedrock Agent (%s)", new.ID.ValueString()), err.Error())
			return
		}

		agent, err := waitAgentUpdated(ctx, conn, new.ID.ValueString(), timeout)

		if err != nil {
			response.Diagnostics.AddError(fmt.Sprintf("waiting for Bedrock Agent (%s) update", new.ID.ValueString()), err.Error())
			return
		}

		if new.PrepareAgent.ValueBool() {
			agent, err = prepareAgent(ctx, conn, new.ID.ValueString(), timeout)

			if err != nil {
				response.Diagnostics.AddError("updating Agent", err.Error())
				return
			}
		}

		removeDefaultPrompts(agent)

		// Set values for unknowns.
		response.Diagnostics.Append(fwflex.Flatten(ctx, agent, &new)...)
		if response.Diagnostics.HasError() {
			return
		}
	} else {
		new.AgentVersion = old.AgentVersion
	}

	response.Diagnostics.Append(response.State.Set(ctx, &new)...)
}

func (r *agentResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var data agentResourceModel
	response.Diagnostics.Append(request.State.Get(ctx, &data)...)
	if response.Diagnostics.HasError() {
		return
	}

	conn := r.Meta().BedrockAgentClient(ctx)

	agentID := data.ID.ValueString()
	input := bedrockagent.DeleteAgentInput{
		AgentId:                aws.String(agentID),
		SkipResourceInUseCheck: fwflex.BoolValueFromFramework(ctx, data.SkipResourceInUseCheck),
	}

	_, err := conn.DeleteAgent(ctx, &input)

	if errs.IsA[*awstypes.ResourceNotFoundException](err) {
		return
	}

	if err != nil {
		response.Diagnostics.AddError(fmt.Sprintf("deleting Bedrock Agent (%s)", agentID), err.Error())
		return
	}

	if _, err := waitAgentDeleted(ctx, conn, agentID, r.DeleteTimeout(ctx, data.Timeouts)); err != nil {
		response.Diagnostics.AddError(fmt.Sprintf("waiting for Bedrock Agent (%s) delete", agentID), err.Error())
		return
	}
}

func (r *agentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root(names.AttrID), req, resp)
	// Set prepare_agent to default value on import
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("prepare_agent"), true)...)
}

func prepareAgent(ctx context.Context, conn *bedrockagent.Client, id string, timeout time.Duration) (*awstypes.Agent, error) {
	input := bedrockagent.PrepareAgentInput{
		AgentId: aws.String(id),
	}

	_, err := retryOpIfPreparing(ctx, timeout,
		func(ctx context.Context) (*bedrockagent.PrepareAgentOutput, error) {
			return conn.PrepareAgent(ctx, &input)
		},
	)

	if err != nil {
		return nil, fmt.Errorf("preparing Bedrock Agent (%s): %w", id, err)
	}

	agent, err := waitAgentPrepared(ctx, conn, id, timeout)

	if err != nil {
		return nil, fmt.Errorf("waiting for Bedrock Agent (%s) prepare: %w", id, err)
	}

	return agent, nil
}

func flexExpandForUpdate(ctx context.Context, value agentResourceModel, apiObject any) diag.Diagnostics {
	return fwflex.Expand(ctx, value, apiObject, fwflex.WithIgnoredFieldNames([]string{"GuardrailConfiguration", "PromptOverrideConfiguration"}))
}

func prepareSupervisorToReleaseCollaborator(ctx context.Context, conn *bedrockagent.Client, id string, timeout time.Duration) diag.Diagnostics {
	_, prepareErr := prepareAgent(ctx, conn, id, timeout)

	var diags diag.Diagnostics

	// This occurs when the last Collaborator from a SUPERVISOR Agent has been removed
	if errs.IsAErrorMessageContains[*awstypes.ValidationException](prepareErr, "The AgentCollaboration attribute is set to SUPERVISOR but no agent collaborators are added.") {
		getAgentInput := bedrockagent.GetAgentInput{
			AgentId: aws.String(id),
		}

		getAgentOutput, err := conn.GetAgent(ctx, &getAgentInput)
		if err != nil {
			diags.AddError("failed to read agent", err.Error())
			return diags
		}

		var state agentResourceModel
		diags.Append(fwflex.Flatten(ctx, getAgentOutput.Agent, &state)...)
		if diags.HasError() {
			return diags
		}

		var updateInput bedrockagent.UpdateAgentInput
		diags.Append(flexExpandForUpdate(ctx, state, &updateInput)...)
		if diags.HasError() {
			return diags
		}

		// Set Collaboration to DISABLED so the agent can be prepared
		updateInput.AgentCollaboration = awstypes.AgentCollaborationDisabled

		_, err = updateAgentWithRetry(ctx, conn, updateInput, timeout)

		if err != nil {
			diags.AddError("failed to update agent", err.Error())
			return diags
		}

		_, err = waitAgentUpdated(ctx, conn, id, timeout)

		if err != nil {
			diags.AddError("failed to wait for agent update", err.Error())
			return diags
		}

		// Preparing the agent releases the reference to the collaborators alias
		_, err = prepareAgent(ctx, conn, id, timeout)

		if err != nil {
			diags.AddError("failed to prepare agent", err.Error())
			return diags
		}

		// Set Collaboration back to SUPERVISOR
		updateInput.AgentCollaboration = awstypes.AgentCollaborationSupervisor
		_, err = updateAgentWithRetry(ctx, conn, updateInput, timeout)
		if err != nil {
			diags.AddError("failed to update agent", err.Error())
			return diags
		}

		_, err = waitAgentUpdated(ctx, conn, id, timeout)
		if err != nil {
			diags.AddError("failed to wait for agent update", err.Error())
			return diags
		}
	} else {
		if prepareErr != nil {
			diags.AddError("failed to prepare agent", prepareErr.Error())
		}
	}
	return diags
}

func updateAgentWithRetry(ctx context.Context, conn *bedrockagent.Client, input bedrockagent.UpdateAgentInput, timeout time.Duration) (*bedrockagent.UpdateAgentOutput, error) {
	return tfresource.RetryGWhen(ctx, timeout,
		func() (*bedrockagent.UpdateAgentOutput, error) {
			return conn.UpdateAgent(ctx, &input)
		},
		func(err error) (bool, error) {
			if errs.IsAErrorMessageContains[*awstypes.ConflictException](err, "Exceeded the number of retries on OptLock failure. Too many concurrent requests. Retry the request later.") {
				return true, err
			}
			if errs.IsAErrorMessageContains[*awstypes.ValidationException](err, "Update operation can't be performed on Agent when it is in Preparing state. Retry the request when the agent is in a valid state.") {
				return true, err
			}
			return false, err
		})
}

// retryOpIfPreparing retries the provided operation when an error message indicates
// the agent is in a Preparing state
//
// Use this to wrap operations which may run concurrently against the same agent.
func retryOpIfPreparing[T any](ctx context.Context, timeout time.Duration, f func(context.Context) (T, error)) (T, error) {
	return tfresource.RetryWhenIsAErrorMessageContains[T, *awstypes.ValidationException](ctx, timeout, f,
		"in Preparing state",
	)
}

func findAgentByID(ctx context.Context, conn *bedrockagent.Client, id string) (*awstypes.Agent, error) {
	input := bedrockagent.GetAgentInput{
		AgentId: aws.String(id),
	}

	output, err := conn.GetAgent(ctx, &input)

	if errs.IsA[*awstypes.ResourceNotFoundException](err) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	if output == nil || output.Agent == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	return output.Agent, nil
}

func statusAgent(ctx context.Context, conn *bedrockagent.Client, id string) retry.StateRefreshFunc {
	return func() (any, string, error) {
		output, err := findAgentByID(ctx, conn, id)

		if tfresource.NotFound(err) {
			return nil, "", nil
		}

		if err != nil {
			return nil, "", err
		}

		return output, string(output.AgentStatus), nil
	}
}

func waitAgentCreated(ctx context.Context, conn *bedrockagent.Client, id string, timeout time.Duration) (*awstypes.Agent, error) {
	stateConf := &retry.StateChangeConf{
		Pending: enum.Slice(awstypes.AgentStatusCreating),
		Target:  enum.Slice(awstypes.AgentStatusNotPrepared),
		Refresh: statusAgent(ctx, conn, id),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*awstypes.Agent); ok {
		tfresource.SetLastError(err, errors.Join(tfslices.ApplyToAll(output.FailureReasons, errors.New)...))

		return output, err
	}

	return nil, err
}

func waitAgentUpdated(ctx context.Context, conn *bedrockagent.Client, id string, timeout time.Duration) (*awstypes.Agent, error) {
	stateConf := &retry.StateChangeConf{
		Pending: enum.Slice(awstypes.AgentStatusUpdating),
		Target:  enum.Slice(awstypes.AgentStatusNotPrepared, awstypes.AgentStatusPrepared),
		Refresh: statusAgent(ctx, conn, id),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*awstypes.Agent); ok {
		tfresource.SetLastError(err, errors.Join(tfslices.ApplyToAll(output.FailureReasons, errors.New)...))

		return output, err
	}

	return nil, err
}

func waitAgentPrepared(ctx context.Context, conn *bedrockagent.Client, id string, timeout time.Duration) (*awstypes.Agent, error) {
	stateConf := &retry.StateChangeConf{
		Pending: enum.Slice(awstypes.AgentStatusNotPrepared, awstypes.AgentStatusPreparing),
		Target:  enum.Slice(awstypes.AgentStatusPrepared),
		Refresh: statusAgent(ctx, conn, id),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*awstypes.Agent); ok {
		tfresource.SetLastError(err, errors.Join(tfslices.ApplyToAll(output.FailureReasons, errors.New)...))

		return output, err
	}

	return nil, err
}

func waitAgentVersioned(ctx context.Context, conn *bedrockagent.Client, id string, timeout time.Duration) (*awstypes.Agent, error) {
	stateConf := &retry.StateChangeConf{
		Pending: enum.Slice(awstypes.AgentStatusVersioning),
		Target:  enum.Slice(awstypes.AgentStatusPrepared),
		Refresh: statusAgent(ctx, conn, id),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*awstypes.Agent); ok {
		tfresource.SetLastError(err, errors.Join(tfslices.ApplyToAll(output.FailureReasons, errors.New)...))

		return output, err
	}

	return nil, err
}

func waitAgentDeleted(ctx context.Context, conn *bedrockagent.Client, id string, timeout time.Duration) (*awstypes.Agent, error) {
	stateConf := &retry.StateChangeConf{
		Pending: enum.Slice(awstypes.AgentStatusDeleting, awstypes.AgentStatusCreating),
		Target:  []string{},
		Refresh: statusAgent(ctx, conn, id),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*awstypes.Agent); ok {
		tfresource.SetLastError(err, errors.Join(tfslices.ApplyToAll(output.FailureReasons, errors.New)...))

		return output, err
	}

	return nil, err
}

func removeDefaultPrompts(agent *awstypes.Agent) {
	pocm := agent.PromptOverrideConfiguration

	overrides := pocm.PromptConfigurations

	var filtered []awstypes.PromptConfiguration

	for _, override := range overrides {
		if override.PromptCreationMode == awstypes.CreationModeOverridden {
			filtered = append(filtered, override)
		}
	}

	pocm.PromptConfigurations = filtered
}

type agentResourceModel struct {
	framework.WithRegionModel
	AgentARN                    types.String                                                      `tfsdk:"agent_arn"`
	AgentID                     types.String                                                      `tfsdk:"agent_id"`
	AgentCollaboration          fwtypes.StringEnum[awstypes.AgentCollaboration]                   `tfsdk:"agent_collaboration"`
	AgentName                   types.String                                                      `tfsdk:"agent_name"`
	AgentResourceRoleARN        fwtypes.ARN                                                       `tfsdk:"agent_resource_role_arn"`
	AgentVersion                types.String                                                      `tfsdk:"agent_version"`
	CustomerEncryptionKeyARN    fwtypes.ARN                                                       `tfsdk:"customer_encryption_key_arn"`
	Description                 types.String                                                      `tfsdk:"description"`
	FoundationModel             types.String                                                      `tfsdk:"foundation_model"`
	GuardrailConfiguration      fwtypes.ListNestedObjectValueOf[guardrailConfigurationModel]      `tfsdk:"guardrail_configuration"`
	ID                          types.String                                                      `tfsdk:"id"`
	IdleSessionTTLInSeconds     types.Int64                                                       `tfsdk:"idle_session_ttl_in_seconds"`
	Instruction                 types.String                                                      `tfsdk:"instruction"`
	MemoryConfiguration         fwtypes.ListNestedObjectValueOf[memoryConfigurationModel]         `tfsdk:"memory_configuration"`
	PrepareAgent                types.Bool                                                        `tfsdk:"prepare_agent"`
	PreparedAt                  timetypes.RFC3339                                                 `tfsdk:"prepared_at"`
	PromptOverrideConfiguration fwtypes.ListNestedObjectValueOf[promptOverrideConfigurationModel] `tfsdk:"prompt_override_configuration"`
	SkipResourceInUseCheck      types.Bool                                                        `tfsdk:"skip_resource_in_use_check"`
	Tags                        tftags.Map                                                        `tfsdk:"tags"`
	TagsAll                     tftags.Map                                                        `tfsdk:"tags_all"`
	Timeouts                    timeouts.Value                                                    `tfsdk:"timeouts"`
}

func (m *agentResourceModel) InitFromID() error {
	m.AgentID = m.ID

	return nil
}

func (m *agentResourceModel) setID() {
	m.ID = m.AgentID
}

type guardrailConfigurationModel struct {
	GuardrailIdentifier types.String `tfsdk:"guardrail_identifier"`
	GuardrailVersion    types.String `tfsdk:"guardrail_version"`
}

type memoryConfigurationModel struct {
	EnabledMemoryTypes fwtypes.ListValueOf[fwtypes.StringEnum[awstypes.MemoryType]] `tfsdk:"enabled_memory_types"`
	StorageDays        types.Int32                                                  `tfsdk:"storage_days"`
}

type promptOverrideConfigurationModel struct {
	OverrideLambda       fwtypes.ARN                                              `tfsdk:"override_lambda"`
	PromptConfigurations fwtypes.SetNestedObjectValueOf[promptConfigurationModel] `tfsdk:"prompt_configurations"`
}

type promptConfigurationModel struct {
	BasePromptTemplate     types.String                                                 `tfsdk:"base_prompt_template"`
	InferenceConfiguration fwtypes.ListNestedObjectValueOf[inferenceConfigurationModel] `tfsdk:"inference_configuration"`
	ParserMode             fwtypes.StringEnum[parserMode]                               `tfsdk:"parser_mode"`
	PromptCreationMode     fwtypes.StringEnum[promptCreationMode]                       `tfsdk:"prompt_creation_mode"`
	PromptState            fwtypes.StringEnum[awstypes.PromptState]                     `tfsdk:"prompt_state"`
	PromptType             fwtypes.StringEnum[awstypes.PromptType]                      `tfsdk:"prompt_type"`
}

type inferenceConfigurationModel struct {
	MaximumLength types.Int64                       `tfsdk:"max_length"`
	StopSequences fwtypes.ListValueOf[types.String] `tfsdk:"stop_sequences"`
	Temperature   types.Float64                     `tfsdk:"temperature"`
	TopK          types.Int64                       `tfsdk:"top_k"`
	TopP          types.Float64                     `tfsdk:"top_p"`
}

type parserMode string

const (
	parserModeDefault    parserMode = "DEFAULT"
	parserModeOverridden parserMode = "OVERRIDDEN"
)

func (parserMode) Values() []parserMode {
	return []parserMode{
		parserModeDefault,
		parserModeOverridden,
	}
}

type promptCreationMode string

const (
	promptCreationModeDefault    promptCreationMode = "DEFAULT"
	promptCreationModeOverridden promptCreationMode = "OVERRIDDEN"
)

func (promptCreationMode) Values() []promptCreationMode {
	return []promptCreationMode{
		promptCreationModeDefault,
		promptCreationModeOverridden,
	}
}
