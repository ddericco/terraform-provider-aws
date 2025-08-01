// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cognitoidp

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"reflect"
	"strings"
	"time"

	"github.com/YakDriver/regexache"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	awstypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/enum"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/flex"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_cognito_user_pool", name="User Pool")
// @Tags(identifierAttribute="arn")
// @Testing(existsType="github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types;awstypes;awstypes.UserPoolType")
func resourceUserPool() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceUserPoolCreate,
		ReadWithoutTimeout:   resourceUserPoolRead,
		UpdateWithoutTimeout: resourceUserPoolUpdate,
		DeleteWithoutTimeout: resourceUserPoolDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"account_recovery_setting": {
				Type:             schema.TypeList,
				Optional:         true,
				MaxItems:         1,
				DiffSuppressFunc: verify.SuppressMissingOptionalConfigurationBlock,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"recovery_mechanism": {
							Type:     schema.TypeSet,
							Optional: true,
							Computed: true,
							MinItems: 1,
							MaxItems: 2,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									names.AttrName: {
										Type:             schema.TypeString,
										Required:         true,
										ValidateDiagFunc: enum.Validate[awstypes.RecoveryOptionNameType](),
									},
									names.AttrPriority: {
										Type:     schema.TypeInt,
										Required: true,
									},
								},
							},
						},
					},
				},
			},
			"admin_create_user_config": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"allow_admin_create_user_only": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"invite_message_template": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"email_message": {
										Type:         schema.TypeString,
										Optional:     true,
										ValidateFunc: validUserPoolInviteTemplateEmailMessage,
									},
									"email_subject": {
										Type:         schema.TypeString,
										Optional:     true,
										ValidateFunc: validUserPoolTemplateEmailSubject,
									},
									"sms_message": {
										Type:         schema.TypeString,
										Optional:     true,
										ValidateFunc: validUserPoolInviteTemplateSMSMessage,
									},
								},
							},
						},
					},
				},
			},
			"alias_attributes": {
				Type:     schema.TypeSet,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Schema{
					Type:             schema.TypeString,
					ValidateDiagFunc: enum.Validate[awstypes.AliasAttributeType](),
				},
				ConflictsWith: []string{"username_attributes"},
			},
			names.AttrARN: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"auto_verified_attributes": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type:             schema.TypeString,
					ValidateDiagFunc: enum.Validate[awstypes.VerifiedAttributeType](),
				},
			},
			names.AttrCreationDate: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"custom_domain": {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrDeletionProtection: {
				Type:             schema.TypeString,
				Optional:         true,
				Default:          awstypes.DeletionProtectionTypeInactive,
				ValidateDiagFunc: enum.Validate[awstypes.DeletionProtectionType](),
			},
			"device_configuration": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"challenge_required_on_new_device": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"device_only_remembered_on_user_prompt": {
							Type:     schema.TypeBool,
							Optional: true,
						},
					},
				},
			},
			names.AttrDomain: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"email_configuration": {
				Type:             schema.TypeList,
				Optional:         true,
				MaxItems:         1,
				DiffSuppressFunc: verify.SuppressMissingOptionalConfigurationBlock,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"configuration_set": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"email_sending_account": {
							Type:             schema.TypeString,
							Optional:         true,
							Default:          awstypes.EmailSendingAccountTypeCognitoDefault,
							ValidateDiagFunc: enum.Validate[awstypes.EmailSendingAccountType](),
						},
						"from_email_address": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"reply_to_email_address": {
							Type:     schema.TypeString,
							Optional: true,
							ValidateFunc: validation.Any(
								validation.StringInSlice([]string{""}, false),
								validation.StringMatch(regexache.MustCompile(`[\p{L}\p{M}\p{S}\p{N}\p{P}]+@[\p{L}\p{M}\p{S}\p{N}\p{P}]+`),
									`must satisfy regular expression pattern: [\p{L}\p{M}\p{S}\p{N}\p{P}]+@[\p{L}\p{M}\p{S}\p{N}\p{P}]+`),
							),
						},
						"source_arn": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
					},
				},
			},
			"email_mfa_configuration": {
				Type:             schema.TypeList,
				Optional:         true,
				MaxItems:         1,
				DiffSuppressFunc: verify.SuppressMissingOptionalConfigurationBlock,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						names.AttrMessage: {
							Type:     schema.TypeString,
							Optional: true,
							ValidateFunc: validation.All(
								validation.StringLenBetween(6, 20000),
								validation.StringMatch(regexache.MustCompile(`[\p{L}\p{M}\p{S}\p{N}\p{P}\s*]*\{####\}[\p{L}\p{M}\p{S}\p{N}\p{P}\s*]*`),
									`must satisfy regular expression pattern: [\p{L}\p{M}\p{S}\p{N}\p{P}\s*]*\{####\}[\p{L}\p{M}\p{S}\p{N}\p{P}\s*]*`),
							),
						},
						"subject": {
							Type:     schema.TypeString,
							Optional: true,
							ValidateFunc: validation.StringMatch(regexache.MustCompile(`[\p{L}\p{M}\p{S}\p{N}\p{P}\s]+`),
								`must satisfy regular expression pattern: [\p{L}\p{M}\p{S}\p{N}\p{P}\s]+`),
						},
					},
				},
			},
			"email_verification_message": {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				ValidateFunc:  validUserPoolEmailVerificationMessage,
				ConflictsWith: []string{"verification_message_template.0.email_message"},
			},
			"email_verification_subject": {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				ValidateFunc:  validUserPoolEmailVerificationSubject,
				ConflictsWith: []string{"verification_message_template.0.email_subject"},
			},
			names.AttrEndpoint: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"estimated_number_of_users": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"lambda_config": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"create_auth_challenge": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"custom_email_sender": {
							Type:         schema.TypeList,
							Optional:     true,
							MaxItems:     1,
							RequiredWith: []string{"lambda_config.0.kms_key_id"},
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"lambda_arn": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: verify.ValidARN,
									},
									"lambda_version": {
										Type:             schema.TypeString,
										Required:         true,
										ValidateDiagFunc: enum.Validate[awstypes.CustomEmailSenderLambdaVersionType](),
									},
								},
							},
						},
						"custom_message": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"custom_sms_sender": {
							Type:         schema.TypeList,
							Optional:     true,
							MaxItems:     1,
							RequiredWith: []string{"lambda_config.0.kms_key_id"},
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"lambda_arn": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: verify.ValidARN,
									},
									"lambda_version": {
										Type:             schema.TypeString,
										Required:         true,
										ValidateDiagFunc: enum.Validate[awstypes.CustomSMSSenderLambdaVersionType](),
									},
								},
							},
						},
						"define_auth_challenge": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						names.AttrKMSKeyID: {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"post_authentication": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"post_confirmation": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"pre_authentication": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"pre_sign_up": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"pre_token_generation": {
							Type:         schema.TypeString,
							Optional:     true,
							Computed:     true,
							ValidateFunc: verify.ValidARN,
						},
						"pre_token_generation_config": {
							Type:     schema.TypeList,
							Optional: true,
							Computed: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"lambda_arn": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: verify.ValidARN,
									},
									"lambda_version": {
										Type:             schema.TypeString,
										Required:         true,
										ValidateDiagFunc: enum.Validate[awstypes.PreTokenGenerationLambdaVersionType](),
									},
								},
							},
						},
						"user_migration": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"verify_auth_challenge_response": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
					},
				},
			},
			"last_modified_date": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"mfa_configuration": {
				Type:             schema.TypeString,
				Optional:         true,
				Default:          awstypes.UserPoolMfaTypeOff,
				ValidateDiagFunc: enum.Validate[awstypes.UserPoolMfaType](),
			},
			names.AttrName: {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.Any(
					validation.StringLenBetween(1, 128),
					validation.StringMatch(regexache.MustCompile(`[\w\s+=,.@-]+`),
						`must satisfy regular expression pattern: [\w\s+=,.@-]+`),
				),
			},
			"password_policy": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"minimum_length": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IntBetween(6, 99),
						},
						"password_history_size": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IntBetween(0, 24),
						},
						"require_lowercase": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"require_numbers": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"require_symbols": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"require_uppercase": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"temporary_password_validity_days": {
							Type:         schema.TypeInt,
							Optional:     true,
							Computed:     true,
							ValidateFunc: validation.IntBetween(0, 365),
						},
					},
				},
			},
			names.AttrSchema: {
				Type:     schema.TypeSet,
				Optional: true,
				MinItems: 1,
				MaxItems: 50,
				Set:      resourceUserPoolSchemaHash,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"attribute_data_type": {
							Type:             schema.TypeString,
							Required:         true,
							ValidateDiagFunc: enum.Validate[awstypes.AttributeDataType](),
						},
						"developer_only_attribute": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"mutable": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						names.AttrName: {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validUserPoolSchemaName,
						},
						"number_attribute_constraints": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"max_value": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"min_value": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
						"required": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"string_attribute_constraints": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"max_length": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"min_length": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
					},
				},
			},
			"sign_in_policy": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"allowed_first_auth_factors": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Schema{
								Type:             schema.TypeString,
								ValidateDiagFunc: enum.Validate[awstypes.AuthFactorType](),
							},
						},
					},
				},
			},
			"sms_authentication_message": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validUserPoolSMSAuthenticationMessage,
			},
			"sms_configuration": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						names.AttrExternalID: {
							Type:     schema.TypeString,
							Required: true,
						},
						"sns_caller_arn": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: verify.ValidARN,
						},
						"sns_region": {
							Type:         schema.TypeString,
							Optional:     true,
							Computed:     true,
							ValidateFunc: verify.ValidRegionName,
						},
					},
				},
			},
			"sms_verification_message": {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				ValidateFunc:  validUserPoolSMSVerificationMessage,
				ConflictsWith: []string{"verification_message_template.0.sms_message"},
			},
			"software_token_mfa_configuration": {
				Type:     schema.TypeList,
				Optional: true,
				MinItems: 1,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						names.AttrEnabled: {
							Type:     schema.TypeBool,
							Required: true,
						},
					},
				},
			},
			names.AttrTags:    tftags.TagsSchema(),
			names.AttrTagsAll: tftags.TagsSchemaComputed(),
			"user_attribute_update_settings": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"attributes_require_verification_before_update": {
							Type:     schema.TypeSet,
							Required: true,
							Elem: &schema.Schema{
								Type:             schema.TypeString,
								ValidateDiagFunc: enum.Validate[awstypes.VerifiedAttributeType](),
							},
						},
					},
				},
			},
			"user_pool_add_ons": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"advanced_security_additional_flows": {
							Type:             schema.TypeList,
							Optional:         true,
							MaxItems:         1,
							DiffSuppressFunc: verify.SuppressMissingOptionalConfigurationBlock,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"custom_auth_mode": {
										Type:             schema.TypeString,
										Optional:         true,
										Computed:         true,
										ValidateDiagFunc: enum.Validate[awstypes.AdvancedSecurityEnabledModeType](),
									},
								},
							},
						},
						"advanced_security_mode": {
							Type:             schema.TypeString,
							Required:         true,
							ValidateDiagFunc: enum.Validate[awstypes.AdvancedSecurityModeType](),
						},
					},
				},
			},
			"user_pool_tier": {
				Type:             schema.TypeString,
				Optional:         true,
				Computed:         true,
				ValidateDiagFunc: enum.Validate[awstypes.UserPoolTierType](),
			},
			"username_attributes": {
				Type:     schema.TypeSet,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Schema{
					Type:             schema.TypeString,
					ValidateDiagFunc: enum.Validate[awstypes.UsernameAttributeType](),
				},
				ConflictsWith: []string{"alias_attributes"},
			},
			"username_configuration": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"case_sensitive": {
							Type:     schema.TypeBool,
							Optional: true,
							Computed: true,
							ForceNew: true,
						},
					},
				},
			},
			"verification_message_template": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"default_email_option": {
							Type:             schema.TypeString,
							Optional:         true,
							Default:          awstypes.DefaultEmailOptionTypeConfirmWithCode,
							ValidateDiagFunc: enum.Validate[awstypes.DefaultEmailOptionType](),
						},
						"email_message": {
							Type:          schema.TypeString,
							Optional:      true,
							Computed:      true,
							ValidateFunc:  validUserPoolTemplateEmailMessage,
							ConflictsWith: []string{"email_verification_message"},
						},
						"email_message_by_link": {
							Type:         schema.TypeString,
							Optional:     true,
							Computed:     true,
							ValidateFunc: validUserPoolTemplateEmailMessageByLink,
						},
						"email_subject": {
							Type:          schema.TypeString,
							Optional:      true,
							Computed:      true,
							ValidateFunc:  validUserPoolTemplateEmailSubject,
							ConflictsWith: []string{"email_verification_subject"},
						},
						"email_subject_by_link": {
							Type:         schema.TypeString,
							Optional:     true,
							Computed:     true,
							ValidateFunc: validUserPoolTemplateEmailSubjectByLink,
						},
						"sms_message": {
							Type:          schema.TypeString,
							Optional:      true,
							Computed:      true,
							ValidateFunc:  validUserPoolTemplateSMSMessage,
							ConflictsWith: []string{"sms_verification_message"},
						},
					},
				},
			},
			"web_authn_configuration": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"relying_party_id": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"user_verification": {
							Type:             schema.TypeString,
							Optional:         true,
							ValidateDiagFunc: enum.Validate[awstypes.UserVerificationType](),
						},
					},
				},
			},
		},
	}
}

func resourceUserPoolCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPClient(ctx)

	name := d.Get(names.AttrName).(string)
	input := &cognitoidentityprovider.CreateUserPoolInput{
		PoolName:     aws.String(name),
		UserPoolTags: getTagsIn(ctx),
	}

	if v, ok := d.GetOk("account_recovery_setting"); ok {
		if config, ok := v.([]any)[0].(map[string]any); ok {
			input.AccountRecoverySetting = expandAccountRecoverySettingType(config)
		}
	}

	if v, ok := d.GetOk("admin_create_user_config"); ok {
		if v, ok := v.([]any)[0].(map[string]any); ok && v != nil {
			input.AdminCreateUserConfig = expandAdminCreateUserConfigType(v)
		}
	}

	if v, ok := d.GetOk("alias_attributes"); ok {
		input.AliasAttributes = flex.ExpandStringyValueSet[awstypes.AliasAttributeType](v.(*schema.Set))
	}

	if v, ok := d.GetOk("auto_verified_attributes"); ok {
		input.AutoVerifiedAttributes = flex.ExpandStringyValueSet[awstypes.VerifiedAttributeType](v.(*schema.Set))
	}

	if v, ok := d.GetOk(names.AttrDeletionProtection); ok {
		input.DeletionProtection = awstypes.DeletionProtectionType(v.(string))
	}

	if v, ok := d.GetOk("device_configuration"); ok {
		if v, ok := v.([]any)[0].(map[string]any); ok && v != nil {
			input.DeviceConfiguration = expandDeviceConfigurationType(v)
		}
	}

	if v, ok := d.GetOk("email_configuration"); ok && len(v.([]any)) > 0 {
		input.EmailConfiguration = expandEmailConfigurationType(v.([]any))
	}

	if v, ok := d.GetOk("email_verification_subject"); ok {
		input.EmailVerificationSubject = aws.String(v.(string))
	}

	if v, ok := d.GetOk("email_verification_message"); ok {
		input.EmailVerificationMessage = aws.String(v.(string))
	}

	if v, ok := d.GetOk("lambda_config"); ok {
		if v, ok := v.([]any)[0].(map[string]any); ok && v != nil {
			input.LambdaConfig = expandLambdaConfigType(v)
		}
	}

	if v, ok := d.GetOk("password_policy"); ok {
		if v, ok := v.([]any)[0].(map[string]any); ok && v != nil {
			passwordPolicy := expandPasswordPolicyType(v)
			if input.Policies == nil {
				input.Policies = &awstypes.UserPoolPolicyType{}
			}
			input.Policies.PasswordPolicy = passwordPolicy
		}
	}

	if v, ok := d.GetOk(names.AttrSchema); ok {
		input.Schema = expandSchemaAttributeTypes(v.(*schema.Set).List())
	}

	if v, ok := d.GetOk("sign_in_policy"); ok {
		if v, ok := v.([]any)[0].(map[string]any); ok && v != nil {
			signInPolicy := expandSignInPolicyType(v)
			if input.Policies == nil {
				input.Policies = &awstypes.UserPoolPolicyType{}
			}
			input.Policies.SignInPolicy = signInPolicy
		}
	}

	// For backwards compatibility, include this outside of MFA configuration
	// since its configuration is allowed by the API even without SMS MFA.
	if v, ok := d.GetOk("sms_authentication_message"); ok {
		input.SmsAuthenticationMessage = aws.String(v.(string))
	}

	// Include the SMS configuration outside of MFA configuration since it
	// can be used for user verification.
	if v, ok := d.GetOk("sms_configuration"); ok {
		input.SmsConfiguration = expandSMSConfigurationType(v.([]any))
	}

	if v, ok := d.GetOk("sms_verification_message"); ok {
		input.SmsVerificationMessage = aws.String(v.(string))
	}

	if v, ok := d.GetOk("username_attributes"); ok {
		input.UsernameAttributes = flex.ExpandStringyValueSet[awstypes.UsernameAttributeType](v.(*schema.Set))
	}

	if v, ok := d.GetOk("username_configuration"); ok {
		if v, ok := v.([]any)[0].(map[string]any); ok && v != nil {
			input.UsernameConfiguration = expandUsernameConfigurationType(v)
		}
	}

	if v, ok := d.GetOk("user_attribute_update_settings"); ok {
		if v, ok := v.([]any)[0].(map[string]any); ok && v != nil {
			input.UserAttributeUpdateSettings = expandUserAttributeUpdateSettingsType(v)
		}
	}

	if v, ok := d.GetOk("user_pool_add_ons"); ok && len(v.([]any)) > 0 {
		input.UserPoolAddOns = expandUserPoolAddOnsType(v.([]any)[0].(map[string]any))
	}

	if v, ok := d.GetOk("verification_message_template"); ok {
		if v, ok := v.([]any)[0].(map[string]any); ok && v != nil {
			input.VerificationMessageTemplate = expandVerificationMessageTemplateType(v)
		}
	}

	if v := awstypes.UserPoolTierType(d.Get("user_pool_tier").(string)); v != awstypes.UserPoolTierTypeEssentials {
		input.UserPoolTier = v
	}

	outputRaw, err := tfresource.RetryWhen(ctx, propagationTimeout, func() (any, error) {
		return conn.CreateUserPool(ctx, input)
	}, userPoolErrorRetryable)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating Cognito User Pool (%s): %s", name, err)
	}

	d.SetId(aws.ToString(outputRaw.(*cognitoidentityprovider.CreateUserPoolOutput).UserPool.Id))

	if mfaConfig := awstypes.UserPoolMfaType(d.Get("mfa_configuration").(string)); mfaConfig != awstypes.UserPoolMfaTypeOff || len(d.Get("web_authn_configuration").([]any)) > 0 {
		input := &cognitoidentityprovider.SetUserPoolMfaConfigInput{
			UserPoolId: aws.String(d.Id()),
		}

		if mfaConfig != awstypes.UserPoolMfaTypeOff {
			input.MfaConfiguration = mfaConfig
			input.SoftwareTokenMfaConfiguration = expandSoftwareTokenMFAConfigType(d.Get("software_token_mfa_configuration").([]any))
		}

		if v := d.Get("email_mfa_configuration").([]any); len(v) > 0 && v[0] != nil {
			input.EmailMfaConfiguration = expandEmailMFAConfigType(v)
		}

		if v := d.Get("sms_configuration").([]any); len(v) > 0 && v[0] != nil {
			input.SmsMfaConfiguration = &awstypes.SmsMfaConfigType{
				SmsConfiguration: expandSMSConfigurationType(v),
			}

			if v, ok := d.GetOk("sms_authentication_message"); ok {
				input.SmsMfaConfiguration.SmsAuthenticationMessage = aws.String(v.(string))
			}
		}

		if webAuthnConfig := d.Get("web_authn_configuration").([]any); len(webAuthnConfig) > 0 {
			input.WebAuthnConfiguration = expandWebAuthnConfigurationConfigType(webAuthnConfig)
		}

		_, err := tfresource.RetryWhen(ctx, propagationTimeout, func() (any, error) {
			return conn.SetUserPoolMfaConfig(ctx, input)
		}, userPoolErrorRetryable)

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "setting Cognito User Pool (%s) MFA configuration: %s", d.Id(), err)
		}
	}

	return append(diags, resourceUserPoolRead(ctx, d, meta)...)
}

func resourceUserPoolRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPClient(ctx)

	userPool, err := findUserPoolByID(ctx, conn, d.Id())

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] Cognito User Pool %s not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Cognito User Pool (%s): %s", d.Id(), err)
	}

	if err := d.Set("account_recovery_setting", flattenAccountRecoverySettingType(userPool.AccountRecoverySetting)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting account_recovery_setting: %s", err)
	}
	if err := d.Set("admin_create_user_config", flattenAdminCreateUserConfigType(userPool.AdminCreateUserConfig)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting admin_create_user_config: %s", err)
	}
	if userPool.AliasAttributes != nil { // nosemgrep:ci.helper-schema-ResourceData-Set-extraneous-nil-check
		d.Set("alias_attributes", userPool.AliasAttributes)
	}
	d.Set(names.AttrARN, userPool.Arn)
	d.Set("auto_verified_attributes", userPool.AutoVerifiedAttributes)
	d.Set(names.AttrCreationDate, userPool.CreationDate.Format(time.RFC3339))
	d.Set("custom_domain", userPool.CustomDomain)
	d.Set(names.AttrDeletionProtection, userPool.DeletionProtection)
	if err := d.Set("device_configuration", flattenDeviceConfigurationType(userPool.DeviceConfiguration)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting device_configuration: %s", err)
	}
	d.Set(names.AttrDomain, userPool.Domain)
	if err := d.Set("email_configuration", flattenEmailConfigurationType(userPool.EmailConfiguration)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting email_configuration: %s", err)
	}
	d.Set("email_verification_subject", userPool.EmailVerificationSubject)
	d.Set("email_verification_message", userPool.EmailVerificationMessage)
	d.Set(names.AttrEndpoint, fmt.Sprintf("%s/%s", meta.(*conns.AWSClient).RegionalHostname(ctx, "cognito-idp"), d.Id()))
	d.Set("estimated_number_of_users", userPool.EstimatedNumberOfUsers)
	if err := d.Set("lambda_config", flattenLambdaConfigType(userPool.LambdaConfig)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting lambda_config: %s", err)
	}
	d.Set("last_modified_date", userPool.LastModifiedDate.Format(time.RFC3339))
	d.Set(names.AttrName, userPool.Name)
	if err := d.Set("password_policy", flattenPasswordPolicyType(userPool.Policies.PasswordPolicy)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting password_policy: %s", err)
	}
	var configuredSchema []any
	if v, ok := d.GetOk(names.AttrSchema); ok {
		configuredSchema = v.(*schema.Set).List()
	}
	if err := d.Set("sign_in_policy", flattenSignInPolicyType(userPool.Policies.SignInPolicy)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting sign_in_policy: %s", err)
	}
	if err := d.Set(names.AttrSchema, flattenSchemaAttributeTypes(expandSchemaAttributeTypes(configuredSchema), userPool.SchemaAttributes)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting schema: %s", err)
	}
	d.Set("sms_authentication_message", userPool.SmsAuthenticationMessage)
	if err := d.Set("sms_configuration", flattenSMSConfigurationType(userPool.SmsConfiguration)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting sms_configuration: %s", err)
	}
	d.Set("sms_verification_message", userPool.SmsVerificationMessage)
	if err := d.Set("user_attribute_update_settings", flattenUserAttributeUpdateSettingsType(userPool.UserAttributeUpdateSettings)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting user_attribute_update_settings: %s", err)
	}
	if err := d.Set("user_pool_add_ons", flattenUserPoolAddOnsType(userPool.UserPoolAddOns)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting user_pool_add_ons: %s", err)
	}
	d.Set("user_pool_tier", userPool.UserPoolTier)
	d.Set("username_attributes", userPool.UsernameAttributes)
	if err := d.Set("username_configuration", flattenUsernameConfigurationType(userPool.UsernameConfiguration)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting username_configuration: %s", err)
	}
	if err := d.Set("verification_message_template", flattenVerificationMessageTemplateType(userPool.VerificationMessageTemplate)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting verification_message_template: %s", err)
	}

	setTagsOut(ctx, userPool.UserPoolTags)

	output, err := findUserPoolMFAConfigByID(ctx, conn, d.Id())

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Cognito User Pool (%s) MFA configuration: %s", d.Id(), err)
	}

	if err := d.Set("email_mfa_configuration", flattenEmailMFAConfigType(output.EmailMfaConfiguration)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting email_mfa_configuration: %s", err)
	}
	d.Set("mfa_configuration", output.MfaConfiguration)
	if err := d.Set("software_token_mfa_configuration", flattenSoftwareTokenMFAConfigType(output.SoftwareTokenMfaConfiguration)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting software_token_mfa_configuration: %s", err)
	}
	if err := d.Set("web_authn_configuration", flattenWebAuthnConfigType(output.WebAuthnConfiguration)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting web_authn_configuration: %s", err)
	}

	return diags
}

func resourceUserPoolUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPClient(ctx)

	// MFA updates.
	if d.HasChanges(
		"email_mfa_configuration",
		"mfa_configuration",
		"sms_authentication_message",
		"sms_configuration",
		"software_token_mfa_configuration",
		"web_authn_configuration",
	) {
		mfaConfiguration := awstypes.UserPoolMfaType(d.Get("mfa_configuration").(string))
		input := &cognitoidentityprovider.SetUserPoolMfaConfigInput{
			MfaConfiguration:              mfaConfiguration,
			EmailMfaConfiguration:         expandEmailMFAConfigType(d.Get("email_mfa_configuration").([]any)),
			SoftwareTokenMfaConfiguration: expandSoftwareTokenMFAConfigType(d.Get("software_token_mfa_configuration").([]any)),
			UserPoolId:                    aws.String(d.Id()),
			WebAuthnConfiguration:         expandWebAuthnConfigurationConfigType(d.Get("web_authn_configuration").([]any)),
		}

		// Since SMS configuration applies to both verification and MFA, only include if MFA is enabled.
		// Otherwise, the API will return the following error:
		// InvalidParameterException: Invalid MFA configuration given, can't turn off MFA and configure an MFA together.
		if v := d.Get("sms_configuration").([]any); len(v) > 0 && v[0] != nil && mfaConfiguration != awstypes.UserPoolMfaTypeOff {
			input.SmsMfaConfiguration = &awstypes.SmsMfaConfigType{
				SmsConfiguration: expandSMSConfigurationType(v),
			}

			if v, ok := d.GetOk("sms_authentication_message"); ok {
				input.SmsMfaConfiguration.SmsAuthenticationMessage = aws.String(v.(string))
			}
		}

		_, err := tfresource.RetryWhen(ctx, propagationTimeout, func() (any, error) {
			return conn.SetUserPoolMfaConfig(ctx, input)
		}, userPoolErrorRetryable)

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "setting Cognito User Pool (%s) MFA configuration: %s", d.Id(), err)
		}
	}

	// Non MFA updates
	// NOTES:
	//  * Include SMS configuration changes since settings are shared between verification and MFA.
	//  * For backwards compatibility, include SMS authentication message changes without SMS MFA since the API allows it.
	if d.HasChanges(
		"account_recovery_setting",
		"admin_create_user_config",
		"auto_verified_attributes",
		names.AttrDeletionProtection,
		"device_configuration",
		"email_configuration",
		"email_verification_message",
		"email_verification_subject",
		"lambda_config",
		names.AttrName,
		"password_policy",
		"sign_in_policy",
		"sms_authentication_message",
		"sms_configuration",
		"sms_verification_message",
		// names.AttrTagsAll,
		"user_attribute_update_settings",
		"user_pool_add_ons",
		"user_pool_tier",
		"verification_message_template",
	) {
		// TODO: `UpdateUserPoolInput` has a field `UserPoolTags` that can be used to set tags directly.
		// However, setting tags directly on the update requires correctly managing Ignored and Default tags.
		// For now, use `UpdateTags`. Once this is fixed, `UpdateTags` will no longer be needed by this package.
		input := &cognitoidentityprovider.UpdateUserPoolInput{
			UserPoolId: aws.String(d.Id()),
			// UserPoolTags: getTagsIn(ctx),
		}

		if v, ok := d.GetOk("account_recovery_setting"); ok {
			if v, ok := v.([]any)[0].(map[string]any); ok {
				input.AccountRecoverySetting = expandAccountRecoverySettingType(v)
			}
		}

		if v, ok := d.GetOk("admin_create_user_config"); ok {
			if v, ok := v.([]any)[0].(map[string]any); ok && v != nil {
				input.AdminCreateUserConfig = expandAdminCreateUserConfigType(v)
			}
		}

		if v, ok := d.GetOk("auto_verified_attributes"); ok {
			input.AutoVerifiedAttributes = flex.ExpandStringyValueSet[awstypes.VerifiedAttributeType](v.(*schema.Set))
		}

		if v, ok := d.GetOk(names.AttrDeletionProtection); ok {
			input.DeletionProtection = awstypes.DeletionProtectionType(v.(string))
		}

		if v, ok := d.GetOk("device_configuration"); ok {
			if v, ok := v.([]any)[0].(map[string]any); ok && v != nil {
				input.DeviceConfiguration = expandDeviceConfigurationType(v)
			}
		}

		if v, ok := d.GetOk("email_configuration"); ok && len(v.([]any)) > 0 {
			input.EmailConfiguration = expandEmailConfigurationType(v.([]any))
		}

		if v, ok := d.GetOk("email_verification_subject"); ok {
			input.EmailVerificationSubject = aws.String(v.(string))
		}

		if v, ok := d.GetOk("email_verification_message"); ok {
			input.EmailVerificationMessage = aws.String(v.(string))
		}

		if v, ok := d.GetOk("lambda_config"); ok {
			if v, ok := v.([]any)[0].(map[string]any); ok && v != nil {
				if d.HasChange("lambda_config.0.pre_token_generation") {
					preTokenGeneration := d.Get("lambda_config.0.pre_token_generation")
					if tfList, ok := v["pre_token_generation_config"].([]any); ok && len(tfList) > 0 && tfList[0] != nil {
						v["pre_token_generation_config"].([]any)[0].(map[string]any)["lambda_arn"] = preTokenGeneration
					} else {
						v["pre_token_generation_config"] = []any{map[string]any{
							"lambda_arn":     preTokenGeneration,
							"lambda_version": string(awstypes.PreTokenGenerationLambdaVersionTypeV10), // A guess...
						}}
					}
				}

				if d.HasChange("lambda_config.0.pre_token_generation_config.0.lambda_arn") {
					v["pre_token_generation"] = d.Get("lambda_config.0.pre_token_generation_config.0.lambda_arn")
				}

				input.LambdaConfig = expandLambdaConfigType(v)
			}
		}

		if v, ok := d.GetOk("mfa_configuration"); ok {
			input.MfaConfiguration = awstypes.UserPoolMfaType(v.(string))
		}

		if v, ok := d.GetOk(names.AttrName); ok {
			input.PoolName = aws.String(v.(string))
		}

		if v, ok := d.GetOk("password_policy"); ok {
			if v, ok := v.([]any)[0].(map[string]any); ok && v != nil {
				passwordPolicy := expandPasswordPolicyType(v)
				if input.Policies == nil {
					input.Policies = &awstypes.UserPoolPolicyType{}
				}
				input.Policies.PasswordPolicy = passwordPolicy
			}
		}

		if v, ok := d.GetOk("sign_in_policy"); ok {
			if v, ok := v.([]any)[0].(map[string]any); ok && v != nil {
				signInPolicy := expandSignInPolicyType(v)
				if input.Policies == nil {
					input.Policies = &awstypes.UserPoolPolicyType{}
				}
				input.Policies.SignInPolicy = signInPolicy
			}
		}

		if v, ok := d.GetOk("sms_authentication_message"); ok {
			input.SmsAuthenticationMessage = aws.String(v.(string))
		}

		if v, ok := d.GetOk("sms_configuration"); ok {
			input.SmsConfiguration = expandSMSConfigurationType(v.([]any))
		}

		if v, ok := d.GetOk("sms_verification_message"); ok {
			input.SmsVerificationMessage = aws.String(v.(string))
		}

		if v, ok := d.GetOk("user_attribute_update_settings"); ok {
			if v, ok := v.([]any)[0].(map[string]any); ok && v != nil {
				input.UserAttributeUpdateSettings = expandUserAttributeUpdateSettingsType(v)
			}
		}
		if d.HasChange("user_attribute_update_settings") && input.UserAttributeUpdateSettings == nil {
			// An empty array must be sent to disable this setting if previously enabled. A nil
			// UserAttibutesUpdateSetting param will result in no modifications.
			input.UserAttributeUpdateSettings = &awstypes.UserAttributeUpdateSettingsType{
				AttributesRequireVerificationBeforeUpdate: []awstypes.VerifiedAttributeType{},
			}
		}

		if v, ok := d.GetOk("user_pool_add_ons"); ok && len(v.([]any)) > 0 && v.([]any)[0] != nil {
			input.UserPoolAddOns = expandUserPoolAddOnsType(v.([]any)[0].(map[string]any))
		}

		if v, ok := d.GetOk("verification_message_template"); ok {
			if v, ok := v.([]any)[0].(map[string]any); ok && v != nil {
				if d.HasChange("email_verification_message") {
					v["email_message"] = d.Get("email_verification_message")
				}
				if d.HasChange("email_verification_subject") {
					v["email_subject"] = d.Get("email_verification_subject")
				}
				if d.HasChange("sms_verification_message") {
					v["sms_message"] = d.Get("sms_verification_message")
				}

				input.VerificationMessageTemplate = expandVerificationMessageTemplateType(v)
			}
		}

		if v, ok := d.GetOk("user_pool_tier"); ok {
			input.UserPoolTier = awstypes.UserPoolTierType(v.(string))
		}

		_, err := tfresource.RetryWhen(ctx, propagationTimeout,
			func() (any, error) {
				return conn.UpdateUserPool(ctx, input)
			},
			func(err error) (bool, error) {
				if ok, err := userPoolErrorRetryable(err); ok {
					return true, err
				}

				switch {
				case errs.IsAErrorMessageContains[*awstypes.InvalidParameterException](err, "Please use TemporaryPasswordValidityDays in PasswordPolicy instead of UnusedAccountValidityDays") && input.AdminCreateUserConfig.UnusedAccountValidityDays != 0:
					input.AdminCreateUserConfig.UnusedAccountValidityDays = 0
					return true, err

				default:
					return false, err
				}
			})

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "updating Cognito User Pool (%s): %s", d.Id(), err)
		}
	}

	if d.HasChange(names.AttrSchema) {
		o, n := d.GetChange(names.AttrSchema)
		os, ns := o.(*schema.Set), n.(*schema.Set)

		if os.Difference(ns).Len() == 0 {
			input := &cognitoidentityprovider.AddCustomAttributesInput{
				CustomAttributes: expandSchemaAttributeTypes(ns.Difference(os).List()),
				UserPoolId:       aws.String(d.Id()),
			}

			_, err := conn.AddCustomAttributes(ctx, input)

			if err != nil {
				return sdkdiag.AppendErrorf(diags, "adding Cognito User Pool (%s) custom attributes: %s", d.Id(), err)
			}
		} else {
			return sdkdiag.AppendErrorf(diags, "updating Cognito User Pool (%s): cannot modify or remove schema items", d.Id())
		}
	}

	return append(diags, resourceUserPoolRead(ctx, d, meta)...)
}

func resourceUserPoolDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPClient(ctx)

	log.Printf("[DEBUG] Deleting Cognito User Pool: %s", d.Id())
	input := cognitoidentityprovider.DeleteUserPoolInput{
		UserPoolId: aws.String(d.Id()),
	}
	_, err := conn.DeleteUserPool(ctx, &input)

	if errs.IsA[*awstypes.ResourceNotFoundException](err) {
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting Cognito user pool (%s): %s", d.Id(), err)
	}

	return diags
}

// IAM roles & policies can take some time to propagate and be attached to the User Pool.
func userPoolErrorRetryable(err error) (bool, error) {
	switch {
	case errs.IsAErrorMessageContains[*awstypes.InvalidSmsRoleTrustRelationshipException](err, "Role does not have a trust relationship allowing Cognito to assume the role"),
		errs.IsAErrorMessageContains[*awstypes.InvalidSmsRoleAccessPolicyException](err, "Role does not have permission to publish with SNS"):
		return true, err

	default:
		return false, err
	}
}

func findUserPoolByID(ctx context.Context, conn *cognitoidentityprovider.Client, id string) (*awstypes.UserPoolType, error) {
	input := &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: aws.String(id),
	}

	output, err := conn.DescribeUserPool(ctx, input)

	if errs.IsA[*awstypes.ResourceNotFoundException](err) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	if output == nil || output.UserPool == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	return output.UserPool, nil
}

func findUserPoolMFAConfigByID(ctx context.Context, conn *cognitoidentityprovider.Client, id string) (*cognitoidentityprovider.GetUserPoolMfaConfigOutput, error) {
	input := &cognitoidentityprovider.GetUserPoolMfaConfigInput{
		UserPoolId: aws.String(id),
	}

	output, err := conn.GetUserPoolMfaConfig(ctx, input)

	if errs.IsA[*awstypes.ResourceNotFoundException](err) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	if output == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	return output, nil
}

func expandEmailMFAConfigType(tfList []any) *awstypes.EmailMfaConfigType {
	if len(tfList) == 0 || tfList[0] == nil {
		return nil
	}

	tfMap := tfList[0].(map[string]any)
	apiObject := &awstypes.EmailMfaConfigType{}

	if v, ok := tfMap[names.AttrMessage].(string); ok && v != "" {
		apiObject.Message = aws.String(v)
	}

	if v, ok := tfMap["subject"].(string); ok && v != "" {
		apiObject.Subject = aws.String(v)
	}

	return apiObject
}

func expandSMSConfigurationType(tfList []any) *awstypes.SmsConfigurationType {
	if len(tfList) == 0 || tfList[0] == nil {
		return nil
	}

	tfMap := tfList[0].(map[string]any)
	apiObject := &awstypes.SmsConfigurationType{}

	if v, ok := tfMap[names.AttrExternalID].(string); ok && v != "" {
		apiObject.ExternalId = aws.String(v)
	}

	if v, ok := tfMap["sns_caller_arn"].(string); ok && v != "" {
		apiObject.SnsCallerArn = aws.String(v)
	}

	if v, ok := tfMap["sns_region"].(string); ok && v != "" {
		apiObject.SnsRegion = aws.String(v)
	}

	return apiObject
}

func expandSoftwareTokenMFAConfigType(tfList []any) *awstypes.SoftwareTokenMfaConfigType {
	if len(tfList) == 0 || tfList[0] == nil {
		return nil
	}

	tfMap := tfList[0].(map[string]any)
	apiObject := &awstypes.SoftwareTokenMfaConfigType{}

	if v, ok := tfMap[names.AttrEnabled].(bool); ok {
		apiObject.Enabled = v
	}

	return apiObject
}

func expandWebAuthnConfigurationConfigType(tfList []any) *awstypes.WebAuthnConfigurationType {
	if len(tfList) == 0 || tfList[0] == nil {
		return nil
	}

	tfMap := tfList[0].(map[string]any)

	apiObject := &awstypes.WebAuthnConfigurationType{}

	if v, ok := tfMap["relying_party_id"].(string); ok && v != "" {
		apiObject.RelyingPartyId = aws.String(v)
	}

	if v, ok := tfMap["user_verification"].(string); ok && v != "" {
		apiObject.UserVerification = awstypes.UserVerificationType(v)
	}

	return apiObject
}

func flattenSMSConfigurationType(apiObject *awstypes.SmsConfigurationType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]any{}

	if v := apiObject.ExternalId; v != nil {
		tfMap[names.AttrExternalID] = aws.ToString(v)
	}

	if v := apiObject.SnsCallerArn; v != nil {
		tfMap["sns_caller_arn"] = aws.ToString(v)
	}

	if v := apiObject.SnsRegion; v != nil {
		tfMap["sns_region"] = aws.ToString(v)
	}

	return []any{tfMap}
}

func flattenEmailMFAConfigType(apiObject *awstypes.EmailMfaConfigType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]any{}

	if v := apiObject.Message; v != nil {
		tfMap[names.AttrMessage] = aws.ToString(v)
	}

	if v := apiObject.Subject; v != nil {
		tfMap["subject"] = aws.ToString(v)
	}

	return []any{tfMap}
}

func flattenSoftwareTokenMFAConfigType(apiObject *awstypes.SoftwareTokenMfaConfigType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]any{
		names.AttrEnabled: apiObject.Enabled,
	}

	return []any{tfMap}
}

func flattenWebAuthnConfigType(apiObject *awstypes.WebAuthnConfigurationType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]any{
		"user_verification": apiObject.UserVerification,
	}

	if v := apiObject.RelyingPartyId; v != nil {
		tfMap["relying_party_id"] = aws.ToString(v)
	}

	return []any{tfMap}
}

func expandAccountRecoverySettingType(tfMap map[string]any) *awstypes.AccountRecoverySettingType {
	if len(tfMap) == 0 {
		return nil
	}

	apiObjects := make([]awstypes.RecoveryOptionType, 0)

	if v, ok := tfMap["recovery_mechanism"]; ok {
		for _, tfMapRaw := range v.(*schema.Set).List() {
			tfMap := tfMapRaw.(map[string]any)
			apiObject := awstypes.RecoveryOptionType{}

			if v, ok := tfMap[names.AttrName]; ok {
				apiObject.Name = awstypes.RecoveryOptionNameType(v.(string))
			}

			if v, ok := tfMap[names.AttrPriority]; ok {
				apiObject.Priority = aws.Int32(int32(v.(int)))
			}

			apiObjects = append(apiObjects, apiObject)
		}
	}

	apiObject := &awstypes.AccountRecoverySettingType{
		RecoveryMechanisms: apiObjects,
	}

	return apiObject
}

func flattenAccountRecoverySettingType(apiObject *awstypes.AccountRecoverySettingType) []any {
	if apiObject == nil || len(apiObject.RecoveryMechanisms) == 0 {
		return nil
	}

	tfList := make([]map[string]any, 0)

	for _, apiObject := range apiObject.RecoveryMechanisms {
		tfMap := map[string]any{
			names.AttrName:     apiObject.Name,
			names.AttrPriority: aws.ToInt32(apiObject.Priority),
		}

		tfList = append(tfList, tfMap)
	}

	tfMap := map[string]any{
		"recovery_mechanism": tfList,
	}

	return []any{tfMap}
}

func flattenEmailConfigurationType(apiObject *awstypes.EmailConfigurationType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := make(map[string]any)

	if apiObject.ConfigurationSet != nil {
		tfMap["configuration_set"] = aws.ToString(apiObject.ConfigurationSet)
	}

	tfMap["email_sending_account"] = apiObject.EmailSendingAccount

	if apiObject.From != nil {
		tfMap["from_email_address"] = aws.ToString(apiObject.From)
	}

	if apiObject.ReplyToEmailAddress != nil {
		tfMap["reply_to_email_address"] = aws.ToString(apiObject.ReplyToEmailAddress)
	}

	if apiObject.SourceArn != nil {
		tfMap["source_arn"] = aws.ToString(apiObject.SourceArn)
	}

	if len(tfMap) > 0 {
		return []any{tfMap}
	}

	return []any{}
}

func expandAdminCreateUserConfigType(tfMap map[string]any) *awstypes.AdminCreateUserConfigType {
	apiObject := &awstypes.AdminCreateUserConfigType{}

	if v, ok := tfMap["allow_admin_create_user_only"]; ok {
		apiObject.AllowAdminCreateUserOnly = v.(bool)
	}

	if v, ok := tfMap["invite_message_template"]; ok {
		if tfList := v.([]any); len(tfList) > 0 {
			if tfMap, ok := tfList[0].(map[string]any); ok {
				imt := &awstypes.MessageTemplateType{}

				if v, ok := tfMap["email_message"]; ok {
					imt.EmailMessage = aws.String(v.(string))
				}

				if v, ok := tfMap["email_subject"]; ok {
					imt.EmailSubject = aws.String(v.(string))
				}

				if v, ok := tfMap["sms_message"]; ok {
					imt.SMSMessage = aws.String(v.(string))
				}

				apiObject.InviteMessageTemplate = imt
			}
		}
	}

	return apiObject
}

func flattenAdminCreateUserConfigType(apiObject *awstypes.AdminCreateUserConfigType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]any{
		"allow_admin_create_user_only": apiObject.AllowAdminCreateUserOnly,
	}

	if apiObject := apiObject.InviteMessageTemplate; apiObject != nil {
		imt := map[string]any{}

		if apiObject.EmailMessage != nil {
			imt["email_message"] = aws.ToString(apiObject.EmailMessage)
		}

		if apiObject.EmailSubject != nil {
			imt["email_subject"] = aws.ToString(apiObject.EmailSubject)
		}

		if apiObject.SMSMessage != nil {
			imt["sms_message"] = aws.ToString(apiObject.SMSMessage)
		}

		if len(imt) > 0 {
			tfMap["invite_message_template"] = []map[string]any{imt}
		}
	}

	return []any{tfMap}
}

func expandDeviceConfigurationType(tfMap map[string]any) *awstypes.DeviceConfigurationType {
	apiObject := &awstypes.DeviceConfigurationType{}

	if v, ok := tfMap["challenge_required_on_new_device"]; ok {
		apiObject.ChallengeRequiredOnNewDevice = v.(bool)
	}

	if v, ok := tfMap["device_only_remembered_on_user_prompt"]; ok {
		apiObject.DeviceOnlyRememberedOnUserPrompt = v.(bool)
	}

	return apiObject
}

func expandLambdaConfigType(tfMap map[string]any) *awstypes.LambdaConfigType {
	apiObject := &awstypes.LambdaConfigType{}

	if v, ok := tfMap["create_auth_challenge"]; ok && v.(string) != "" {
		apiObject.CreateAuthChallenge = aws.String(v.(string))
	}

	if v, ok := tfMap["custom_email_sender"].([]any); ok && len(v) > 0 {
		if v, ok := v[0].(map[string]any); ok && v != nil {
			apiObject.CustomEmailSender = expandCustomEmailLambdaVersionConfigType(v)
		}
	}

	if v, ok := tfMap["custom_message"]; ok && v.(string) != "" {
		apiObject.CustomMessage = aws.String(v.(string))
	}

	if v, ok := tfMap["custom_sms_sender"].([]any); ok && len(v) > 0 {
		if v, ok := v[0].(map[string]any); ok && v != nil {
			apiObject.CustomSMSSender = expandCustomSMSLambdaVersionConfigType(v)
		}
	}

	if v, ok := tfMap["define_auth_challenge"]; ok && v.(string) != "" {
		apiObject.DefineAuthChallenge = aws.String(v.(string))
	}

	if v, ok := tfMap[names.AttrKMSKeyID]; ok && v.(string) != "" {
		apiObject.KMSKeyID = aws.String(v.(string))
	}

	if v, ok := tfMap["post_authentication"]; ok && v.(string) != "" {
		apiObject.PostAuthentication = aws.String(v.(string))
	}

	if v, ok := tfMap["post_confirmation"]; ok && v.(string) != "" {
		apiObject.PostConfirmation = aws.String(v.(string))
	}

	if v, ok := tfMap["pre_authentication"]; ok && v.(string) != "" {
		apiObject.PreAuthentication = aws.String(v.(string))
	}

	if v, ok := tfMap["pre_sign_up"]; ok && v.(string) != "" {
		apiObject.PreSignUp = aws.String(v.(string))
	}

	if v, ok := tfMap["pre_token_generation"]; ok && v.(string) != "" {
		apiObject.PreTokenGeneration = aws.String(v.(string))
	}

	if v, ok := tfMap["pre_token_generation_config"].([]any); ok && len(v) > 0 {
		if v, ok := v[0].(map[string]any); ok && v != nil {
			apiObject.PreTokenGenerationConfig = expandPreTokenGenerationVersionConfigType(v)
		}
	}

	if v, ok := tfMap["user_migration"]; ok && v.(string) != "" {
		apiObject.UserMigration = aws.String(v.(string))
	}

	if v, ok := tfMap["verify_auth_challenge_response"]; ok && v.(string) != "" {
		apiObject.VerifyAuthChallengeResponse = aws.String(v.(string))
	}

	return apiObject
}

func flattenLambdaConfigType(apiObject *awstypes.LambdaConfigType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]any{}

	if apiObject.CreateAuthChallenge != nil {
		tfMap["create_auth_challenge"] = aws.ToString(apiObject.CreateAuthChallenge)
	}

	if apiObject.CustomEmailSender != nil {
		tfMap["custom_email_sender"] = flattenCustomEmailLambdaVersionConfigType(apiObject.CustomEmailSender)
	}

	if apiObject.CustomMessage != nil {
		tfMap["custom_message"] = aws.ToString(apiObject.CustomMessage)
	}

	if apiObject.CustomSMSSender != nil {
		tfMap["custom_sms_sender"] = flattenCustomSMSLambdaVersionConfigType(apiObject.CustomSMSSender)
	}

	if apiObject.DefineAuthChallenge != nil {
		tfMap["define_auth_challenge"] = aws.ToString(apiObject.DefineAuthChallenge)
	}

	if apiObject.KMSKeyID != nil {
		tfMap[names.AttrKMSKeyID] = aws.ToString(apiObject.KMSKeyID)
	}

	if apiObject.PostAuthentication != nil {
		tfMap["post_authentication"] = aws.ToString(apiObject.PostAuthentication)
	}

	if apiObject.PostConfirmation != nil {
		tfMap["post_confirmation"] = aws.ToString(apiObject.PostConfirmation)
	}

	if apiObject.PreAuthentication != nil {
		tfMap["pre_authentication"] = aws.ToString(apiObject.PreAuthentication)
	}

	if apiObject.PreSignUp != nil {
		tfMap["pre_sign_up"] = aws.ToString(apiObject.PreSignUp)
	}

	if apiObject.PreTokenGeneration != nil {
		tfMap["pre_token_generation"] = aws.ToString(apiObject.PreTokenGeneration)
	}

	if apiObject.PreTokenGenerationConfig != nil {
		tfMap["pre_token_generation_config"] = flattenPreTokenGenerationVersionConfigType(apiObject.PreTokenGenerationConfig)
	}

	if apiObject.UserMigration != nil {
		tfMap["user_migration"] = aws.ToString(apiObject.UserMigration)
	}

	if apiObject.VerifyAuthChallengeResponse != nil {
		tfMap["verify_auth_challenge_response"] = aws.ToString(apiObject.VerifyAuthChallengeResponse)
	}

	if len(tfMap) > 0 {
		return []any{tfMap}
	}

	return []any{}
}

func expandPasswordPolicyType(tfMap map[string]any) *awstypes.PasswordPolicyType {
	apiObject := &awstypes.PasswordPolicyType{}

	if v, ok := tfMap["minimum_length"]; ok {
		apiObject.MinimumLength = aws.Int32(int32(v.(int)))
	}

	if v, ok := tfMap["password_history_size"]; ok {
		apiObject.PasswordHistorySize = aws.Int32(int32(v.(int)))
	}

	if v, ok := tfMap["require_lowercase"]; ok {
		apiObject.RequireLowercase = v.(bool)
	}

	if v, ok := tfMap["require_numbers"]; ok {
		apiObject.RequireNumbers = v.(bool)
	}

	if v, ok := tfMap["require_symbols"]; ok {
		apiObject.RequireSymbols = v.(bool)
	}

	if v, ok := tfMap["require_uppercase"]; ok {
		apiObject.RequireUppercase = v.(bool)
	}

	if v, ok := tfMap["temporary_password_validity_days"]; ok {
		apiObject.TemporaryPasswordValidityDays = int32(v.(int))
	}

	return apiObject
}

func expandSignInPolicyType(tfMap map[string]any) *awstypes.SignInPolicyType {
	apiObject := &awstypes.SignInPolicyType{}

	if v, ok := tfMap["allowed_first_auth_factors"]; ok {
		apiObject.AllowedFirstAuthFactors = flex.ExpandStringyValueSet[awstypes.AuthFactorType](v.(*schema.Set))
	}

	return apiObject
}

func expandUserPoolAddOnsType(tfMap map[string]any) *awstypes.UserPoolAddOnsType {
	if tfMap == nil {
		return nil
	}

	apiObject := &awstypes.UserPoolAddOnsType{}

	if v, ok := tfMap["advanced_security_additional_flows"].([]any); ok && len(v) > 0 && v[0] != nil {
		apiObject.AdvancedSecurityAdditionalFlows = expandAdvancedSecurityAdditionalFlowType(v[0].(map[string]any))
	}

	if v, ok := tfMap["advanced_security_mode"].(string); ok {
		apiObject.AdvancedSecurityMode = awstypes.AdvancedSecurityModeType(v)
	}

	return apiObject
}

func expandAdvancedSecurityAdditionalFlowType(tfMap map[string]any) *awstypes.AdvancedSecurityAdditionalFlowsType {
	if tfMap == nil {
		return nil
	}

	apiObject := &awstypes.AdvancedSecurityAdditionalFlowsType{}

	if v, ok := tfMap["custom_auth_mode"].(string); ok {
		apiObject.CustomAuthMode = awstypes.AdvancedSecurityEnabledModeType(v)
	}

	return apiObject
}

func flattenUserPoolAddOnsType(apiObject *awstypes.UserPoolAddOnsType) []any {
	if apiObject == nil {
		return []any{}
	}

	tfMap := make(map[string]any)

	tfMap["advanced_security_additional_flows"] = flattenAdvancedSecurityAdditionalFlowType(apiObject.AdvancedSecurityAdditionalFlows)
	tfMap["advanced_security_mode"] = apiObject.AdvancedSecurityMode

	return []any{tfMap}
}

func flattenAdvancedSecurityAdditionalFlowType(apiObject *awstypes.AdvancedSecurityAdditionalFlowsType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := make(map[string]any)

	if v := apiObject.CustomAuthMode; v != "" {
		tfMap["custom_auth_mode"] = v
	}

	return []any{tfMap}
}

func expandSchemaAttributeTypes(tfList []any) []awstypes.SchemaAttributeType {
	apiObjects := make([]awstypes.SchemaAttributeType, len(tfList))

	for i, tfMapRaw := range tfList {
		tfMap := tfMapRaw.(map[string]any)
		apiObject := awstypes.SchemaAttributeType{}

		if v, ok := tfMap["attribute_data_type"]; ok {
			apiObject.AttributeDataType = awstypes.AttributeDataType(v.(string))
		}

		if v, ok := tfMap["developer_only_attribute"]; ok {
			apiObject.DeveloperOnlyAttribute = aws.Bool(v.(bool))
		}

		if v, ok := tfMap["mutable"]; ok {
			apiObject.Mutable = aws.Bool(v.(bool))
		}

		if v, ok := tfMap[names.AttrName]; ok {
			apiObject.Name = aws.String(v.(string))
		}

		if v, ok := tfMap["number_attribute_constraints"]; ok {
			if tfList := v.([]any); len(tfList) > 0 {
				if tfMap, ok := tfList[0].(map[string]any); ok {
					nact := &awstypes.NumberAttributeConstraintsType{}

					if v, ok := tfMap["max_value"]; ok && v.(string) != "" {
						nact.MaxValue = aws.String(v.(string))
					}

					if v, ok := tfMap["min_value"]; ok && v.(string) != "" {
						nact.MinValue = aws.String(v.(string))
					}

					apiObject.NumberAttributeConstraints = nact
				}
			}
		}

		if v, ok := tfMap["required"]; ok {
			apiObject.Required = aws.Bool(v.(bool))
		}

		if v, ok := tfMap["string_attribute_constraints"]; ok {
			if tfList := v.([]any); len(tfList) > 0 {
				if tfMap, ok := tfList[0].(map[string]any); ok {
					sact := &awstypes.StringAttributeConstraintsType{}

					if v, ok := tfMap["max_length"]; ok && v.(string) != "" {
						sact.MaxLength = aws.String(v.(string))
					}

					if v, ok := tfMap["min_length"]; ok && v.(string) != "" {
						sact.MinLength = aws.String(v.(string))
					}

					if sact.MinLength == nil && sact.MaxLength == nil {
						apiObject.StringAttributeConstraints = nil
					} else {
						apiObject.StringAttributeConstraints = sact
					}
				}
			}
		}

		apiObjects[i] = apiObject
	}

	return apiObjects
}

func flattenSchemaAttributeTypes(configuredAttributes, apiObjects []awstypes.SchemaAttributeType) []any {
	tfList := make([]any, 0)

	for _, apiObject := range apiObjects {
		// The API returns all standard attributes
		// https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#cognito-user-pools-standard-attributes
		// Ignore setting them in state if they are unconfigured to prevent a huge and unexpected diff
		configured := false

		for _, configuredAttribute := range configuredAttributes {
			if reflect.DeepEqual(apiObject, configuredAttribute) {
				configured = true
			}
		}

		if !configured {
			if userPoolSchemaAttributeMatchesStandardAttribute(&apiObject) {
				continue
			}

			// When adding a Cognito Identity Provider, the API will automatically add an "identities" attribute
			identitiesAttribute := awstypes.SchemaAttributeType{
				AttributeDataType:          awstypes.AttributeDataTypeString,
				DeveloperOnlyAttribute:     aws.Bool(false),
				Mutable:                    aws.Bool(true),
				Name:                       aws.String("identities"),
				Required:                   aws.Bool(false),
				StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{},
			}

			if reflect.DeepEqual(apiObject, identitiesAttribute) {
				continue
			}
		}

		var tfMap = map[string]any{
			"attribute_data_type":      apiObject.AttributeDataType,
			"developer_only_attribute": aws.ToBool(apiObject.DeveloperOnlyAttribute),
			"mutable":                  aws.ToBool(apiObject.Mutable),
			names.AttrName:             strings.TrimPrefix(strings.TrimPrefix(aws.ToString(apiObject.Name), attributeDevPrefix), attributeCustomPrefix),
			"required":                 aws.ToBool(apiObject.Required),
		}

		if apiObject.NumberAttributeConstraints != nil {
			nact := make(map[string]any)

			if apiObject.NumberAttributeConstraints.MaxValue != nil {
				nact["max_value"] = aws.ToString(apiObject.NumberAttributeConstraints.MaxValue)
			}

			if apiObject.NumberAttributeConstraints.MinValue != nil {
				nact["min_value"] = aws.ToString(apiObject.NumberAttributeConstraints.MinValue)
			}

			tfMap["number_attribute_constraints"] = []any{nact}
		}

		if apiObject.StringAttributeConstraints != nil && !skipFlatteningStringAttributeContraints(configuredAttributes, &apiObject) {
			sact := make(map[string]any)

			if apiObject.StringAttributeConstraints.MaxLength != nil {
				sact["max_length"] = aws.ToString(apiObject.StringAttributeConstraints.MaxLength)
			}

			if apiObject.StringAttributeConstraints.MinLength != nil {
				sact["min_length"] = aws.ToString(apiObject.StringAttributeConstraints.MinLength)
			}

			tfMap["string_attribute_constraints"] = []any{sact}
		}

		tfList = append(tfList, tfMap)
	}

	return tfList
}

func expandUsernameConfigurationType(tfMap map[string]any) *awstypes.UsernameConfigurationType {
	apiObject := &awstypes.UsernameConfigurationType{
		CaseSensitive: aws.Bool(tfMap["case_sensitive"].(bool)),
	}

	return apiObject
}

func flattenUsernameConfigurationType(apiObject *awstypes.UsernameConfigurationType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]any{}

	tfMap["case_sensitive"] = aws.ToBool(apiObject.CaseSensitive)

	return []any{tfMap}
}

func expandVerificationMessageTemplateType(tfMap map[string]any) *awstypes.VerificationMessageTemplateType {
	apiObject := &awstypes.VerificationMessageTemplateType{}

	if v, ok := tfMap["default_email_option"]; ok && v.(string) != "" {
		apiObject.DefaultEmailOption = awstypes.DefaultEmailOptionType(v.(string))
	}

	if v, ok := tfMap["email_message"]; ok && v.(string) != "" {
		apiObject.EmailMessage = aws.String(v.(string))
	}

	if v, ok := tfMap["email_message_by_link"]; ok && v.(string) != "" {
		apiObject.EmailMessageByLink = aws.String(v.(string))
	}

	if v, ok := tfMap["email_subject"]; ok && v.(string) != "" {
		apiObject.EmailSubject = aws.String(v.(string))
	}

	if v, ok := tfMap["email_subject_by_link"]; ok && v.(string) != "" {
		apiObject.EmailSubjectByLink = aws.String(v.(string))
	}

	if v, ok := tfMap["sms_message"]; ok && v.(string) != "" {
		apiObject.SmsMessage = aws.String(v.(string))
	}

	return apiObject
}

func flattenVerificationMessageTemplateType(apiObject *awstypes.VerificationMessageTemplateType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]any{
		"default_email_option": apiObject.DefaultEmailOption,
	}

	if apiObject.EmailMessage != nil {
		tfMap["email_message"] = aws.ToString(apiObject.EmailMessage)
	}

	if apiObject.EmailMessageByLink != nil {
		tfMap["email_message_by_link"] = aws.ToString(apiObject.EmailMessageByLink)
	}

	if apiObject.EmailSubject != nil {
		tfMap["email_subject"] = aws.ToString(apiObject.EmailSubject)
	}

	if apiObject.EmailSubjectByLink != nil {
		tfMap["email_subject_by_link"] = aws.ToString(apiObject.EmailSubjectByLink)
	}

	if apiObject.SmsMessage != nil {
		tfMap["sms_message"] = aws.ToString(apiObject.SmsMessage)
	}

	if len(tfMap) > 0 {
		return []any{tfMap}
	}

	return []any{}
}

func flattenDeviceConfigurationType(apiObject *awstypes.DeviceConfigurationType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]any{
		"challenge_required_on_new_device":      apiObject.ChallengeRequiredOnNewDevice,
		"device_only_remembered_on_user_prompt": apiObject.DeviceOnlyRememberedOnUserPrompt,
	}

	return []any{tfMap}
}

func flattenPasswordPolicyType(apiObject *awstypes.PasswordPolicyType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]any{
		"require_lowercase":                apiObject.RequireLowercase,
		"require_numbers":                  apiObject.RequireNumbers,
		"require_symbols":                  apiObject.RequireSymbols,
		"require_uppercase":                apiObject.RequireUppercase,
		"temporary_password_validity_days": apiObject.TemporaryPasswordValidityDays,
	}

	if apiObject.MinimumLength != nil {
		tfMap["minimum_length"] = aws.ToInt32(apiObject.MinimumLength)
	}

	if apiObject.PasswordHistorySize != nil {
		tfMap["password_history_size"] = aws.ToInt32(apiObject.PasswordHistorySize)
	}

	if len(tfMap) > 0 {
		return []any{tfMap}
	}

	return []any{}
}

func flattenSignInPolicyType(apiObject *awstypes.SignInPolicyType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]any{
		"allowed_first_auth_factors": apiObject.AllowedFirstAuthFactors,
	}

	if len(tfMap) > 0 {
		return []any{tfMap}
	}

	return []any{}
}

func expandPreTokenGenerationVersionConfigType(tfMap map[string]any) *awstypes.PreTokenGenerationVersionConfigType {
	apiObject := &awstypes.PreTokenGenerationVersionConfigType{
		LambdaArn:     aws.String(tfMap["lambda_arn"].(string)),
		LambdaVersion: awstypes.PreTokenGenerationLambdaVersionType(tfMap["lambda_version"].(string)),
	}

	return apiObject
}

func flattenPreTokenGenerationVersionConfigType(apiObject *awstypes.PreTokenGenerationVersionConfigType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]any{}

	tfMap["lambda_arn"] = aws.ToString(apiObject.LambdaArn)
	tfMap["lambda_version"] = apiObject.LambdaVersion

	return []any{tfMap}
}

func expandCustomSMSLambdaVersionConfigType(tfMap map[string]any) *awstypes.CustomSMSLambdaVersionConfigType {
	apiObject := &awstypes.CustomSMSLambdaVersionConfigType{
		LambdaArn:     aws.String(tfMap["lambda_arn"].(string)),
		LambdaVersion: awstypes.CustomSMSSenderLambdaVersionType(tfMap["lambda_version"].(string)),
	}

	return apiObject
}

func flattenCustomSMSLambdaVersionConfigType(apiObject *awstypes.CustomSMSLambdaVersionConfigType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]any{}

	tfMap["lambda_arn"] = aws.ToString(apiObject.LambdaArn)
	tfMap["lambda_version"] = apiObject.LambdaVersion

	return []any{tfMap}
}

func expandCustomEmailLambdaVersionConfigType(tfMap map[string]any) *awstypes.CustomEmailLambdaVersionConfigType {
	apiObject := &awstypes.CustomEmailLambdaVersionConfigType{
		LambdaArn:     aws.String(tfMap["lambda_arn"].(string)),
		LambdaVersion: awstypes.CustomEmailSenderLambdaVersionType(tfMap["lambda_version"].(string)),
	}

	return apiObject
}

func flattenCustomEmailLambdaVersionConfigType(apiObject *awstypes.CustomEmailLambdaVersionConfigType) []any {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]any{}

	tfMap["lambda_arn"] = aws.ToString(apiObject.LambdaArn)
	tfMap["lambda_version"] = apiObject.LambdaVersion

	return []any{tfMap}
}

func expandEmailConfigurationType(tfList []any) *awstypes.EmailConfigurationType {
	tfMap := tfList[0].(map[string]any)
	apiObject := &awstypes.EmailConfigurationType{}

	if v, ok := tfMap["configuration_set"]; ok && v.(string) != "" {
		apiObject.ConfigurationSet = aws.String(v.(string))
	}

	if v, ok := tfMap["email_sending_account"]; ok && v.(string) != "" {
		apiObject.EmailSendingAccount = awstypes.EmailSendingAccountType(v.(string))
	}

	if v, ok := tfMap["from_email_address"]; ok && v.(string) != "" {
		apiObject.From = aws.String(v.(string))
	}

	if v, ok := tfMap["reply_to_email_address"]; ok && v.(string) != "" {
		apiObject.ReplyToEmailAddress = aws.String(v.(string))
	}

	if v, ok := tfMap["source_arn"]; ok && v.(string) != "" {
		apiObject.SourceArn = aws.String(v.(string))
	}

	return apiObject
}

func expandUserAttributeUpdateSettingsType(tfMap map[string]any) *awstypes.UserAttributeUpdateSettingsType {
	apiObject := &awstypes.UserAttributeUpdateSettingsType{}

	if v, ok := tfMap["attributes_require_verification_before_update"]; ok {
		apiObject.AttributesRequireVerificationBeforeUpdate = flex.ExpandStringyValueSet[awstypes.VerifiedAttributeType](v.(*schema.Set))
	}

	return apiObject
}

func flattenUserAttributeUpdateSettingsType(apiObject *awstypes.UserAttributeUpdateSettingsType) []any {
	if apiObject == nil {
		return nil
	}

	// If this setting is enabled then disabled, the API returns a nested empty slice instead of nil
	if len(apiObject.AttributesRequireVerificationBeforeUpdate) == 0 {
		return nil
	}

	tfMap := map[string]any{}
	tfMap["attributes_require_verification_before_update"] = apiObject.AttributesRequireVerificationBeforeUpdate

	return []any{tfMap}
}

// skipFlatteningStringAttributeContraints returns true when all of the schema arguments
// match an existing configured attribute, except an empty "string_attribute_constraints" block.
// In this situation the Describe API returns default constraint values, and a persistent diff
// would be present if written to state.
func skipFlatteningStringAttributeContraints(configuredAttributes []awstypes.SchemaAttributeType, apiObject *awstypes.SchemaAttributeType) bool {
	for _, configuredAttribute := range configuredAttributes {
		// Root elements are all equal
		if reflect.DeepEqual(apiObject.AttributeDataType, configuredAttribute.AttributeDataType) &&
			reflect.DeepEqual(apiObject.DeveloperOnlyAttribute, configuredAttribute.DeveloperOnlyAttribute) &&
			reflect.DeepEqual(apiObject.Mutable, configuredAttribute.Mutable) &&
			reflect.DeepEqual(apiObject.Name, configuredAttribute.Name) &&
			reflect.DeepEqual(apiObject.Required, configuredAttribute.Required) &&
			// The configured "string_attribute_constraints" object is empty, but the returned value is not
			(configuredAttribute.AttributeDataType == awstypes.AttributeDataTypeString &&
				configuredAttribute.StringAttributeConstraints == nil &&
				apiObject.StringAttributeConstraints != nil) {
			return true
		}
	}

	return false
}

func userPoolSchemaAttributeMatchesStandardAttribute(apiObject *awstypes.SchemaAttributeType) bool {
	if apiObject == nil {
		return false
	}

	// All standard attributes always returned by API
	// https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#cognito-user-pools-standard-attributes
	var standardAttributes = []awstypes.SchemaAttributeType{
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String(names.AttrAddress),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("birthdate"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("10"),
				MinLength: aws.String("10"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String(names.AttrEmail),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeBoolean,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("email_verified"),
			Required:               aws.Bool(false),
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("family_name"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("gender"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("given_name"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("locale"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("middle_name"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String(names.AttrName),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("nickname"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("phone_number"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeBoolean,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("phone_number_verified"),
			Required:               aws.Bool(false),
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("picture"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("preferred_username"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String(names.AttrProfile),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(false),
			Name:                   aws.String("sub"),
			Required:               aws.Bool(true),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("1"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeNumber,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("updated_at"),
			NumberAttributeConstraints: &awstypes.NumberAttributeConstraintsType{
				MinValue: aws.String("0"),
			},
			Required: aws.Bool(false),
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("website"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      awstypes.AttributeDataTypeString,
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("zoneinfo"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &awstypes.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
	}

	for _, standardAttribute := range standardAttributes {
		if reflect.DeepEqual(*apiObject, standardAttribute) {
			return true
		}
	}

	return false
}

func resourceUserPoolSchemaHash(v any) int {
	var buf bytes.Buffer
	m, ok := v.(map[string]any)
	if !ok {
		return 0
	}

	fmt.Fprintf(&buf, "%s-", m[names.AttrName].(string))
	fmt.Fprintf(&buf, "%s-", m["attribute_data_type"].(string))
	fmt.Fprintf(&buf, "%t-", m["developer_only_attribute"].(bool))
	fmt.Fprintf(&buf, "%t-", m["mutable"].(bool))
	fmt.Fprintf(&buf, "%t-", m["required"].(bool))

	if v, ok := m["string_attribute_constraints"]; ok {
		data := v.([]any)

		if len(data) > 0 {
			buf.WriteString("string_attribute_constraints-")
			m, _ := data[0].(map[string]any)
			if ok {
				if l, ok := m["min_length"]; ok && l.(string) != "" {
					fmt.Fprintf(&buf, "%s-", l.(string))
				}

				if l, ok := m["max_length"]; ok && l.(string) != "" {
					fmt.Fprintf(&buf, "%s-", l.(string))
				}
			}
		}
	}

	if v, ok := m["number_attribute_constraints"]; ok {
		data := v.([]any)

		if len(data) > 0 {
			buf.WriteString("number_attribute_constraints-")
			m, _ := data[0].(map[string]any)
			if ok {
				if l, ok := m["min_value"]; ok && l.(string) != "" {
					fmt.Fprintf(&buf, "%s-", l.(string))
				}

				if l, ok := m["max_value"]; ok && l.(string) != "" {
					fmt.Fprintf(&buf, "%s-", l.(string))
				}
			}
		}
	}
	return create.StringHashcode(buf.String())
}
