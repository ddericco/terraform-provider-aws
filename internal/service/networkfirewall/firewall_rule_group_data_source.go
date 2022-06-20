package networkfirewall

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/customdiff"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
)

func DataSourceRuleGroup() *schema.Resource {
	return &schema.Resource{
		ReadContext: resourceRuleGroupRead,
		Schema: map[string]*schema.Schema{
			"arn": {
				Type:         schema.TypeString,
				AtLeastOneOf: []string{"arn", "name"},
				//Computed: true,
				Optional: true,
			},
			"capacity": {
				Type: schema.TypeInt,
				//Required: true,
				//ForceNew: true,
				Computed: true,
			},
			"description": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"name": {
				// name requires type of stateful or stateless:
				// https://docs.aws.amazon.com/sdk-for-go/api/service/networkfirewall/#DescribeRuleGroupInput
				Type:         schema.TypeString,
				AtLeastOneOf: []string{"arn", "name"},
				Optional:     true,
			},
			"rule_group": {
				Type: schema.TypeList,
				//MaxItems: 1,
				//Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"rule_variables": {
							Type:     schema.TypeList,
							Computed: true,
							//Optional: true,
							//MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"ip_sets": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"key": {
													Type:     schema.TypeString,
													Computed: true,
													// Required: true,
													// ValidateFunc: validation.All(
													// 	validation.StringLenBetween(1, 32),
													// 	validation.StringMatch(regexp.MustCompile(`^[A-Za-z]`), "must begin with alphabetic character"),
													// 	validation.StringMatch(regexp.MustCompile(`^[A-Za-z0-9_]+$`), "must contain only alphanumeric and underscore characters"),
													// ),
												},
												"ip_set": {
													Type:     schema.TypeList,
													Computed: true,
													// Required: true,
													// MaxItems: 1,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"definition": {
																Type:     schema.TypeSet,
																Computed: true,
																// Required: true,
																// Elem:     &schema.Schema{Type: schema.TypeString},
															},
														},
													},
												},
											},
										},
									},
									"port_sets": {
										Type:     schema.TypeSet,
										Computed: true,
										// Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"key": {
													Type:     schema.TypeString,
													Computed: true,
													// Required: true,
													// ValidateFunc: validation.All(
													// 	validation.StringLenBetween(1, 32),
													// 	validation.StringMatch(regexp.MustCompile(`^[A-Za-z]`), "must begin with alphabetic character"),
													// 	validation.StringMatch(regexp.MustCompile(`^[A-Za-z0-9_]+$`), "must contain only alphanumeric and underscore characters"),
													// ),
												},
												"port_set": {
													Type:     schema.TypeList,
													Computed: true,
													// Required: true,
													// MaxItems: 1,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"definition": {
																Type:     schema.TypeSet,
																Computed: true,
																// Required: true,
																// Elem:     &schema.Schema{Type: schema.TypeString},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
						"rules_source": {
							Type:     schema.TypeList,
							Computed: true,
							// Required: true,
							// MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"rules_source_list": {
										Type:     schema.TypeList,
										Computed: true,
										// Optional: true,
										// MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"generated_rules_type": {
													Type:     schema.TypeString,
													Computed: true,
													// Required:     true,
													// ValidateFunc: validation.StringInSlice(networkfirewall.GeneratedRulesType_Values(), false),
												},
												"target_types": {
													Type:     schema.TypeSet,
													Computed: true,
													// Required: true,
													Elem: &schema.Schema{
														Type:     schema.TypeString,
														Computed: true,
														// ValidateFunc: validation.StringInSlice(networkfirewall.TargetType_Values(), false),
													},
												},
												"targets": {
													Type:     schema.TypeSet,
													Computed: true,
													// Required: true,
													Elem: &schema.Schema{Type: schema.TypeString},
												},
											},
										},
									},
									"rules_string": {
										Type:     schema.TypeString,
										Computed: true,
										// Optional: true,
									},
									"stateful_rule": {
										Type:     schema.TypeSet,
										Computed: true,
										// Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"action": {
													Type:     schema.TypeString,
													Computed: true,
													// Required:     true,
													// ValidateFunc: validation.StringInSlice(networkfirewall.StatefulAction_Values(), false),
												},
												"header": {
													Type:     schema.TypeList,
													Computed: true,
													// Required: true,
													// MaxItems: 1,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"destination": {
																Type:     schema.TypeString,
																Computed: true,
																// Required: true,
															},
															"destination_port": {
																Type:     schema.TypeString,
																Computed: true,
																// Required: true,
															},
															"direction": {
																Type:     schema.TypeString,
																Computed: true,
																// Required:     true,
																// ValidateFunc: validation.StringInSlice(networkfirewall.StatefulRuleDirection_Values(), false),
															},
															"protocol": {
																Type:     schema.TypeString,
																Computed: true,
																// Required:     true,
																// ValidateFunc: validation.StringInSlice(networkfirewall.StatefulRuleProtocol_Values(), false),
															},
															"source": {
																Type:     schema.TypeString,
																Computed: true,
																// Required: true,
															},
															"source_port": {
																Type:     schema.TypeString,
																Computed: true,
																// Required: true,
															},
														},
													},
												},
												"rule_option": {
													Type:     schema.TypeSet,
													Computed: true,
													// Required: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"keyword": {
																Type:     schema.TypeString,
																Computed: true,
																// Required: true,
															},
															"settings": {
																Type:     schema.TypeSet,
																Computed: true,
																// Optional: true,
																Elem: &schema.Schema{Type: schema.TypeString},
															},
														},
													},
												},
											},
										},
									},
									"stateless_rules_and_custom_actions": {
										Type:     schema.TypeList,
										Computed: true,
										// MaxItems: 1,
										// Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"custom_action": customActionSchema(),
												"stateless_rule": {
													Type:     schema.TypeSet,
													Computed: true,
													// Required: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"priority": {
																Type:     schema.TypeInt,
																Computed: true,
																// Required: true,
															},
															"rule_definition": {
																Type:     schema.TypeList,
																Computed: true,
																// MaxItems: 1,
																// Required: true,
																Elem: &schema.Resource{
																	Schema: map[string]*schema.Schema{
																		"actions": {
																			Type:     schema.TypeSet,
																			Computed: true,
																			// Required: true,
																			Elem: &schema.Schema{Type: schema.TypeString},
																		},
																		"match_attributes": {
																			Type:     schema.TypeList,
																			Computed: true,
																			// MaxItems: 1,
																			// Required: true,
																			Elem: &schema.Resource{
																				Schema: map[string]*schema.Schema{
																					"destination": {
																						Type:     schema.TypeSet,
																						Computed: true,
																						// Optional: true,
																						Elem: &schema.Resource{
																							Schema: map[string]*schema.Schema{
																								"address_definition": {
																									Type:     schema.TypeString,
																									Computed: true,
																									// Required:     true,
																									// ValidateFunc: verify.ValidIPv4CIDRNetworkAddress,
																								},
																							},
																						},
																					},
																					"destination_port": {
																						Type:     schema.TypeSet,
																						Computed: true,
																						// Optional: true,
																						Elem: &schema.Resource{
																							Schema: map[string]*schema.Schema{
																								"from_port": {
																									Type:     schema.TypeInt,
																									Computed: true,
																									// Required: true,
																								},
																								"to_port": {
																									Type:     schema.TypeInt,
																									Computed: true,
																									// Optional: true,
																								},
																							},
																						},
																					},
																					"protocols": {
																						Type:     schema.TypeSet,
																						Computed: true,
																						// Optional: true,
																						Elem: &schema.Schema{Type: schema.TypeInt},
																					},
																					"source": {
																						Type:     schema.TypeSet,
																						Computed: true,
																						// Optional: true,
																						Elem: &schema.Resource{
																							Schema: map[string]*schema.Schema{
																								"address_definition": {
																									Type:     schema.TypeString,
																									Computed: true,
																									// Required:     true,
																									// ValidateFunc: verify.ValidIPv4CIDRNetworkAddress,
																								},
																							},
																						},
																					},
																					"source_port": {
																						Type:     schema.TypeSet,
																						Computed: true,
																						// Optional: true,
																						Elem: &schema.Resource{
																							Schema: map[string]*schema.Schema{
																								"from_port": {
																									Type:     schema.TypeInt,
																									Computed: true,
																									// Required: true,
																								},
																								"to_port": {
																									Type:     schema.TypeInt,
																									Computed: true,
																									// Optional: true,
																								},
																							},
																						},
																					},
																					"tcp_flag": {
																						Type:     schema.TypeSet,
																						Computed: true,
																						// Optional: true,
																						Elem: &schema.Resource{
																							Schema: map[string]*schema.Schema{
																								"flags": {
																									Type:     schema.TypeSet,
																									Computed: true,
																									// Required: true,
																									Elem: &schema.Schema{
																										Type:     schema.TypeString,
																										Computed: true,
																										// ValidateFunc: validation.StringInSlice(networkfirewall.TCPFlag_Values(), false),
																									},
																								},
																								"masks": {
																									Type:     schema.TypeSet,
																									Computed: true,
																									// Optional: true,
																									Elem: &schema.Schema{
																										Type:     schema.TypeString,
																										Computed: true,
																										// ValidateFunc: validation.StringInSlice(networkfirewall.TCPFlag_Values(), false),
																									},
																								},
																							},
																						},
																					},
																				},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
						"stateful_rule_options": {
							Type:     schema.TypeList,
							Computed: true,
							// Optional: true,
							// MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"rule_order": {
										Type:     schema.TypeString,
										Computed: true,
										// Required:     true,
										// ValidateFunc: validation.StringInSlice(networkfirewall.RuleOrder_Values(), false),
									},
								},
							},
						},
					},
				},
			},
			"rules": {
				Type:     schema.TypeString,
				Computed: true,
				// Optional: true,
			},
			"tags":     tftags.TagsSchema(),
			"tags_all": tftags.TagsSchemaComputed(),
			"type": {
				Type:     schema.TypeString,
				Computed: true,
				// Required:     true,
				// ValidateFunc: validation.StringInSlice(networkfirewall.RuleGroupType_Values(), false),
			},
			"update_token": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},

		CustomizeDiff: customdiff.Sequence(
			// The stateful rule_order default action can be explicitly or implicitly set,
			// so ignore spurious diffs if toggling between the two.
			func(_ context.Context, d *schema.ResourceDiff, meta interface{}) error {
				return forceNewIfNotRuleOrderDefault("rule_group.0.stateful_rule_options.0.rule_order", d)
			},
			verify.SetTagsDiff,
		),
	}
}

func resourceRuleGroupRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).NetworkFirewallConn
	defaultTagsConfig := meta.(*conns.AWSClient).DefaultTagsConfig
	ignoreTagsConfig := meta.(*conns.AWSClient).IgnoreTagsConfig

	log.Printf("[DEBUG] Reading NetworkFirewall Rule Group %s", d.Id())

	output, err := FindRuleGroup(ctx, conn, d.Id())
	// if !d.IsNewResource() && tfawserr.ErrCodeEquals(err, networkfirewall.ErrCodeResourceNotFoundException) {
	// 	log.Printf("[WARN] NetworkFirewall Rule Group (%s) not found, removing from state", d.Id())
	// 	d.SetId("")
	// 	return nil
	// }
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading NetworkFirewall Rule Group (%s): %w", d.Id(), err))
	}

	if output == nil {
		return diag.FromErr(fmt.Errorf("error reading NetworkFirewall Rule Group (%s): empty output", d.Id()))
	}
	if output.RuleGroupResponse == nil {
		return diag.FromErr(fmt.Errorf("error reading NetworkFirewall Rule Group (%s): empty output.RuleGroupResponse", d.Id()))
	}
	if output.RuleGroup == nil {
		return diag.FromErr(fmt.Errorf("error reading NetworkFirewall Rule Group (%s): empty output.RuleGroup", d.Id()))
	}

	resp := output.RuleGroupResponse
	ruleGroup := output.RuleGroup

	d.Set("arn", resp.RuleGroupArn)
	d.Set("capacity", resp.Capacity)
	d.Set("description", resp.Description)
	d.Set("name", resp.RuleGroupName)
	d.Set("type", resp.Type)
	d.Set("update_token", output.UpdateToken)

	if err := d.Set("rule_group", flattenRuleGroup(ruleGroup)); err != nil {
		return diag.FromErr(fmt.Errorf("error setting rule_group: %w", err))
	}

	tags := KeyValueTags(resp.Tags).IgnoreAWS().IgnoreConfig(ignoreTagsConfig)

	//lintignore:AWSR002
	if err := d.Set("tags", tags.RemoveDefaultConfig(defaultTagsConfig).Map()); err != nil {
		return diag.FromErr(fmt.Errorf("error setting tags: %w", err))
	}

	if err := d.Set("tags_all", tags.Map()); err != nil {
		return diag.FromErr(fmt.Errorf("error setting tags_all: %w", err))
	}

	return nil
}
