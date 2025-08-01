// Code generated by internal/generate/servicepackage/main.go; DO NOT EDIT.

package organizations

import (
	"context"
	"unique"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	inttypes "github.com/hashicorp/terraform-provider-aws/internal/types"
	"github.com/hashicorp/terraform-provider-aws/internal/vcr"
	"github.com/hashicorp/terraform-provider-aws/names"
)

type servicePackage struct{}

func (p *servicePackage) FrameworkDataSources(ctx context.Context) []*inttypes.ServicePackageFrameworkDataSource {
	return []*inttypes.ServicePackageFrameworkDataSource{}
}

func (p *servicePackage) FrameworkResources(ctx context.Context) []*inttypes.ServicePackageFrameworkResource {
	return []*inttypes.ServicePackageFrameworkResource{}
}

func (p *servicePackage) SDKDataSources(ctx context.Context) []*inttypes.ServicePackageSDKDataSource {
	return []*inttypes.ServicePackageSDKDataSource{
		{
			Factory:  dataSourceDelegatedAdministrators,
			TypeName: "aws_organizations_delegated_administrators",
			Name:     "Delegated Administrators",
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
		},
		{
			Factory:  dataSourceDelegatedServices,
			TypeName: "aws_organizations_delegated_services",
			Name:     "Delegated Services",
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
		},
		{
			Factory:  dataSourceOrganization,
			TypeName: "aws_organizations_organization",
			Name:     "Organization",
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
		},
		{
			Factory:  dataSourceOrganizationalUnit,
			TypeName: "aws_organizations_organizational_unit",
			Name:     "Organizational Unit",
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
		},
		{
			Factory:  dataSourceOrganizationalUnitChildAccounts,
			TypeName: "aws_organizations_organizational_unit_child_accounts",
			Name:     "Organizational Unit Child Accounts",
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
		},
		{
			Factory:  dataSourceOrganizationalUnitDescendantAccounts,
			TypeName: "aws_organizations_organizational_unit_descendant_accounts",
			Name:     "Organizational Unit Descendant Accounts",
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
		},
		{
			Factory:  dataSourceOrganizationalUnitDescendantOrganizationalUnits,
			TypeName: "aws_organizations_organizational_unit_descendant_organizational_units",
			Name:     "Organizational Unit Descendant Organization Units",
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
		},
		{
			Factory:  dataSourceOrganizationalUnits,
			TypeName: "aws_organizations_organizational_units",
			Name:     "Organizational Unit",
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
		},
		{
			Factory:  dataSourcePolicies,
			TypeName: "aws_organizations_policies",
			Name:     "Policies",
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
		},
		{
			Factory:  dataSourcePoliciesForTarget,
			TypeName: "aws_organizations_policies_for_target",
			Name:     "Policies For Target",
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
		},
		{
			Factory:  dataSourcePolicy,
			TypeName: "aws_organizations_policy",
			Name:     "Policy",
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
		},
		{
			Factory:  dataSourceResourceTags,
			TypeName: "aws_organizations_resource_tags",
			Name:     "Resource Tags",
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
		},
	}
}

func (p *servicePackage) SDKResources(ctx context.Context) []*inttypes.ServicePackageSDKResource {
	return []*inttypes.ServicePackageSDKResource{
		{
			Factory:  resourceAccount,
			TypeName: "aws_organizations_account",
			Name:     "Account",
			Tags: unique.Make(inttypes.ServicePackageResourceTags{
				IdentifierAttribute: names.AttrID,
			}),
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
			Identity: inttypes.GlobalSingleParameterIdentity(names.AttrID),
			Import: inttypes.SDKv2Import{
				CustomImport: true,
			},
		},
		{
			Factory:  resourceDelegatedAdministrator,
			TypeName: "aws_organizations_delegated_administrator",
			Name:     "Delegated Administrator",
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
			Identity: inttypes.GlobalParameterizedIdentity([]inttypes.IdentityAttribute{
				inttypes.StringIdentityAttribute("service_principal", true),
				inttypes.StringIdentityAttributeWithMappedName("delegated_account_id", true, names.AttrAccountID),
			}),
			Import: inttypes.SDKv2Import{
				WrappedImport: true,
				ImportID:      delegatedAdministratorImportID{},
			},
		},
		{
			Factory:  resourceOrganization,
			TypeName: "aws_organizations_organization",
			Name:     "Organization",
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
			Identity: inttypes.GlobalSingleParameterIdentity(names.AttrID),
			Import: inttypes.SDKv2Import{
				CustomImport: true,
			},
		},
		{
			Factory:  resourceOrganizationalUnit,
			TypeName: "aws_organizations_organizational_unit",
			Name:     "Organizational Unit",
			Tags: unique.Make(inttypes.ServicePackageResourceTags{
				IdentifierAttribute: names.AttrID,
			}),
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
			Identity: inttypes.GlobalSingleParameterIdentity(names.AttrID),
			Import: inttypes.SDKv2Import{
				WrappedImport: true,
			},
		},
		{
			Factory:  resourcePolicy,
			TypeName: "aws_organizations_policy",
			Name:     "Policy",
			Tags: unique.Make(inttypes.ServicePackageResourceTags{
				IdentifierAttribute: names.AttrID,
			}),
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
			Identity: inttypes.GlobalSingleParameterIdentity(names.AttrID),
			Import: inttypes.SDKv2Import{
				CustomImport: true,
			},
		},
		{
			Factory:  resourcePolicyAttachment,
			TypeName: "aws_organizations_policy_attachment",
			Name:     "Policy Attachment",
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
			Identity: inttypes.GlobalParameterizedIdentity([]inttypes.IdentityAttribute{
				inttypes.StringIdentityAttribute("policy_id", true),
				inttypes.StringIdentityAttribute("target_id", true),
			}),
			Import: inttypes.SDKv2Import{
				WrappedImport: true,
				ImportID:      policyAttachmentImportID{},
			},
		},
		{
			Factory:  resourceResourcePolicy,
			TypeName: "aws_organizations_resource_policy",
			Name:     "Resource Policy",
			Tags: unique.Make(inttypes.ServicePackageResourceTags{
				IdentifierAttribute: names.AttrID,
			}),
			Region:   unique.Make(inttypes.ResourceRegionDisabled()),
			Identity: inttypes.GlobalSingleParameterIdentity(names.AttrID),
			Import: inttypes.SDKv2Import{
				WrappedImport: true,
			},
		},
	}
}

func (p *servicePackage) ServicePackageName() string {
	return names.Organizations
}

// NewClient returns a new AWS SDK for Go v2 client for this service package's AWS API.
func (p *servicePackage) NewClient(ctx context.Context, config map[string]any) (*organizations.Client, error) {
	cfg := *(config["aws_sdkv2_config"].(*aws.Config))
	optFns := []func(*organizations.Options){
		organizations.WithEndpointResolverV2(newEndpointResolverV2()),
		withBaseEndpoint(config[names.AttrEndpoint].(string)),
		func(o *organizations.Options) {
			if region := config[names.AttrRegion].(string); o.Region != region {
				tflog.Info(ctx, "overriding provider-configured AWS API region", map[string]any{
					"service":         p.ServicePackageName(),
					"original_region": o.Region,
					"override_region": region,
				})
				o.Region = region
			}
		},
		func(o *organizations.Options) {
			if inContext, ok := conns.FromContext(ctx); ok && inContext.VCREnabled() {
				tflog.Info(ctx, "overriding retry behavior to immediately return VCR errors")
				o.Retryer = conns.AddIsErrorRetryables(cfg.Retryer().(aws.RetryerV2), retry.IsErrorRetryableFunc(vcr.InteractionNotFoundRetryableFunc))
			}
		},
		withExtraOptions(ctx, p, config),
	}

	return organizations.NewFromConfig(cfg, optFns...), nil
}

// withExtraOptions returns a functional option that allows this service package to specify extra API client options.
// This option is always called after any generated options.
func withExtraOptions(ctx context.Context, sp conns.ServicePackage, config map[string]any) func(*organizations.Options) {
	if v, ok := sp.(interface {
		withExtraOptions(context.Context, map[string]any) []func(*organizations.Options)
	}); ok {
		optFns := v.withExtraOptions(ctx, config)

		return func(o *organizations.Options) {
			for _, optFn := range optFns {
				optFn(o)
			}
		}
	}

	return func(*organizations.Options) {}
}

func ServicePackage(ctx context.Context) conns.ServicePackage {
	return &servicePackage{}
}
