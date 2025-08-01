// Code generated by internal/generate/servicepackage/main.go; DO NOT EDIT.

package networkfirewall

import (
	"context"
	"unique"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
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
	return []*inttypes.ServicePackageFrameworkResource{
		{
			Factory:  newFirewallTransitGatewayAttachmentAccepterResource,
			TypeName: "aws_networkfirewall_firewall_transit_gateway_attachment_accepter",
			Name:     "Firewall Transit Gateway Attachment Accepter",
			Region:   unique.Make(inttypes.ResourceRegionDefault()),
		},
		{
			Factory:  newTLSInspectionConfigurationResource,
			TypeName: "aws_networkfirewall_tls_inspection_configuration",
			Name:     "TLS Inspection Configuration",
			Tags: unique.Make(inttypes.ServicePackageResourceTags{
				IdentifierAttribute: names.AttrARN,
			}),
			Region:   unique.Make(inttypes.ResourceRegionDefault()),
			Identity: inttypes.RegionalARNIdentity(inttypes.WithIdentityDuplicateAttrs(names.AttrID)),
			Import: inttypes.FrameworkImport{
				WrappedImport: true,
			},
		},
	}
}

func (p *servicePackage) SDKDataSources(ctx context.Context) []*inttypes.ServicePackageSDKDataSource {
	return []*inttypes.ServicePackageSDKDataSource{
		{
			Factory:  dataSourceFirewall,
			TypeName: "aws_networkfirewall_firewall",
			Name:     "Firewall",
			Tags:     unique.Make(inttypes.ServicePackageResourceTags{}),
			Region:   unique.Make(inttypes.ResourceRegionDefault()),
		},
		{
			Factory:  dataSourceFirewallPolicy,
			TypeName: "aws_networkfirewall_firewall_policy",
			Name:     "Firewall Policy",
			Tags:     unique.Make(inttypes.ServicePackageResourceTags{}),
			Region:   unique.Make(inttypes.ResourceRegionDefault()),
		},
		{
			Factory:  dataSourceResourcePolicy,
			TypeName: "aws_networkfirewall_resource_policy",
			Name:     "Resource Policy",
			Region:   unique.Make(inttypes.ResourceRegionDefault()),
		},
	}
}

func (p *servicePackage) SDKResources(ctx context.Context) []*inttypes.ServicePackageSDKResource {
	return []*inttypes.ServicePackageSDKResource{
		{
			Factory:  resourceFirewall,
			TypeName: "aws_networkfirewall_firewall",
			Name:     "Firewall",
			Tags: unique.Make(inttypes.ServicePackageResourceTags{
				IdentifierAttribute: names.AttrID,
			}),
			Region: unique.Make(inttypes.ResourceRegionDefault()),
		},
		{
			Factory:  resourceFirewallPolicy,
			TypeName: "aws_networkfirewall_firewall_policy",
			Name:     "Firewall Policy",
			Tags: unique.Make(inttypes.ServicePackageResourceTags{
				IdentifierAttribute: names.AttrID,
			}),
			Region: unique.Make(inttypes.ResourceRegionDefault()),
		},
		{
			Factory:  resourceLoggingConfiguration,
			TypeName: "aws_networkfirewall_logging_configuration",
			Name:     "Logging Configuration",
			Region:   unique.Make(inttypes.ResourceRegionDefault()),
		},
		{
			Factory:  resourceResourcePolicy,
			TypeName: "aws_networkfirewall_resource_policy",
			Name:     "Resource Policy",
			Region:   unique.Make(inttypes.ResourceRegionDefault()),
		},
		{
			Factory:  resourceRuleGroup,
			TypeName: "aws_networkfirewall_rule_group",
			Name:     "Rule Group",
			Tags: unique.Make(inttypes.ServicePackageResourceTags{
				IdentifierAttribute: names.AttrID,
			}),
			Region: unique.Make(inttypes.ResourceRegionDefault()),
		},
	}
}

func (p *servicePackage) ServicePackageName() string {
	return names.NetworkFirewall
}

// NewClient returns a new AWS SDK for Go v2 client for this service package's AWS API.
func (p *servicePackage) NewClient(ctx context.Context, config map[string]any) (*networkfirewall.Client, error) {
	cfg := *(config["aws_sdkv2_config"].(*aws.Config))
	optFns := []func(*networkfirewall.Options){
		networkfirewall.WithEndpointResolverV2(newEndpointResolverV2()),
		withBaseEndpoint(config[names.AttrEndpoint].(string)),
		func(o *networkfirewall.Options) {
			if region := config[names.AttrRegion].(string); o.Region != region {
				tflog.Info(ctx, "overriding provider-configured AWS API region", map[string]any{
					"service":         p.ServicePackageName(),
					"original_region": o.Region,
					"override_region": region,
				})
				o.Region = region
			}
		},
		func(o *networkfirewall.Options) {
			if inContext, ok := conns.FromContext(ctx); ok && inContext.VCREnabled() {
				tflog.Info(ctx, "overriding retry behavior to immediately return VCR errors")
				o.Retryer = conns.AddIsErrorRetryables(cfg.Retryer().(aws.RetryerV2), retry.IsErrorRetryableFunc(vcr.InteractionNotFoundRetryableFunc))
			}
		},
		withExtraOptions(ctx, p, config),
	}

	return networkfirewall.NewFromConfig(cfg, optFns...), nil
}

// withExtraOptions returns a functional option that allows this service package to specify extra API client options.
// This option is always called after any generated options.
func withExtraOptions(ctx context.Context, sp conns.ServicePackage, config map[string]any) func(*networkfirewall.Options) {
	if v, ok := sp.(interface {
		withExtraOptions(context.Context, map[string]any) []func(*networkfirewall.Options)
	}); ok {
		optFns := v.withExtraOptions(ctx, config)

		return func(o *networkfirewall.Options) {
			for _, optFn := range optFns {
				optFn(o)
			}
		}
	}

	return func(*networkfirewall.Options) {}
}

func ServicePackage(ctx context.Context) conns.ServicePackage {
	return &servicePackage{}
}
