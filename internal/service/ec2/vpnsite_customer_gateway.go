// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ec2

import (
	"context"
	"log"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	awstypes "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/hashicorp/aws-sdk-go-base/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/enum"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_customer_gateway", name="Customer Gateway")
// @Tags(identifierAttribute="id")
// @Testing(tagsTest=false)
func resourceCustomerGateway() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceCustomerGatewayCreate,
		ReadWithoutTimeout:   resourceCustomerGatewayRead,
		UpdateWithoutTimeout: resourceCustomerGatewayUpdate,
		DeleteWithoutTimeout: resourceCustomerGatewayDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			names.AttrARN: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"bgp_asn": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ValidateFunc:  verify.Valid4ByteASN,
				ConflictsWith: []string{"bgp_asn_extended"},
			},
			"bgp_asn_extended": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ValidateFunc:  verify.Valid4ByteASN,
				ConflictsWith: []string{"bgp_asn"},
			},
			names.AttrCertificateARN: {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				ValidateFunc: verify.ValidARN,
			},
			names.AttrDeviceName: {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringLenBetween(1, 255),
			},
			names.AttrIPAddress: {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				ValidateFunc: validation.IsIPv4Address,
			},
			names.AttrTags:    tftags.TagsSchema(),
			names.AttrTagsAll: tftags.TagsSchemaComputed(),
			names.AttrType: {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				ValidateDiagFunc: enum.Validate[awstypes.GatewayType](),
			},
		},
	}
}

func resourceCustomerGatewayCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).EC2Client(ctx)

	input := ec2.CreateCustomerGatewayInput{
		TagSpecifications: getTagSpecificationsIn(ctx, awstypes.ResourceTypeCustomerGateway),
		Type:              awstypes.GatewayType(d.Get(names.AttrType).(string)),
	}

	if v, ok := d.GetOk("bgp_asn"); ok {
		v, err := strconv.ParseInt(v.(string), 10, 32)

		if err != nil {
			return sdkdiag.AppendFromErr(diags, err)
		}

		input.BgpAsn = aws.Int32(int32(v))
	}

	if v, ok := d.GetOk("bgp_asn_extended"); ok {
		v, err := strconv.ParseInt(v.(string), 10, 64)

		if err != nil {
			return sdkdiag.AppendFromErr(diags, err)
		}

		input.BgpAsnExtended = aws.Int64(v)
	}

	if v, ok := d.GetOk(names.AttrCertificateARN); ok {
		input.CertificateArn = aws.String(v.(string))
	}

	if v, ok := d.GetOk(names.AttrDeviceName); ok {
		input.DeviceName = aws.String(v.(string))
	}

	if v, ok := d.GetOk(names.AttrIPAddress); ok {
		input.IpAddress = aws.String(v.(string))
	}

	output, err := conn.CreateCustomerGateway(ctx, &input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating EC2 Customer Gateway: %s", err)
	}

	d.SetId(aws.ToString(output.CustomerGateway.CustomerGatewayId))

	if _, err := waitCustomerGatewayCreated(ctx, conn, d.Id()); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for EC2 Customer Gateway (%s) create: %s", d.Id(), err)
	}

	return append(diags, resourceCustomerGatewayRead(ctx, d, meta)...)
}

func resourceCustomerGatewayRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	c := meta.(*conns.AWSClient)
	conn := c.EC2Client(ctx)

	customerGateway, err := findCustomerGatewayByID(ctx, conn, d.Id())

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] EC2 Customer Gateway (%s) not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading EC2 Customer Gateway (%s): %s", d.Id(), err)
	}

	d.Set(names.AttrARN, customerGatewayARN(ctx, c, d.Id()))
	d.Set("bgp_asn", customerGateway.BgpAsn)
	d.Set("bgp_asn_extended", customerGateway.BgpAsnExtended)
	d.Set(names.AttrCertificateARN, customerGateway.CertificateArn)
	d.Set(names.AttrDeviceName, customerGateway.DeviceName)
	d.Set(names.AttrIPAddress, customerGateway.IpAddress)
	d.Set(names.AttrType, customerGateway.Type)

	setTagsOut(ctx, customerGateway.Tags)

	return diags
}

func resourceCustomerGatewayUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	// Tags only.
	return resourceCustomerGatewayRead(ctx, d, meta)
}

func resourceCustomerGatewayDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).EC2Client(ctx)

	log.Printf("[INFO] Deleting EC2 Customer Gateway: %s", d.Id())
	input := ec2.DeleteCustomerGatewayInput{
		CustomerGatewayId: aws.String(d.Id()),
	}
	_, err := conn.DeleteCustomerGateway(ctx, &input)

	if tfawserr.ErrCodeEquals(err, errCodeInvalidCustomerGatewayIDNotFound) {
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting EC2 Customer Gateway (%s): %s", d.Id(), err)
	}

	if _, err := waitCustomerGatewayDeleted(ctx, conn, d.Id()); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for EC2 Customer Gateway (%s) delete: %s", d.Id(), err)
	}

	return diags
}

func customerGatewayARN(ctx context.Context, c *conns.AWSClient, customerGatewayID string) string {
	return c.RegionalARN(ctx, names.EC2, "customer-gateway/"+customerGatewayID)
}
