// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !generate
// +build !generate

package s3

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	awstypes "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/hashicorp/aws-sdk-go-base/v2/endpoints"
	"github.com/hashicorp/aws-sdk-go-base/v2/tfawserr"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	tfs3control "github.com/hashicorp/terraform-provider-aws/internal/service/s3control"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/types/option"
)

// Custom S3 tag functions using the same format as generated code.

func bucketCreateTags(ctx context.Context, conn *s3.Client, identifier string, tags []awstypes.Tag) error {
	if len(tags) == 0 {
		return nil
	}

	return bucketUpdateTags(ctx, conn, identifier, nil, keyValueTags(ctx, tags))
}

// bucketListTags lists S3 bucket tags.
// The identifier is the bucket name.
func bucketListTags(ctx context.Context, conn *s3.Client, identifier string, optFns ...func(*s3.Options)) (tftags.KeyValueTags, error) {
	input := s3.GetBucketTaggingInput{
		Bucket: aws.String(identifier),
	}

	output, err := conn.GetBucketTagging(ctx, &input, optFns...)

	if tfawserr.ErrCodeEquals(err, errCodeNoSuchTagSet, errCodeNoSuchTagSetError, errCodeMethodNotAllowed, errCodeNotImplemented, errCodeXNotImplemented, errCodeUnsupportedOperation) {
		return tftags.New(ctx, nil), nil
	}
	if err != nil {
		return tftags.New(ctx, nil), err
	}

	return keyValueTags(ctx, output.TagSet), nil
}

// bucketUpdateTags updates S3 bucket tags.
// The identifier is the bucket name.
func bucketUpdateTags(ctx context.Context, conn *s3.Client, identifier string, oldTagsMap, newTagsMap any, optFns ...func(*s3.Options)) error {
	oldTags := tftags.New(ctx, oldTagsMap)
	newTags := tftags.New(ctx, newTagsMap)

	// We need to also consider any existing ignored tags.
	allTags, err := bucketListTags(ctx, conn, identifier, optFns...)

	if err != nil {
		return fmt.Errorf("listing resource tags (%s): %w", identifier, err)
	}

	ignoredTags := allTags.Ignore(oldTags).Ignore(newTags)

	if len(newTags)+len(ignoredTags) > 0 {
		input := s3.PutBucketTaggingInput{
			Bucket: aws.String(identifier),
			Tagging: &awstypes.Tagging{
				TagSet: svcTags(newTags.Merge(ignoredTags)),
			},
		}

		_, err := conn.PutBucketTagging(ctx, &input, optFns...)

		if err != nil {
			return fmt.Errorf("setting resource tags (%s): %w", identifier, err)
		}
	} else if len(oldTags) > 0 && len(ignoredTags) == 0 {
		input := s3.DeleteBucketTaggingInput{
			Bucket: aws.String(identifier),
		}

		_, err := conn.DeleteBucketTagging(ctx, &input, optFns...)

		if err != nil {
			return fmt.Errorf("deleting resource tags (%s): %w", identifier, err)
		}
	}

	return nil
}

// objectListTags lists S3 object tags.
func objectListTags(ctx context.Context, conn *s3.Client, bucket, key string, optFns ...func(*s3.Options)) (tftags.KeyValueTags, error) {
	input := s3.GetObjectTaggingInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	output, err := conn.GetObjectTagging(ctx, &input, optFns...)

	if tfawserr.ErrCodeEquals(err, errCodeNoSuchTagSet, errCodeNoSuchTagSetError) {
		return tftags.New(ctx, nil), nil
	}

	if tfawserr.ErrHTTPStatusCodeEquals(err, http.StatusNotImplemented) { // Directory buckets return HTTP status code 501, NotImplemented.
		return tftags.New(ctx, nil), nil
	}

	if err != nil {
		return tftags.New(ctx, nil), err
	}

	return keyValueTags(ctx, output.TagSet), nil
}

// objectUpdateTags updates S3 object tags.
func objectUpdateTags(ctx context.Context, conn *s3.Client, bucket, key string, oldTagsMap, newTagsMap any, optFns ...func(*s3.Options)) error {
	oldTags := tftags.New(ctx, oldTagsMap)
	newTags := tftags.New(ctx, newTagsMap)

	// We need to also consider any existing ignored tags.
	allTags, err := objectListTags(ctx, conn, bucket, key, optFns...)

	if err != nil {
		return fmt.Errorf("listing resource tags (%s/%s): %w", bucket, key, err)
	}

	ignoredTags := allTags.Ignore(oldTags).Ignore(newTags)

	if len(newTags)+len(ignoredTags) > 0 {
		input := s3.PutObjectTaggingInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
			Tagging: &awstypes.Tagging{
				TagSet: svcTags(newTags.Merge(ignoredTags)),
			},
		}

		_, err := conn.PutObjectTagging(ctx, &input, optFns...)

		if err != nil {
			return fmt.Errorf("setting resource tags (%s/%s): %w", bucket, key, err)
		}
	} else if len(oldTags) > 0 && len(ignoredTags) == 0 {
		input := s3.DeleteObjectTaggingInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		}

		_, err := conn.DeleteObjectTagging(ctx, &input, optFns...)

		if err != nil {
			return fmt.Errorf("deleting resource tags (%s/%s): %w", bucket, key, err)
		}
	}

	return nil
}

// ListTags lists s3 service tags and set them in Context.
// It is called from outside this package.
func (p *servicePackage) ListTags(ctx context.Context, meta any, identifier, resourceType string) error {
	var (
		tags tftags.KeyValueTags
		err  error
	)
	c := meta.(*conns.AWSClient)
	conn := c.S3Client(ctx)

	switch resourceType {
	case "Bucket":
		tags, err = bucketListTags(ctx, conn, identifier)

	case "DirectoryBucket":
		tags, err = tfs3control.ListTags(ctx, c.S3ControlClient(ctx), identifier, c.AccountID(ctx))

	case "Object", "ObjectCopy", "BucketObject":
		var objectARN objectARN
		objectARN, err = parseObjectARN(identifier)
		if err != nil {
			return err
		}

		if isDirectoryBucket(objectARN.Bucket) {
			conn = meta.(*conns.AWSClient).S3ExpressClient(ctx)
		}

		var optFns []func(*s3.Options)
		// Via S3 access point: "Invalid configuration: region from ARN `us-east-1` does not match client region `aws-global` and UseArnRegion is `false`".
		if arn.IsARN(objectARN.Bucket) && conn.Options().Region == endpoints.AwsGlobalRegionID {
			optFns = append(optFns, func(o *s3.Options) { o.UseARNRegion = true })
		}

		tags, err = objectListTags(ctx, conn, objectARN.Bucket, objectARN.Key, optFns...)

	default:
		return nil
	}

	if err != nil {
		return err
	}

	if inContext, ok := tftags.FromContext(ctx); ok {
		inContext.TagsOut = option.Some(tags)
	}

	return nil
}

// UpdateTags updates s3 service tags.
// It is called from outside this package.
func (p *servicePackage) UpdateTags(ctx context.Context, meta any, identifier, resourceType string, oldTags, newTags any) error {
	c := meta.(*conns.AWSClient)
	conn := c.S3Client(ctx)

	switch resourceType {
	case "Bucket":
		return bucketUpdateTags(ctx, conn, identifier, oldTags, newTags)

	case "DirectoryBucket":
		return tfs3control.UpdateTags(ctx, c.S3ControlClient(ctx), identifier, c.AccountID(ctx), oldTags, newTags)

	case "Object", "ObjectCopy", "BucketObject":
		objectARN, err := parseObjectARN(identifier)
		if err != nil {
			return err
		}

		if isDirectoryBucket(objectARN.Bucket) {
			conn = meta.(*conns.AWSClient).S3ExpressClient(ctx)
		}

		var optFns []func(*s3.Options)
		// Via S3 access point: "Invalid configuration: region from ARN `us-east-1` does not match client region `aws-global` and UseArnRegion is `false`".
		if arn.IsARN(objectARN.Bucket) && conn.Options().Region == endpoints.AwsGlobalRegionID {
			optFns = append(optFns, func(o *s3.Options) { o.UseARNRegion = true })
		}

		return objectUpdateTags(ctx, conn, objectARN.Bucket, objectARN.Key, oldTags, newTags, optFns...)

	default:
		return nil
	}
}

func getContextTags(ctx context.Context) tftags.KeyValueTags {
	if inContext, ok := tftags.FromContext(ctx); ok {
		return inContext.TagsIn.UnwrapOrDefault()
	}
	return nil
}
