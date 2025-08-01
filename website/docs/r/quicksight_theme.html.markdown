---
subcategory: "QuickSight"
layout: "aws"
page_title: "AWS: aws_quicksight_theme"
description: |-
  Manages a QuickSight Theme.
---

# Resource: aws_quicksight_theme

Resource for managing a QuickSight Theme.

## Example Usage

### Basic Usage

```terraform
resource "aws_quicksight_theme" "example" {
  theme_id = "example"
  name     = "example"

  base_theme_id = "MIDNIGHT"

  configuration {
    data_color_palette {
      colors = [
        "#FFFFFF",
        "#111111",
        "#222222",
        "#333333",
        "#444444",
        "#555555",
        "#666666",
        "#777777",
        "#888888",
        "#999999"
      ]
      empty_fill_color = "#FFFFFF"
      min_max_gradient = [
        "#FFFFFF",
        "#111111",
      ]
    }
  }
}
```

## Argument Reference

The following arguments are required:

* `base_theme_id` - (Required) The ID of the theme that a custom theme will inherit from. All themes inherit from one of the starting themes defined by Amazon QuickSight. For a list of the starting themes, use ListThemes or choose Themes from within an analysis.
* `configuration` - (Required) The theme configuration, which contains the theme display properties. See [configuration](#configuration).
* `name` - (Required) Display name of the theme.
* `theme_id` - (Required, Forces new resource) Identifier of the theme.

The following arguments are optional:

* `aws_account_id` - (Optional, Forces new resource) AWS account ID. Defaults to automatically determined account ID of the Terraform AWS provider.
* `permissions` - (Optional) A set of resource permissions on the theme. Maximum of 64 items. See [permissions](#permissions).
* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `tags` - (Optional) Key-value map of resource tags. If configured with a provider [`default_tags` configuration block](/docs/providers/aws/index.html#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.
* `version_description` - (Optional) A description of the current theme version being created/updated.

### permissions

* `actions` - (Required) List of IAM actions to grant or revoke permissions on.
* `principal` - (Required) ARN of the principal. See the [ResourcePermission documentation](https://docs.aws.amazon.com/quicksight/latest/APIReference/API_ResourcePermission.html) for the applicable ARN values.

### configuration

* `data_color_palette` - (Optional) Color properties that apply to chart data colors. See [data_color_palette](#data_color_palette).
* `sheet` - (Optional) Display options related to sheets. See [sheet](#sheet).
* `typography` - (Optional) Determines the typography options. See [typography](#typography).
* `ui_color_palette` - (Optional) Color properties that apply to the UI and to charts, excluding the colors that apply to data. See [ui_color_palette](#ui_color_palette).

### data_color_palette

* `colors` - (Optional) List of hexadecimal codes for the colors. Minimum of 8 items and maximum of 20 items.
* `empty_fill_color` - (Optional) The hexadecimal code of a color that applies to charts where a lack of data is highlighted.
* `min_max_gradient` - (Optional) The minimum and maximum hexadecimal codes that describe a color gradient. List of exactly 2 items.

### sheet

* `tile` - (Optional) The display options for tiles. See [tile](#tile).
* `tile_layout` - (Optional) The layout options for tiles. See [tile_layout](#tile_layout).

### tile

* `border` - (Optional) The border around a tile. See [border](#border).

### border

* `show` - (Optional) The option to enable display of borders for visuals.

### tile_layout

* `gutter` - (Optional) The gutter settings that apply between tiles. See [gutter](#gutter).
* `margin` - (Optional) The margin settings that apply around the outside edge of sheets. See [margin](#margin).

### gutter

* `show` - (Optional) This Boolean value controls whether to display a gutter space between sheet tiles.

### margin

* `show` - (Optional) This Boolean value controls whether to display sheet margins.

### typography

* `font_families` - (Optional) Determines the list of font families. Maximum number of 5 items. See [font_families](#font_families).

### font_families

* `font_family` - (Optional) Font family name.

### ui_color_palette

* `accent` - (Optional) Color (hexadecimal) that applies to selected states and buttons.
* `accent_foreground` - (Optional) Color (hexadecimal) that applies to any text or other elements that appear over the accent color.
* `danger` - (Optional) Color (hexadecimal) that applies to error messages.
* `danger_foreground` - (Optional) Color (hexadecimal) that applies to any text or other elements that appear over the error color.
* `dimension` - (Optional) Color (hexadecimal) that applies to the names of fields that are identified as dimensions.
* `dimension_foreground` - (Optional) Color (hexadecimal) that applies to any text or other elements that appear over the dimension color.
* `measure` - (Optional) Color (hexadecimal) that applies to the names of fields that are identified as measures.
* `measure_foreground` - (Optional) Color (hexadecimal) that applies to any text or other elements that appear over the measure color.
* `primary_background` - (Optional) Color (hexadecimal) that applies to visuals and other high emphasis UI.
* `primary_foreground` - (Optional) Color (hexadecimal) of text and other foreground elements that appear over the primary background regions, such as grid lines, borders, table banding, icons, and so on.
* `secondary_background` - (Optional) Color (hexadecimal) that applies to the sheet background and sheet controls.
* `secondary_foreground` - (Optional) Color (hexadecimal) that applies to any sheet title, sheet control text, or UI that appears over the secondary background.
* `success` - (Optional) Color (hexadecimal) that applies to success messages, for example the check mark for a successful download.
* `success_foreground` - (Optional) Color (hexadecimal) that applies to any text or other elements that appear over the success color.
* `warning` - (Optional) Color (hexadecimal) that applies to warning and informational messages.
* `warning_foreground` - (Optional) Color (hexadecimal) that applies to any text or other elements that appear over the warning color.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - ARN of the theme.
* `created_time` - The time that the theme was created.
* `id` - A comma-delimited string joining AWS account ID and theme ID.
* `last_updated_time` - The time that the theme was last updated.
* `status` - The theme creation status.
* `tags_all` - A map of tags assigned to the resource, including those inherited from the provider [`default_tags` configuration block](/docs/providers/aws/index.html#default_tags-configuration-block).
* `version_number` - The version number of the theme version.

## Timeouts

[Configuration options](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

* `create` - (Default `5m`)
* `update` - (Default `5m`)
* `delete` - (Default `5m`)

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import a QuickSight Theme using the AWS account ID and theme ID separated by a comma (`,`). For example:

```terraform
import {
  to = aws_quicksight_theme.example
  id = "123456789012,example-id"
}
```

Using `terraform import`, import a QuickSight Theme using the AWS account ID and theme ID separated by a comma (`,`). For example:

```console
% terraform import aws_quicksight_theme.example 123456789012,example-id
```
