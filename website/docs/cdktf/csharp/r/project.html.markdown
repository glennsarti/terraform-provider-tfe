---
layout: "tfe"
page_title: "Terraform Enterprise: tfe_project"
description: |-
Manages projects.
---


<!-- Please do not edit this file, it is generated. -->
# tfe_project

Provides a project resource.

## Example Usage

Basic usage:

```csharp
using Constructs;
using HashiCorp.Cdktf;
/*Provider bindings are generated by running cdktf get.
See https://cdk.tf/provider-generation for more details.*/
using Gen.Providers.Tfe;
class MyConvertedCode : TerraformStack
{
    public MyConvertedCode(Construct scope, string name) : base(scope, name)
    {
        var tfeOrganizationTestOrganization = new Organization.Organization(this, "test-organization", new OrganizationConfig {
            Email = "admin@company.com",
            Name = "my-org-name"
        });
        new Project.Project(this, "test", new ProjectConfig {
            Name = "projectname",
            Organization = Token.AsString(tfeOrganizationTestOrganization.Name)
        });
    }
}
```

## Argument Reference

The following arguments are supported:

* `Name` - (Required) Name of the project.
    *  TFE versions v202404-2 and earlier support between 3-36 characters
    *  TFE versions v202405-1 and later support between 3-40 characters
* `Organization` - (Optional) Name of the organization. If omitted, organization must be defined in the provider config.
* `Description` - (Optional) A description for the project.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `Id` - The project ID.

## Import

Projects can be imported; use `<PROJECT ID>` as the import ID. For example:

```shell
terraform import tfe_project.test prj-niVoeESBXT8ZREhr
```

<!-- cache-key: cdktf-0.17.0-pre.15 input-43a63826c3cef967034969841a29eab7e340b22c271c86f196fdfaa7f4ba39c9 -->