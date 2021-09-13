package auth0

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"gopkg.in/auth0.v5/management"
)

func newLogStream() *schema.Resource {
	return &schema.Resource{
		CreateContext: createLogStream,
		ReadContext:   readLogStream,
		UpdateContext: updateLogStream,
		DeleteContext: deleteLogStream,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.StringInSlice([]string{
					"eventbridge",
					"eventgrid",
					"http",
					"datadog",
					"splunk",
					"sumo",
				}, true),
				ForceNew:    true,
				Description: "Type of the log stream, which indicates the sink provider",
			},
			"status": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ValidateFunc: validation.StringInSlice([]string{
					"active",
					"paused",
					"suspended",
				}, false),
				Description: "Status of the LogStream",
			},
			"sink": {
				Type:     schema.TypeList,
				MaxItems: 1,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"aws_account_id": {
							Type:         schema.TypeString,
							Optional:     true,
							ForceNew:     true,
							RequiredWith: []string{"sink.0.aws_region"},
						},
						"aws_region": {
							Type:         schema.TypeString,
							Optional:     true,
							ForceNew:     true,
							RequiredWith: []string{"sink.0.aws_account_id"},
						},
						"aws_partner_event_source": {
							Type:        schema.TypeString,
							Computed:    true,
							Optional:    true,
							Description: "Name of the Partner Event Source to be used with AWS, if the type is 'eventbridge'",
						},
						"azure_subscription_id": {
							Type:         schema.TypeString,
							Optional:     true,
							ForceNew:     true,
							RequiredWith: []string{"sink.0.azure_resource_group", "sink.0.azure_region"},
						},
						"azure_resource_group": {
							Type:         schema.TypeString,
							Optional:     true,
							ForceNew:     true,
							RequiredWith: []string{"sink.0.azure_subscription_id", "sink.0.azure_region"},
						},
						"azure_region": {
							Type:         schema.TypeString,
							Optional:     true,
							ForceNew:     true,
							RequiredWith: []string{"sink.0.azure_subscription_id", "sink.0.azure_resource_group"},
						},
						"azure_partner_topic": {
							Type:        schema.TypeString,
							Computed:    true,
							Optional:    true,
							Description: "Name of the Partner Topic to be used with Azure, if the type is 'eventgrid'",
						},
						"http_content_format": {
							Type:         schema.TypeString,
							Optional:     true,
							RequiredWith: []string{"sink.0.http_endpoint", "sink.0.http_authorization", "sink.0.http_content_type"},
							Description:  "HTTP Content Format can be JSONLINES or JSONARRAY",
							ValidateFunc: validation.StringInSlice([]string{
								"JSONLINES",
								"JSONARRAY",
							}, false),
						},
						"http_content_type": {
							Type:         schema.TypeString,
							Optional:     true,
							Description:  "HTTP Content Type",
							RequiredWith: []string{"sink.0.http_endpoint", "sink.0.http_authorization", "sink.0.http_content_format"},
						},
						"http_endpoint": {
							Type:         schema.TypeString,
							Optional:     true,
							Description:  "HTTP endpoint",
							RequiredWith: []string{"sink.0.http_content_format", "sink.0.http_authorization", "sink.0.http_content_type"},
						},
						"http_authorization": {
							Type:         schema.TypeString,
							Optional:     true,
							Sensitive:    true,
							RequiredWith: []string{"sink.0.http_content_format", "sink.0.http_endpoint", "sink.0.http_content_type"},
						},
						"http_custom_headers": {
							Type:        schema.TypeSet,
							Elem:        &schema.Schema{Type: schema.TypeString},
							Optional:    true,
							Default:     nil,
							Description: "Custom HTTP headers",
						},

						"datadog_region": {
							Type:      schema.TypeString,
							Sensitive: true,
							Optional:  true,
							ValidateFunc: validation.StringInSlice([]string{
								"eu",
								"us",
							}, false),
							RequiredWith: []string{"sink.0.datadog_api_key"},
						},
						"datadog_api_key": {
							Type:         schema.TypeString,
							Optional:     true,
							Sensitive:    true,
							RequiredWith: []string{"sink.0.datadog_region"},
						},
						"splunk_domain": {
							Type:         schema.TypeString,
							Optional:     true,
							RequiredWith: []string{"sink.0.splunk_token", "sink.0.splunk_port", "sink.0.splunk_secure"},
						},
						"splunk_token": {
							Type:         schema.TypeString,
							Optional:     true,
							Sensitive:    true,
							RequiredWith: []string{"sink.0.splunk_domain", "sink.0.splunk_port", "sink.0.splunk_secure"},
						},
						"splunk_port": {
							Type:         schema.TypeString,
							Optional:     true,
							RequiredWith: []string{"sink.0.splunk_domain", "sink.0.splunk_token", "sink.0.splunk_secure"},
						},
						"splunk_secure": {
							Type:         schema.TypeBool,
							Optional:     true,
							Default:      nil,
							RequiredWith: []string{"sink.0.splunk_domain", "sink.0.splunk_port", "sink.0.splunk_token"},
						},
						"sumo_source_address": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  nil,
						},
					},
				},
			},
		},
	}
}

func createLogStream(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ls := expandLogStream(d)

	api := m.(*management.Management)
	if err := api.LogStream.Create(ls, management.Context(ctx)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(ls.GetID())

	// The Management API only allows updating a log stream's status. Therefore
	// if the status field was present in the configuration, we perform an
	// additional operation to modify it.
	s := String(d, "status")
	if s != nil && s != ls.Status {
		err := api.LogStream.Update(ls.GetID(), &management.LogStream{Status: s}, management.Context(ctx))
		if err != nil {
			return diag.FromErr(err)
		}
	}

	return readLogStream(ctx, d, m)
}

func readLogStream(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	ls, err := api.LogStream.Read(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}

	d.SetId(ls.GetID())
	_ = d.Set("name", ls.Name)
	_ = d.Set("status", ls.Status)
	_ = d.Set("type", ls.Type)
	_ = d.Set("sink", flattenLogStreamSink(ls.Sink))
	return nil
}

func updateLogStream(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ls := expandLogStream(d)

	api := m.(*management.Management)
	err := api.LogStream.Update(d.Id(), ls, management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	return readLogStream(ctx, d, m)
}

func deleteLogStream(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	err := api.LogStream.Delete(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}
	return nil
}

func flattenLogStreamSink(sink interface{}) []interface{} {

	var m interface{}

	switch o := sink.(type) {
	case *management.LogStreamSinkAmazonEventBridge:
		m = flattenLogStreamSinkAmazonEventBridge(o)
	case *management.LogStreamSinkAzureEventGrid:
		m = flattenLogStreamSinkAzureEventGrid(o)
	case *management.LogStreamSinkHTTP:
		m = flattenLogStreamSinkHTTP(o)
	case *management.LogStreamSinkDatadog:
		m = flattenLogStreamSinkDatadog(o)
	case *management.LogStreamSinkSplunk:
		m = flattenLogStreamSinkSplunk(o)
	case *management.LogStreamSinkSumo:
		m = flattenLogStreamSinkSumo(o)
	}
	return []interface{}{m}
}

func flattenLogStreamSinkAmazonEventBridge(o *management.LogStreamSinkAmazonEventBridge) interface{} {
	return map[string]interface{}{
		"aws_account_id":           o.GetAccountID(),
		"aws_region":               o.GetRegion(),
		"aws_partner_event_source": o.GetPartnerEventSource(),
	}
}

func flattenLogStreamSinkAzureEventGrid(o *management.LogStreamSinkAzureEventGrid) interface{} {
	return map[string]interface{}{
		"azure_subscription_id": o.GetSubscriptionID(),
		"azure_resource_group":  o.GetResourceGroup(),
		"azure_region":          o.GetRegion(),
		"azure_partner_topic":   o.GetPartnerTopic(),
	}
}

func flattenLogStreamSinkHTTP(o *management.LogStreamSinkHTTP) interface{} {
	data := map[string]interface{}{
		"http_endpoint":       o.GetEndpoint(),
		"http_content_format": o.GetContentFormat(),
		"http_content_type":   o.GetContentType(),
		"http_authorization":  o.GetAuthorization(),
		"http_custom_headers": o.CustomHeaders,
	}
	return data
}

func flattenLogStreamSinkDatadog(o *management.LogStreamSinkDatadog) interface{} {
	return map[string]interface{}{
		"datadog_region":  o.GetRegion(),
		"datadog_api_key": o.GetAPIKey(),
	}
}

func flattenLogStreamSinkSplunk(o *management.LogStreamSinkSplunk) interface{} {
	return map[string]interface{}{
		"splunk_domain": o.GetDomain(),
		"splunk_token":  o.GetToken(),
		"splunk_port":   o.GetPort(),
		"splunk_secure": o.GetSecure(),
	}
}

func flattenLogStreamSinkSumo(o *management.LogStreamSinkSumo) interface{} {
	return map[string]interface{}{
		"sumo_source_address": o.GetSourceAddress(),
	}
}

func expandLogStream(d ResourceData) *management.LogStream {

	ls := &management.LogStream{
		Name:   String(d, "name"),
		Type:   String(d, "type", IsNewResource()),
		Status: String(d, "status", Not(IsNewResource())),
	}

	s := d.Get("type").(string)

	List(d, "sink").Elem(func(d ResourceData) {
		switch s {
		case management.LogStreamTypeAmazonEventBridge:
			// LogStreamTypeAmazonEventBridge cannot be updated
			if d.IsNewResource() {
				ls.Sink = expandLogStreamSinkAmazonEventBridge(d)
			}
		case management.LogStreamTypeAzureEventGrid:
			// LogStreamTypeAzureEventGrid cannot be updated
			if d.IsNewResource() {
				ls.Sink = expandLogStreamSinkAzureEventGrid(d)
			}
		case management.LogStreamTypeHTTP:
			ls.Sink = expandLogStreamSinkHTTP(d)
		case management.LogStreamTypeDatadog:
			ls.Sink = expandLogStreamSinkDatadog(d)
		case management.LogStreamTypeSplunk:
			ls.Sink = expandLogStreamSinkSplunk(d)
		case management.LogStreamTypeSumo:
			ls.Sink = expandLogStreamSinkSumo(d)
		default:
			log.Printf("[WARN]: Unsupported log stream sink %s", s)
			log.Printf("[WARN]: Raise an issue with the auth0 provider in order to support it:")
			log.Printf("[WARN]: 	https://github.com/alekc/terraform-provider-auth0/issues/new")
		}
	})

	return ls
}

func expandLogStreamSinkAmazonEventBridge(d ResourceData) *management.LogStreamSinkAmazonEventBridge {
	o := &management.LogStreamSinkAmazonEventBridge{
		AccountID: String(d, "aws_account_id"),
		Region:    String(d, "aws_region"),
	}
	return o
}

func expandLogStreamSinkAzureEventGrid(d ResourceData) *management.LogStreamSinkAzureEventGrid {
	o := &management.LogStreamSinkAzureEventGrid{
		SubscriptionID: String(d, "azure_subscription_id"),
		ResourceGroup:  String(d, "azure_resource_group"),
		Region:         String(d, "azure_region"),
		PartnerTopic:   String(d, "azure_partner_topic"),
	}
	return o
}

func expandLogStreamSinkHTTP(d ResourceData) *management.LogStreamSinkHTTP {
	o := &management.LogStreamSinkHTTP{
		ContentFormat: String(d, "http_content_format"),
		ContentType:   String(d, "http_content_type"),
		Endpoint:      String(d, "http_endpoint"),
		Authorization: String(d, "http_authorization"),
		CustomHeaders: Set(d, "http_custom_headers").List(),
	}
	return o
}
func expandLogStreamSinkDatadog(d ResourceData) *management.LogStreamSinkDatadog {
	o := &management.LogStreamSinkDatadog{
		Region: String(d, "datadog_region"),
		APIKey: String(d, "datadog_api_key"),
	}
	return o
}
func expandLogStreamSinkSplunk(d ResourceData) *management.LogStreamSinkSplunk {
	o := &management.LogStreamSinkSplunk{
		Domain: String(d, "splunk_domain"),
		Token:  String(d, "splunk_token"),
		Port:   String(d, "splunk_port"),
		Secure: Bool(d, "splunk_secure"),
	}
	return o
}
func expandLogStreamSinkSumo(d ResourceData) *management.LogStreamSinkSumo {
	o := &management.LogStreamSinkSumo{
		SourceAddress: String(d, "sumo_source_address"),
	}
	return o
}
