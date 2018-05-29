package cloudflare

import (
	"fmt"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
)

func resourceCloudFlareFirewallAccessRule() *schema.Resource {
	return &schema.Resource{
		Create: resourceCloudFlareFirewallAccessRuleCreate,
		Read:   resourceCloudFlareFirewallAccessRuleRead,
		Update: resourceCloudFlareFirewallAccessRuleUpdate,
		Delete: resourceCloudFlareFirewallAccessRuleDelete,
		Importer: &schema.ResourceImporter{
			State: resourceCloudFlareFirewallAccessRuleImport,
		},

		SchemaVersion: 0,
		Schema: map[string]*schema.Schema{
			"zone": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"zone_id": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"org_id": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"scope": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"zone", "organization"}, false),
			},

			"mode": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringInSlice([]string{"block", "challenge", "whitelist", "js_challenge"}, false),
			},

			"target": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringInSlice([]string{"ip", "ip_range", "asn", "country"}, false),
			},

			"value": {
				Type:     schema.TypeString,
				Required: true,
			},

			"notes": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringLenBetween(0, 1024),
			},
		},
	}
}

func resourceCloudFlareFirewallAccessRuleCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*cloudflare.API)
	zoneName := d.Get("zone").(string)
	scope := d.Get("scope").(string)

	zoneID, err := client.ZoneIDByName(zoneName)
	if err != nil {
		return err
	}
	d.Set("zone_id", zoneID)

	orgID := "N/A"
	if scope != "zone" {
		zone, err := client.ZoneDetails(zoneID)
		if err != nil {
			return err
		}
		orgID = zone.Owner.ID
	}
	d.Set("org_id", orgID)

	rule := cloudflare.AccessRule{
		Mode: d.Get("mode").(string),
		Configuration: cloudflare.AccessRuleConfiguration{
			Target: d.Get("target").(string),
			Value:  d.Get("value").(string),
		},
		Notes: d.Get("notes").(string),
	}

	var res *cloudflare.AccessRuleResponse
	if scope == "zone" {
		res, err = client.CreateZoneAccessRule(zoneID, rule)
		if err != nil {
			return err
		}
	} else {
		res, err = client.CreateOrganizationAccessRule(orgID, rule)
		if err != nil {
			return err
		}
	}
	ruleID := res.Result.ID
	if ruleID == "" {
		return fmt.Errorf("failed to find ID in Create response; resource was empty")
	}
	d.SetId(ruleID)

	return resourceCloudFlareFirewallAccessRuleRead(d, meta)
}

func resourceCloudFlareFirewallAccessRuleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*cloudflare.API)
	zoneID := d.Get("zone_id").(string)
	orgID := d.Get("org_id").(string)
	scope := d.Get("scope").(string)
	ruleID := d.Id()

	var err error
	var rule *cloudflare.AccessRule
	if scope == "zone" {
		rule, err = findZoneAccessRule(client, zoneID, ruleID)
	} else {
		rule, err = findOrganizationAccessRule(client, orgID, ruleID)
	}
	if err != nil {
		return err
	}

	d.Set("mode", rule.Mode)
	d.Set("target", rule.Configuration.Target)
	d.Set("value", rule.Configuration.Value)
	d.Set("notes", rule.Notes)
	return nil
}

func findZoneAccessRule(client *cloudflare.API, zoneID string, ruleID string) (*cloudflare.AccessRule, error) {
	page := 1
	search := cloudflare.AccessRule{}
	search.Scope.Type = "zone"
	for {
		res, err := client.ListZoneAccessRules(zoneID, search, page)
		if err != nil {
			return nil, err
		}
		for _, rule := range res.Result {
			if rule.ID == ruleID {
				return &rule, nil
			}
		}
		if res.TotalPages == 0 || res.TotalPages == page {
			return nil, fmt.Errorf("cannot find zone firewall access rule for ID %v", ruleID)
		}
		page += 1
	}
}

func findOrganizationAccessRule(client *cloudflare.API, orgID string, ruleID string) (*cloudflare.AccessRule, error) {
	search := cloudflare.AccessRule{}
	search.Scope.Type = "organization"
	page := 1
	for {
		res, err := client.ListOrganizationAccessRules(orgID, search, page)
		if err != nil {
			return nil, err
		}
		for _, rule := range res.Result {
			if rule.ID == ruleID {
				return &rule, nil
			}
		}
		if res.TotalPages == 0 || res.TotalPages == page {
			return nil, fmt.Errorf("cannot find organization firewall access rule for ID %v", ruleID)
		}
		page += 1
	}
}

func resourceCloudFlareFirewallAccessRuleUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*cloudflare.API)
	zoneID := d.Get("zone_id").(string)
	orgID := d.Get("org_id").(string)
	scope := d.Get("scope").(string)
	ruleID := d.Id()

	var rule = cloudflare.AccessRule{
		ID:   ruleID,
		Mode: d.Get("mode").(string),
		Configuration: cloudflare.AccessRuleConfiguration{
			Target: d.Get("target").(string),
			Value:  d.Get("value").(string),
		},
		Notes: d.Get("notes").(string),
	}

	if scope == "zone" {
		if _, err := client.UpdateZoneAccessRule(zoneID, ruleID, rule); err != nil {
			return err
		}
	} else {
		if _, err := client.UpdateOrganizationAccessRule(orgID, ruleID, rule); err != nil {
			return err
		}
	}

	return resourceCloudFlareFirewallAccessRuleRead(d, meta)
}

func resourceCloudFlareFirewallAccessRuleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*cloudflare.API)
	zoneID := d.Get("zone_id").(string)
	orgID := d.Get("org_id").(string)
	scope := d.Get("scope").(string)
	ruleID := d.Id()

	if scope == "zone" {
		if _, err := client.DeleteZoneAccessRule(zoneID, ruleID); err != nil {
			return err
		}
	} else {
		if _, err := client.DeleteOrganizationAccessRule(orgID, ruleID); err != nil {
			return err
		}
	}
	return nil
}

func resourceCloudFlareFirewallAccessRuleImport(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	client := meta.(*cloudflare.API)

	tokens := strings.SplitN(d.Id(), "/", 3)
	if len(tokens) != 3 {
		return nil, fmt.Errorf("invalid id (\"%s\") specified, should be in format \"scope/zoneName/ruleID\"", d.Id())
	}

	scope := tokens[0]
	zoneName := tokens[1]
	ruleID := tokens[2]

	zoneID, err := client.ZoneIDByName(zoneName)
	if err != nil {
		return nil, err
	}

	orgID := "N/A"
	if scope != "zone" {
		zone, err := client.ZoneDetails(zoneID)
		if err != nil {
			return nil, err
		}
		orgID = zone.Owner.ID
	}

	d.Set("scope", scope)
	d.Set("zone", zoneName)
	d.Set("zone_id", zoneID)
	d.Set("org_id", orgID)
	d.SetId(ruleID)
	return []*schema.ResourceData{d}, nil
}
