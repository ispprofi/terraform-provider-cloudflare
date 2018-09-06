package cloudflare

import (
	"fmt"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
)

func resourceCloudflareFirewallAccessRule() *schema.Resource {
	return &schema.Resource{
		Create: resourceCloudflareFirewallAccessRuleCreate,
		Read:   resourceCloudflareFirewallAccessRuleRead,
		Update: resourceCloudflareFirewallAccessRuleUpdate,
		Delete: resourceCloudflareFirewallAccessRuleDelete,
		Importer: &schema.ResourceImporter{
			State: resourceCloudflareFirewallAccessRuleImport,
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

func resourceCloudflareFirewallAccessRuleCreate(d *schema.ResourceData, meta interface{}) error {
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

	return resourceCloudflareFirewallAccessRuleRead(d, meta)
}

func resourceCloudflareFirewallAccessRuleRead(d *schema.ResourceData, meta interface{}) error {
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

var zoneAccessRules = make(map[string]map[string]cloudflare.AccessRule)

func getZoneAccessRules(client *cloudflare.API, zoneID string) (map[string]cloudflare.AccessRule, error) {
	if rules, exist := zoneAccessRules[zoneID]; exist {
		return rules, nil
	}
	rules := make(map[string]cloudflare.AccessRule)
	search := cloudflare.AccessRule{}
	search.Scope.Type = "zone"
	page := 1
	for {
		res, err := client.ListZoneAccessRules(zoneID, search, page)
		if err != nil {
			return nil, err
		}
		for _, rule := range res.Result {
			rules[rule.ID] = rule
		}
		if res.TotalPages == 0 || res.TotalPages == page {
			break
		}
		page += 1
	}
	zoneAccessRules[zoneID] = rules
	return rules, nil
}

func findZoneAccessRule(client *cloudflare.API, zoneID string, ruleID string) (*cloudflare.AccessRule, error) {
	rules, err := getZoneAccessRules(client, zoneID)
	if err != nil {
		return nil, err
	}
	if rule, exists := rules[ruleID]; exists {
		return &rule, nil
	}
	return nil, fmt.Errorf("cannot find zone firewall access rule for ID %v", ruleID)
}

var organizationAccessRules = make(map[string]map[string]cloudflare.AccessRule)

func getOrganizationAccessRules(client *cloudflare.API, orgID string) (map[string]cloudflare.AccessRule, error) {
	if rules, exist := organizationAccessRules[orgID]; exist {
		return rules, nil
	}
	rules := make(map[string]cloudflare.AccessRule)
	search := cloudflare.AccessRule{}
	search.Scope.Type = "organization"
	page := 1
	for {
		res, err := client.ListOrganizationAccessRules(orgID, search, page)
		if err != nil {
			return nil, err
		}
		for _, rule := range res.Result {
			rules[rule.ID] = rule
		}
		if res.TotalPages == 0 || res.TotalPages == page {
			break
		}
		page += 1
	}
	organizationAccessRules[orgID] = rules
	return rules, nil
}

func findOrganizationAccessRule(client *cloudflare.API, orgID string, ruleID string) (*cloudflare.AccessRule, error) {
	rules, err := getOrganizationAccessRules(client, orgID)
	if err != nil {
		return nil, err
	}
	if rule, exists := rules[ruleID]; exists {
		return &rule, nil
	}
	return nil, fmt.Errorf("cannot find organization firewall access rule for ID %v", ruleID)
}

func resourceCloudflareFirewallAccessRuleUpdate(d *schema.ResourceData, meta interface{}) error {
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

	return resourceCloudflareFirewallAccessRuleRead(d, meta)
}

func resourceCloudflareFirewallAccessRuleDelete(d *schema.ResourceData, meta interface{}) error {
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

func resourceCloudflareFirewallAccessRuleImport(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
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
