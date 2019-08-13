package cloudflare

import (
	"os"
	"testing"
)

func TestAPI_VirtualDNS(t *testing.T) {
	api, err := New(os.Getenv("CF_API_KEY"), os.Getenv("CF_API_EMAIL"))
	if err != nil {
		t.Fatal("cannot create client", err)
	}

	api.OrganizationID = os.Getenv("CF_ORG_ID")
	vdnsID := os.Getenv("VDNS_ID")

	list, err := api.ListOrganizationVirtualDNS(api.OrganizationID)
	if err != nil {
		t.Fatal("cannot list instances", err)
	}
	for i, item := range list {
		t.Logf("List[%d]: %+v", i, item)
	}

	vv, err := api.OrganizationVirtualDNS(api.OrganizationID, vdnsID)
	if err != nil {
		t.Fatal("cannot fetch instance", err)
	}
	t.Logf("Instance: %+v", vv)

	err = api.UpdateOrganizationVirtualDNS(api.OrganizationID, vdnsID, vv)
	if err != nil {
		t.Fatal("cannot update instance", err)
	}
	t.Log("Updated without error")
}
