package cloudflare

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// VirtualDNS represents a Virtual DNS configuration.
//
// API reference: https://api.cloudflare.com/#dns-firewall-accounts--properties
type VirtualDNS struct {
	ID                   string   `json:"id,omitempty"`
	Name                 string   `json:"name"`
	OriginIPs            []string `json:"origin_ips"`
	VirtualDNSIPs        []string `json:"virtual_dns_ips,omitempty"`
	MinimumCacheTTL      uint     `json:"minimum_cache_ttl"`
	MaximumCacheTTL      uint     `json:"maximum_cache_ttl"`
	DeprecateAnyRequests bool     `json:"deprecate_any_requests"`
	ModifiedOn           string   `json:"modified_on,omitempty"`
	EcsFallback          bool     `json:"ecs_fallback"`
	RateLimit            uint     `json:"ratelimit"`
}

// VirtualDNSAnalyticsMetrics respresents a group of aggregated Virtual DNS metrics.
type VirtualDNSAnalyticsMetrics struct {
	QueryCount         *int64   `json:"queryCount"`
	UncachedCount      *int64   `json:"uncachedCount"`
	StaleCount         *int64   `json:"staleCount"`
	ResponseTimeAvg    *float64 `json:"responseTimeAvg"`
	ResponseTimeMedian *float64 `json:"responseTimeMedian"`
	ResponseTime90th   *float64 `json:"responseTime90th"`
	ResponseTime99th   *float64 `json:"responseTime99th"`
}

// VirtualDNSAnalytics represents a set of aggregated Virtual DNS metrics.
// TODO: Add the queried data and not only the aggregated values.
type VirtualDNSAnalytics struct {
	Totals VirtualDNSAnalyticsMetrics `json:"totals"`
	Min    VirtualDNSAnalyticsMetrics `json:"min"`
	Max    VirtualDNSAnalyticsMetrics `json:"max"`
}

// VirtualDNSUserAnalyticsOptions represents range and dimension selection on analytics endpoint
type VirtualDNSUserAnalyticsOptions struct {
	Metrics []string
	Since   *time.Time
	Until   *time.Time
}

// VirtualDNSResponse represents a Virtual DNS response.
type VirtualDNSResponse struct {
	Response
	Result *VirtualDNS `json:"result"`
}

// VirtualDNSListResponse represents an array of Virtual DNS responses.
type VirtualDNSListResponse struct {
	Response
	Result []*VirtualDNS `json:"result"`
}

// VirtualDNSAnalyticsResponse represents a Virtual DNS analytics response.
type VirtualDNSAnalyticsResponse struct {
	Response
	Result VirtualDNSAnalytics `json:"result"`
}

// CreateUserVirtualDNS creates a new Virtual DNS cluster.
//
// API reference: https://api.cloudflare.com/#virtual-dns-users--create-a-virtual-dns-cluster
func (api *API) CreateUserVirtualDNS(v *VirtualDNS) (*VirtualDNS, error) {
	return api.createVirtualDNS("/user/virtual_dns", v)
}

// CreateOrganizationVirtualDNS creates a new Virtual DNS cluster.
//
// API reference: https://api.cloudflare.com/#dns-firewall-accounts--create-dns-firewall-cluster
func (api *API) CreateOrganizationVirtualDNS(organizationID string, v *VirtualDNS) (*VirtualDNS, error) {
	uri := fmt.Sprintf("/accounts/%v/virtual_dns", organizationID)
	return api.createVirtualDNS(uri, v)
}

func (api *API) createVirtualDNS(uri string, v *VirtualDNS) (*VirtualDNS, error) {
	res, err := api.makeRequest("POST", uri, v)
	if err != nil {
		return nil, errors.Wrap(err, errMakeRequestError)
	}
	response := &VirtualDNSResponse{}
	err = json.Unmarshal(res, response)
	if err != nil {
		return nil, errors.Wrap(err, errUnmarshalError)
	}
	return response.Result, nil
}

// UserVirtualDNS fetches a single virtual DNS cluster.
//
// API reference: https://api.cloudflare.com/#virtual-dns-users--get-a-virtual-dns-cluster
func (api *API) UserVirtualDNS(virtualDNSID string) (*VirtualDNS, error) {
	uri := "/user/virtual_dns/" + virtualDNSID
	return api.getVirtualDNS(uri)
}

// OrganizationVirtualDNS fetches a single virtual DNS cluster.
//
// API reference: https://api.cloudflare.com/#dns-firewall-accounts--dns-firewall-cluster-details
func (api *API) OrganizationVirtualDNS(organizationID string, virtualDNSID string) (*VirtualDNS, error) {
	uri := fmt.Sprintf("/accounts/%v/virtual_dns/%v", organizationID, virtualDNSID)
	return api.getVirtualDNS(uri)
}

func (api *API) getVirtualDNS(uri string) (*VirtualDNS, error) {
	res, err := api.makeRequest("GET", uri, nil)
	if err != nil {
		return nil, errors.Wrap(err, errMakeRequestError)
	}
	response := &VirtualDNSResponse{}
	err = json.Unmarshal(res, response)
	if err != nil {
		return nil, errors.Wrap(err, errUnmarshalError)
	}
	return response.Result, nil
}

// ListUserVirtualDNS lists the virtual DNS clusters associated with an account.
//
// API reference: https://api.cloudflare.com/#virtual-dns-users--get-virtual-dns-clusters
func (api *API) ListUserVirtualDNS() ([]*VirtualDNS, error) {
	return api.listVirtualDNS("/user/virtual_dns")
}

// ListOrganizationVirtualDNS lists the virtual DNS clusters associated with an account.
//
// API reference: https://api.cloudflare.com/#dns-firewall-accounts--list-dns-firewall-clusters
func (api *API) ListOrganizationVirtualDNS(organizationID string) ([]*VirtualDNS, error) {
	uri := fmt.Sprintf("/accounts/%v/virtual_dns", organizationID)
	return api.listVirtualDNS(uri)
}

func (api *API) listVirtualDNS(uri string) ([]*VirtualDNS, error) {
	res, err := api.makeRequest("GET", uri, nil)
	if err != nil {
		return nil, errors.Wrap(err, errMakeRequestError)
	}
	response := &VirtualDNSListResponse{}
	err = json.Unmarshal(res, response)
	if err != nil {
		return nil, errors.Wrap(err, errUnmarshalError)
	}
	return response.Result, nil
}

// UpdateUserVirtualDNS updates a Virtual DNS cluster.
//
// API reference: https://api.cloudflare.com/#virtual-dns-users--modify-a-virtual-dns-cluster
func (api *API) UpdateUserVirtualDNS(virtualDNSID string, vv *VirtualDNS) error {
	uri := "/user/virtual_dns/" + virtualDNSID
	return api.updateVirtualDNS(uri, vv)
}

// UpdateOrganizationVirtualDNS updates a Virtual DNS cluster.
//
// API reference: https://api.cloudflare.com/#dns-firewall-accounts--update-dns-firewall-cluster
func (api *API) UpdateOrganizationVirtualDNS(organizationID string, virtualDNSID string, vv *VirtualDNS) error {
	uri := fmt.Sprintf("/accounts/%v/virtual_dns/%v", organizationID, virtualDNSID)
	return api.updateVirtualDNS(uri, vv)
}

func (api *API) updateVirtualDNS(uri string, vv *VirtualDNS) error {
	res, err := api.makeRequest("PUT", uri, vv)
	if err != nil {
		return errors.Wrap(err, errMakeRequestError)
	}
	response := &VirtualDNSResponse{}
	err = json.Unmarshal(res, response)
	if err != nil {
		return errors.Wrap(err, errUnmarshalError)
	}
	return nil
}

// DeleteUserVirtualDNS deletes a Virtual DNS cluster. Note that this cannot be
// undone, and will stop all traffic to that cluster.
//
// API reference: https://api.cloudflare.com/#virtual-dns-users--delete-a-virtual-dns-cluster
func (api *API) DeleteUserVirtualDNS(virtualDNSID string) error {
	uri := "/user/virtual_dns/" + virtualDNSID
	return api.deleteVirtualDNS(uri)
}

// DeleteOrganizationVirtualDNS deletes a Virtual DNS cluster. Note that this cannot be
// undone, and will stop all traffic to that cluster.
//
// API reference: https://api.cloudflare.com/#dns-firewall-accounts--delete-dns-firewall-cluster
func (api *API) DeleteOrganizationVirtualDNS(organizationID string, virtualDNSID string) error {
	uri := fmt.Sprintf("/accounts/%v/virtual_dns/%v", organizationID, virtualDNSID)
	return api.deleteVirtualDNS(uri)
}

func (api *API) deleteVirtualDNS(uri string) error {
	res, err := api.makeRequest("DELETE", uri, nil)
	if err != nil {
		return errors.Wrap(err, errMakeRequestError)
	}
	response := &VirtualDNSResponse{}
	err = json.Unmarshal(res, response)
	if err != nil {
		return errors.Wrap(err, errUnmarshalError)
	}
	return nil
}

// encode encodes non-nil fields into URL encoded form.
func (o VirtualDNSUserAnalyticsOptions) encode() string {
	v := url.Values{}
	if o.Since != nil {
		v.Set("since", (*o.Since).UTC().Format(time.RFC3339))
	}
	if o.Until != nil {
		v.Set("until", (*o.Until).UTC().Format(time.RFC3339))
	}
	if o.Metrics != nil {
		v.Set("metrics", strings.Join(o.Metrics, ","))
	}
	return v.Encode()
}

// UserVirtualDNSUserAnalytics retrieves analytics report for a specified dimension and time range
func (api *API) UserVirtualDNSUserAnalytics(virtualDNSID string, o VirtualDNSUserAnalyticsOptions) (VirtualDNSAnalytics, error) {
	uri := "/user/virtual_dns/" + virtualDNSID + "/dns_analytics/report?" + o.encode()
	return api.virtualDNSUserAnalytics(uri)
}

// OrganizationVirtualDNSUserAnalytics retrieves analytics report for a specified dimension and time range
//
// API referernce: https://api.cloudflare.com/#dns-firewall-analytics-accounts--table
func (api *API) OrganizationVirtualDNSUserAnalytics(organizationID string, virtualDNSID string, o VirtualDNSUserAnalyticsOptions) (VirtualDNSAnalytics, error) {
	uri := fmt.Sprintf("/accounts/%v/virtual_dns/%v/dns_analytics/report?%v", organizationID, virtualDNSID, o.encode())
	return api.virtualDNSUserAnalytics(uri)
}

func (api *API) virtualDNSUserAnalytics(uri string) (VirtualDNSAnalytics, error) {
	res, err := api.makeRequest("GET", uri, nil)
	if err != nil {
		return VirtualDNSAnalytics{}, errors.Wrap(err, errMakeRequestError)
	}
	response := VirtualDNSAnalyticsResponse{}
	err = json.Unmarshal(res, &response)
	if err != nil {
		return VirtualDNSAnalytics{}, errors.Wrap(err, errUnmarshalError)
	}
	return response.Result, nil
}
