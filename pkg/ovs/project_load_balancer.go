package ovs

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	"github.com/kubeovn/kube-ovn/pkg/ovsdb/ovnnb"
)

// Project-owned default load balancers are precreated by their owner. Their
// names are permanently reserved, including after the owner deletes the rows.
// The vendor must never create, rename or explicitly reinsert these rows.
// This is an absence protocol; it does not fence ordinary VIP mutations.
const (
	ProjectLoadBalancerPrefix       = "kdc_project_"
	ProjectLoadBalancerContract     = "kdc-lb-contract"
	ProjectLoadBalancerProjectUID   = "kdc-project-uid"
	ProjectLoadBalancerNamespaceUID = "kdc-namespace-uid"
	ProjectLoadBalancerNonce        = "kdc-lb-nonce"
	ProjectLoadBalancerFenceUUID    = "kdc-lb-fence-uuid"
)

var projectLoadBalancerName = regexp.MustCompile(`^kdc_project_([a-f0-9]{32})_(tcp|udp|sctp)(_session)?$`)

// IsProjectLoadBalancerName also reserves malformed names under this prefix.
func IsProjectLoadBalancerName(name string) bool {
	return strings.HasPrefix(name, ProjectLoadBalancerPrefix)
}

func IsProjectLoadBalancer(lb *ovnnb.LoadBalancer) bool {
	if lb == nil {
		return false
	}
	if IsProjectLoadBalancerName(lb.Name) {
		return true
	}
	for _, key := range projectLoadBalancerOwnerKeys() {
		if _, present := lb.ExternalIDs[key]; present {
			return true
		}
	}
	return false
}

func projectLoadBalancerOwnerKeys() []string {
	return []string{ProjectLoadBalancerContract, ProjectLoadBalancerProjectUID, ProjectLoadBalancerNamespaceUID, ProjectLoadBalancerNonce, ProjectLoadBalancerFenceUUID}
}

// ValidateProjectLoadBalancer rejects adoption of an unmarked reserved row.
func ValidateProjectLoadBalancer(lb *ovnnb.LoadBalancer) error {
	if lb == nil {
		return errors.New("reserved load balancer is missing")
	}
	parts := projectLoadBalancerName.FindStringSubmatch(lb.Name)
	if len(parts) == 0 || lb.UUID == "" || lb.ExternalIDs["vendor"] != "kube-ovn" || lb.ExternalIDs[ProjectLoadBalancerContract] != "v1" {
		return fmt.Errorf("reserved load balancer %q has no valid owner receipt", lb.Name)
	}
	if strings.ReplaceAll(lb.ExternalIDs[ProjectLoadBalancerProjectUID], "-", "") != parts[1] {
		return fmt.Errorf("reserved load balancer %q has a different Project owner", lb.Name)
	}
	for _, key := range []string{ProjectLoadBalancerNamespaceUID, ProjectLoadBalancerNonce, ProjectLoadBalancerFenceUUID} {
		if !canonicalProjectLoadBalancerUUID(lb.ExternalIDs[key]) {
			return fmt.Errorf("reserved load balancer %q is missing %s", lb.Name, key)
		}
	}
	if !canonicalProjectLoadBalancerUUID(lb.UUID) || !canonicalProjectLoadBalancerUUID(lb.ExternalIDs[ProjectLoadBalancerProjectUID]) {
		return errors.New("project load balancer identity requires canonical nonzero UUIDs")
	}
	if lb.Protocol == nil || *lb.Protocol != parts[2] {
		return fmt.Errorf("reserved load balancer %q has the wrong protocol", lb.Name)
	}
	fields := slices.Clone(lb.SelectionFields)
	slices.Sort(fields)
	if (parts[3] == "" && len(fields) != 0) || (parts[3] != "" && !slices.Equal(fields, []string{"ip_src", "ipv6_src"})) {
		return fmt.Errorf("reserved load balancer %q has the wrong session selection fields", lb.Name)
	}
	return nil
}

func canonicalProjectLoadBalancerUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func validateProjectLoadBalancerRequest(lb *ovnnb.LoadBalancer, protocol string, selectFields []string) error {
	if err := ValidateProjectLoadBalancer(lb); err != nil {
		return err
	}
	actual, requested := slices.Clone(lb.SelectionFields), slices.Clone(selectFields)
	slices.Sort(actual)
	slices.Sort(requested)
	if *lb.Protocol != strings.ToLower(protocol) || !slices.Equal(actual, requested) {
		return errors.New("precreated Project load balancer does not match the requested protocol/selection fields")
	}
	return nil
}

// Transact checks the creation closure at the common NB transaction boundary.
// All ordinary vendor operations still use the shared ovsDbClient delegate.
func (c *OVNNbClient) Transact(method string, operations []ovsdb.Operation) error {
	var rows map[string]model.Model
	for _, op := range operations {
		if op.Table == ovnnb.LoadBalancerTable && op.Op != ovsdb.OperationInsert {
			if c.Client != nil && c.Cache() != nil {
				if table := c.Cache().Table(ovnnb.LoadBalancerTable); table != nil {
					rows = table.Rows()
				}
			}
			break
		}
	}
	if err := guardProjectLoadBalancerOperations(operations, rows); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	var err error
	if operations, err = withLoadBalancerIdentityWaits(operations, rows); err != nil {
		return err
	}
	return c.ovsDbClient.Transact(method, operations)
}

func withLoadBalancerIdentityWaits(operations []ovsdb.Operation, rows map[string]model.Model) ([]ovsdb.Operation, error) {
	result := make([]ovsdb.Operation, 0, len(operations)*2)
	for _, op := range operations {
		if op.Table == ovnnb.LoadBalancerTable && (op.Op == ovsdb.OperationUpdate || op.Op == ovsdb.OperationMutate || op.Op == ovsdb.OperationDelete) {
			lb := rows[loadBalancerOperationUUID(op)].(*ovnnb.LoadBalancer)
			ids, err := ovsdb.NewOvsMap(lb.ExternalIDs)
			if err != nil {
				return nil, fmt.Errorf("encode load balancer identity wait: %w", err)
			}
			timeout := 0
			result = append(result, ovsdb.Operation{
				Op: ovsdb.OperationWait, Table: ovnnb.LoadBalancerTable, Timeout: &timeout,
				Where:   []ovsdb.Condition{{Column: "_uuid", Function: ovsdb.ConditionEqual, Value: ovsdb.UUID{GoUUID: lb.UUID}}},
				Columns: []string{"_uuid", "name", "external_ids", "protocol", "selection_fields"}, Until: string(ovsdb.WaitConditionEqual),
				Rows: []ovsdb.Row{{"_uuid": ovsdb.UUID{GoUUID: lb.UUID}, "name": lb.Name, "external_ids": ids, "protocol": loadBalancerProtocolValue(lb), "selection_fields": loadBalancerSelectionValue(lb)}},
			})
		}
		result = append(result, op)
	}
	return result, nil
}

func guardProjectLoadBalancerOperations(operations []ovsdb.Operation, rows map[string]model.Model) error {
	for _, op := range operations {
		if op.Table != ovnnb.LoadBalancerTable {
			continue
		}
		if err := validateLoadBalancerWireFields(op); err != nil {
			return err
		}
		switch op.Op {
		case ovsdb.OperationInsert:
			if _, explicit := op.Row["_uuid"]; explicit || op.UUID != "" {
				return errors.New("vendor load balancer insertion cannot specify a UUID")
			}
			name, ok := op.Row["name"].(string)
			if !ok || IsProjectLoadBalancerName(name) {
				return fmt.Errorf("vendor cannot create reserved load balancer %q", name)
			}
			if projectContractInRow(op.Row) {
				return errors.New("vendor cannot create a Project-owned load balancer")
			}
		case ovsdb.OperationUpdate, ovsdb.OperationMutate, ovsdb.OperationDelete:
			if err := guardExistingProjectLoadBalancer(op, rows); err != nil {
				return err
			}
		}
	}
	return nil
}

func guardExistingProjectLoadBalancer(op ovsdb.Operation, rows map[string]model.Model) error {
	id := loadBalancerOperationUUID(op)
	old, known := rows[id].(*ovnnb.LoadBalancer)
	if id == "" || !known || old == nil {
		return errors.New("load balancer mutation requires an exact known UUID; retry after the monitor catches up")
	}
	for _, mutation := range op.Mutations {
		if mutation.Column == "external_ids" && projectOwnerKeysInMap(mutation.Value) && !IsProjectLoadBalancer(old) {
			return errors.New("vendor cannot add prospective ownership fields to a legacy load balancer")
		}
	}
	// A reserved name cannot be assigned through a legacy row's rename.
	if name, ok := op.Row["name"].(string); ok && IsProjectLoadBalancerName(name) {
		if old.Name != name {
			return errors.New("vendor cannot rename a load balancer into a reserved name")
		}
	}
	if projectContractInRow(op.Row) {
		if !IsProjectLoadBalancerName(old.Name) {
			return errors.New("vendor cannot adopt a legacy load balancer for a Project")
		}
	}
	if !IsProjectLoadBalancer(old) {
		return nil
	}
	if op.Op == ovsdb.OperationDelete {
		return fmt.Errorf("vendor cannot delete Project-owned load balancer %q", old.Name)
	}
	if err := ValidateProjectLoadBalancer(old); err != nil {
		return err
	}
	return guardProjectLoadBalancerIdentity(op, old)
}

func guardProjectLoadBalancerIdentity(op ovsdb.Operation, lb *ovnnb.LoadBalancer) error {
	if name, ok := op.Row["name"].(string); ok && name != lb.Name {
		return errors.New("vendor cannot rename a Project-owned load balancer")
	}
	if value, present := op.Row["protocol"]; present {
		protocol, ok := loadBalancerStringSet(value)
		if !ok || len(protocol) != 1 || lb.Protocol == nil || protocol[0] != *lb.Protocol {
			return errors.New("vendor cannot change Project load balancer protocol")
		}
	}
	if value, present := op.Row["selection_fields"]; present {
		fields, ok := loadBalancerStringSet(value)
		actual := slices.Clone(lb.SelectionFields)
		slices.Sort(actual)
		slices.Sort(fields)
		if !ok || !slices.Equal(fields, actual) {
			return errors.New("vendor cannot change Project load balancer selection fields")
		}
	}
	if raw, ok := op.Row["external_ids"]; ok {
		ids, ok := raw.(ovsdb.OvsMap)
		if !ok {
			return errors.New("unrecognized Project load balancer ownership update")
		}
		for _, key := range []string{"vendor", ProjectLoadBalancerContract, ProjectLoadBalancerProjectUID, ProjectLoadBalancerNamespaceUID, ProjectLoadBalancerNonce, ProjectLoadBalancerFenceUUID} {
			if ids.GoMap[key] != lb.ExternalIDs[key] {
				return fmt.Errorf("vendor cannot change Project load balancer ownership field %s", key)
			}
		}
	}
	for _, mutation := range op.Mutations {
		if mutation.Column == "name" || mutation.Column == "external_ids" || mutation.Column == "protocol" || mutation.Column == "selection_fields" {
			return errors.New("vendor cannot mutate Project load balancer identity")
		}
	}
	return nil
}

func validateLoadBalancerWireFields(op ovsdb.Operation) error {
	if value, present := op.Row["name"]; present {
		if _, canonical := value.(string); !canonical {
			return errors.New("unrecognized load balancer name representation")
		}
	}
	if value, present := op.Row["external_ids"]; present && !canonicalLoadBalancerMap(value) {
		return errors.New("unrecognized load balancer ownership representation")
	}
	for _, mutation := range op.Mutations {
		if mutation.Column == "name" {
			return errors.New("vendor cannot mutate load balancer names")
		}
		if mutation.Column == "external_ids" {
			if canonicalLoadBalancerMap(mutation.Value) {
				continue
			}
			if mutation.Mutator == ovsdb.MutateOperationDelete {
				if _, valid := loadBalancerStringSet(mutation.Value); valid {
					continue
				}
			}
			return errors.New("unrecognized load balancer ownership mutation")
		}
	}
	return nil
}

func canonicalLoadBalancerMap(raw any) bool {
	value, ok := raw.(ovsdb.OvsMap)
	if !ok {
		return false
	}
	for key, item := range value.GoMap {
		if _, ok := key.(string); !ok {
			return false
		}
		if _, ok := item.(string); !ok {
			return false
		}
	}
	return true
}

func loadBalancerStringSet(raw any) ([]string, bool) {
	if value, ok := raw.(string); ok {
		return []string{value}, true
	}
	value, ok := raw.(ovsdb.OvsSet)
	if !ok {
		return nil, false
	}
	result := make([]string, 0, len(value.GoSet))
	for _, item := range value.GoSet {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		result = append(result, text)
	}
	return result, true
}

func loadBalancerOperationUUID(op ovsdb.Operation) string {
	for _, condition := range op.Where {
		if condition.Column == "_uuid" && condition.Function == ovsdb.ConditionEqual {
			if id, ok := condition.Value.(ovsdb.UUID); ok {
				return id.GoUUID
			}
		}
	}
	return ""
}

func projectContractInRow(row ovsdb.Row) bool {
	return projectOwnerKeysInMap(row["external_ids"])
}

func projectOwnerKeysInMap(raw any) bool {
	ids, ok := raw.(ovsdb.OvsMap)
	if !ok {
		return false
	}
	for _, key := range projectLoadBalancerOwnerKeys() {
		if _, present := ids.GoMap[key]; present {
			return true
		}
	}
	return false
}

func loadBalancerProtocolValue(lb *ovnnb.LoadBalancer) ovsdb.OvsSet {
	if lb.Protocol == nil {
		return ovsdb.OvsSet{}
	}
	return ovsdb.OvsSet{GoSet: []any{*lb.Protocol}}
}

func loadBalancerSelectionValue(lb *ovnnb.LoadBalancer) ovsdb.OvsSet {
	values := make([]any, 0, len(lb.SelectionFields))
	for _, field := range lb.SelectionFields {
		values = append(values, field)
	}
	return ovsdb.OvsSet{GoSet: values}
}
