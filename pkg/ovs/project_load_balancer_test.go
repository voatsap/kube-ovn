package ovs

import (
	"testing"

	"github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	"github.com/stretchr/testify/require"

	"github.com/kubeovn/kube-ovn/pkg/ovsdb/ovnnb"
)

func projectLoadBalancerFixture() *ovnnb.LoadBalancer {
	protocol := "tcp"
	return &ovnnb.LoadBalancer{
		UUID:     "62876c82-eef9-41c4-9db2-c6ce51fc67c8",
		Name:     "kdc_project_9d7f6780db05461096d5b408ad2341dc_tcp",
		Protocol: &protocol,
		ExternalIDs: map[string]string{
			"vendor":                        "kube-ovn",
			ProjectLoadBalancerContract:     "v1",
			ProjectLoadBalancerProjectUID:   "9d7f6780-db05-4610-96d5-b408ad2341dc",
			ProjectLoadBalancerNamespaceUID: "b3b90d79-91ed-4a8d-b582-928f8e650535",
			ProjectLoadBalancerNonce:        "0c904f80-3c30-41a3-9e99-e35e1016a4b5",
			ProjectLoadBalancerFenceUUID:    "a8bca25f-0c20-4ddd-a829-d00cc32a74bb",
		},
	}
}

func TestProjectLoadBalancerCreationClosure(t *testing.T) {
	lb := projectLoadBalancerFixture()
	rows := map[string]model.Model{lb.UUID: lb}
	where := []ovsdb.Condition{{Column: "_uuid", Function: ovsdb.ConditionEqual, Value: ovsdb.UUID{GoUUID: lb.UUID}}}
	ids, err := ovsdb.NewOvsMap(lb.ExternalIDs)
	require.NoError(t, err)
	cases := []struct {
		name   string
		op     ovsdb.Operation
		denied bool
	}{
		{"legacy-generated-insert", ovsdb.Operation{Op: ovsdb.OperationInsert, UUIDName: "legacy-lb", Row: ovsdb.Row{"name": "vpc-legacy-tcp-load"}}, false},
		{"reserved-insert", ovsdb.Operation{Op: ovsdb.OperationInsert, Row: ovsdb.Row{"name": lb.Name}}, true},
		{"malformed-prefix-insert", ovsdb.Operation{Op: ovsdb.OperationInsert, Row: ovsdb.Row{"name": ProjectLoadBalancerPrefix + "invalid"}}, true},
		{"explicit-uuid-under-legacy-name", ovsdb.Operation{Op: ovsdb.OperationInsert, UUID: lb.UUID, Row: ovsdb.Row{"name": "legacy-name"}}, true},
		{"rename-legacy-to-reserved", ovsdb.Operation{Op: ovsdb.OperationUpdate, Where: []ovsdb.Condition{{Column: "name", Function: ovsdb.ConditionEqual, Value: "legacy"}}, Row: ovsdb.Row{"name": lb.Name}}, true},
		{"rename-reserved-to-legacy", ovsdb.Operation{Op: ovsdb.OperationUpdate, Where: where, Row: ovsdb.Row{"name": "legacy-name"}}, true},
		{"reserved-exact-unchanged-name", ovsdb.Operation{Op: ovsdb.OperationUpdate, Where: where, Row: ovsdb.Row{"name": lb.Name}}, false},
		{"reserved-delete", ovsdb.Operation{Op: ovsdb.OperationDelete, Where: where}, true},
		{"broad-delete", ovsdb.Operation{Op: ovsdb.OperationDelete}, true},
		{"reserved-vip-subtraction", ovsdb.Operation{Op: ovsdb.OperationMutate, Where: where, Mutations: []ovsdb.Mutation{{Column: "vips", Mutator: ovsdb.MutateOperationDelete, Value: ovsdb.OvsSet{}}}}, false},
		{"unchanged-owner-fields", ovsdb.Operation{Op: ovsdb.OperationUpdate, Where: where, Row: ovsdb.Row{"external_ids": ids}}, false},
		{"owner-fields-removal", ovsdb.Operation{Op: ovsdb.OperationUpdate, Where: where, Row: ovsdb.Row{"external_ids": ovsdb.OvsMap{}}}, true},
		{"owner-fields-mutation", ovsdb.Operation{Op: ovsdb.OperationMutate, Where: where, Mutations: []ovsdb.Mutation{{Column: "external_ids", Mutator: ovsdb.MutateOperationDelete, Value: ids}}}, true},
		{"reserved-name-mutation", ovsdb.Operation{Op: ovsdb.OperationMutate, Where: where, Mutations: []ovsdb.Mutation{{Column: "name", Mutator: ovsdb.MutateOperationInsert, Value: lb.Name}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.op.Table = ovnnb.LoadBalancerTable
			err := guardProjectLoadBalancerOperations([]ovsdb.Operation{tc.op}, rows)
			if tc.denied {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
	legacy := &ovnnb.LoadBalancer{UUID: "cb973cdd-307f-4c95-abcc-2f08bf9a77cb", Name: "legacy"}
	rows[legacy.UUID] = legacy
	err = guardProjectLoadBalancerOperations([]ovsdb.Operation{{Table: ovnnb.LoadBalancerTable, Op: ovsdb.OperationUpdate, Where: []ovsdb.Condition{{Column: "_uuid", Function: ovsdb.ConditionEqual, Value: ovsdb.UUID{GoUUID: legacy.UUID}}}, Row: ovsdb.Row{"external_ids": ids}}}, rows)
	require.Error(t, err, "a legacy row cannot acquire the prospective ownership marker")
}

func TestProjectLoadBalancerPrecreationOwnership(t *testing.T) {
	lb := projectLoadBalancerFixture()
	require.NoError(t, ValidateProjectLoadBalancer(lb))
	for _, key := range []string{"vendor", ProjectLoadBalancerContract, ProjectLoadBalancerProjectUID, ProjectLoadBalancerNamespaceUID, ProjectLoadBalancerNonce, ProjectLoadBalancerFenceUUID} {
		t.Run(key, func(t *testing.T) {
			changed := projectLoadBalancerFixture()
			delete(changed.ExternalIDs, key)
			require.Error(t, ValidateProjectLoadBalancer(changed))
		})
	}
	lb.Name = "kdc_project_ffffffffffffffffffffffffffffffff_tcp"
	require.Error(t, ValidateProjectLoadBalancer(lb))
	lb = projectLoadBalancerFixture()
	protocol := "udp"
	lb.Protocol = &protocol
	require.Error(t, ValidateProjectLoadBalancer(lb))
}

func TestProjectLoadBalancerCacheAbsenceHoldsMutation(t *testing.T) {
	lb := projectLoadBalancerFixture()
	for _, op := range []string{ovsdb.OperationUpdate, ovsdb.OperationMutate, ovsdb.OperationDelete} {
		t.Run(op, func(t *testing.T) {
			mutation := ovsdb.Operation{Table: ovnnb.LoadBalancerTable, Op: op, Where: []ovsdb.Condition{{Column: "_uuid", Function: ovsdb.ConditionEqual, Value: ovsdb.UUID{GoUUID: lb.UUID}}}}
			require.Error(t, guardProjectLoadBalancerOperations([]ovsdb.Operation{mutation}, nil))
			mutation.Where = nil
			require.Error(t, guardProjectLoadBalancerOperations([]ovsdb.Operation{mutation}, nil))
		})
	}
	legacy := &ovnnb.LoadBalancer{UUID: "cb973cdd-307f-4c95-abcc-2f08bf9a77cb", Name: "legacy"}
	for _, key := range projectLoadBalancerOwnerKeys() {
		legacy.ExternalIDs = map[string]string{key: ""}
		require.True(t, IsProjectLoadBalancer(legacy), key)
		ids, err := ovsdb.NewOvsMap(legacy.ExternalIDs)
		require.NoError(t, err)
		require.Error(t, guardProjectLoadBalancerOperations([]ovsdb.Operation{{Table: ovnnb.LoadBalancerTable, Op: ovsdb.OperationInsert, Row: ovsdb.Row{"name": "legacy", "external_ids": ids}}}, nil), key)
	}
}

func TestProjectLoadBalancerWireBypasses(t *testing.T) {
	lb := projectLoadBalancerFixture()
	legacy := &ovnnb.LoadBalancer{UUID: "cb973cdd-307f-4c95-abcc-2f08bf9a77cb", Name: "legacy"}
	rows := map[string]model.Model{lb.UUID: lb, legacy.UUID: legacy, "typed-nil": (*ovnnb.LoadBalancer)(nil)}
	for _, id := range []string{lb.UUID, legacy.UUID, "typed-nil"} {
		for _, row := range []ovsdb.Row{
			{"name": ovsdb.OvsSet{GoSet: []any{lb.Name}}},
			{"external_ids": []any{"map", []any{[]any{ProjectLoadBalancerNonce, ""}}}},
		} {
			op := ovsdb.Operation{Table: ovnnb.LoadBalancerTable, Op: ovsdb.OperationUpdate, Where: []ovsdb.Condition{{Column: "_uuid", Function: ovsdb.ConditionEqual, Value: ovsdb.UUID{GoUUID: id}}}, Row: row}
			require.Error(t, guardProjectLoadBalancerOperations([]ovsdb.Operation{op}, rows))
		}
	}
	for _, mutation := range []ovsdb.Mutation{
		{Column: "name", Mutator: ovsdb.MutateOperationInsert, Value: lb.Name},
		{Column: "external_ids", Mutator: ovsdb.MutateOperationInsert, Value: ovsdb.OvsMap{GoMap: map[any]any{ProjectLoadBalancerNonce: ""}}},
		{Column: "external_ids", Mutator: ovsdb.MutateOperationInsert, Value: []any{"map", []any{[]any{ProjectLoadBalancerNonce, ""}}}},
	} {
		op := ovsdb.Operation{Table: ovnnb.LoadBalancerTable, Op: ovsdb.OperationMutate, Where: []ovsdb.Condition{{Column: "_uuid", Function: ovsdb.ConditionEqual, Value: ovsdb.UUID{GoUUID: legacy.UUID}}}, Mutations: []ovsdb.Mutation{mutation}}
		require.Error(t, guardProjectLoadBalancerOperations([]ovsdb.Operation{op}, rows))
	}
	for _, field := range []string{"protocol", "selection_fields"} {
		op := ovsdb.Operation{Table: ovnnb.LoadBalancerTable, Op: ovsdb.OperationUpdate, Where: []ovsdb.Condition{{Column: "_uuid", Function: ovsdb.ConditionEqual, Value: ovsdb.UUID{GoUUID: lb.UUID}}}, Row: ovsdb.Row{field: ovsdb.OvsSet{GoSet: []any{"udp"}}}}
		require.Error(t, guardProjectLoadBalancerOperations([]ovsdb.Operation{op}, rows))
		op.Op = ovsdb.OperationMutate
		op.Row = nil
		op.Mutations = []ovsdb.Mutation{{Column: field, Mutator: ovsdb.MutateOperationInsert, Value: "udp"}}
		require.Error(t, guardProjectLoadBalancerOperations([]ovsdb.Operation{op}, rows))
	}
}

func TestProjectLoadBalancerRequestProtocolAndSession(t *testing.T) {
	lb := projectLoadBalancerFixture()
	require.NoError(t, validateProjectLoadBalancerRequest(lb, "TCP", nil))
	require.Error(t, validateProjectLoadBalancerRequest(lb, "udp", nil))
	require.Error(t, validateProjectLoadBalancerRequest(lb, "tcp", []string{"ip_src"}))
	lb.Name += "_session"
	require.Error(t, ValidateProjectLoadBalancer(lb))
	lb.SelectionFields = []string{"ipv6_src", "ip_src"}
	require.NoError(t, ValidateProjectLoadBalancer(lb))
	require.NoError(t, validateProjectLoadBalancerRequest(lb, "tcp", []string{"ip_src", "ipv6_src"}))
	require.Error(t, validateProjectLoadBalancerRequest(lb, "tcp", nil))
}
