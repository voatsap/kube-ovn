package ovs

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	"github.com/stretchr/testify/require"

	"github.com/kubeovn/kube-ovn/pkg/ovsdb/ovnnb"
)

// This qualification uses the real ovsdb-server transaction engine. The usual
// libovsdb in-memory fixture does not establish weak reference or GC behavior.
func realProjectLoadBalancerDatabase(t *testing.T) string {
	t.Helper()
	tool, server := os.Getenv("KDC_TEST_OVSDB_TOOL"), os.Getenv("KDC_TEST_OVSDB_SERVER")
	if tool == "" || server == "" {
		t.Skip("set KDC_TEST_OVSDB_TOOL and KDC_TEST_OVSDB_SERVER for real OVSDB qualification")
	}
	dir, err := os.MkdirTemp("", "kdc-nb-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(dir)) })
	data, err := json.Marshal(ovnnb.Schema())
	require.NoError(t, err)
	schema, database := filepath.Join(dir, "schema.json"), filepath.Join(dir, "nb.db")
	require.NoError(t, os.WriteFile(schema, data, 0o600))
	output, err := exec.Command(tool, "create", database, schema).CombinedOutput()
	require.NoError(t, err, string(output))
	log, err := os.Create(filepath.Join(dir, "server.log"))
	require.NoError(t, err)
	socket := filepath.Join(dir, "socket")
	command := exec.Command(server, "--remote=punix:"+socket, "--unixctl="+filepath.Join(dir, "control"), "--pidfile="+filepath.Join(dir, "pid"), database)
	command.Stdout, command.Stderr = log, log
	require.NoError(t, command.Start())
	t.Cleanup(func() {
		require.NoError(t, command.Process.Kill())
		_ = command.Wait()
		require.NoError(t, log.Close())
	})
	require.Eventually(t, func() bool {
		_, err := os.Stat(socket)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)
	return "unix:" + socket
}

func projectLoadBalancerLiveRows(t *testing.T, c *OVNNbClient, table string, where []ovsdb.Condition) []ovsdb.Row {
	t.Helper()
	operations := []ovsdb.Operation{{Op: ovsdb.OperationSelect, Table: table, Where: where}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := c.Client.Transact(ctx, operations...)
	require.NoError(t, err)
	_, err = ovsdb.CheckOperationResults(results, operations)
	require.NoError(t, err)
	return results[0].Rows
}

func projectLoadBalancerUUIDWhere(id string) []ovsdb.Condition {
	return []ovsdb.Condition{{Column: "_uuid", Function: ovsdb.ConditionEqual, Value: ovsdb.UUID{GoUUID: id}}}
}

func TestProjectLoadBalancerRealOVSDBAbsenceClosure(t *testing.T) {
	endpoint := realProjectLoadBalancerDatabase(t)
	c, err := newOvnNbClient(t, endpoint, 5)
	require.NoError(t, err)
	t.Cleanup(c.Close)
	lb := projectLoadBalancerFixture()
	lb.UUID = ""
	operations, err := c.Create(lb)
	require.NoError(t, err)
	// The owner has its own connection and is the sole writer allowed to insert
	// these rows. Bypass the vendor guard only to represent that owner here.
	require.NoError(t, c.ovsDbClient.Transact("project-owner-create", operations))
	require.Eventually(t, func() bool {
		found, getErr := c.GetLoadBalancer(lb.Name, true)
		if getErr != nil || found == nil {
			return false
		}
		lb = found
		return true
	}, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, c.CreateLoadBalancer(lb.Name, "tcp"))
	require.Error(t, c.CreateLoadBalancer(lb.Name, "udp"))
	require.Error(t, c.CreateLoadBalancer(lb.Name, "tcp", "ip_src"))
	require.Error(t, c.DeleteLoadBalancer(lb.Name))
	require.NoError(t, c.CreateLoadBalancer("ordinary-lb", "tcp"))
	require.Eventually(t, func() bool { found, _ := c.GetLoadBalancer("ordinary-lb", true); return found != nil }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, c.DeleteLoadBalancers(nil))
	require.Len(t, projectLoadBalancerLiveRows(t, c, ovnnb.LoadBalancerTable, nil), 1, "startup GC must retain precreated reserved rows")

	// Changing identity after vendor classification must abort the actual
	// database transaction, rather than trusting a monitor snapshot.
	vendor := []ovsdb.Operation{{Op: ovsdb.OperationUpdate, Table: ovnnb.LoadBalancerTable, Where: projectLoadBalancerUUIDWhere(lb.UUID), Row: ovsdb.Row{"vips": ovsdb.OvsMap{GoMap: map[any]any{"10.0.0.1:80": "10.0.0.2:80"}}}}}
	fenced, err := withLoadBalancerIdentityWaits(vendor, c.Cache().Table(ovnnb.LoadBalancerTable).Rows())
	require.NoError(t, err)
	changed := map[string]string{}
	for key, value := range lb.ExternalIDs {
		changed[key] = value
	}
	changed[ProjectLoadBalancerNonce] = "325f7aa1-fd78-4d1f-b760-51134db4e84d"
	ids, err := ovsdb.NewOvsMap(changed)
	require.NoError(t, err)
	require.NoError(t, c.ovsDbClient.Transact("test-concurrent-owner-change", []ovsdb.Operation{{Op: ovsdb.OperationUpdate, Table: ovnnb.LoadBalancerTable, Where: projectLoadBalancerUUIDWhere(lb.UUID), Row: ovsdb.Row{"external_ids": ids}}}))
	require.Error(t, c.ovsDbClient.Transact("test-stale-identity", fenced))
	originalIDs, err := ovsdb.NewOvsMap(lb.ExternalIDs)
	require.NoError(t, err)
	require.NoError(t, c.ovsDbClient.Transact("test-restore-owner", []ovsdb.Operation{{Op: ovsdb.OperationUpdate, Table: ovnnb.LoadBalancerTable, Where: projectLoadBalancerUUIDWhere(lb.UUID), Row: ovsdb.Row{"external_ids": originalIDs}}}))

	require.NoError(t, c.CreateBareLogicalSwitch("late-reference"))
	require.Eventually(t, func() bool { found, _ := c.GetLogicalSwitch("late-reference", true); return found != nil }, 5*time.Second, 10*time.Millisecond)
	switchRow, err := c.GetLogicalSwitch("late-reference", false)
	require.NoError(t, err)
	require.NoError(t, c.ovsDbClient.Transact("project-owner-exact-delete", []ovsdb.Operation{{Op: ovsdb.OperationDelete, Table: ovnnb.LoadBalancerTable, Where: projectLoadBalancerUUIDWhere(lb.UUID)}}))
	require.Empty(t, projectLoadBalancerLiveRows(t, c, ovnnb.LoadBalancerTable, nil))

	// OVN schema 7.11.0 has WEAK LS/LR/LB-group -> LB references. A delayed
	// attachment succeeds but is pruned and cannot resurrect the deleted root.
	require.NoError(t, c.Transact("test-late-weak-reference", []ovsdb.Operation{{Op: ovsdb.OperationMutate, Table: ovnnb.LogicalSwitchTable, Where: projectLoadBalancerUUIDWhere(switchRow.UUID), Mutations: []ovsdb.Mutation{{Column: "load_balancer", Mutator: ovsdb.MutateOperationInsert, Value: ovsdb.OvsSet{GoSet: []any{ovsdb.UUID{GoUUID: lb.UUID}}}}}}}))
	liveSwitch := projectLoadBalancerLiveRows(t, c, ovnnb.LogicalSwitchTable, projectLoadBalancerUUIDWhere(switchRow.UUID))
	require.Equal(t, ovsdb.OvsSet{GoSet: []any{}}, liveSwitch[0]["load_balancer"])
	require.Empty(t, projectLoadBalancerLiveRows(t, c, ovnnb.LoadBalancerTable, nil))

	// Health-check rows are non-root and require a strong LB reference. A
	// delayed insertion after LB deletion is garbage-collected in this commit.
	require.NoError(t, c.ovsDbClient.Transact("test-late-health-check", []ovsdb.Operation{{Op: ovsdb.OperationInsert, Table: ovnnb.LoadBalancerHealthCheckTable, UUIDName: "late_hc", Row: ovsdb.Row{"vip": "10.0.0.1:80"}}, {Op: ovsdb.OperationMutate, Table: ovnnb.LoadBalancerTable, Where: projectLoadBalancerUUIDWhere(lb.UUID), Mutations: []ovsdb.Mutation{{Column: "health_check", Mutator: ovsdb.MutateOperationInsert, Value: ovsdb.OvsSet{GoSet: []any{ovsdb.UUID{GoUUID: "late_hc"}}}}}}}))
	require.Empty(t, projectLoadBalancerLiveRows(t, c, ovnnb.LoadBalancerHealthCheckTable, nil))

	require.Eventually(t, func() bool { found, _ := c.GetLoadBalancer(lb.Name, true); return found == nil }, 5*time.Second, 10*time.Millisecond)
	require.Error(t, c.CreateLoadBalancer(lb.Name, "tcp"))
	require.Error(t, c.Transact("test-explicit-old-uuid", []ovsdb.Operation{{Op: ovsdb.OperationInsert, Table: ovnnb.LoadBalancerTable, UUID: lb.UUID, Row: ovsdb.Row{"name": "alias"}}}))
	c.Close()
	c, err = newOvnNbClient(t, endpoint, 5)
	require.NoError(t, err)
	t.Cleanup(c.Close)
	require.NoError(t, c.DeleteLoadBalancers(nil))
	require.Error(t, c.CreateLoadBalancer(lb.Name, "tcp"))
	require.Empty(t, projectLoadBalancerLiveRows(t, c, ovnnb.LoadBalancerTable, nil), "monitor restart must preserve terminal absence")
}
