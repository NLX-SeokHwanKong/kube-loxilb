package loadbalancer

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/loxilb-io/kube-loxilb/pkg/ippool"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/loxilb-io/kube-loxilb/pkg/agent/config"
	"github.com/loxilb-io/kube-loxilb/pkg/api"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
)

func quicTestService() *corev1.Service {
	return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", UID: types.UID("service-1"), Annotations: map[string]string{quicCIDAnnotation: "yes"}},
		Spec: corev1.ServiceSpec{ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyTypeLocal,
			Ports: []corev1.ServicePort{{Name: "https", Protocol: corev1.ProtocolTCP, Port: 443, NodePort: 30443}, {Name: "h3", Protocol: corev1.ProtocolUDP, Port: 443, NodePort: 30443}}}}
}
func quicTestSlice(node, ip string, ready bool) *discoveryv1.EndpointSlice {
	name, protocol := "h3", corev1.ProtocolUDP
	targetPort := int32(443)
	return &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "slice-" + node, Namespace: "default", Labels: map[string]string{discoveryv1.LabelServiceName: "web"}},
		AddressType: discoveryv1.AddressTypeIPv4, Ports: []discoveryv1.EndpointPort{{Name: &name, Protocol: &protocol, Port: &targetPort}},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{ip}, NodeName: &node, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}}}
}
func quicTestManager(slices ...*discoveryv1.EndpointSlice) *Manager {
	index := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	for _, s := range slices {
		_ = index.Add(s)
	}
	nodeIndex := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	_ = nodeIndex.Add(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "a"}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "198.51.100.21"}}}})
	return &Manager{networkConfig: &config.NetworkConfig{}, kubeClient: fake.NewSimpleClientset(), nodeLister: corelisters.NewNodeLister(nodeIndex), endpointSliceLister: discoverylisters.NewEndpointSliceLister(index)}
}

func TestQuicCIDPolicy(t *testing.T) {
	cases := []struct {
		name             string
		pod              bool
		change           func(*corev1.Service)
		slices           []*discoveryv1.EndpointSlice
		allowed, refused bool
	}{
		{name: "T1", pod: true, allowed: true},
		{name: "T2", slices: []*discoveryv1.EndpointSlice{quicTestSlice("a", "192.0.2.21", true), quicTestSlice("b", "192.0.2.22", true)}, allowed: true},
		{name: "T3 Cluster", change: func(s *corev1.Service) { s.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeCluster }, refused: true},
		{name: "T3 duplicate node", slices: []*discoveryv1.EndpointSlice{func() *discoveryv1.EndpointSlice {
			s := quicTestSlice("a", "192.0.2.21", true)
			ep := s.Endpoints[0]
			ep.Addresses = []string{"192.0.2.22"}
			s.Endpoints = append(s.Endpoints, ep)
			return s
		}()}, refused: true},
		{name: "missing node", slices: []*discoveryv1.EndpointSlice{func() *discoveryv1.EndpointSlice {
			s := quicTestSlice("a", "192.0.2.21", true)
			s.Endpoints[0].NodeName = nil
			return s
		}()}, refused: true},
		{name: "no ready endpoint", slices: []*discoveryv1.EndpointSlice{quicTestSlice("a", "192.0.2.21", false)}, refused: true},
		{name: "CR8", pod: true, change: func(s *corev1.Service) { s.Annotations[quicCIDCRAnnotation] = "8" }, refused: true},
		{name: "CR negative", pod: true, change: func(s *corev1.Service) { s.Annotations[quicCIDCRAnnotation] = "-1" }, refused: true},
		{name: "CR malformed", pod: true, change: func(s *corev1.Service) { s.Annotations[quicCIDCRAnnotation] = "abc" }, refused: true},
		{name: "disabled", pod: true, change: func(s *corev1.Service) { s.Annotations[quicCIDAnnotation] = "no" }},
		{name: "removed", pod: true, change: func(s *corev1.Service) { s.Annotations = nil }},
		{name: "TCP only", pod: true, change: func(s *corev1.Service) { s.Spec.Ports = s.Spec.Ports[:1] }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := quicTestService()
			if c.change != nil {
				c.change(svc)
			}
			q, reason := quicTestManager(c.slices...).quicCIDPolicy(svc, c.pod, false, false, "ipv4", 0, false, false, []string{"198.51.100.21"})
			if (q != nil) != c.allowed || (reason != "") != c.refused {
				t.Fatalf("q=%v reason=%q", q, reason)
			}
		})
	}
}

func TestQuicCIDModesAndRotation(t *testing.T) {
	for mode := 0; mode <= 5; mode++ {
		for cr := 0; cr < 8; cr++ {
			s := quicTestService()
			s.Annotations[quicCIDCRAnnotation] = string(rune('0' + cr))
			q, reason := quicTestManager().quicCIDPolicy(s, true, false, false, "ipv4", mode, false, false, []string{"192.0.2.21"})
			if mode <= 2 || mode == api.LBModeHostOneArm {
				if q == nil || int(q.Cr) != cr || q.SidLen != 4 {
					t.Fatalf("mode %d cr %d: %v %s", mode, cr, q, reason)
				}
			} else if q != nil || reason == "" {
				t.Fatal("unsupported mode accepted")
			}
		}
	}
}

func TestQuicCIDSliceDedupAndReadiness(t *testing.T) {
	s := quicTestService()
	a := quicTestSlice("a", "192.0.2.21", true)
	b := a.DeepCopy()
	b.Name = "duplicate-slice"
	if r := quicCIDLocalTopology(s, []*discoveryv1.EndpointSlice{a, b}); r != "" {
		t.Fatal(r)
	}
	dead := a.Endpoints[0]
	dead.Addresses = []string{"192.0.2.22"}
	no := false
	dead.Conditions.Ready = &no
	a.Endpoints = append(a.Endpoints, dead)
	if r := quicCIDLocalTopology(s, []*discoveryv1.EndpointSlice{a}); r != "" {
		t.Fatal(r)
	}
	s.Spec.PublishNotReadyAddresses = true
	if r := quicCIDLocalTopology(s, []*discoveryv1.EndpointSlice{a}); r == "" {
		t.Fatal("published non-ready endpoint ignored")
	}
}

func TestQuicCIDModelUDPOnlyAndOmission(t *testing.T) {
	m := quicTestManager()
	svc := quicTestService()
	args := &LbArgs{externalIP: "192.0.2.100", endpointIPs: []string{"198.51.100.21"}, lbMode: 0, sel: api.LbSelHash, quicLb: &api.QuicLbArg{SidLen: 4, Cr: 3}}
	for _, port := range svc.Spec.Ports {
		model, err := m.makeLoxiLoadBalancerModel(args, svc, port)
		if err != nil {
			t.Fatal(err)
		}
		if port.Protocol == corev1.ProtocolUDP {
			if model.Service.Sel != 7 || model.Service.QuicLb == nil || model.Service.QuicLb.Cr != 3 {
				t.Fatalf("%+v", model.Service)
			}
		} else {
			if model.Service.Sel != api.LbSelHash || model.Service.QuicLb != nil {
				t.Fatalf("TCP changed: %+v", model.Service)
			}
		}
	}
	args.quicLb = nil
	model, err := m.makeLoxiLoadBalancerModel(args, svc, svc.Spec.Ports[1])
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(model)
	if strings.Contains(string(raw), "quicLb") || model.Service.Sel != api.LbSelHash {
		t.Fatal(string(raw))
	}
}

func TestQuicCIDRefusalEventAggregation(t *testing.T) {
	m := quicTestManager()
	s := quicTestService()
	m.reportQuicCIDRefusal(s, "multiple ready endpoints")
	m.reportQuicCIDRefusal(s, "multiple ready endpoints")
	events, err := m.kubeClient.CoreV1().Events(s.Namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil || len(events.Items) != 1 {
		t.Fatalf("events=%v err=%v", events, err)
	}
	e := events.Items[0]
	if e.Count != 2 || e.Reason != quicCIDRefused || e.InvolvedObject.UID != s.UID || e.Type != corev1.EventTypeWarning {
		t.Fatalf("%+v", e)
	}
}

// Exercise the real reconciliation and REST serialization path against an HTTP
// fixture. This is controller unit evidence, not Kubernetes/datapath evidence.
type quicHTTPFixture struct {
	mu              sync.Mutex
	state           map[string]api.LoadBalancerModel
	calls           []string
	failMethod      string
	failProtocol    string
	failAfterDelete bool
}

func (f *quicHTTPFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"result":"Success"}`)
		return
	}
	var model api.LoadBalancerModel
	if err := json.NewDecoder(r.Body).Decode(&model); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	protocol := model.Service.Protocol
	f.calls = append(f.calls, r.Method+" "+protocol)
	if r.Method == f.failMethod && (f.failProtocol == "" || f.failProtocol == protocol) {
		if r.Method == http.MethodDelete && f.failAfterDelete {
			delete(f.state, protocol)
		}
		w.WriteHeader(503)
		fmt.Fprint(w, `{"result":"injected API failure"}`)
		return
	}
	if r.Method == http.MethodDelete {
		if _, exists := f.state[protocol]; !exists {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"result":"no-rule error"}`)
			return
		}
		delete(f.state, protocol)
	} else {
		f.state[protocol] = model
	}
	fmt.Fprint(w, `{"result":"Success"}`)
}
func quicReconcileFixture(t *testing.T) (*Manager, *corev1.Service, cache.Indexer, *quicHTTPFixture) {
	t.Helper()
	svc := quicTestService()
	class := "loxilb.io/loxilb"
	svc.Spec.LoadBalancerClass = &class
	svc.Spec.Selector = map[string]string{"app": "web"}
	svc.Annotations[endPointSelAnnotation] = "hash"
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.0.2.100"}}
	m := quicTestManager()
	m.networkConfig.NumZoneInst = 1
	m.networkConfig.LoxilbLoadBalancerClass = class
	m.lbCache = make(LbCacheTable)
	_, cidr, _ := net.ParseCIDR("203.0.113.0/24")
	m.ipPoolTbl = map[string]*ippool.IPPool{defaultPoolName: {NetCIDR: cidr}}
	m.kubeClient = fake.NewSimpleClientset(svc.DeepCopy(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: svc.Namespace, Labels: svc.Spec.Selector}, Status: corev1.PodStatus{HostIP: "198.51.100.21"}})
	index := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	if err := index.Add(quicTestSlice("a", "192.0.2.21", true)); err != nil {
		t.Fatal(err)
	}
	m.endpointSliceLister = discoverylisters.NewEndpointSliceLister(index)
	fixture := &quicHTTPFixture{state: map[string]api.LoadBalancerModel{}}
	server := httptest.NewServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(server.Close)
	base, _ := url.Parse(server.URL)
	rest, err := api.NewRESTClient(base, "netlox", "v1", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	m.LoxiClients = &api.LoxiClientPool{Clients: []*api.LoxiClient{{RestClient: rest, Host: base.Hostname(), Url: server.URL}}}
	return m, svc, index, fixture
}
func quicAssertInstalled(t *testing.T, f *quicHTTPFixture, enabled bool, cr uint8) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, protocol := range []string{"tcp", "udp"} {
		model, ok := f.state[protocol]
		if !ok {
			t.Fatalf("missing installed %s rule: %v", protocol, f.calls)
		}
		want := api.LbSelHash
		if protocol == "udp" && enabled {
			want = api.LbSelQuicCID
		}
		if model.Service.Sel != want {
			t.Fatalf("%s selector=%d want=%d", protocol, model.Service.Sel, want)
		}
		raw, err := json.Marshal(model)
		if err != nil {
			t.Fatal(err)
		}
		if protocol == "udp" && enabled {
			if model.Service.QuicLb == nil || model.Service.QuicLb.SidLen != 4 || model.Service.QuicLb.Cr != cr {
				t.Fatalf("wrong CID arguments: %s", raw)
			}
		} else if model.Service.QuicLb != nil || strings.Contains(string(raw), "quicLb") {
			t.Fatalf("CID leaked into fallback: %s", raw)
		}
	}
}
func TestQuicCIDReconcileLifecycle(t *testing.T) {
	m, svc, index, f := quicReconcileFixture(t)
	reconcile := func(enabled bool, cr uint8) {
		t.Helper()
		if err := m.addLoadBalancer(svc); err != nil {
			t.Fatal(err)
		}
		quicAssertInstalled(t, f, enabled, cr)
	}
	delete(svc.Annotations, quicCIDAnnotation)
	reconcile(false, 0)
	svc.Annotations[quicCIDAnnotation] = "yes"
	reconcile(true, 0)
	svc.Annotations[quicCIDCRAnnotation] = "7"
	reconcile(true, 7)
	delete(svc.Annotations, quicCIDAnnotation)
	reconcile(false, 0)
	svc.Annotations[quicCIDAnnotation] = "yes"
	reconcile(true, 7)
	// T3 after previously valid T2: endpoint IP set is unchanged; policy alone
	// must trigger replacement and retain the configured hash selector.
	slice := quicTestSlice("a", "192.0.2.21", true)
	ep := slice.Endpoints[0]
	ep.Addresses = []string{"192.0.2.22"}
	slice.Endpoints = append(slice.Endpoints, ep)
	if err := index.Update(slice); err != nil {
		t.Fatal(err)
	}
	reconcile(false, 0)
	events, err := m.kubeClient.CoreV1().Events(svc.Namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil || len(events.Items) != 1 || events.Items[0].Reason != quicCIDRefused {
		t.Fatalf("missing refusal event: %v %v", events, err)
	}
	if err := index.Update(quicTestSlice("a", "192.0.2.21", true)); err != nil {
		t.Fatal(err)
	}
	reconcile(true, 7)
	svc.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeCluster
	reconcile(false, 0)
	svc.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeLocal
	reconcile(true, 7)
	svc.Annotations[quicCIDCRAnnotation] = "8"
	reconcile(false, 0)
	svc.Annotations[quicCIDCRAnnotation] = "0"
	reconcile(true, 0)
	// No changes must converge without extra LB writes.
	before := len(f.calls)
	reconcile(true, 0)
	if len(f.calls) != before {
		t.Fatalf("no-op reconcile wrote LB: %v", f.calls[before:])
	}
	if err := m.deleteLoadBalancer(svc.Namespace, svc.Name, true); err != nil {
		t.Fatal(err)
	}
	if len(f.state) != 0 || len(m.lbCache) != 0 {
		t.Fatal("service deletion left state")
	}
	t.Log("PASS: off -> enable -> CR update -> remove -> re-enable -> T3 duplicate/hash -> recovery -> T3 Cluster/hash -> recovery -> invalid CR/hash -> recovery -> no-op -> delete")
}
func TestQuicCIDReconcileEventFailureFallback(t *testing.T) {
	for _, verb := range []string{"get", "create", "update"} {
		t.Run(verb, func(t *testing.T) {
			m, svc, _, f := quicReconcileFixture(t)
			svc.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeCluster
			if verb == "update" {
				if err := m.addLoadBalancer(svc); err != nil {
					t.Fatal(err)
				}
			}
			client := m.kubeClient.(*fake.Clientset)
			failed := 0
			client.PrependReactor(verb, "events", func(ktesting.Action) (bool, runtime.Object, error) {
				failed++
				return true, nil, fmt.Errorf("injected Event API failure")
			})
			if err := m.addLoadBalancer(svc); err != nil {
				t.Fatal(err)
			}
			if failed != 1 {
				t.Fatalf("fault not reached: %d", failed)
			}
			quicAssertInstalled(t, f, false, 0)
			client.ReactionChain = client.ReactionChain[1:]
			if err := m.addLoadBalancer(svc); err != nil {
				t.Fatal(err)
			}
			events, err := client.CoreV1().Events(svc.Namespace).List(context.Background(), metav1.ListOptions{})
			if err != nil || len(events.Items) != 1 {
				t.Fatalf("Event did not recover: %v %v", events, err)
			}
			quicAssertInstalled(t, f, false, 0)
		})
	}
}
func TestQuicCIDReconcileLBFailureRecovery(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			m, svc, _, f := quicReconcileFixture(t)
			if err := m.addLoadBalancer(svc); err != nil {
				t.Fatal(err)
			}
			delete(svc.Annotations, quicCIDAnnotation)
			f.failMethod = method
			if method == http.MethodPost {
				f.failProtocol = "udp"
			}
			if err := m.addLoadBalancer(svc); err == nil {
				t.Fatal("injected LB failure swallowed")
			}
			f.failMethod = ""
			if err := m.addLoadBalancer(svc); err != nil {
				t.Fatal(err)
			}
			quicAssertInstalled(t, f, false, 0)
			before := len(f.calls)
			if err := m.addLoadBalancer(svc); err != nil {
				t.Fatal(err)
			}
			if len(f.calls) != before {
				t.Fatal("recovered rule did not converge")
			}
		})
	}
}

func TestQuicCIDInitialInstallFailureThenFallback(t *testing.T) {
	for _, change := range []string{"retry CID", "remove annotation", "invalid CR"} {
		t.Run(change, func(t *testing.T) {
			m, svc, _, f := quicReconcileFixture(t)
			f.failMethod = http.MethodPost
			f.failProtocol = "udp"
			if err := m.addLoadBalancer(svc); err == nil {
				t.Fatal("initial partial install failure swallowed")
			}
			f.failMethod = ""
			switch change {
			case "remove annotation":
				delete(svc.Annotations, quicCIDAnnotation)
			case "invalid CR":
				svc.Annotations[quicCIDCRAnnotation] = "8"
			}
			if err := m.addLoadBalancer(svc); err != nil {
				t.Fatal(err)
			}
			quicAssertInstalled(t, f, change == "retry CID", 0)
		})
	}
}
func TestQuicCIDUnnamedServicePort(t *testing.T) {
	svc := quicTestService()
	svc.Spec.Ports = svc.Spec.Ports[1:]
	svc.Spec.Ports[0].Name = ""
	slice := quicTestSlice("a", "192.0.2.21", true)
	slice.Ports[0].Name = nil
	if reason := quicCIDLocalTopology(svc, []*discoveryv1.EndpointSlice{slice}, "a"); reason != "" {
		t.Fatal(reason)
	}
}

func TestQuicCIDRefusedPreservesSelectors(t *testing.T) {
	for _, selector := range []api.EpSelect{api.LbSelRr, api.LbSelHash, api.LbSelPrio, api.LbSelRrPersist, api.LbSelLeastConnections, api.LbSelN2, api.LbSelN2DET, api.LbSelN3} {
		m := quicTestManager()
		svc := quicTestService()
		svc.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeCluster
		q, reason := m.quicCIDPolicy(svc, false, false, false, "ipv4", 0, false, false, []string{"198.51.100.21"})
		if q != nil || reason == "" {
			t.Fatal("T3 accepted")
		}
		args := &LbArgs{externalIP: "192.0.2.100", endpointIPs: []string{"198.51.100.21"}, sel: selector, quicLb: q}
		for _, port := range svc.Spec.Ports {
			model, err := m.makeLoxiLoadBalancerModel(args, svc, port)
			if err != nil {
				t.Fatal(err)
			}
			if model.Service.Sel != selector || model.Service.QuicLb != nil {
				t.Fatalf("fallback changed selector %d: %+v", selector, model.Service)
			}
		}
	}
}

type quicFailingSlices struct {
	discoverylisters.EndpointSliceLister
}

func (f quicFailingSlices) EndpointSlices(namespace string) discoverylisters.EndpointSliceNamespaceLister {
	return quicFailingNamespace{f.EndpointSliceLister.EndpointSlices(namespace)}
}

type quicFailingNamespace struct {
	discoverylisters.EndpointSliceNamespaceLister
}

func (quicFailingNamespace) List(labels.Selector) ([]*discoveryv1.EndpointSlice, error) {
	return nil, fmt.Errorf("injected slice lister error")
}

type quicFailingNodes struct{ corelisters.NodeLister }

func (quicFailingNodes) List(labels.Selector) ([]*corev1.Node, error) {
	return nil, fmt.Errorf("injected node lister error")
}
func TestQuicCIDTopologyFailureRecovery(t *testing.T) {
	for _, kind := range []string{"slices", "nodes"} {
		t.Run(kind, func(t *testing.T) {
			m, svc, _, f := quicReconcileFixture(t)
			if err := m.addLoadBalancer(svc); err != nil {
				t.Fatal(err)
			}
			slices, nodes := m.endpointSliceLister, m.nodeLister
			if kind == "slices" {
				m.endpointSliceLister = quicFailingSlices{slices}
			} else {
				m.nodeLister = quicFailingNodes{nodes}
			}
			if err := m.addLoadBalancer(svc); err != nil {
				t.Fatal(err)
			}
			quicAssertInstalled(t, f, false, 0)
			m.endpointSliceLister, m.nodeLister = slices, nodes
			if err := m.addLoadBalancer(svc); err != nil {
				t.Fatal(err)
			}
			quicAssertInstalled(t, f, true, 0)
		})
	}
}

func TestQuicCIDUnsupportedCombinations(t *testing.T) {
	cases := []struct {
		name, address                  string
		external, multus, ppv2, egress bool
		endpoints                      []string
	}{
		{name: "IPv6 address mode", address: "ipv6"},
		{name: "NAT64", address: "ipv6to4"},
		{name: "external endpoints", external: true},
		{name: "multus", multus: true},
		{name: "proxy protocol", ppv2: true},
		{name: "egress", egress: true},
		{name: "IPv6 endpoint", endpoints: []string{"2001:db8::21"}},
		{name: "invalid endpoint", endpoints: []string{"invalid"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			address := c.address
			if address == "" {
				address = "ipv4"
			}
			endpoints := c.endpoints
			if endpoints == nil {
				endpoints = []string{"192.0.2.21"}
			}
			q, r := quicTestManager().quicCIDPolicy(quicTestService(), true, c.external, c.multus, address, 0, c.ppv2, c.egress, endpoints)
			if q != nil || r == "" {
				t.Fatalf("unsupported combination accepted: %v %q", q, r)
			}
		})
	}
}
func TestQuicCIDDefaultModeAndCRRemoval(t *testing.T) {
	m := quicTestManager()
	m.networkConfig.SetLBMode = api.LBModeHostOneArm
	svc := quicTestService()
	svc.Annotations[quicCIDCRAnnotation] = "7"
	q, r := m.quicCIDPolicy(svc, true, false, false, "ipv4", -1, false, false, []string{"192.0.2.21"})
	if q == nil || q.Cr != 7 || r != "" {
		t.Fatalf("default HostOneArm: %v %q", q, r)
	}
	delete(svc.Annotations, quicCIDCRAnnotation)
	q, r = m.quicCIDPolicy(svc, true, false, false, "ipv4", -1, false, false, []string{"192.0.2.21"})
	if q == nil || q.Cr != 0 || r != "" {
		t.Fatalf("removed CR: %v %q", q, r)
	}
	m.networkConfig.SetLBMode = api.LBModeDsr
	if q, r = m.quicCIDPolicy(svc, true, false, false, "ipv4", -1, false, false, []string{"192.0.2.21"}); q != nil || r == "" {
		t.Fatal("default DSR accepted")
	}
}

func TestQuicCIDMissingTargetPort(t *testing.T) {
	svc := quicTestService()
	slice := quicTestSlice("a", "192.0.2.21", true)
	slice.Ports[0].Port = nil
	if reason := quicCIDLocalTopology(svc, []*discoveryv1.EndpointSlice{slice}, "a"); reason == "" {
		t.Fatal("undefined target port accepted")
	}
}

func TestQuicCIDPartialDeleteThenReenable(t *testing.T) {
	m, svc, _, f := quicReconcileFixture(t)
	if err := m.addLoadBalancer(svc); err != nil {
		t.Fatal(err)
	}
	delete(svc.Annotations, quicCIDAnnotation)
	f.failMethod = http.MethodDelete
	f.failProtocol = "udp"
	if err := m.addLoadBalancer(svc); err == nil {
		t.Fatal("partial deletion failure swallowed")
	}
	// Desired state can return to the previous CID value before the retry.
	f.failMethod = ""
	svc.Annotations[quicCIDAnnotation] = "yes"
	if err := m.addLoadBalancer(svc); err != nil {
		t.Fatal(err)
	}
	quicAssertInstalled(t, f, true, 0)
}

func TestQuicCIDPartialDeleteAcrossClients(t *testing.T) {
	m, svc, _, first := quicReconcileFixture(t)
	second := &quicHTTPFixture{state: map[string]api.LoadBalancerModel{}}
	server := httptest.NewServer(http.HandlerFunc(second.serve))
	t.Cleanup(server.Close)
	base, _ := url.Parse(server.URL)
	rest, err := api.NewRESTClient(base, "netlox", "v1", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	m.LoxiClients.Clients = append(m.LoxiClients.Clients, &api.LoxiClient{RestClient: rest, Host: base.Hostname(), Url: server.URL})
	if err := m.addLoadBalancer(svc); err != nil {
		t.Fatal(err)
	}
	delete(svc.Annotations, quicCIDAnnotation)
	second.failMethod = http.MethodDelete
	second.failProtocol = "udp"
	if err := m.addLoadBalancer(svc); err == nil {
		t.Fatal("partial peer deletion failure swallowed")
	}
	second.failMethod = ""
	if err := m.addLoadBalancer(svc); err != nil {
		t.Fatal(err)
	}
	quicAssertInstalled(t, first, false, 0)
	quicAssertInstalled(t, second, false, 0)
}

func TestQuicCIDLegacyMissingRuleStillErrors(t *testing.T) {
	m, svc, _, f := quicReconcileFixture(t)
	delete(svc.Annotations, quicCIDAnnotation)
	if err := m.addLoadBalancer(svc); err != nil {
		t.Fatal(err)
	}
	delete(f.state, "tcp")
	if err := m.deleteLoadBalancer(svc.Namespace, svc.Name, true); err == nil {
		t.Fatal("legacy deletion error was suppressed")
	}
	if len(m.lbCache) == 0 {
		t.Fatal("legacy error released service cache")
	}
}

func TestQuicCIDDeleteCommittedBeforeError(t *testing.T) {
	m, svc, _, f := quicReconcileFixture(t)
	if err := m.addLoadBalancer(svc); err != nil {
		t.Fatal(err)
	}
	delete(svc.Annotations, quicCIDAnnotation)
	f.failMethod = http.MethodDelete
	f.failProtocol = "udp"
	f.failAfterDelete = true
	if err := m.addLoadBalancer(svc); err == nil {
		t.Fatal("ambiguous deletion result swallowed")
	}
	f.failMethod = ""
	if err := m.addLoadBalancer(svc); err != nil {
		t.Fatal(err)
	}
	quicAssertInstalled(t, f, false, 0)
}
