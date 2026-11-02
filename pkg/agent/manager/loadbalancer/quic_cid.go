package loadbalancer

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/loxilb-io/kube-loxilb/pkg/api"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
)

const quicCIDAnnotation = "loxilb.io/quic-cid"
const quicCIDCRAnnotation = "loxilb.io/quic-cid-cr"
const quicCIDRefused = "QuicCIDUnsupported"

// Policy is additive: a refusal leaves the normal selector and traffic path intact.
func (m *Manager) quicCIDPolicy(svc *corev1.Service, pod, external, multus bool, address string, mode int, ppv2, egress bool, endpoints []string) (*api.QuicLbArg, string) {
	udp := false
	for _, port := range svc.Spec.Ports {
		udp = udp || port.Protocol == corev1.ProtocolUDP
	}
	enabled := svc.Annotations[quicCIDAnnotation]
	if !udp || enabled == "" || enabled == "no" {
		return nil, ""
	}
	if enabled != "yes" {
		return nil, "quic-cid must be yes or no"
	}
	cr := 0
	if raw, ok := svc.Annotations[quicCIDCRAnnotation]; ok {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 || value > 7 {
			return nil, "quic-cid-cr must be an integer from 0 to 7"
		}
		cr = value
	}
	if mode < 0 {
		mode = int(m.networkConfig.SetLBMode)
	}
	if address != "ipv4" || ppv2 || egress || (mode != api.LBModeDefault && mode != api.LBModeOneArm && mode != api.LBModeFullNat && mode != api.LBModeHostOneArm) {
		return nil, "quic-cid requires IPv4 Default, OneArm, FullNAT or HostOneArm without proxyprotocolv2 or egress"
	}
	for _, ip := range endpoints {
		if net.ParseIP(ip).To4() == nil {
			return nil, "quic-cid requires IPv4 endpoints"
		}
	}
	if external || multus {
		return nil, "quic-cid requires pod-network or supported Local NodePort endpoints"
	}
	if !pod {
		if svc.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyTypeLocal {
			return nil, "quic-cid NodePort requires externalTrafficPolicy Local and one ready endpoint per node"
		}
		slices, err := m.endpointSliceLister.EndpointSlices(svc.Namespace).List(labels.SelectorFromSet(labels.Set{discoveryv1.LabelServiceName: svc.Name}))
		if err != nil {
			return nil, "cannot verify quic-cid NodePort endpoint topology"
		}
		nodes, err := m.nodeLister.List(labels.Everything())
		if err != nil {
			return nil, "cannot verify quic-cid NodePort node identities"
		}
		selected := []string{}
		for _, ip := range endpoints {
			name := ""
			for _, node := range nodes {
				for _, addr := range node.Status.Addresses {
					if addr.Address == ip {
						name = node.Name
					}
				}
			}
			if name == "" {
				return nil, "quic-cid NodePort target has no matching node"
			}
			selected = append(selected, name)
		}
		if reason := quicCIDLocalTopology(svc, slices, selected...); reason != "" {
			return nil, reason
		}
	}
	return &api.QuicLbArg{SidLen: 4, Cr: uint8(cr)}, ""
}

// Count endpoint identities per node, deduplicating repeated slice observations.
// Unknown readiness follows kube-proxy's ready semantics; unknown node identity
// is refused because a single local destination cannot be established.
func quicCIDLocalTopology(svc *corev1.Service, slices []*discoveryv1.EndpointSlice, selected ...string) string {
	for _, port := range svc.Spec.Ports {
		if port.Protocol != corev1.ProtocolUDP {
			continue
		}
		nodes := map[string]map[string]bool{}
		for _, slice := range slices {
			if slice.AddressType != discoveryv1.AddressTypeIPv4 {
				continue
			}
			matches := false
			for _, p := range slice.Ports {
				name := ""
				if p.Name != nil {
					name = *p.Name
				}
				if p.Protocol != nil && *p.Protocol == corev1.ProtocolUDP && name == port.Name && p.Port != nil && *p.Port > 0 && *p.Port <= 65535 {
					matches = true
				}
			}
			if !matches {
				continue
			}
			for _, ep := range slice.Endpoints {
				if ep.Conditions.Ready != nil && !*ep.Conditions.Ready && !svc.Spec.PublishNotReadyAddresses {
					continue
				}
				if ep.NodeName == nil || *ep.NodeName == "" {
					return "quic-cid NodePort endpoint has no node identity"
				}
				identity := ""
				if ep.TargetRef != nil && ep.TargetRef.UID != "" {
					identity = string(ep.TargetRef.UID)
				}
				if identity == "" && len(ep.Addresses) == 1 {
					identity = ep.Addresses[0]
				}
				if identity == "" {
					return "quic-cid NodePort endpoint identity is ambiguous"
				}
				node := *ep.NodeName
				if nodes[node] == nil {
					nodes[node] = map[string]bool{}
				}
				nodes[node][identity] = true
				if len(nodes[node]) > 1 {
					return "quic-cid NodePort has multiple ready endpoints on one node"
				}
			}
		}
		if len(nodes) == 0 {
			return "quic-cid NodePort has no verifiable ready local endpoints"
		}
		for _, node := range selected {
			if len(nodes[node]) != 1 {
				return "quic-cid NodePort target has no single ready local endpoint"
			}
		}
	}
	return ""
}

// Aggregate repeated refusals using one stable Event per service UID and reason.
// Event API failures are logged; they never suppress the normal LB configuration.
func (m *Manager) reportQuicCIDRefusal(svc *corev1.Service, reason string) {
	klog.Warningf("service %s/%s: %s: %s", svc.Namespace, svc.Name, quicCIDRefused, reason)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	digest := sha256.Sum256([]byte(string(svc.UID) + "/" + svc.Name + "/" + reason))
	name := fmt.Sprintf("quic-cid-%x", digest[:12])
	events := m.kubeClient.CoreV1().Events(svc.Namespace)
	event, err := events.Get(ctx, name, metav1.GetOptions{})
	now := metav1.Now()
	if apierrors.IsNotFound(err) {
		_, err = events.Create(ctx, &corev1.Event{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: svc.Namespace},
			InvolvedObject: corev1.ObjectReference{APIVersion: "v1", Kind: "Service", Namespace: svc.Namespace, Name: svc.Name, UID: svc.UID},
			Type:           corev1.EventTypeWarning, Reason: quicCIDRefused, Message: reason, Count: 1,
			FirstTimestamp: now, LastTimestamp: now, Source: corev1.EventSource{Component: "kube-loxilb"}}, metav1.CreateOptions{})
	} else if err == nil {
		event.Count++
		event.LastTimestamp = now
		_, err = events.Update(ctx, event, metav1.UpdateOptions{})
	}
	if err != nil {
		klog.Warningf("cannot record quic-cid Service Event: %v", err)
	}
}
