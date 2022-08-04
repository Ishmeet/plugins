package main

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CIDR is a string representation of a CIDR
type CIDR string

// IPAddress is a string representation of an IP v4 or v6 address
type IPAddress string

// StateType contains a valid resource state
type StateType string

// CommonStatus contains Contrail resource fields all types must implement in their status
type CommonStatus struct {
	ReconcilerState `json:",inline" protobuf:"bytes,1,opt,name=reconcilerState"`
}

// ReconcilerState describes a resource's reconciliation status including the State
// of the reconciliation as well as an Observation with additional information about
// the State.
type ReconcilerState struct {
	// State describe the current readiness of a resource after the last reconciliation.
	// The possible states include Pending, Success, and Failure.
	State StateType `json:"state" protobuf:"bytes,1,opt,name=state,casttype=StateType"`

	// Observation provides additional information related to the state of the
	// resource. For example, if a reconciliation error occurs, Observation will
	// contain a brief description of the problem.
	Observation string `json:"observation" protobuf:"bytes,2,opt,name=observation"`
}

// ContrailFqName contains the specific FqName field necessary for the Contrail
// Control-node.
type ContrailFqName struct {
	// FqName is the list of resource names that fully qualify a Contrail resource.
	// +optional
	FqName []string `json:"fqName,omitempty" protobuf:"bytes,1,rep,name=fqName"`
}

// CommonSpec contains Contrail resource fields all types must implement in their spec.
type CommonSpec struct {
	ContrailFqName `json:",inline" protobuf:"bytes,1,opt,name=contrailFqName"`
}

// SubnetSpec defines the desired state of a Subnet.
type SubnetSpec struct {
	// Common spec fields
	CommonSpec `json:",inline" protobuf:"bytes,1,opt,name=commonSpec"`

	// Subnet range in CIDR notation.
	// +optional
	CIDR CIDR `json:"cidr,omitempty" protobuf:"bytes,3,opt,name=cidr,casttype=CIDR"`

	// Default Gateway IP address in the subnet.
	// If not provided, one is auto-generated by the system.
	// +optional
	DefaultGateway IPAddress `json:"defaultGateway,omitempty" protobuf:"bytes,4,opt,name=defaultGateway,casttype=IPAddress"`

	// List of DNS servers associated with the subnet.
	// +optional
	DNSNameservers []IPAddress `json:"dnsNameservers,omitempty" protobuf:"bytes,5,rep,name=dnsNameservers,casttype=IPAddress"`

	// Ranges, when present, define the IP allocation ranges corresponding to
	// a given key.
	// If not provided, IP allocation is determined by the CIDR.
	// +optional
	Ranges []Range `json:"ranges,omitempty" protobuf:"bytes,6,rep,name=ranges"`

	// Disables auto allocation of BGPaaSPrimaryIP and BGPaaSecondaryIP. False by
	// default, automatic allocation is enabled. IPs are auto allocated when at
	// least one BGPAsAService is configured under this subnet. If DisableBGPaaSIPAutoAllocation
	// is set to true, BGPaaSPrimaryIP and BGPaaSSecondaryIP must be specified.
	// Leave this flag false if the BGPAsAService feature is not required.
	// +optional
	DisableBGPaaSIPAutoAllocation bool `json:"disableBGPaaSIPAutoAllocation,omitempty" protobuf:"varint,7,opt,name=disableBGPaaSIPAutoAllocation"`

	// Primary IP address used for the BGP as a service session.
	// +optional
	BGPaaSPrimaryIP IPAddress `json:"bgpaasPrimaryIP,omitempty" protobuf:"bytes,8,opt,name=bgpaasPrimaryIP,casttype=IPAddress"`

	// Secondary IP address used for the BGP as a service session when the
	// second control node is present.
	// +optional
	BGPaaSSecondaryIP IPAddress `json:"bgpaasSecondaryIP,omitempty" protobuf:"bytes,9,opt,name=bgpaasSecondaryIP,casttype=IPAddress"`
}

// Range is a list of IPRanges associated with a given key.
type Range struct {
	// Key is a text string defining the Range collection. Setting a Range with
	// an existing key will overwrite the exiting Range.
	Key string `json:"key,omitempty" protobuf:"bytes,1,rep,name=key"`
	// IPRanges lists one or more IPRange instance.
	IPRanges []IPRange `json:"ipRanges,omitempty" protobuf:"bytes,2,rep,name=ipRanges"`
}

// IPRange specifies the start and end for a range of IP addresses.
type IPRange struct {
	// From indicates beginning IP address for the allocation range.
	From IPAddress `json:"from" protobuf:"bytes,1,opt,name=from"`

	// To indicates last IP address for the allocation range.
	To IPAddress `json:"to" protobuf:"bytes,2,opt,name=to"`
}

// SubnetStatus defines the observed state of a Subnet.
type SubnetStatus struct {
	// Common status fields
	CommonStatus `json:",inline" protobuf:"bytes,1,opt,name=commonStatus"`

	// IPCount is the current number of allocated IP addresses in the Subnet.
	// +optional
	IPCount int64 `json:"ipCount,omitempty" protobuf:"varint,2,opt,name=ipCount"`

	// AllocationUsage is current percentage of allocated addresses in the Subnet.
	// +optional
	AllocationUsage string `json:"allocationUsage,omitempty" protobuf:"varint,3,opt,name=allocationUsage"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Subnet represents a block of IP addresses and its configuration.
// IPAM allocates and releases IP address from that block on demand.
// It can be used by different VirtualNetwork in the mean time.
// +k8s:openapi-gen=true
// +resource:path=subnets,strategy=SubnetStrategy,shortname=sn,categories=contrail;ipam;networking
type Subnet struct {
	metav1.TypeMeta `json:",inline"`

	// Standard object's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Specification of the desired state of the Subnet.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	// +optional
	Spec SubnetSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`

	// The most recently observed status of the Subnet.
	// This data may not be up-to-date.
	// Populated by the system.
	// Read-only.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	// +optional
	Status SubnetStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// SubnetList is a list of Subnet.
type SubnetList struct {
	metav1.TypeMeta `json:",inline"`

	// Standard list's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#lists-and-simple-kinds
	// +optional
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Items contains all of the Subnet instances in the SubnetList.
	Items []Subnet `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// IPFamily defines the IP address family type: v4 of v6
type IPFamily string

// There are IP family types
const (
	IPFamilyV4 IPFamily = "v4"
	IPFamilyV6 IPFamily = "v6"
)

type ObjectReference struct {
	// Kind of the referent.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
	// +optional
	Kind string `json:"kind,omitempty" protobuf:"bytes,1,opt,name=kind"`
	// Namespace of the referent.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
	// +optional
	Namespace string `json:"namespace,omitempty" protobuf:"bytes,2,opt,name=namespace"`
	// Name of the referent.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
	// +optional
	Name string `json:"name,omitempty" protobuf:"bytes,3,opt,name=name"`
	// UID of the referent.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids
	// +optional
	// UID types.UID `json:"uid,omitempty" protobuf:"bytes,4,opt,name=uid,casttype=k8s.io/apimachinery/pkg/types.UID"`
	// API version of the referent.
	// +optional
	APIVersion string `json:"apiVersion,omitempty" protobuf:"bytes,5,opt,name=apiVersion"`
	// Specific resourceVersion to which this reference is made, if any.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
	// +optional
	ResourceVersion string `json:"resourceVersion,omitempty" protobuf:"bytes,6,opt,name=resourceVersion"`

	// If referring to a piece of an object instead of an entire object, this string
	// should contain a valid JSON/Go field access statement, such as desiredState.manifest.containers[2].
	// For example, if the object reference is to a container within a pod, this would take on a value like:
	// "spec.containers{name}" (where "name" refers to the name of the container that triggered
	// the event) or if no container name is specified "spec.containers[2]" (container with
	// index 2 in this pod). This syntax is chosen only to have some well-defined way of
	// referencing a part of an object.
	// TODO: this design is not final and this field is subject to change in the future.
	// +optional
	FieldPath string `json:"fieldPath,omitempty" protobuf:"bytes,7,opt,name=fieldPath"`
}

// ResourceReference is an ObjectReference to a Contrail resource that contains
// the ContrailFqName of the resource being referenced.
type ResourceReference struct {
	ObjectReference `json:",inline" protobuf:"bytes,1,opt,name=objectReference"`
	ContrailFqName  `json:",inline" protobuf:"bytes,2,opt,name=contrailFqName"`
}

// InstanceIPSpec defines the desired state of the InstanceIP.
type InstanceIPSpec struct {
	// Common spec fields
	CommonSpec `json:",inline" protobuf:"bytes,1,opt,name=commonSpec"`

	// IP address value for InstanceIP.
	// +optional
	IPAddress IPAddress `json:"instanceIPAddress,omitempty" protobuf:"bytes,2,opt,name=instanceIPAddress,casttype=IPAddress"`

	// IP address family for the InstanceIP: "v4" or "v6" for IPv4 or IPv6.
	// +optional
	IPFamily IPFamily `json:"instanceIPFamily,omitempty" protobuf:"bytes,3,opt,name=instanceIPFamily,casttype=IPFamily"`

	// Subnet is the CIDR the InstanceIP belongs to.
	// +optional
	Subnet CIDR `json:"cidr,omitempty" protobuf:"bytes,4,opt,name=cidr,casttype=CIDR"`

	// VirtualNetworkReference determines the VirtualNetwork the InstanceIP belongs to.
	// +optional
	VirtualNetworkReference *ResourceReference `json:"virtualNetworkReference,omitempty" protobuf:"bytes,5,opt,name=virtualNetworkReference"`

	// VirtualMachineInterfaceReferences determines the VirtualMachineInterface
	// the InstanceIP belongs to.
	// +optional
	VirtualMachineInterfaceReferences []ResourceReference `json:"virtualMachineInterfaceReferences,omitempty" protobuf:"bytes,6,rep,name=virtualMachineInterfaceReferences"`
	// TODO(edouard): should be InstanceIPSpec.VirtualMachineInterfaceReferences limited to one ref ?

	// IPRangeKeys is used to identify the subnet range for IP allocation.
	// +optional
	IPRangeKeys []string `json:"ipRangeKeys,omitempty" protobuf:"bytes,7,opt,name=ipRangeKeys"`
}

// InstanceIPStatus defines the observed state of the InstanceIP.
type InstanceIPStatus struct {
	// Common status fields
	CommonStatus `json:",inline" protobuf:"bytes,1,opt,name=commonStatus"`

	// SubnetReference refers to the Subnet this InstanceIP belongs to.
	// +optional
	SubnetReference *ResourceReference `json:"subnetReference,omitempty" protobuf:"bytes,2,opt,name=subnetReference"`
}

// +kubebuilder:printcolumn:JSONPath=.status.state,description="Contrail resource state",name=State,priority=0,type=string
// +kubebuilder:printcolumn:JSONPath=.status.observation,description="Contrail resource state observation",name=Observation,priority=1,type=string
// +kubebuilder:printcolumn:JSONPath=.spec.fqName,description="Contrail FQ name resource",name=FQName,priority=1,type=string

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient:nonNamespaced

// InstanceIP represents an IP address and its configuration used for interfaces.
// +k8s:openapi-gen=true
// +resource:path=instanceips,strategy=InstanceIPStrategy,shortname=iip,categories=contrail;ipam;networking
type InstanceIP struct {
	metav1.TypeMeta `json:",inline"`

	// Standard object's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Specification of the desired state of the InstanceIP.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	// +optional
	Spec InstanceIPSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`

	// The most recently observed status of the InstanceIP.
	// This data may not be up-to-date.
	// Populated by the system.
	// Read-only.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	// +optional
	Status InstanceIPStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

type InstanceIPList struct {
	metav1.TypeMeta `json:",inline"`

	// Standard list's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#lists-and-simple-kinds
	// +optional
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Items contains all of the InstanceIP instances in the InstanceIPList.
	Items []InstanceIP `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// Annotations are used to pass information from kube-manager to Plugin
type Annotations struct {
	Cluster          string `json:"cluster"`
	Kind             string `json:"kind"`
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
	Network          string `json:"network"`
	Owner            string `json:"owner"`
	Project          string `json:"project"`
	Index            string `json:"index"`
	Interface        string `json:"interface"`
	InterfaceType    string `json:"interface-type"`
	PodUid           string `json:"pod-uid"`
	PodVhostMode     string `json:"vhost-mode"`
	VlanId           string `json:"vlan-id"`
	VmiAddressFamily string `json:"vmi-address-family"`
}

type Result struct {
	VmUuid       string   `json:"vm-uuid"`
	Nw           string   `json:"network-label"`
	Ip           string   `json:"ip-address"`
	Plen         int      `json:"plen"`
	Gw           string   `json:"gateway"`
	Dns          string   `json:"dns-server"`
	Mac          string   `json:"mac-address"`
	VlanId       int      `json:"vlan-id"`
	SubInterface bool     `json:"sub-interface"`
	VnId         string   `json:"vn-id"`
	VnName       string   `json:"vn-name"`
	VmiUuid      string   `json:"id"`
	IpV6         string   `json:"v6-ip-address"`
	DnsV6        string   `json:"v6-dns-server"`
	GwV6         string   `json:"v6-gateway"`
	PlenV6       int      `json:"v6-plen"`
	Args         []string `json:"annotations"`
	Annotations  Annotations
}

// Add request to VRouter
type ContrailAddMsg struct {
	Time            string `json:"time"`
	Vm              string `json:"vm-id"`
	VmUuid          string `json:"vm-uuid"`
	VmName          string `json:"vm-name"`
	HostIfName      string `json:"host-ifname"`
	ContainerIfName string `json:"vm-ifname"`
	Namespace       string `json:"vm-namespace"`
	VnId            string `json:"vn-uuid"`
	VmiUuid         string `json:"vmi-uuid"`
	VhostMode       int    `json:"vhostuser-mode"`
	VhostSockDir    string `json:"vhostsocket-dir"`
	VhostSockName   string `json:"vhostsocket-filename"`
	VmiType         string `json:"vmi-type"`
	PodUid          string `json:"pod-uid"`
}
