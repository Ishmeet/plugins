// Copyright 2018 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// The top-level network config - IPAM plugins are passed the full configuration
// of the calling plugin, not just the IPAM section.
type Net struct {
	Name       string      `json:"name"`
	CNIVersion string      `json:"cniVersion"`
	IPAM       *IPAMConfig `json:"ipam"`

	RuntimeConfig struct {
		IPs []string `json:"ips,omitempty"`
	} `json:"runtimeConfig,omitempty"`
	Args *struct {
		A *IPAMArgs `json:"cni"`
	} `json:"args"`
}

type IPAMConfig struct {
	Name      string
	Type      string         `json:"type"`
	Routes    []*types.Route `json:"routes"`
	Addresses []Address      `json:"addresses,omitempty"`
	DNS       types.DNS      `json:"dns"`
}

type IPAMEnvArgs struct {
	types.CommonArgs
	IP      types.UnmarshallableString `json:"ip,omitempty"`
	GATEWAY types.UnmarshallableString `json:"gateway,omitempty"`
}

type IPAMArgs struct {
	IPs []string `json:"ips"`
}

type Address struct {
	AddressStr string `json:"address"`
	Gateway    net.IP `json:"gateway,omitempty"`
	Address    net.IPNet
	Version    string
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("static"))
}

func loadNetConf(bytes []byte) (*types.NetConf, string, error) {
	n := &types.NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, n.CNIVersion, nil
}

func cmdCheck(args *skel.CmdArgs) error {
	// ipamConf, _, err := LoadIPAMConfig(args.StdinData, args.Args)
	// if err != nil {
	// 	return err
	// }

	// // Get PrevResult from stdin... store in RawPrevResult
	// n, _, err := loadNetConf(args.StdinData)
	// if err != nil {
	// 	return err
	// }

	// // Parse previous result.
	// if n.RawPrevResult == nil {
	// 	return fmt.Errorf("Required prevResult missing")
	// }

	// if err := version.ParsePrevResult(n); err != nil {
	// 	return err
	// }

	// result, err := current.NewResultFromResult(n.PrevResult)
	// if err != nil {
	// 	return err
	// }

	// // Each configured IP should be found in result.IPs
	// for _, rangeset := range ipamConf.Addresses {
	// 	for _, ips := range result.IPs {
	// 		// Ensure values are what we expect
	// 		if rangeset.Address.IP.Equal(ips.Address.IP) {
	// 			if rangeset.Gateway == nil {
	// 				break
	// 			} else if rangeset.Gateway.Equal(ips.Gateway) {
	// 				break
	// 			}
	// 			return fmt.Errorf("static: Failed to match addr %v on interface %v", ips.Address.IP, args.IfName)
	// 		}
	// 	}
	// }

	return nil
}

// canonicalizeIP makes sure a provided ip is in standard form
func canonicalizeIP(ip *net.IP) error {
	if ip.To4() != nil {
		*ip = ip.To4()
		return nil
	} else if ip.To16() != nil {
		*ip = ip.To16()
		return nil
	}
	return fmt.Errorf("IP %s not v4 nor v6", *ip)
}

// LoadIPAMConfig creates IPAMConfig using json encoded configuration provided
// as `bytes`. At the moment values provided in envArgs are ignored so there
// is no possibility to overload the json configuration using envArgs
func LoadIPAMConfig(bytes []byte, envArgs string) (*IPAMConfig, string, error) {
	n := Net{}
	if err := json.Unmarshal(bytes, &n); err != nil {
		return nil, "", err
	}
	if n.IPAM == nil {
		return nil, "", fmt.Errorf("IPAM config missing 'ipam' key")
	}

	// load IP from CNI_ARGS
	if envArgs != "" {
		e := IPAMEnvArgs{}
		err := types.LoadArgs(envArgs, &e)
		if err != nil {
			return nil, "", err
		}

		if e.IP != "" {
			for _, item := range strings.Split(string(e.IP), ",") {
				ipstr := strings.TrimSpace(item)

				ip, subnet, err := net.ParseCIDR(ipstr)
				if err != nil {
					return nil, "", fmt.Errorf("the 'ip' field is expected to be in CIDR notation, got: '%s'", ipstr)
				}

				addr := Address{
					Address:    net.IPNet{IP: ip, Mask: subnet.Mask},
					AddressStr: ipstr,
				}
				n.IPAM.Addresses = append(n.IPAM.Addresses, addr)
			}
		}

		if e.GATEWAY != "" {
			for _, item := range strings.Split(string(e.GATEWAY), ",") {
				gwip := net.ParseIP(strings.TrimSpace(item))
				if gwip == nil {
					return nil, "", fmt.Errorf("invalid gateway address: %s", item)
				}

				for i := range n.IPAM.Addresses {
					if n.IPAM.Addresses[i].Address.Contains(gwip) {
						n.IPAM.Addresses[i].Gateway = gwip
					}
				}
			}
		}
	}

	// import address from args
	if n.Args != nil && n.Args.A != nil && len(n.Args.A.IPs) != 0 {
		// args IP overwrites IP, so clear IPAM Config
		n.IPAM.Addresses = make([]Address, 0, len(n.Args.A.IPs))
		for _, addrStr := range n.Args.A.IPs {
			ip, addr, err := net.ParseCIDR(addrStr)
			if err != nil {
				return nil, "", fmt.Errorf("an entry in the 'ips' field is NOT in CIDR notation, got: '%s'", addrStr)
			}
			addr.IP = ip
			n.IPAM.Addresses = append(n.IPAM.Addresses, Address{AddressStr: addrStr, Address: *addr})
		}
	}

	// import address from runtimeConfig
	if len(n.RuntimeConfig.IPs) != 0 {
		// runtimeConfig IP overwrites IP, so clear IPAM Config
		n.IPAM.Addresses = make([]Address, 0, len(n.RuntimeConfig.IPs))
		for _, addrStr := range n.RuntimeConfig.IPs {
			ip, addr, err := net.ParseCIDR(addrStr)
			if err != nil {
				return nil, "", fmt.Errorf("an entry in the 'ips' field is NOT in CIDR notation, got: '%s'", addrStr)
			}
			addr.IP = ip
			n.IPAM.Addresses = append(n.IPAM.Addresses, Address{AddressStr: addrStr, Address: *addr})
		}
	}

	// Validate all ranges
	numV4 := 0
	numV6 := 0

	for i := range n.IPAM.Addresses {
		if n.IPAM.Addresses[i].Address.IP == nil {
			ip, addr, err := net.ParseCIDR(n.IPAM.Addresses[i].AddressStr)
			if err != nil {
				return nil, "", fmt.Errorf(
					"the 'address' field is expected to be in CIDR notation, got: '%s'", n.IPAM.Addresses[i].AddressStr)
			}
			n.IPAM.Addresses[i].Address = *addr
			n.IPAM.Addresses[i].Address.IP = ip
		}

		if err := canonicalizeIP(&n.IPAM.Addresses[i].Address.IP); err != nil {
			return nil, "", fmt.Errorf("invalid address %d: %s", i, err)
		}

		if n.IPAM.Addresses[i].Address.IP.To4() != nil {
			numV4++
		} else {
			numV6++
		}
	}

	// CNI spec 0.2.0 and below supported only one v4 and v6 address
	if numV4 > 1 || numV6 > 1 {
		if ok, _ := version.GreaterThanOrEqualTo(n.CNIVersion, "0.3.0"); !ok {
			return nil, "", fmt.Errorf("CNI version %v does not support more than 1 address per family", n.CNIVersion)
		}
	}

	// Copy net name into IPAM so not to drag Net struct around
	n.IPAM.Name = n.Name

	return n.IPAM, n.CNIVersion, nil
}

func setHeaders(req *http.Request, key string, value string) *http.Request {
	req.Header.Set(key, value)
	return req
}

//executeHttpMethod - execute the specified httpMethod (POST, PUT)
func executeHttpMethod(url string, httpMethod string, bodyBytes []byte, authToken string) (*http.Response, error) {
	body := &bytes.Buffer{}
	body.WriteString(string(bodyBytes))

	log.Printf("======= Ishmeet Calling %s %s \n", httpMethod, url)
	request, err := http.NewRequestWithContext(context.Background(), httpMethod, url, body)
	if err != nil {
		return nil, err
	}
	request = setHeaders(request, "Content-Type", "application/json")
	if authToken != "" {
		request = setHeaders(request, "AuthToken", authToken)
	}
	client := http.Client{}
	//nolint: bodyclose
	resp, err := client.Do(request)
	if err != nil {
		log.Printf("Error while executing http request - %v", err)
		return nil, err
	}
	log.Printf("======= Ishmeet Status: %d \n", resp.StatusCode)
	return resp, nil
}

//GET - execute GET HTTP request
func GET(url string, respObj interface{}, authToken string) (*http.Response, error) {
	resp, err := executeHttpMethod(url, "GET", nil, authToken)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	if respObj == nil {
		return resp, nil
	}
	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body - %v", err)
		return resp, err
	}

	log.Printf("======= Ishmeet resp.Body: %v \n", string(respBodyBytes))

	err = json.Unmarshal(respBodyBytes, respObj)
	if err != nil {
		log.Printf("Failed to unmarshall response body - %v", err)
		return resp, err
	}
	return resp, nil
}

func POST(url string, bodyBytes []byte, respObj interface{}, authToken string) (*http.Response, error) {
	resp, err := executeHttpMethod(url, "POST", bodyBytes, authToken)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// if respObj == nil {
	// 	return nil
	// }
	// respBodyBytes, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	log.Printf("Failed to read response body - %v", err)
	// 	return err
	// }
	// err = json.Unmarshal(respBodyBytes, respObj)
	// if err != nil {
	// 	log.Printf("Failed to unmarshall response body - %v", err)
	// 	return err
	// }
	return resp, nil
}

func makeMsg(vmName, vmUuid, vmID, containerNamespace,
	containerIfName, hostIfName, vmiUuid, vnId string,
	vhostMode string, sockDir string, sockName string, vmiType string, podUid string) []byte {
	t := time.Now()
	//Convert vhost-mode string to uint8 0-client, 1-server
	var mode int = 0

	addMsg := ContrailAddMsg{Time: t.String(), Vm: vmID,
		VmUuid: vmUuid, VmName: vmName, HostIfName: hostIfName,
		ContainerIfName: containerIfName, Namespace: containerNamespace,
		VmiUuid: vmiUuid, VnId: vnId, VhostMode: mode, VhostSockDir: sockDir,
		VhostSockName: sockName, VmiType: vmiType, PodUid: podUid}

	msg, err := json.MarshalIndent(addMsg, "", "\t")
	if err != nil {
		return nil
	}

	return msg
}

func cmdAdd(args *skel.CmdArgs) error {

	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "/root/.kube/config", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	log.Printf("======= Ishmeet kubeconfig: %s homedir.HomeDir(): %s \n", *kubeconfig, homedir.HomeDir())

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		log.Printf("======= Ishmeet Panic here 1 %v \n", err)
		panic(err.Error())
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Printf("======= Ishmeet Panic here 2 %v \n", err)
		panic(err.Error())
	}

	log.Printf("======= Ishmeet Calling API %s \n", "/apis/core.contrail.juniper.net/v1alpha1/namespaces/telco-profile1/subnets")
	subnetData := clientset.RESTClient().Get().
		AbsPath("/apis/core.contrail.juniper.net/v1alpha1/namespaces/telco-profile1/subnets").
		Do(context.TODO())

	log.Printf("======= Ishmeet Called subnets API \n")
	var statusCode int
	subnetData.StatusCode(&statusCode)
	log.Printf("======= Ishmeet Subnet Status code: %d \n", statusCode)
	body, _ := subnetData.Raw()

	subnetList := &SubnetList{}
	err = json.Unmarshal(body, subnetList)
	if err != nil {
		log.Printf("======= Ishmeet Unable to unmarshal %v \n", err)
	}
	for _, subnet := range subnetList.Items {
		log.Printf("======= Ishmeet IP CIDR %v \n", subnet.Spec.CIDR)
		log.Printf("======= Ishmeet IP Gateway %s \n", string(subnet.Spec.DefaultGateway))
	}

	iipData := clientset.RESTClient().Get().
		AbsPath("/apis/core.contrail.juniper.net/v1alpha1/instanceips").
		Do(context.TODO())

	var iipStatusCode int
	iipData.StatusCode(&iipStatusCode)
	log.Printf("======= Ishmeet IIP Status code: %d\n", iipStatusCode)
	body, _ = iipData.Raw()

	iipList := &InstanceIPList{}
	err = json.Unmarshal(body, iipList)
	if err != nil {
		log.Printf("======= Ishmeet Unable to unmarshal %v \n", err)
	}

	for _, iip := range iipList.Items {
		log.Printf("======= Ishmeet %s, %s, %s \n", iip.Spec.IPAddress, iip.Spec.IPFamily, iip.ObjectMeta.Name)
	}

	url := "http://127.0.0.1:9091/vm-cfg/" + "__" + "telco-profile1" + "__" + "sriov-pod-vlan-70"
	vmCfgResponse := &[]Result{}
	for i := 0; i < 10; i++ {
		resp, err := GET(url, vmCfgResponse, "")
		if err != nil {
			log.Printf("======= Ishmeet Failed to get vm-cfg - %v", err)
			break
		}

		log.Printf("======= Ishmeet vm-cfg response %d. Retry-Count: %d \n", resp.StatusCode, i)
		if resp.StatusCode == 200 {
			break
		}
		time.Sleep(1 * time.Second)
	}
	log.Printf("======= Ishmeet vm-cfg: %v", vmCfgResponse)

	for _, vmCfg := range *vmCfgResponse {
		if strings.Contains(vmCfg.Annotations.Network, "sriov-net-70") {
			addMsg := makeMsg("__"+"telco-profile1"+"__"+"sriov-pod-vlan-70", vmCfg.VmUuid, args.ContainerID, args.Netns,
				args.IfName, args.IfName, vmCfg.VmiUuid, vmCfg.VnId, "client", "", "", "", "")
			log.Printf("======= Ishmeet addMsg %v \n", addMsg)

			resp, err := POST("http://127.0.0.1:9091/vm", addMsg, nil, "")
			if err != nil {
				log.Printf("======= Ishmeet Failed to post vm - %v", err)
			}
			log.Printf("======= Ishmeet post vm response %d \n", resp.StatusCode)
		}
	}

	for _, vmCfg := range *vmCfgResponse {
		url2 := "http://127.0.0.1:9091/vm/" + vmCfg.VmUuid + "/" + vmCfg.VmiUuid
		vmResponse := &[]Result{}
		for i := 0; i < 10; i++ {
			resp, err := GET(url2, vmResponse, "")
			if err != nil {
				log.Printf("======= Ishmeet Failed to get vm - %v", err)
			}

			log.Printf("======= Ishmeet vm response %d. Retry-Count: %d \n", resp.StatusCode, i)
			if resp.StatusCode == 200 {
				break
			}
			time.Sleep(1 * time.Second)
		}
		log.Printf("======= Ishmeet vm: %v", vmResponse)
	}

	// =================================== DELAY 20secs ===================================
	for i := 0; i < 10; i++ {
		log.Printf("======= Ishmeet Sleeping 2 seconds Count %d/10 ...", i+1)
		time.Sleep(2 * time.Second)
	}
	// ====================================================================================

	var addressIPCidr *net.IPNet
	var gatewayIP net.IP
	if len(subnetList.Items) > 0 {
		_, addressIPCidr, _ = net.ParseCIDR(string(subnetList.Items[0].Spec.CIDR))
		gatewayIP = net.ParseIP(string(subnetList.Items[0].Spec.DefaultGateway))
	}

	routeIP, routeIPCidr, _ := net.ParseCIDR("0.0.0.0/0")
	// _, addressIPCidr, _ = net.ParseCIDR("70.101.1.5/32")
	// gatewayIP = net.ParseIP("70.101.1.1")
	confVersion := "0.3.1"

	log.Printf("======= Ishmeet ADDRESS_CIDR: %s \n", addressIPCidr)
	log.Printf("======= Ishmeet DEFAULT_GW: %s \n", gatewayIP)

	ipamConfig := &IPAMConfig{
		Name: "cn2-ipam",
		Type: "cn2-ipam",
		Routes: append([]*types.Route{}, &types.Route{
			Dst: *routeIPCidr,
			GW:  routeIP,
		}),
		Addresses: append([]Address{}, Address{
			AddressStr: "70.101.1.5/32",
			Address:    *addressIPCidr,
			Gateway:    gatewayIP,
		}),
	}

	log.Printf("======= Ishmeet NW: %s, GW: %s \n", "70.101.1.5/32", "70.101.1.1")
	log.Printf("======= Ishmeet %v \n", args)
	log.Printf("======= Ishmeet Container ID: %s \n", string(args.ContainerID))
	log.Printf("======= Ishmeet Netns: %s \n", string(args.Netns))
	log.Printf("======= Ishmeet Interface name %s \n", string(args.IfName))
	log.Printf("======= Ishmeet Args %s \n", string(args.Args))
	log.Printf("======= Ishmeet Path %s \n", string(args.Path))
	log.Printf("======= Ishmeet StdinData %v \n", string(args.StdinData))

	result := &current.Result{
		CNIVersion: current.ImplementedSpecVersion,
		DNS:        ipamConfig.DNS,
		Routes:     ipamConfig.Routes,
	}
	for _, v := range ipamConfig.Addresses {
		result.IPs = append(result.IPs, &current.IPConfig{
			Address: v.Address,
			Gateway: v.Gateway,
		})
	}

	return types.PrintResult(result, confVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	// Nothing required because of no resource allocation in static plugin.
	return nil
}
