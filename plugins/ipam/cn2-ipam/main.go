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
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
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

const FileNotExist = "File/Dir does not exist"

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
	return resp, nil
}

//DELETE - execute DELETE HTTP request
func DELETE(url string, bodyBytes []byte, respObj interface{}, authToken string) (*http.Response, error) {
	resp, err := executeHttpMethod(url, "DELETE", bodyBytes, authToken)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return resp, nil
}

func getPodInfo(args string) string {
	re := regexp.MustCompile(
		"(K8S_POD_NAMESPACE|K8S_POD_NAME)=([a-zA-z0-9-\\.]+)")
	result := re.FindAllStringSubmatchIndex(args, -1)
	kv := make(map[string]string)
	/*
	 * match[0] --> first char of the regex pattern
	 * match[1] --> last char of the regex pattern
	 * match[2] --> first char of the first substring in the regex pattern
	 * match[3] --> first char of the second substring in the regex pattern
	 * match[4] --> first char of the third substring in the regex pattern
	 * match[5] --> last char of the regex pattern
	 */
	for _, match := range result {
		key := args[match[2]:match[3]]
		value := args[match[4]:match[5]]
		kv[key] = value
	}
	containerName := "" + "__" +
		kv["K8S_POD_NAMESPACE"] + "__" + kv["K8S_POD_NAME"]

	return containerName
}

func checkFileOrDirExists(fname string) bool {
	if _, err := os.Stat(fname); err != nil {
		log.Printf("File/Dir - %s does not exist. Error - %+v", fname, err)
		return false
	}

	log.Printf("File/Dir - %s exists", fname)
	return true
}

func makeFileName(VmiUUID string, containerName string) string {
	fname := filePath + "/" + containerName
	if VmiUUID != "" {
		fname = fname + "/" + VmiUUID
	}
	return fname
}

func addVmFile(addMsg []byte, vmiUuid string, containerName string) error {
	// Check if path to directory exists exists, else create directory
	path := filePath + "/" + containerName
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0777); err != nil {
			log.Printf("Error creating VM directory %s. Error : %s", path, err)
			return err
		}
	}

	// Write file with VMI UUID as the file name
	fname := makeFileName(vmiUuid, containerName)
	err := os.WriteFile(fname, addMsg, 0777)
	if err != nil {
		log.Printf("Error writing VM config file %s. Error : %s", fname, err)
		return err
	}

	return nil
}

func delVmFile(vmiUuid, containerIfName string) (error, error) {
	fname := makeFileName(vmiUuid, containerIfName)
	_, err := os.Stat(fname)
	// File not present... nothing to do
	if err != nil {
		log.Printf("File %s not found. Error : %s", fname, err)
		return nil, nil
	}

	err = os.Remove(fname)
	if err != nil {
		log.Printf("Failed deleting file %s. Error : %s", fname, err)
		return nil, nil
	}

	log.Printf("file %s deleted", fname)
	return nil, nil
}

func readContrailAddMsg(fname string) (ContrailAddMsg, error) {
	var msg ContrailAddMsg
	if checkFileOrDirExists(fname) {
		file, err := os.ReadFile(fname)
		if err != nil {
			log.Printf("Error reading file %s. Error : %s", fname, err)
			return msg, fmt.Errorf("Error reading file %s. Error : %+v", fname, err)
		}

		err = json.Unmarshal(file, &msg)
		if err != nil {
			log.Printf("Error decoding file. Error : %+v", err)
			return msg, err
		}

		return msg, nil
	}
	err := errors.New(FileNotExist)
	return msg, err
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
	n := CN2Net{}
	if err := json.Unmarshal(args.StdinData, &n); err != nil {
		log.Printf("======= Ishmeet Failed to unmarshall StdinData - %v", err)
		return err
	}

	containerName := getPodInfo(args.Args)
	log.Printf("======= Ishmeet containerName: %s \n", containerName)
	log.Printf("======= Ishmeet CN2Net: %v \n", n)

	url := fmt.Sprintf("%s/vm-cfg/%s", vrouterURL, containerName)
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
	for _, vmcffg := range *vmCfgResponse {
		log.Printf("======= Ishmeet vm-cfg-Args: %v", vmcffg.Args)
	}

	isFound := false
	vmiResult := &Result{}
	for _, vmCfg := range *vmCfgResponse {
		for _, vmArgs := range vmCfg.Args {
			if strings.Contains(vmArgs, n.Name) {
				addMsg := makeMsg(containerName, vmCfg.VmUuid, args.ContainerID, args.Netns,
					args.IfName, args.IfName, vmCfg.VmiUuid, vmCfg.VnId, "client", "", "", "", "")
				log.Printf("======= Ishmeet addMsg %v \n", string(addMsg))

				// Store config to file for persistency
				if err := addVmFile(addMsg, vmCfg.VmiUuid, containerName); err != nil {
					log.Printf("======= Ishmeet Error storing config file")
					return err
				}

				url := fmt.Sprintf("%s/vm", vrouterURL)
				resp, err := POST(url, addMsg, nil, "")
				if err != nil {
					log.Printf("======= Ishmeet Failed to post vm - %v", err)
				}
				log.Printf("======= Ishmeet post vm response %d \n", resp.StatusCode)
				isFound = true
				vmiResult = &vmCfg
				break
			}
		}
		if isFound {
			break
		}
	}

	vmResponse := &[]Result{}
	if isFound {
		url2 := fmt.Sprintf("%s/vm/"+vmiResult.VmUuid+"/"+vmiResult.VmiUuid, vrouterURL)
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

	var addressIPCidr *net.IPNet
	var gatewayIP net.IP
	if isFound {
		for _, vm := range *vmResponse {
			mask := net.CIDRMask(vm.Plen, 32)
			addressIPCidr = &net.IPNet{IP: net.ParseIP(vm.Ip), Mask: mask}
			gatewayIP = net.ParseIP(vm.Gw)
		}
	} else {
		_, addressIPCidr, _ = net.ParseCIDR(string("1.1.1.2/32"))
		gatewayIP = net.ParseIP(string("1.1.1.1"))
	}

	routeIP, routeIPCidr, _ := net.ParseCIDR("0.0.0.0/0")
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
	n := CN2Net{}
	if err := json.Unmarshal(args.StdinData, &n); err != nil {
		log.Printf("======= Ishmeet Failed to unmarshall StdinData - %v", err)
		return err
	}

	containerName := getPodInfo(args.Args)
	log.Printf("======= Ishmeet DeletePath containerName: %s \n", containerName)
	log.Printf("======= Ishmeet DeletePath CN2Net: %v \n", n)

	dir, err := os.ReadDir(filePath + "/" + containerName)
	if err != nil {
		return fmt.Errorf("unable to find path %s, Err: %s", filePath, err)
	}

	isFound := false
	for _, file := range dir {
		log.Printf("fileName: %s", file.Name())
		contrailMsg, err := readContrailAddMsg(filePath + "/" + containerName + "/" + file.Name())
		if err != nil {
			return fmt.Errorf("unable to read file %s, Err: %s", file.Name(), err)
		}

		log.Printf("======= Ishmeet DeletePath %s,%s\n", contrailMsg.ContainerIfName, args.IfName)
		if contrailMsg.ContainerIfName == args.IfName {
			log.Printf("======= Ishmeet DeletePath Interface %s found\n", args.IfName)
			isFound = true

			_, _ = delVmFile(file.Name(), containerName)

			delMsg := makeMsg("", contrailMsg.VmUuid, contrailMsg.Vm, "", "", "", "", "", "", "", "", "", "")
			url := fmt.Sprintf("%s/vm/%s", vrouterURL, contrailMsg.VmUuid)
			resp, err := DELETE(url, delMsg, nil, "")
			if err != nil {
				log.Printf("======= Ishmeet Failed to delete vm - %v", err)
			}
			log.Printf("======= Ishmeet delete vm response %d \n", resp.StatusCode)
		}
	}
	if !isFound {
		log.Printf("======= Ishmeet DeletePath interface %s not found", args.IfName)
		return fmt.Errorf("interface %s not found", args.IfName)
	}

	return nil
}

var filePath = "/var/lib/contrail/ports/vm"

func setFilePath(path string) {
	filePath = path
}

var vrouterURL = "http://127.0.0.1:9091"

func setVRouterURL(url string) {
	vrouterURL = url
}
