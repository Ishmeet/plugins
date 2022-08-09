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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
)

const getVmCfg = `[{
	"id": "85db7b6e-3c94-4625-8ed8-43bd435358b8",
	"vm-uuid": "e44c5dce-d4c1-4f3c-ad6b-c67d98ae4afb",
	"vn-id": "692547d0-f4e6-4585-a730-aaecad7498f3",
	"vn-name": "default-domain:telco-profile1:sriov-net-70",
	"mac-address": "02:85:db:7b:6e:3c",
	"sub-interface": false,
	"vlan-id": 65535,
	"annotations": [
		"{index:1/2}",
		"{interface:eth1}",
		"{network:sriov-net-70}",
		"{vmi-address-family:ipV4}"
	]
},{
	"id": "d15de402-8729-435e-8945-521e59a0638c",
	"vm-uuid": "e44c5dce-d4c1-4f3c-ad6b-c67d98ae4afb",
	"vn-id": "96558d54-6b3b-437d-a04b-5b8f3fa9b6b6",
	"vn-name": "default-domain:contrail-k8s-kubemanager-cluster-local-contrail:default-podnetwork",
	"mac-address": "02:d1:5d:e4:02:87",
	"sub-interface": false,
	"vlan-id": 65535,
	"annotations": [
		"{index:0/2}",
		"{interface:eth0}",
		"{network:default-podnetwork}",
		"{vmi-address-family:ipV4}"
	]
}]`

const getVmCfg_Fail = `[{
	"id": "d15de402-8729-435e-8945-521e59a0638c",
	"vm-uuid": "e44c5dce-d4c1-4f3c-ad6b-c67d98ae4afb",
	"vn-id": "96558d54-6b3b-437d-a04b-5b8f3fa9b6b6",
	"vn-name": "default-domain:contrail-k8s-kubemanager-cluster-local-contrail:default-podnetwork",
	"mac-address": "02:d1:5d:e4:02:87",
	"sub-interface": false,
	"vlan-id": 65535,
	"annotations": [
		"{index:0/2}",
		"{interface:eth0}",
		"{network:default-podnetwork}",
		"{vmi-address-family:ipV4}"
	]
}]`

const getVM = `[{ 
    "id": "9c78dbf6-efe1-4d40-b188-31ecdea0f7dd", 
    "instance-id": "820841b0-4a87-4ec8-bb17-c071ed8cb3a3", 
    "vn-id": "96558d54-6b3b-437d-a04b-5b8f3fa9b6b6", 
    "vm-project-id": "00000000-0000-0000-0000-000000000000", 
    "mac-address": "02:9c:78:db:f6:ef", 
    "system-name": "tapeth0-820841", 
    "rx-vlan-id": 65535, 
    "tx-vlan-id": 65535, 
    "vhostuser-mode": 0, 
    "ip-address": "10.232.67.3", 
    "plen": 18, 
    "dns-server": "10.232.64.1", 
    "gateway": "10.232.64.1", 
    "author": "/contrail-vrouter-agent", 
    "time": "460818:14:49.935126" 
}] `

func Test_cmdAdd(t *testing.T) {
	conf := `{
		"type": "sriov",
		"cniVersion": "0.3.1",
		"name": "sriov-net-70",
		"ipam": {
		  "type": "cn2-ipam"
		}
	  }`

	type args struct {
		args *skel.CmdArgs
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Success case",
			args: args{
				args: &skel.CmdArgs{
					ContainerID: "445e42b29e2b7e58cd6e238269a37a015641a9af5aa3b4ad5940401fbeda914d",
					Netns:       "/var/run/netns/4f67545a-9b8d-4891-a6e0-ec8e4f251569",
					IfName:      "net1",
					StdinData:   []byte(conf),
					Args:        "IgnoreUnknown=true;K8S_POD_NAMESPACE=telco-profile1;K8S_POD_NAME=sriov-pod-vlan-70;K8S_POD_INFRA_CONTAINER_ID=445e42b29e2b7e58cd6e238269a37a015641a9af5aa3b4ad5940401fbeda914d",
					Path:        "/opt/cni/bin:/opt/cni/bin:/usr/libexec/cni",
				},
			},
			wantErr: false,
		},
		{
			name: "Fail case 1",
			args: args{
				args: &skel.CmdArgs{
					ContainerID: "445e42b29e2b7e58cd6e238269a37a015641a9af5aa3b4ad5940401fbeda914d",
					Netns:       "/var/run/netns/4f67545a-9b8d-4891-a6e0-ec8e4f251569",
					IfName:      "net1",
					StdinData:   []byte(conf),
					Args:        "IgnoreUnknown=true;K8S_POD_NAMESPACE=telco-profile1;K8S_POD_NAME=sriov-pod-vlan-71;K8S_POD_INFRA_CONTAINER_ID=445e42b29e2b7e58cd6e238269a37a015641a9af5aa3b4ad5940401fbeda914d",
					Path:        "/opt/cni/bin:/opt/cni/bin:/usr/libexec/cni",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					if strings.Contains(r.URL.Path, "/vm-cfg/__telco-profile1__sriov-pod-vlan-70") {
						w.WriteHeader(200)
						_, _ = w.Write([]byte(getVmCfg))
					} else if strings.Contains(r.URL.Path, "/vm/e44c5dce-d4c1-4f3c-ad6b-c67d98ae4afb/85db7b6e-3c94-4625-8ed8-43bd435358b8") {
						w.WriteHeader(200)
						_, _ = w.Write([]byte(getVM))
					} else if strings.Contains(r.URL.Path, "/vm-cfg/__telco-profile1__sriov-pod-vlan-71") {
						w.WriteHeader(200)
						_, _ = w.Write([]byte(getVmCfg_Fail))
					}
				} else if r.Method == "POST" {
					if strings.Contains(r.URL.Path, "/vm") {
						w.WriteHeader(200)
					}
				}
			}))

			setVRouterURL(testServer.URL)
			defer testServer.Close()
			setFilePath("/Users/ishmeets")

			if err := cmdAdd(tt.args.args); (err != nil) != tt.wantErr {
				t.Errorf("cmdAdd() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_cmdDel(t *testing.T) {
	conf := `{
		"type": "sriov",
		"cniVersion": "0.3.1",
		"name": "sriov-net-70",
		"ipam": {
		  "type": "cn2-ipam"
		}
	  }`

	type args struct {
		args *skel.CmdArgs
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Success case",
			args: args{
				args: &skel.CmdArgs{
					ContainerID: "445e42b29e2b7e58cd6e238269a37a015641a9af5aa3b4ad5940401fbeda914d",
					Netns:       "/var/run/netns/4f67545a-9b8d-4891-a6e0-ec8e4f251569",
					IfName:      "net1",
					StdinData:   []byte(conf),
					Args:        "IgnoreUnknown=true;K8S_POD_NAMESPACE=telco-profile1;K8S_POD_NAME=sriov-pod-vlan-70;K8S_POD_INFRA_CONTAINER_ID=445e42b29e2b7e58cd6e238269a37a015641a9af5aa3b4ad5940401fbeda914d",
					Path:        "/opt/cni/bin:/opt/cni/bin:/usr/libexec/cni",
				},
			},
			wantErr: false,
		},
		{
			name: "Fail case 1",
			args: args{
				args: &skel.CmdArgs{
					ContainerID: "445e42b29e2b7e58cd6e238269a37a015641a9af5aa3b4ad5940401fbeda914d",
					Netns:       "/var/run/netns/4f67545a-9b8d-4891-a6e0-ec8e4f251569",
					IfName:      "net23",
					StdinData:   []byte(conf),
					Args:        "IgnoreUnknown=true;K8S_POD_NAMESPACE=telco-profile1;K8S_POD_NAME=sriov-pod-vlan-70;K8S_POD_INFRA_CONTAINER_ID=445e42b29e2b7e58cd6e238269a37a015641a9af5aa3b4ad5940401fbeda914d",
					Path:        "/opt/cni/bin:/opt/cni/bin:/usr/libexec/cni",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "DELETE" {
					if strings.Contains(r.URL.Path, "/vm/e44c5dce-d4c1-4f3c-ad6b-c67d98ae4afb") {
						w.WriteHeader(204)
					}
				}
			}))

			setVRouterURL(testServer.URL)
			defer testServer.Close()
			setFilePath("/Users/ishmeets")

			if err := cmdDel(tt.args.args); (err != nil) != tt.wantErr {
				t.Errorf("cmdDel() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
