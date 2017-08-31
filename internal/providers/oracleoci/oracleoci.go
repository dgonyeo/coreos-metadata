// Copyright 2017 CoreOS, Inc.
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

package oracleoci

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/coreos/coreos-metadata/internal/providers"
	"github.com/coreos/coreos-metadata/internal/retry"
)

type instanceData struct {
	AvailabilityDomain string   `json:"availabilityDomain"`
	CompartmentId      string   `json:"compartmentId"`
	DisplayName        string   `json:"displayName"`
	Id                 string   `json:"id"`
	Image              string   `json:"image"`
	Region             string   `json:"region"`
	Shape              string   `json:"shape"`
	TimeCreated        uint64   `json:"timeCreated"`
	Metadata           metadata `json:"metadata"`
}

type networkData struct {
	VnicId          string `json:"vnicId"`
	PrivateIp       string `json:"privateIp"`
	VlanTag         int    `json:"vlanTag"`
	MacAddr         string `json:"macAddr"`
	VirtualRouterIp string `json:"virtualRouterIp"`
	SubnetCidrBlock string `json:"subnetCidrBlock"`
	NicIndex        int    `json:"nicIndex"`
}

type metadata struct {
	SshAuthorizedKeys string `json:"ssh_authorized_keys"`
}

func FetchMetadata() (providers.Metadata, error) {
	client := retry.Client{
		InitialBackoff: time.Second,
		MaxBackoff:     time.Second * 5,
		MaxAttempts:    10,
	}

	instanceDataBlob, err := client.Get("http://169.254.169.254/opc/v1/instance/")
	if err != nil {
		return providers.Metadata{}, err
	}

	var instanceData instanceData
	err = json.Unmarshal(instanceDataBlob, &instanceData)
	if err != nil {
		return providers.Metadata{}, err
	}

	networkDataBlob, err := client.Get("http://169.254.169.254/opc/v1/vnics/")
	if err != nil {
		return providers.Metadata{}, err
	}

	var networkData []networkData
	err = json.Unmarshal(networkDataBlob, &networkData)
	if err != nil {
		return providers.Metadata{}, err
	}

	network, netdev, err := parseNetwork(networkData)
	if err != nil {
		return providers.Metadata{}, fmt.Errorf("failed to parse network config from metadata: %v", err)
	}

	return providers.Metadata{
		Attributes: map[string]string{
			"ORACLE_OCI_HOSTNAME": instanceData.DisplayName,
		},
		Hostname: instanceData.DisplayName,
		SshKeys:  strings.Split(instanceData.Metadata.SshAuthorizedKeys, "\n"),
		Network:  network,
		NetDev:   netdev,
	}, nil
}

/*
[ {
  "vnicId" : "ocid1.vnic.oc1.phx.abyhqljsl6ccxil4bywjlkj7n4ko3voet3xuth3veezszrky23jxd3vit5ta",
  "privateIp" : "10.0.0.76",
  "vlanTag" : 0,
  "macAddr" : "90:e2:ba:e5:09:e8",
  "virtualRouterIp" : "10.0.0.1",
  "subnetCidrBlock" : "10.0.0.0/24",
  "nicIndex" : 0
}, {
  "vnicId" : "ocid1.vnic.oc1.phx.abyhqljssfinka7ntqtltr75neqkqyw2kwrcuhmi4zxyvyv53z33qmbv5mmq",
  "privateIp" : "10.0.0.3",
  "vlanTag" : 1,
  "macAddr" : "00:00:17:01:1B:E2",
  "virtualRouterIp" : "10.0.0.1",
  "subnetCidrBlock" : "10.0.0.0/24",
  "nicIndex" : 0
} ]
*/

func parseNetwork(netdatas []networkData) ([]providers.NetworkInterface, []providers.NetworkDevice, error) {
	var ifaces []providers.NetworkInterface
	var netdevs []providers.NetworkDevice
	var macvlanNames []string
	for _, netdata := range netdatas {
		if netdata.VlanTag == 0 {
			continue
		}
		vlanName := fmt.Sprintf("vlan%d", netdata.VlanTag)
		macvlanName := fmt.Sprintf("macvlan%d", netdata.VlanTag)
		macvlanNames = append(macvlanNames, macvlanName)
		// Create a .netdev file with a MACVLAN to hold the new mac address
		mac, err := net.ParseMAC(netdata.MacAddr)
		if err != nil {
			return nil, nil, err
		}
		netdevs = append(netdevs, providers.NetworkDevice{
			Name:            macvlanName,
			Kind:            "macvlan",
			HardwareAddress: mac,
			Priority:        5,
			Sections: []providers.Section{
				{
					Name: "MACVLAN",
					Attributes: [][2]string{
						{
							"macvlan",
							"passthru",
						},
					},
				},
			},
		})
		// Create a .netdev file with a VLAN for the new MACVLAN device
		netdevs = append(netdevs, providers.NetworkDevice{
			Name: vlanName,
			Kind: "vlan",
			//HardwareAddress: mac,
			Priority: 5,
			Sections: []providers.Section{
				{
					Name: "VLAN",
					Attributes: [][2]string{
						{
							"Id",
							fmt.Sprintf("%d", netdata.VlanTag),
						},
					},
				},
			},
		})
		// Create a .network file for the macvlan to tie the vlan to it
		ifaces = append(ifaces, providers.NetworkInterface{
			Name:            fmt.Sprintf("macvlan%d", netdata.VlanTag),
			HardwareAddress: mac,
			Priority:        5,
			Vlan:            []string{vlanName},
		})
		// Create a .network file detailing the network settings for the VLAN
		ip := net.ParseIP(netdata.PrivateIp)
		if ip == nil {
			return nil, nil, fmt.Errorf("couldn't parse IP address %q", netdata.PrivateIp)
		}
		gatewayIp := net.ParseIP(netdata.VirtualRouterIp)
		if gatewayIp == nil {
			return nil, nil, fmt.Errorf("couldn't parse IP address %q", netdata.VirtualRouterIp)
		}
		_, subnet, err := net.ParseCIDR(netdata.SubnetCidrBlock)
		if err != nil {
			return nil, nil, err
		}
		if subnet == nil {
			return nil, nil, fmt.Errorf("couldn't parse subnet %q", netdata.SubnetCidrBlock)
		}
		ifaces = append(ifaces, providers.NetworkInterface{
			Name: fmt.Sprintf("vlan%d", netdata.VlanTag),
			//HardwareAddress: mac,
			Priority:    5,
			Nameservers: nil,
			IPAddresses: []net.IPNet{
				{
					IP:   ip,
					Mask: subnet.Mask,
				},
			},
			Routes: []providers.NetworkRoute{
				{
					Destination: *subnet,
					Gateway:     gatewayIp,
				},
			},
			RouteTable: 100 + netdata.VlanTag,
		})
	}
	// Create the .network file for the main interface
	for _, netdata := range netdatas {
		if netdata.VlanTag != 0 {
			continue
		}
		mac, err := net.ParseMAC(netdata.MacAddr)
		if err != nil {
			return nil, nil, err
		}
		ifaces = append(ifaces, providers.NetworkInterface{
			Name:            netdata.MacAddr,
			HardwareAddress: mac,
			Priority:        5,
			DHCP:            "yes",
			Macvlan:         macvlanNames,
		})
	}
	return ifaces, netdevs, nil
}
