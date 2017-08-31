// Copyright 2016 CoreOS, Inc.
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

package providers

import (
	"fmt"
	"net"
	"reflect"
)

type Metadata struct {
	Attributes map[string]string
	Hostname   string
	SshKeys    []string
	Network    []NetworkInterface
	NetDev     []NetworkDevice
}

type NetworkInterface struct {
	Name            string
	HardwareAddress net.HardwareAddr
	Priority        int
	Nameservers     []net.IP
	IPAddresses     []net.IPNet
	Routes          []NetworkRoute
	Bond            string
	Vlan            []string
}

type NetworkRoute struct {
	Destination net.IPNet
	Gateway     net.IP
}

type NetworkDevice struct {
	Name            string
	Kind            string
	HardwareAddress net.HardwareAddr
	Priority        int
	Sections        []Section
}

type Section struct {
	Name       string
	Attributes [][2]string
}

func (i NetworkInterface) UnitName() string {
	priority := i.Priority
	if priority == 0 {
		priority = 10
	}
	name := i.Name
	if name == "" {
		name = i.HardwareAddress.String()
	}
	return fmt.Sprintf("%02d-%s.network", priority, name)
}

func (i NetworkInterface) NetworkConfig() string {
	config := "[Match]\n"
	if i.Name != "" {
		config += fmt.Sprintf("Name=%s\n", i.Name)
	}
	if i.HardwareAddress != nil {
		config += fmt.Sprintf("MACAddress=%s\n", i.HardwareAddress)
	}

	config += "\n[Network]\n"
	for _, nameserver := range i.Nameservers {
		config += fmt.Sprintf("DNS=%s\n", nameserver)
	}
	if i.Bond != "" {
		config += fmt.Sprintf("Bond=%s\n", i.Bond)
	}
	for _, vlan := range i.Vlan {
		config += fmt.Sprintf("VLAN=%s\n", vlan)
	}

	for _, addr := range i.IPAddresses {
		config += fmt.Sprintf("\n[Address]\nAddress=%s\n", addr.String())
	}
	for _, route := range i.Routes {
		config += fmt.Sprintf("\n[Route]\nDestination=%s\nGateway=%s\n", route.Destination.String(), route.Gateway)
	}

	return config
}

func (d NetworkDevice) UnitName() string {
	priority := d.Priority
	if priority == 0 {
		priority = 10
	}
	return fmt.Sprintf("%02d-%s.netdev", priority, d.Name)
}

func (d NetworkDevice) NetdevConfig() string {
	config := fmt.Sprintf("[NetDev]\nName=%s\nKind=%s\nMACAddress=%s\n", d.Name, d.Kind, d.HardwareAddress)

	for _, section := range d.Sections {
		config += fmt.Sprintf("\n[%s]\n", section.Name)
		for _, attr := range section.Attributes {
			config += fmt.Sprintf("%s=%s\n", attr[0], attr[1])
		}
	}

	return config
}

func String(s fmt.Stringer) string {
	if reflect.ValueOf(s).IsNil() {
		return ""
	}

	return s.String()
}
