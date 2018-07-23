/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"net"
	"strings"
	"testing"
)

func initTestIPAllocator(t *testing.T) (*IPAllocator) {
	testReserved := make(map[string]bool)
	testUnreserved := make(map[string][]string)
	return &IPAllocator{
		unreserved: testUnreserved,
		reserved:   testReserved,
	}
}
func TestAllIPBlocksAvailable(t *testing.T) {
	ipAllocator := initTestIPAllocator(t)
	ips := [8]string{"192.168.92.32/29", "192.168.92.40/29", "192.168.92.48/29", "192.168.92.56/29"}

	cidr := "192.168.92.32/27"

	ip, err := ipAllocator.GetAvailableIPBlock(cidr)
	if err != nil {
		t.Errorf(err.Error())
	}
	if ip != ips[0] {
		t.Errorf("Expected IP %s to be released from the free IP pool but got IP %s", ips[0], ip)
	}
	var reservedUpdated = make(map[string]bool)
	ipAllocator.UpdateReservedIPs(reservedUpdated)
}

func TestSomeIPBlocksAvailable(t *testing.T) {
	ipAllocator := initTestIPAllocator(t)
	reserved := map[string]bool{
		"192.168.92.33": true,
		"192.168.92.43": true,
	}
	ips := [8]string{"192.168.92.32/29", "192.168.92.40/29", "192.168.92.48/29"}
	ipAllocator.reserved = reserved

	cidr := "192.168.92.32/27"
	ip, err := ipAllocator.GetAvailableIPBlock(cidr)
	if err != nil {
		t.Errorf(err.Error())
	}
	if ip != ips[2] {
		t.Errorf("Expected IP %s to be released from the free IP pool but got IP %s", ips[2], ip)
	}

	var reservedUpdated = make(map[string]bool)
	ipAllocator.UpdateReservedIPs(reservedUpdated)
}
func TestNoIPBlocksAvailable(t *testing.T) {
	ipAllocator := initTestIPAllocator(t)
	ips := [8]string{"192.168.92.32/29", "192.168.92.40/29", "192.168.92.48/29", "192.168.92.56/29"}

	reserved := make(map[string]bool)
	for _, ip := range ips {
		reserved[strings.Split(ip, "/")[0]] = true
	}
	ipAllocator.reserved = reserved

	cidr := "192.168.92.32/27"
	ip, err := ipAllocator.GetAvailableIPBlock(cidr)
	expectedErrorMessage := "All /29 ranges in the specified CIDR 192.168.92.32/27 already in use"
	if err == nil || err.Error() != expectedErrorMessage {
		t.Errorf("Expected error as all the ips in the cidr %s had been reserved but got ip %s as unreserved", cidr, ip)
	}

	var reservedUpdated = make(map[string]bool)
	ipAllocator.UpdateReservedIPs(reservedUpdated)
}

func TestOverlappingCIDR(t *testing.T) {
	ipAllocator := initTestIPAllocator(t)
	ips := [8]string{"192.168.92.32/29", "192.168.92.40/29", "192.168.92.48/29", "192.168.92.56/29"}

	cidr := "192.168.92.32/27"
	ip, err := ipAllocator.GetAvailableIPBlock(cidr)
	if err != nil {
		t.Errorf(err.Error())
	}
	if ip != ips[0] {
		t.Errorf("Expected IP %s to be released from the free IP pool but got IP %s", ips[0], ip)
	}
	overlappingCIDR := "192.168.92.32/26"
	ip, err = ipAllocator.GetAvailableIPBlock(overlappingCIDR)
	expectedErrorMessage := "The specified cidr overlaps with cidr range 192.168.92.32/27"
	if err == nil || err.Error() != expectedErrorMessage {
		t.Errorf("Expected error as CIDR %s and CIDR %s overlap but received IP %s as unreserved", cidr, overlappingCIDR, ip)
	}
}

func TestUnreserveIPBlock(t *testing.T) {
	ipAllocator := initTestIPAllocator(t)
	ips := [8]string{"192.168.92.32/29", "192.168.92.40/29", "192.168.92.48/29", "192.168.92.56/29"}
	cidr := "192.168.92.32/27"
	err := ipAllocator.UnreserveIPBlock(ips[0])
	if err == nil {
		t.Errorf("IP %s was not present in the reserved pool but able to add it to the unreserved pool ", ips[0])
	}

	ip, err := ipAllocator.GetAvailableIPBlock(cidr)

	err = ipAllocator.UnreserveIPBlock(ip)
	if err != nil {
		t.Errorf(err.Error())
	}

	testIP := "192.168.1.0/29"

	err = ipAllocator.UnreserveIPBlock(testIP)

	expectedErrorMessage := "No accessed CIDR block contains the provided IP address 192.168.1.0"
	if err == nil || err.Error() != expectedErrorMessage {
		t.Errorf("Expected error due to free request for IP from unaccessed CIDR but call succeeded")
	}
}

func TestIncrementIP(t *testing.T) {
	currentIP := "192.168.92.32"
	nextIP := "192.168.92.40"
	ip := net.ParseIP(currentIP)
	incrementIP(ip, 8)

	if ip.String() != nextIP {
		t.Errorf("Error while incrementing IP expected %s but got %s", nextIP, ip.String())
	}

	currentIP = "255.255.255.254"
	ip = net.ParseIP(currentIP)
	step := 8
	err := incrementIP(ip, byte(step))
	if err == nil {
		t.Errorf("IP Overflow not caught for IP %s increment by %d", ip.String(), 8)
	}
}

func TestCloneIP(t *testing.T) {
	originalIP := net.ParseIP("192.168.92.32")
	cloneIP := cloneIP(originalIP)
	if cloneIP.String() != originalIP.String() {
		t.Errorf("Error while cloning IP %s", originalIP.String())
	}
}
