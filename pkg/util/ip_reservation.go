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
	"bytes"
	"fmt"
	"net"
	"sync"
)

// IPAllocator object keeps track of both the reserved and unreserved /29 IPAllocator. The unreserved list is a map with the key as cidr address and the value as the list of
//available /29 IPs in that CIDR.
type IPAllocator struct {
	unreserved map[string][]string
	reserved   map[string]bool
	mutex      sync.Mutex
}

// InitIPBlocks initializes the reserved and unreserved /29 blocks list. The reserved list is mapped against a cidr
func NewIPAllocator(unreserved map[string][]string, reserved map[string]bool) *IPAllocator {
	return &IPAllocator{
		unreserved: unreserved,
		reserved:   reserved,
	}
}

// ReserveIPs reserves all the IPs in a /29 blocks by adding them to the reserved list. Also, if any of the cidr's contain this /29 address, we need to evict it as it
//has been added to the reserved list
func (ipAllocator *IPAllocator) ReserveIPs(ipBlock string) {
	ip, ipnet, _ := net.ParseCIDR(ipBlock)
	var err error
	for ; ipnet.Contains(ip) && err == nil; err = incrementIP(ip, 1) {
		ipAllocator.reserved[ip.String()] = true
	}
	for cidr := range ipAllocator.unreserved {
		err = ipAllocator.validateCIDROverlap(ipBlock)
		if err != nil {
			availableIPBlocks, err := ipAllocator.getAvailableIPBlocks(cidr)
			if err == nil {
				ipAllocator.unreserved[cidr] = availableIPBlocks
				break
			}
		}
	}
}

// UpdateReservedIPs refreshes the reserved ips list. Every time you update the list of reserved IPs, the list of getUnreserved() IPs also gets updated
func (ipAllocator *IPAllocator) UpdateReservedIPs(reservedUpdated map[string]bool) error {
	ipAllocator.reserved = reservedUpdated
	for cidr := range ipAllocator.unreserved {
		availableIPBlocks, err := ipAllocator.getAvailableIPBlocks(cidr)
		if err != nil {
			return err
		}
		ipAllocator.unreserved[cidr] = availableIPBlocks
	}
	return nil
}

// GetAvailableIPBlock caches all the availableIPs in the provided cidr for future requests if the cidr is not accessed. If accessed before, returns a /29 ip block from the unused ip pool
func (ipAllocator *IPAllocator) GetAvailableIPBlock(cidr string) (string, error) {
	availableIPBlocks, cidrExisting := ipAllocator.unreserved[cidr]

	//CIDR was not reserved before. Reserve it and cache all the available IPs

	if !cidrExisting {
		//Check if this CIDR overlaps with any of the accessed cidr's
		err := ipAllocator.validateCIDROverlap(cidr)
		if err != nil {
			return "", err
		}

		//Get the list of getUnreserved() IPs in this CIDR
		availableIPBlocks, err = ipAllocator.getAvailableIPBlocks(cidr)
		if err != nil {
			return "", err
		}
	}

	//If no getUnreserved() IP is available in this CIDR, return error
	if len(availableIPBlocks) == 0 {
		return "", fmt.Errorf("All /29 ranges in the specified CIDR %s already in use", cidr)
	}
	//Return first IP from the list and cache the other IPs
	unreservedIP, availableIPBlocks := getIPFromList(availableIPBlocks)
	ipAllocator.unreserved[cidr] = availableIPBlocks
	return unreservedIP, nil
}

// Check if the CIDR overlaps with any of the accessed CIDRs
func (ipAllocator *IPAllocator) validateCIDROverlap(cidr string) error {
	_, ipnet1, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	for requestedCIDR := range ipAllocator.unreserved {
		_, ipnet, err := net.ParseCIDR(requestedCIDR)
		if err != nil {
			return err
		}
		if ipnet.Contains(ipnet1.IP) || (ipnet1.Contains(ipnet.IP)) {
			return fmt.Errorf("The specified cidr overlaps with cidr range %s", requestedCIDR)
		}
	}
	return nil
}

// getAvailableIPBlocks is called when the cidr in the request was never accessed. It returns a lis to all available IPs in that cidr that are not present in the reserved list
func (ipAllocator *IPAllocator) getAvailableIPBlocks(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("Invalid CIDR %s format provided", cidr)
	}
	var availableIPBlocks []string
	buffer := bytes.NewBufferString("")

	// Iterate over all the IPs in the /29 IP. If any of the IPs is reserved, we cannot return the /29 block
	for cidrIPBlock := cloneIP(ip.Mask(ipnet.Mask)); ipnet.Contains(cidrIPBlock) && err == nil; err = incrementIP(cidrIPBlock, 8) {
		isOverlap := false
		for i := 0; i < 8; i++ {
			netIP := cloneIP(cidrIPBlock)
			err = incrementIP(netIP, byte(i))
			// If IP rollover occurs no need to test further
			if err != nil {
				break
			}
			if ipAllocator.reserved[netIP.String()] {
				// This IP in the /29 block is present in the reserved list. Cannot consider this /29 block unreserved
				isOverlap = true
			}
		}

		// None of the IPs in the /29 block is currently in the reserved list. We can mark the block as unreserved
		if !isOverlap {
			buffer.WriteString(cidrIPBlock.String())
			buffer.WriteString("/29")
			availableIPBlocks = append(availableIPBlocks, buffer.String())
			buffer.Reset()
		}
	}
	return availableIPBlocks, nil
}

// Get first IP from list and remove it from the list
func getIPFromList(availableIPBlocks []string) (string, []string) {
	return availableIPBlocks[0], availableIPBlocks[1:]
}

// Increment the given IP value by the provided step
func incrementIP(ip net.IP, step byte) error {
	if uint8(255)-uint8(ip[len(ip)-1]) < uint8(step) {
		return fmt.Errorf("IP overflow occured when incrementing ip %s with step %d", ip.String(), step)
	}
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j] += step
		if ip[j] > 0 {
			break
		}
	}
	return nil
}

// Clone the provided IP and return the copy
func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

// UnreserveIPBlock frees up the reserved /29 IP in the containing CIDR and returns error if the provided IP do not overlap with any of the CIDR
func (ipAllocator *IPAllocator) UnreserveIPBlock(ipBlock string) error {
	ip, ipnet, err := net.ParseCIDR(ipBlock)
	if err != nil {
		return err
	}
	for requestedCIDR := range ipAllocator.unreserved {
		_, ipnetCIDR, err := net.ParseCIDR(requestedCIDR)
		if err != nil {
			return err
		}
		buffer := bytes.NewBufferString("")
		if ipnetCIDR.Contains(ip) {
			buffer.WriteString(ip.String())
			buffer.WriteString("/29")
			ipAllocator.unreserved[requestedCIDR] = append(ipAllocator.unreserved[requestedCIDR], buffer.String())
			for cidrIP := cloneIP(ip); ipnet.Contains(cidrIP) && err == nil; err = incrementIP(cidrIP, 1) {
				delete(ipAllocator.reserved, cidrIP.String())
			}
			return nil
		}
	}
	return fmt.Errorf("No accessed CIDR block contains the provided IP address %s", ip.String())
}

func (ipAllocator *IPAllocator) FreeIPBlocks(updatedReservedIPs map[string] bool)  error{
	freedIPs := make (map[string] bool) 
	for reservedIPBlock := range ipAllocator.reserved {
		if !updatedReservedIPs[reservedIPBlock] {
			freedIPs[reservedIPBlock] = true
		}
	}
	unreservedIPBlocks := make(map[string]bool);
	buffer := bytes.NewBufferString("")
	for ipString  := range freedIPs {
		buffer.WriteString(ipString)
		buffer.WriteString("/29")
		ip, ipnet, err := net.ParseCIDR(buffer.String())
		if err != nil {
			return err
		}
		ip = ip.Mask(ipnet.Mask)
		buffer.Reset()
		buffer.WriteString(ip.String())
		buffer.WriteString("/29")
		if !unreservedIPBlocks[buffer.String()] {
			err =  ipAllocator.UnreserveIPBlock(buffer.String())
			if err != nil {
				return err
			}
			unreservedIPBlocks[buffer.String()] = true
		}
	}
	return nil
}

func (ipAllocator *IPAllocator) Lock(){ 
	ipAllocator.mutex.Lock()
}

func (ipAllocator *IPAllocator) Unlock(){ 
	ipAllocator.mutex.Unlock()
} 
