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

package file

import (
	"context"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/golang/glog"
	"google.golang.org/api/googleapi"
	"k8s.io/apimachinery/pkg/util/wait"

	beta "sigs.k8s.io/gcp-filestore-csi-driver/pkg/cloud_provider/generated/file/v1beta1"
	"sigs.k8s.io/gcp-filestore-csi-driver/pkg/util"
)

type ServiceInstance struct {
	Project  string
	Name     string
	Location string
	Tier     string
	Network  Network
	Volume   Volume
}

type Volume struct {
	Name      string
	SizeBytes int64
}

type Network struct {
	Name            string
	ReservedIpRange string
	Ip              string
}

type Service interface {
	CreateInstance(ctx context.Context, obj *ServiceInstance) (*ServiceInstance, error)
	DeleteInstance(ctx context.Context, obj *ServiceInstance) error
	GetInstance(ctx context.Context, obj *ServiceInstance) (*ServiceInstance, error)
	ListInstances(ctx context.Context) ([]*ServiceInstance, error)
}

type gcfsServiceManager struct {
	fileService       *beta.Service
	instancesService  *beta.ProjectsLocationsInstancesService
	operationsService *beta.ProjectsLocationsOperationsService
}

const (
	locationURIFmt  = "projects/%s/locations/%s"
	instanceURIFmt  = locationURIFmt + "/instances/%s"
	operationURIFmt = locationURIFmt + "/operations/%s"
)

var _ Service = &gcfsServiceManager{}

func NewGCFSService(version string) (Service, error) {
	client, err := newOauthClient()
	if err != nil {
		return nil, err
	}

	fileService, err := beta.New(client)
	if err != nil {
		return nil, err
	}
	fileService.UserAgent = fmt.Sprintf("Google Cloud Filestore CSI Driver/%s (%s %s)", version, runtime.GOOS, runtime.GOARCH)

	return &gcfsServiceManager{
		fileService:       fileService,
		instancesService:  beta.NewProjectsLocationsInstancesService(fileService),
		operationsService: beta.NewProjectsLocationsOperationsService(fileService),
	}, nil
}

func (manager *gcfsServiceManager) CreateInstance(ctx context.Context, obj *ServiceInstance) (*ServiceInstance, error) {
	// TODO: add some labels to to tag this plugin
	betaObj := &beta.Instance{
		Tier: obj.Tier,
		FileShares: []*beta.FileShareConfig{
			{
				Name:       obj.Volume.Name,
				CapacityGb: util.RoundBytesToGb(obj.Volume.SizeBytes),
			},
		},
		Networks: []*beta.NetworkConfig{
			{
				Network:         obj.Network.Name,
				Modes:           []string{"MODE_IPV4"},
				ReservedIpRange: obj.Network.ReservedIpRange,
			},
		},
	}

	glog.Infof("Starting CreateInstance cloud operation")
	glog.V(4).Infof("Creating instance %v: location %v, tier %v, capacity %v, network %v, ipRange %v",
		obj.Name,
		obj.Location,
		betaObj.Tier,
		betaObj.FileShares[0].CapacityGb,
		betaObj.Networks[0].Network,
		betaObj.Networks[0].ReservedIpRange)
	op, err := manager.instancesService.Create(locationURI(obj.Project, obj.Location), betaObj).InstanceId(obj.Name).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("CreateInstance operation failed: %v", err)
	}

	err = manager.waitForOp(ctx, op)
	if err != nil {
		return nil, fmt.Errorf("WaitFor CreateInstance operation failed: %v", err)
	}
	instance, err := manager.GetInstance(ctx, obj)
	if err != nil {
		return nil, fmt.Errorf("failed to get instance after creation: %v", err)
	}
	return instance, nil
}

func (manager *gcfsServiceManager) GetInstance(ctx context.Context, obj *ServiceInstance) (*ServiceInstance, error) {
	instance, err := manager.instancesService.Get(instanceURI(obj.Project, obj.Location, obj.Name)).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	if instance != nil {
		newInstance, err := cloudInstanceToServiceInstance(instance)
		if err != nil {
			return nil, fmt.Errorf("failed to convert instance: %v", err)
		}
		switch instance.State {
		case "READY":
			return newInstance, nil
		default:
			// Instance exists but is not usable
			return newInstance, fmt.Errorf("instance %v is %v", obj.Name, instance.State)
		}
	}
	return nil, fmt.Errorf("failed to get instance")
}

func cloudInstanceToServiceInstance(instance *beta.Instance) (*ServiceInstance, error) {
	project, location, name, err := getInstanceNameFromURI(instance.Name)
	if err != nil {
		return nil, err
	}
	return &ServiceInstance{
		Project:  project,
		Location: location,
		Name:     name,
		Tier:     instance.Tier,
		Volume: Volume{
			Name:      instance.FileShares[0].Name,
			SizeBytes: util.GbToBytes(instance.FileShares[0].CapacityGb),
		},
		Network: Network{
			Name:            instance.Networks[0].Network,
			Ip:              instance.Networks[0].IpAddresses[0],
			ReservedIpRange: instance.Networks[0].ReservedIpRange,
		},
	}, nil
}

func CompareInstances(a, b *ServiceInstance) error {
	mismatches := []string{}
	if strings.ToLower(a.Tier) != strings.ToLower(b.Tier) {
		mismatches = append(mismatches, "tier")
	}
	if a.Volume.Name != b.Volume.Name {
		mismatches = append(mismatches, "volume name")
	}
	if util.RoundBytesToGb(a.Volume.SizeBytes) != util.RoundBytesToGb(b.Volume.SizeBytes) {
		mismatches = append(mismatches, "volume size")
	}
	if a.Network.Name != b.Network.Name {
		mismatches = append(mismatches, "network name")
	}

	if len(mismatches) > 0 {
		return fmt.Errorf("instance %v already exists but doesn't match expected: %+v", a.Name, mismatches)
	}
	return nil
}

func (manager *gcfsServiceManager) DeleteInstance(ctx context.Context, obj *ServiceInstance) error {
	instance, err := manager.GetInstance(ctx, obj)
	if err != nil {
		if IsNotFoundErr(err) {
			glog.Infof("Instance %v not found", obj.Name)
			return nil
		}
		return err
	}

	glog.Infof("Starting DeleteInstance cloud operation")
	op, err := manager.instancesService.Delete(instanceURI(obj.Project, obj.Location, obj.Name)).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("DeleteInstance operation failed: %v", err)
	}

	err = manager.waitForOp(ctx, op)
	if err != nil {
		return fmt.Errorf("WaitFor DeleteInstance operation failed: %v", err)
	}

	instance, err = manager.GetInstance(ctx, obj)
	if err != nil {
		return fmt.Errorf("failed to get instance after deletion: %v", err)
	}
	if instance != nil {
		return fmt.Errorf("instance %v still exists after delete operation", obj.Name)
	}

	glog.Infof("Instance %v has been deleted", obj.Name)
	return nil
}

func (manager *gcfsServiceManager) ListInstances(ctx context.Context) ([]*ServiceInstance, error) {
	instances, err := manager.instancesService.List("-").Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	var activeInstances []*ServiceInstance
	for _, activeInstance := range instances.Instances {
		serviceInstance, err := cloudInstanceToServiceInstance(activeInstance) 
		if err != nil {
			return nil, err
		}
		activeInstances = append(activeInstances, serviceInstance)
	}
	return activeInstances, nil
}

func (manager *gcfsServiceManager) waitForOp(ctx context.Context, op *beta.Operation) error {
	return wait.Poll(5*time.Second, 5*time.Minute, func() (bool, error) {
		pollOp, err := manager.operationsService.Get(op.Name).Context(ctx).Do()
		if err != nil {
			return false, err
		}
		return isOpDone(pollOp)
	})
}

func isOpDone(op *beta.Operation) (bool, error) {
	if op == nil {
		return false, nil
	}
	if op.Error != nil {
		return true, fmt.Errorf("operation %v failed (%v): %v", op.Name, op.Error.Code, op.Error.Message)
	}
	return op.Done, nil
}

func locationURI(project, location string) string {
	return fmt.Sprintf(locationURIFmt, project, location)
}

func instanceURI(project, location, name string) string {
	return fmt.Sprintf(instanceURIFmt, project, location, name)
}

func operationURI(project, location, name string) string {
	return fmt.Sprintf(operationURIFmt, project, location, name)
}

func getInstanceNameFromURI(uri string) (project, location, name string, err error) {
	var uriRegex = regexp.MustCompile(`^projects/([^/]+)/locations/([^/]+)/instances/([^/]+)$`)

	substrings := uriRegex.FindStringSubmatch(uri)
	if substrings == nil {
		err = fmt.Errorf("failed to parse uri %v", uri)
		return
	}
	return substrings[1], substrings[2], substrings[3], nil
}

func IsNotFoundErr(err error) bool {
	apiErr, ok := err.(*googleapi.Error)
	if !ok {
		return false
	}

	for _, e := range apiErr.Errors {
		if e.Reason == "notFound" {
			return true
		}
	}
	return false
}
