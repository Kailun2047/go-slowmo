package server

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/google/uuid"
	"github.com/kailun2047/slowmo/logging"
	"github.com/kailun2047/slowmo/proto"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
)

const (
	instancePollPeriod  = 2 * time.Second
	cloudInitConfigPath = "./config/cloud-init.yaml"
)

type GoogleComputeEngineConnector struct {
	client          *compute.InstancesClient
	project         string
	imageURL        string
	zone            string
	machineType     string
	cloudInitConfig string
	serviceAccount  string
}

func (gce *GoogleComputeEngineConnector) GetCompileAndRunResponseStream(ctx context.Context, req *proto.CompileAndRunRequest) (grpc.ServerStreamingClient[proto.CompileAndRunResponse], error) {
	var (
		instanceName       = fmt.Sprintf("slowmo-%s", uuid.NewString())
		machineTypeSpec    = fmt.Sprintf("zones/%s/machineTypes/%s", gce.zone, gce.machineType)
		bootDiskType       = "PERSISTENT"
		isBootDisk         = true
		autoDeleteDisk     = true
		netConfigType      = "ONE_TO_ONE_NAT"
		netConfigName      = "External NAT"
		globalNetwork      = "global/networks/default"
		cloudInitConfigKey = "user-data"
		scopeFullAccess    = "https://www.googleapis.com/auth/cloud-platform" // cloud-platform scope allows full access to all cloud APIs permitted by IAM role
	)

	logging.Logger().Debugf("[GoogleComputeEngineConnector] Start creating instance with name: %s", instanceName)
	op, err := gce.client.Insert(ctx, &computepb.InsertInstanceRequest{
		Project: gce.project,
		InstanceResource: &computepb.Instance{
			Name:        &instanceName,
			MachineType: &machineTypeSpec,
			NetworkInterfaces: []*computepb.NetworkInterface{
				{
					AccessConfigs: []*computepb.AccessConfig{
						{
							Type: &netConfigType,
							Name: &netConfigName,
						},
					},
					Network: &globalNetwork,
				},
			},
			Disks: []*computepb.AttachedDisk{
				{
					Type:       &bootDiskType,
					Boot:       &isBootDisk,
					AutoDelete: &autoDeleteDisk,
					InitializeParams: &computepb.AttachedDiskInitializeParams{
						SourceImage: &gce.imageURL,
					},
				},
			},
			Metadata: &computepb.Metadata{
				Items: []*computepb.Items{
					{
						Key:   &cloudInitConfigKey,
						Value: &gce.cloudInitConfig,
					},
				},
			},
			ServiceAccounts: []*computepb.ServiceAccount{
				{
					Email:  &gce.serviceAccount,
					Scopes: []string{scopeFullAccess},
				},
			},
		},
		Zone: gce.zone,
	})
	if err != nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Error starting instance creation operation: %v", err)
		return nil, ErrInternalExecution
	}

	// Implement polling by ourselves since op.Wait() uses backoff-with-jitter
	// style polling, which may increase the wait time even more.
	opErrCh := make(chan error)
	go func(ctx context.Context, op *compute.Operation) {
		var opErr error
		defer func() {
			opErrCh <- opErr
		}()
		ticker := time.NewTicker(instancePollPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				err := op.Poll(ctx)
				if err != nil {
					logging.Logger().Errorf("[GoogleComputeEngineConnector] Error polling instance creation: %v", err)
					opErr = ErrInternalExecution
					return
				}
				if op.Done() {
					return
				}
			case <-ctx.Done():
				logging.Logger().Errorf("[GoogleComputeEngineConnector] Timeout waiting for instance creation")
				opErr = ErrNoAvailableServer
				return
			}
		}
	}(ctx, op)

	err = <-opErrCh
	if err != nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Error creating instance: %v", err)
		return nil, err
	}
	logging.Logger().Debugf("[GoogleComputeEngineConnector] Created instance with name: %s", instanceName)

	return nil, fmt.Errorf("unimplemented")
}

func NewGoogleComputeEngineConnector() *GoogleComputeEngineConnector {
	project := os.Getenv("PROJECT")
	imageURL := os.Getenv("GCE_IMAGE_URL")
	zone := os.Getenv("GCE_ZONE")
	machineType := os.Getenv("GCE_MACHINE_TYPE")
	serviceAccount := os.Getenv("GCE_SERVICE_ACCOUNT")
	if len(project) == 0 || len(imageURL) == 0 || len(zone) == 0 || len(machineType) == 0 {
		panic("one or more GCE config is missing from env var")
	}
	f, err := os.Open(cloudInitConfigPath)
	if err != nil {
		panic(fmt.Sprintf("error opening cloud-init config: %v", err))
	}
	cloudInitConfigBytes, err := io.ReadAll(f)
	if err != nil {
		panic(fmt.Sprintf("error reading cloud-init config: %v", err))
	}
	client, err := compute.NewInstancesRESTClient(context.Background(), option.WithQuotaProject(project))
	if err != nil {
		panic(fmt.Sprintf("Error creating compute engine instances client: %v", err))
	}
	return &GoogleComputeEngineConnector{
		client:          client,
		project:         project,
		imageURL:        imageURL,
		zone:            zone,
		machineType:     machineType,
		cloudInitConfig: string(cloudInitConfigBytes),
		serviceAccount:  serviceAccount,
	}
}
