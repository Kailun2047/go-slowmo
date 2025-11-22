package server

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/google/uuid"
	"github.com/kailun2047/slowmo/logging"
	"github.com/kailun2047/slowmo/proto"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	instanceOpPollPeriod = 2 * time.Second
	cloudInitConfigPath  = "./config/cloud-init.yaml"
)

type GoogleComputeEngineConnector struct {
	client          *compute.InstancesClient
	project         string
	imageURL        string
	zone            string
	machineType     string
	cloudInitConfig string
	serviceAccount  string
	port            int
}

type GoogleCloudEngineStream struct {
	instanceName string
	stream       grpc.ServerStreamingClient[proto.CompileAndRunResponse]
}

func (gceStream *GoogleCloudEngineStream) Stream() grpc.ServerStreamingClient[proto.CompileAndRunResponse] {
	return gceStream.stream
}

func (gceStream *GoogleCloudEngineStream) ID() string {
	return gceStream.instanceName
}

func (gce *GoogleComputeEngineConnector) GetCompileAndRunResponseStream(ctx context.Context, req *proto.CompileAndRunRequest) (StreamWithID, error) {
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
	opErrCh := make(chan error)
	go poll(ctx, op, opErrCh)
	err = <-opErrCh
	if err != nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Error creating instance %s: %v", instanceName, err)
		return nil, ErrInternalExecution
	}
	logging.Logger().Debugf("[GoogleComputeEngineConnector] Created instance with name: %s", instanceName)

	instance, err := gce.client.Get(ctx, &computepb.GetInstanceRequest{
		Instance: instanceName,
		Project:  gce.project,
		Zone:     gce.zone,
	})
	if err != nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Error retrieving info of instance %s: %v", instanceName, err)
		return nil, ErrInternalExecution
	}
	if len(instance.NetworkInterfaces) <= 0 || instance.NetworkInterfaces[0].NetworkIP == nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Cannot retrieve internal IP address of instance %s", instanceName)
		return nil, ErrInternalExecution
	}
	internalIP := *instance.NetworkInterfaces[0].NetworkIP
	conn, err := grpc.NewClient(fmt.Sprintf("%s:%d", internalIP, gce.port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Error creating gRPC connection to instance %s: %v", instanceName, err)
		return nil, ErrInternalExecution
	}
	slowmoClient := proto.NewSlowmoServiceClient(conn)
	compileAndRunStream, err := slowmoClient.CompileAndRun(ctx, req)
	if err != nil {
		logging.Logger().Error("[GoogleComputeEngineConnector] Error making CompileAndRun request: %v", err)
		return nil, ErrInternalExecution
	}
	return &GoogleCloudEngineStream{
		instanceName: instanceName,
		stream:       compileAndRunStream,
	}, nil
}

func (gce *GoogleComputeEngineConnector) CloseStream(ctx context.Context, streamID string) error {
	logging.Logger().Debugf("[GoogleComputeEngineConnector] Start deleting instance %s", streamID)
	op, err := gce.client.Delete(ctx, &computepb.DeleteInstanceRequest{
		Instance: streamID,
		Project:  gce.project,
		Zone:     gce.zone,
	})
	if err != nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Error starting delete instance operation for %s: %v", streamID, err)
		return ErrInternalCleanup
	}
	opErrCh := make(chan error)
	go poll(ctx, op, opErrCh)
	err = <-opErrCh
	if err != nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Error deleting instance %s: %v", streamID, err)
		return ErrInternalCleanup
	}
	logging.Logger().Debugf("[GoogleComputeEngineConnector] Deleted instance %s", streamID)
	return nil
}

// Implement polling by ourselves since op.Wait() uses backoff-with-jitter style
// polling, which may increase the wait time even more.
func poll(ctx context.Context, op *compute.Operation, opErrCh chan error) {
	var opErr error
	defer func() {
		opErrCh <- opErr
	}()
	ticker := time.NewTicker(instanceOpPollPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			err := op.Poll(ctx)
			if err != nil {
				opErr = err
				return
			}
			if op.Done() {
				opErr = context.DeadlineExceeded
				return
			}
		case <-ctx.Done():
			opErr = ErrNoAvailableServer
			return
		}
	}
}

func NewGoogleComputeEngineConnector() *GoogleComputeEngineConnector {
	project := os.Getenv("PROJECT")
	imageURL := os.Getenv("GCE_IMAGE_URL")
	zone := os.Getenv("GCE_ZONE")
	machineType := os.Getenv("GCE_MACHINE_TYPE")
	serviceAccount := os.Getenv("GCE_SERVICE_ACCOUNT")
	portStr := os.Getenv("GCE_PORT")
	if len(project) == 0 || len(imageURL) == 0 || len(zone) == 0 || len(machineType) == 0 || len(portStr) == 0 {
		panic("one or more GCE config is missing from env var")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		panic("invalid GCE port number")
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
		port:            port,
	}
}
