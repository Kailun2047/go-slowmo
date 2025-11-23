package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/google/uuid"
	"github.com/googleapis/gax-go/v2"
	"github.com/kailun2047/slowmo/logging"
	"github.com/kailun2047/slowmo/proto"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	instanceOpPollPeriod = 2 * time.Second
	connPollPeriod       = 1 * time.Second
	dialTimeout          = 1 * time.Second
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

var gceAPIRetryer = func() gax.Retryer {
	return gax.OnErrorFunc(gax.Backoff{
		Max: 5 * time.Second,
	}, func(err error) bool { return true })
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
	err = pollOp(ctx, op)
	if err != nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Error creating instance %s: %v", instanceName, err)
		return nil, ErrInternalExecution
	}
	logging.Logger().Debugf("[GoogleComputeEngineConnector] Created instance with name: %s", instanceName)
	ret := &GoogleCloudEngineStream{
		instanceName: instanceName,
	}

	instance, err := gce.client.Get(ctx, &computepb.GetInstanceRequest{
		Instance: instanceName,
		Project:  gce.project,
		Zone:     gce.zone,
	}, gax.WithRetry(gceAPIRetryer))
	if err != nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Error retrieving info of instance %s: %v", instanceName, err)
		return ret, ErrInternalExecution
	}
	if len(instance.NetworkInterfaces) <= 0 || instance.NetworkInterfaces[0].NetworkIP == nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Cannot retrieve internal IP address of instance %s", instanceName)
		return ret, ErrInternalExecution
	}
	internalIP := *instance.NetworkInterfaces[0].NetworkIP

	// When InstancesClient.Insert() call returns, it only ensures that the VM
	// instance is provisioned, but doesn't wait until cloud-init finishes
	// execution. We need to poll connection to the instance to make sure a grpc
	// connection is ready to be established before issuing a request.
	// grpc.NewClient() cannot be used for this polling purpose, since it only
	// configures the dialing options and then lazily dial when a request is
	// made using the returned grpc.ClientConn.
	addr := fmt.Sprintf("%s:%d", internalIP, gce.port)
	err = pollConn(ctx, addr)
	if err != nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Error checking connectivity with instance %s: %v", instanceName, err)
		return ret, ErrInternalExecution
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Error creating gRPC connection to instance %s: %v", instanceName, err)
		return ret, ErrInternalExecution
	}
	slowmoClient := proto.NewSlowmoServiceClient(conn)
	compileAndRunStream, err := slowmoClient.CompileAndRun(ctx, req)
	if err != nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Error making CompileAndRun request: %v", err)
		return ret, ErrInternalExecution
	}
	ret.stream = compileAndRunStream
	return ret, nil
}

func (gce *GoogleComputeEngineConnector) CloseStream(ctx context.Context, streamID string) error {
	logging.Logger().Debugf("[GoogleComputeEngineConnector] Start deleting instance %s", streamID)
	op, err := gce.client.Delete(ctx, &computepb.DeleteInstanceRequest{
		Instance: streamID,
		Project:  gce.project,
		Zone:     gce.zone,
	}, gax.WithRetry(gceAPIRetryer))
	if err != nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Error starting delete instance operation for %s: %v", streamID, err)
		return ErrInternalCleanup
	}
	err = pollOp(ctx, op)
	if err != nil {
		logging.Logger().Errorf("[GoogleComputeEngineConnector] Error deleting instance %s: %v", streamID, err)
		return ErrInternalCleanup
	}
	logging.Logger().Debugf("[GoogleComputeEngineConnector] Deleted instance %s", streamID)
	return nil
}

// Implement polling by ourselves since op.Wait() uses backoff-with-jitter style
// polling, which may increase the wait time even more.
func pollOp(ctx context.Context, op *compute.Operation) error {
	ticker := time.NewTicker(instanceOpPollPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			err := op.Poll(ctx)
			if err != nil {
				return err
			}
			if op.Done() {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func pollConn(ctx context.Context, address string) error {
	var (
		dialer net.Dialer
		conn   net.Conn
		ticker = time.NewTicker(connPollPeriod)
		err    error
	)
	defer func() {
		if conn != nil {
			conn.Close()
		}
		ticker.Stop()
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			dialCtx, cancelFunc := context.WithTimeout(ctx, dialTimeout)
			conn, err = dialer.DialContext(dialCtx, "tcp", address)
			cancelFunc()
			if err == nil {
				return nil
			}
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
