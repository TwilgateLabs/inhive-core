// libbox_proxy.go — S3.3a dual-channel migration: thin proxy exposing the
// upstream sing-box StartedServiceServer (libbox API) on our existing gRPC
// listener (127.0.0.1:18078). The proxy registers BEFORE Start() so the
// service is reachable at server-startup time, then forwards every call to
// the live `static.StartedService` once it is assigned in start.go.
//
// Why a proxy at all: a gRPC server cannot accept new service registrations
// after Serve() is called. `static.StartedService` is nil until the user
// invokes Start(), so we cannot pass the live instance to
// RegisterStartedServiceServer at boot. The proxy bridges this gap with a
// nil-check + delegate pattern.
//
// Design rules (S3.3a scope):
//   - Minimum: nil-check + delegate. No caching, no metrics, no logging.
//   - Atomic read of `static.StartedService` once per call to minimise the
//     race window (the field is mutated by start.go:176 without a mutex —
//     pre-existing condition, NOT introduced here).
//   - Forward-compat: embed UnimplementedStartedServiceServer so future
//     upstream methods compile cleanly until the proxy is updated.
package hcore

import (
	"context"

	"github.com/sagernet/sing-box/daemon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// liveStartedServiceProxy forwards every StartedServiceServer RPC to the
// live `static.StartedService` (assigned in start.go after the sing-box
// instance is built). When the core has not been started yet, every call
// returns codes.Unavailable so clients can distinguish "not started" from
// "method missing".
type liveStartedServiceProxy struct {
	// Embed by value so unimplemented methods (future upstream additions)
	// stay forward-compatible without panicking.
	daemon.UnimplementedStartedServiceServer
}

// Compile-time assertion: every StartedServiceServer method must be
// satisfied by liveStartedServiceProxy (directly or via the embedded
// UnimplementedStartedServiceServer fallback).
var _ daemon.StartedServiceServer = (*liveStartedServiceProxy)(nil)

// errCoreNotStarted is the canonical "core not started" gRPC error.
// codes.Unavailable signals to clients that the service exists but is
// temporarily unable to serve — they should retry after Start().
func errCoreNotStarted() error {
	return status.Error(codes.Unavailable, "core not started — call Start() first")
}

// ───────────────────────── unary RPCs (15) ─────────────────────────

func (p *liveStartedServiceProxy) StopService(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	ss := static.StartedService
	if ss == nil {
		return nil, errCoreNotStarted()
	}
	return ss.StopService(ctx, req)
}

func (p *liveStartedServiceProxy) ReloadService(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	ss := static.StartedService
	if ss == nil {
		return nil, errCoreNotStarted()
	}
	return ss.ReloadService(ctx, req)
}

func (p *liveStartedServiceProxy) GetDefaultLogLevel(ctx context.Context, req *emptypb.Empty) (*daemon.DefaultLogLevel, error) {
	ss := static.StartedService
	if ss == nil {
		return nil, errCoreNotStarted()
	}
	return ss.GetDefaultLogLevel(ctx, req)
}

func (p *liveStartedServiceProxy) ClearLogs(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	ss := static.StartedService
	if ss == nil {
		return nil, errCoreNotStarted()
	}
	return ss.ClearLogs(ctx, req)
}

func (p *liveStartedServiceProxy) GetClashModeStatus(ctx context.Context, req *emptypb.Empty) (*daemon.ClashModeStatus, error) {
	ss := static.StartedService
	if ss == nil {
		return nil, errCoreNotStarted()
	}
	return ss.GetClashModeStatus(ctx, req)
}

func (p *liveStartedServiceProxy) SetClashMode(ctx context.Context, req *daemon.ClashMode) (*emptypb.Empty, error) {
	ss := static.StartedService
	if ss == nil {
		return nil, errCoreNotStarted()
	}
	return ss.SetClashMode(ctx, req)
}

func (p *liveStartedServiceProxy) URLTest(ctx context.Context, req *daemon.URLTestRequest) (*emptypb.Empty, error) {
	ss := static.StartedService
	if ss == nil {
		return nil, errCoreNotStarted()
	}
	return ss.URLTest(ctx, req)
}

func (p *liveStartedServiceProxy) SelectOutbound(ctx context.Context, req *daemon.SelectOutboundRequest) (*emptypb.Empty, error) {
	ss := static.StartedService
	if ss == nil {
		return nil, errCoreNotStarted()
	}
	return ss.SelectOutbound(ctx, req)
}

func (p *liveStartedServiceProxy) SetGroupExpand(ctx context.Context, req *daemon.SetGroupExpandRequest) (*emptypb.Empty, error) {
	ss := static.StartedService
	if ss == nil {
		return nil, errCoreNotStarted()
	}
	return ss.SetGroupExpand(ctx, req)
}

func (p *liveStartedServiceProxy) GetSystemProxyStatus(ctx context.Context, req *emptypb.Empty) (*daemon.SystemProxyStatus, error) {
	ss := static.StartedService
	if ss == nil {
		return nil, errCoreNotStarted()
	}
	return ss.GetSystemProxyStatus(ctx, req)
}

func (p *liveStartedServiceProxy) SetSystemProxyEnabled(ctx context.Context, req *daemon.SetSystemProxyEnabledRequest) (*emptypb.Empty, error) {
	ss := static.StartedService
	if ss == nil {
		return nil, errCoreNotStarted()
	}
	return ss.SetSystemProxyEnabled(ctx, req)
}

func (p *liveStartedServiceProxy) CloseConnection(ctx context.Context, req *daemon.CloseConnectionRequest) (*emptypb.Empty, error) {
	ss := static.StartedService
	if ss == nil {
		return nil, errCoreNotStarted()
	}
	return ss.CloseConnection(ctx, req)
}

func (p *liveStartedServiceProxy) CloseAllConnections(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	ss := static.StartedService
	if ss == nil {
		return nil, errCoreNotStarted()
	}
	return ss.CloseAllConnections(ctx, req)
}

func (p *liveStartedServiceProxy) GetDeprecatedWarnings(ctx context.Context, req *emptypb.Empty) (*daemon.DeprecatedWarnings, error) {
	ss := static.StartedService
	if ss == nil {
		return nil, errCoreNotStarted()
	}
	return ss.GetDeprecatedWarnings(ctx, req)
}

func (p *liveStartedServiceProxy) GetStartedAt(ctx context.Context, req *emptypb.Empty) (*daemon.StartedAt, error) {
	ss := static.StartedService
	if ss == nil {
		return nil, errCoreNotStarted()
	}
	return ss.GetStartedAt(ctx, req)
}

// ───────────────────────── server-streaming RPCs (6) ─────────────────────────

func (p *liveStartedServiceProxy) SubscribeServiceStatus(req *emptypb.Empty, stream grpc.ServerStreamingServer[daemon.ServiceStatus]) error {
	ss := static.StartedService
	if ss == nil {
		return errCoreNotStarted()
	}
	return ss.SubscribeServiceStatus(req, stream)
}

func (p *liveStartedServiceProxy) SubscribeLog(req *emptypb.Empty, stream grpc.ServerStreamingServer[daemon.Log]) error {
	ss := static.StartedService
	if ss == nil {
		return errCoreNotStarted()
	}
	return ss.SubscribeLog(req, stream)
}

func (p *liveStartedServiceProxy) SubscribeStatus(req *daemon.SubscribeStatusRequest, stream grpc.ServerStreamingServer[daemon.Status]) error {
	ss := static.StartedService
	if ss == nil {
		return errCoreNotStarted()
	}
	return ss.SubscribeStatus(req, stream)
}

func (p *liveStartedServiceProxy) SubscribeGroups(req *emptypb.Empty, stream grpc.ServerStreamingServer[daemon.Groups]) error {
	ss := static.StartedService
	if ss == nil {
		return errCoreNotStarted()
	}
	return ss.SubscribeGroups(req, stream)
}

func (p *liveStartedServiceProxy) SubscribeClashMode(req *emptypb.Empty, stream grpc.ServerStreamingServer[daemon.ClashMode]) error {
	ss := static.StartedService
	if ss == nil {
		return errCoreNotStarted()
	}
	return ss.SubscribeClashMode(req, stream)
}

func (p *liveStartedServiceProxy) SubscribeConnections(req *daemon.SubscribeConnectionsRequest, stream grpc.ServerStreamingServer[daemon.ConnectionEvents]) error {
	ss := static.StartedService
	if ss == nil {
		return errCoreNotStarted()
	}
	return ss.SubscribeConnections(req, stream)
}
