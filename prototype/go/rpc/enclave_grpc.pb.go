// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package rpc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// EnclaveClient is the client API for Enclave service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type EnclaveClient interface {
	Schedule(ctx context.Context, in *SchedulingRequest, opts ...grpc.CallOption) (*SchedulingResponse, error)
	Aggregate(ctx context.Context, in *AggregateRequest, opts ...grpc.CallOption) (*AggregateResponse, error)
}

type enclaveClient struct {
	cc grpc.ClientConnInterface
}

func NewEnclaveClient(cc grpc.ClientConnInterface) EnclaveClient {
	return &enclaveClient{cc}
}

func (c *enclaveClient) Schedule(ctx context.Context, in *SchedulingRequest, opts ...grpc.CallOption) (*SchedulingResponse, error) {
	out := new(SchedulingResponse)
	err := c.cc.Invoke(ctx, "/rpc.enclave/schedule", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *enclaveClient) Aggregate(ctx context.Context, in *AggregateRequest, opts ...grpc.CallOption) (*AggregateResponse, error) {
	out := new(AggregateResponse)
	err := c.cc.Invoke(ctx, "/rpc.enclave/aggregate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EnclaveServer is the server API for Enclave service.
// All implementations must embed UnimplementedEnclaveServer
// for forward compatibility
type EnclaveServer interface {
	Schedule(context.Context, *SchedulingRequest) (*SchedulingResponse, error)
	Aggregate(context.Context, *AggregateRequest) (*AggregateResponse, error)
	mustEmbedUnimplementedEnclaveServer()
}

// UnimplementedEnclaveServer must be embedded to have forward compatible implementations.
type UnimplementedEnclaveServer struct {
}

func (*UnimplementedEnclaveServer) Schedule(context.Context, *SchedulingRequest) (*SchedulingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Schedule not implemented")
}
func (*UnimplementedEnclaveServer) Aggregate(context.Context, *AggregateRequest) (*AggregateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Aggregate not implemented")
}
func (*UnimplementedEnclaveServer) mustEmbedUnimplementedEnclaveServer() {}

func RegisterEnclaveServer(s *grpc.Server, srv EnclaveServer) {
	s.RegisterService(&_Enclave_serviceDesc, srv)
}

func _Enclave_Schedule_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SchedulingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EnclaveServer).Schedule(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/rpc.enclave/Schedule",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EnclaveServer).Schedule(ctx, req.(*SchedulingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Enclave_Aggregate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AggregateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EnclaveServer).Aggregate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/rpc.enclave/Aggregate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EnclaveServer).Aggregate(ctx, req.(*AggregateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Enclave_serviceDesc = grpc.ServiceDesc{
	ServiceName: "rpc.enclave",
	HandlerType: (*EnclaveServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "schedule",
			Handler:    _Enclave_Schedule_Handler,
		},
		{
			MethodName: "aggregate",
			Handler:    _Enclave_Aggregate_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "enclave.proto",
}
