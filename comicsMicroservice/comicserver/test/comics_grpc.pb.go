// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.23.2
// source: comics.proto

package test

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	ComicsService_CreateComic_FullMethodName = "/comics.ComicsService/CreateComic"
	ComicsService_ReadComic_FullMethodName   = "/comics.ComicsService/ReadComic"
	ComicsService_UpdateComic_FullMethodName = "/comics.ComicsService/UpdateComic"
	ComicsService_DeleteComic_FullMethodName = "/comics.ComicsService/DeleteComic"
)

// ComicsServiceClient is the client API for ComicsService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ComicsServiceClient interface {
	CreateComic(ctx context.Context, in *CreateComicRequest, opts ...grpc.CallOption) (*Comic, error)
	ReadComic(ctx context.Context, in *ReadComicRequest, opts ...grpc.CallOption) (*Comic, error)
	UpdateComic(ctx context.Context, in *UpdateComicRequest, opts ...grpc.CallOption) (*Comic, error)
	DeleteComic(ctx context.Context, in *DeleteComicRequest, opts ...grpc.CallOption) (*DeleteComicResponse, error)
}

type comicsServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewComicsServiceClient(cc grpc.ClientConnInterface) ComicsServiceClient {
	return &comicsServiceClient{cc}
}

func (c *comicsServiceClient) CreateComic(ctx context.Context, in *CreateComicRequest, opts ...grpc.CallOption) (*Comic, error) {
	out := new(Comic)
	err := c.cc.Invoke(ctx, ComicsService_CreateComic_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *comicsServiceClient) ReadComic(ctx context.Context, in *ReadComicRequest, opts ...grpc.CallOption) (*Comic, error) {
	out := new(Comic)
	err := c.cc.Invoke(ctx, ComicsService_ReadComic_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *comicsServiceClient) UpdateComic(ctx context.Context, in *UpdateComicRequest, opts ...grpc.CallOption) (*Comic, error) {
	out := new(Comic)
	err := c.cc.Invoke(ctx, ComicsService_UpdateComic_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *comicsServiceClient) DeleteComic(ctx context.Context, in *DeleteComicRequest, opts ...grpc.CallOption) (*DeleteComicResponse, error) {
	out := new(DeleteComicResponse)
	err := c.cc.Invoke(ctx, ComicsService_DeleteComic_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ComicsServiceServer is the server API for ComicsService service.
// All implementations must embed UnimplementedComicsServiceServer
// for forward compatibility
type ComicsServiceServer interface {
	CreateComic(context.Context, *CreateComicRequest) (*Comic, error)
	ReadComic(context.Context, *ReadComicRequest) (*Comic, error)
	UpdateComic(context.Context, *UpdateComicRequest) (*Comic, error)
	DeleteComic(context.Context, *DeleteComicRequest) (*DeleteComicResponse, error)
	mustEmbedUnimplementedComicsServiceServer()
}

// UnimplementedComicsServiceServer must be embedded to have forward compatible implementations.
type UnimplementedComicsServiceServer struct {
}

func (UnimplementedComicsServiceServer) CreateComic(context.Context, *CreateComicRequest) (*Comic, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateComic not implemented")
}
func (UnimplementedComicsServiceServer) ReadComic(context.Context, *ReadComicRequest) (*Comic, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReadComic not implemented")
}
func (UnimplementedComicsServiceServer) UpdateComic(context.Context, *UpdateComicRequest) (*Comic, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateComic not implemented")
}
func (UnimplementedComicsServiceServer) DeleteComic(context.Context, *DeleteComicRequest) (*DeleteComicResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteComic not implemented")
}
func (UnimplementedComicsServiceServer) mustEmbedUnimplementedComicsServiceServer() {}

// UnsafeComicsServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ComicsServiceServer will
// result in compilation errors.
type UnsafeComicsServiceServer interface {
	mustEmbedUnimplementedComicsServiceServer()
}

func RegisterComicsServiceServer(s grpc.ServiceRegistrar, srv ComicsServiceServer) {
	s.RegisterService(&ComicsService_ServiceDesc, srv)
}

func _ComicsService_CreateComic_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateComicRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ComicsServiceServer).CreateComic(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ComicsService_CreateComic_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ComicsServiceServer).CreateComic(ctx, req.(*CreateComicRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ComicsService_ReadComic_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReadComicRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ComicsServiceServer).ReadComic(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ComicsService_ReadComic_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ComicsServiceServer).ReadComic(ctx, req.(*ReadComicRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ComicsService_UpdateComic_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateComicRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ComicsServiceServer).UpdateComic(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ComicsService_UpdateComic_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ComicsServiceServer).UpdateComic(ctx, req.(*UpdateComicRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ComicsService_DeleteComic_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteComicRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ComicsServiceServer).DeleteComic(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ComicsService_DeleteComic_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ComicsServiceServer).DeleteComic(ctx, req.(*DeleteComicRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ComicsService_ServiceDesc is the grpc.ServiceDesc for ComicsService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ComicsService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "comics.ComicsService",
	HandlerType: (*ComicsServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateComic",
			Handler:    _ComicsService_CreateComic_Handler,
		},
		{
			MethodName: "ReadComic",
			Handler:    _ComicsService_ReadComic_Handler,
		},
		{
			MethodName: "UpdateComic",
			Handler:    _ComicsService_UpdateComic_Handler,
		},
		{
			MethodName: "DeleteComic",
			Handler:    _ComicsService_DeleteComic_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "comics.proto",
}