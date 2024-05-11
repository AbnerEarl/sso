// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.24.4
// source: api/v2/api.proto

package api

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
	Provider_GetClient_FullMethodName      = "/api.Provider/GetClient"
	Provider_CreateClient_FullMethodName   = "/api.Provider/CreateClient"
	Provider_UpdateClient_FullMethodName   = "/api.Provider/UpdateClient"
	Provider_DeleteClient_FullMethodName   = "/api.Provider/DeleteClient"
	Provider_CreatePassword_FullMethodName = "/api.Provider/CreatePassword"
	Provider_UpdatePassword_FullMethodName = "/api.Provider/UpdatePassword"
	Provider_DeletePassword_FullMethodName = "/api.Provider/DeletePassword"
	Provider_ListPasswords_FullMethodName  = "/api.Provider/ListPasswords"
	Provider_GetVersion_FullMethodName     = "/api.Provider/GetVersion"
	Provider_ListRefresh_FullMethodName    = "/api.Provider/ListRefresh"
	Provider_RevokeRefresh_FullMethodName  = "/api.Provider/RevokeRefresh"
	Provider_VerifyPassword_FullMethodName = "/api.Provider/VerifyPassword"
)

// ProviderClient is the client API for provider service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ProviderClient interface {
	// GetClient gets a client.
	GetClient(ctx context.Context, in *GetClientReq, opts ...grpc.CallOption) (*GetClientResp, error)
	// CreateClient creates a client.
	CreateClient(ctx context.Context, in *CreateClientReq, opts ...grpc.CallOption) (*CreateClientResp, error)
	// UpdateClient updates an existing client
	UpdateClient(ctx context.Context, in *UpdateClientReq, opts ...grpc.CallOption) (*UpdateClientResp, error)
	// DeleteClient deletes the provided client.
	DeleteClient(ctx context.Context, in *DeleteClientReq, opts ...grpc.CallOption) (*DeleteClientResp, error)
	// CreatePassword creates a password.
	CreatePassword(ctx context.Context, in *CreatePasswordReq, opts ...grpc.CallOption) (*CreatePasswordResp, error)
	// UpdatePassword modifies existing password.
	UpdatePassword(ctx context.Context, in *UpdatePasswordReq, opts ...grpc.CallOption) (*UpdatePasswordResp, error)
	// DeletePassword deletes the password.
	DeletePassword(ctx context.Context, in *DeletePasswordReq, opts ...grpc.CallOption) (*DeletePasswordResp, error)
	// ListPassword lists all password entries.
	ListPasswords(ctx context.Context, in *ListPasswordReq, opts ...grpc.CallOption) (*ListPasswordResp, error)
	// GetVersion returns version information of the server.
	GetVersion(ctx context.Context, in *VersionReq, opts ...grpc.CallOption) (*VersionResp, error)
	// ListRefresh lists all the refresh token entries for a particular user.
	ListRefresh(ctx context.Context, in *ListRefreshReq, opts ...grpc.CallOption) (*ListRefreshResp, error)
	// RevokeRefresh revokes the refresh token for the provided user-client pair.
	//
	// Note that each user-client pair can have only one refresh token at a time.
	RevokeRefresh(ctx context.Context, in *RevokeRefreshReq, opts ...grpc.CallOption) (*RevokeRefreshResp, error)
	// VerifyPassword returns whether a password matches a hash for a specific email or not.
	VerifyPassword(ctx context.Context, in *VerifyPasswordReq, opts ...grpc.CallOption) (*VerifyPasswordResp, error)
}

type providerClient struct {
	cc grpc.ClientConnInterface
}

func NewProviderClient(cc grpc.ClientConnInterface) ProviderClient {
	return &providerClient{cc}
}

func (c *providerClient) GetClient(ctx context.Context, in *GetClientReq, opts ...grpc.CallOption) (*GetClientResp, error) {
	out := new(GetClientResp)
	err := c.cc.Invoke(ctx, Provider_GetClient_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *providerClient) CreateClient(ctx context.Context, in *CreateClientReq, opts ...grpc.CallOption) (*CreateClientResp, error) {
	out := new(CreateClientResp)
	err := c.cc.Invoke(ctx, Provider_CreateClient_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *providerClient) UpdateClient(ctx context.Context, in *UpdateClientReq, opts ...grpc.CallOption) (*UpdateClientResp, error) {
	out := new(UpdateClientResp)
	err := c.cc.Invoke(ctx, Provider_UpdateClient_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *providerClient) DeleteClient(ctx context.Context, in *DeleteClientReq, opts ...grpc.CallOption) (*DeleteClientResp, error) {
	out := new(DeleteClientResp)
	err := c.cc.Invoke(ctx, Provider_DeleteClient_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *providerClient) CreatePassword(ctx context.Context, in *CreatePasswordReq, opts ...grpc.CallOption) (*CreatePasswordResp, error) {
	out := new(CreatePasswordResp)
	err := c.cc.Invoke(ctx, Provider_CreatePassword_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *providerClient) UpdatePassword(ctx context.Context, in *UpdatePasswordReq, opts ...grpc.CallOption) (*UpdatePasswordResp, error) {
	out := new(UpdatePasswordResp)
	err := c.cc.Invoke(ctx, Provider_UpdatePassword_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *providerClient) DeletePassword(ctx context.Context, in *DeletePasswordReq, opts ...grpc.CallOption) (*DeletePasswordResp, error) {
	out := new(DeletePasswordResp)
	err := c.cc.Invoke(ctx, Provider_DeletePassword_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *providerClient) ListPasswords(ctx context.Context, in *ListPasswordReq, opts ...grpc.CallOption) (*ListPasswordResp, error) {
	out := new(ListPasswordResp)
	err := c.cc.Invoke(ctx, Provider_ListPasswords_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *providerClient) GetVersion(ctx context.Context, in *VersionReq, opts ...grpc.CallOption) (*VersionResp, error) {
	out := new(VersionResp)
	err := c.cc.Invoke(ctx, Provider_GetVersion_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *providerClient) ListRefresh(ctx context.Context, in *ListRefreshReq, opts ...grpc.CallOption) (*ListRefreshResp, error) {
	out := new(ListRefreshResp)
	err := c.cc.Invoke(ctx, Provider_ListRefresh_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *providerClient) RevokeRefresh(ctx context.Context, in *RevokeRefreshReq, opts ...grpc.CallOption) (*RevokeRefreshResp, error) {
	out := new(RevokeRefreshResp)
	err := c.cc.Invoke(ctx, Provider_RevokeRefresh_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *providerClient) VerifyPassword(ctx context.Context, in *VerifyPasswordReq, opts ...grpc.CallOption) (*VerifyPasswordResp, error) {
	out := new(VerifyPasswordResp)
	err := c.cc.Invoke(ctx, Provider_VerifyPassword_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ProviderServer is the server API for provider service.
// All implementations must embed UnimplementedProviderServer
// for forward compatibility
type ProviderServer interface {
	// GetClient gets a client.
	GetClient(context.Context, *GetClientReq) (*GetClientResp, error)
	// CreateClient creates a client.
	CreateClient(context.Context, *CreateClientReq) (*CreateClientResp, error)
	// UpdateClient updates an existing client
	UpdateClient(context.Context, *UpdateClientReq) (*UpdateClientResp, error)
	// DeleteClient deletes the provided client.
	DeleteClient(context.Context, *DeleteClientReq) (*DeleteClientResp, error)
	// CreatePassword creates a password.
	CreatePassword(context.Context, *CreatePasswordReq) (*CreatePasswordResp, error)
	// UpdatePassword modifies existing password.
	UpdatePassword(context.Context, *UpdatePasswordReq) (*UpdatePasswordResp, error)
	// DeletePassword deletes the password.
	DeletePassword(context.Context, *DeletePasswordReq) (*DeletePasswordResp, error)
	// ListPassword lists all password entries.
	ListPasswords(context.Context, *ListPasswordReq) (*ListPasswordResp, error)
	// GetVersion returns version information of the server.
	GetVersion(context.Context, *VersionReq) (*VersionResp, error)
	// ListRefresh lists all the refresh token entries for a particular user.
	ListRefresh(context.Context, *ListRefreshReq) (*ListRefreshResp, error)
	// RevokeRefresh revokes the refresh token for the provided user-client pair.
	//
	// Note that each user-client pair can have only one refresh token at a time.
	RevokeRefresh(context.Context, *RevokeRefreshReq) (*RevokeRefreshResp, error)
	// VerifyPassword returns whether a password matches a hash for a specific email or not.
	VerifyPassword(context.Context, *VerifyPasswordReq) (*VerifyPasswordResp, error)
	mustEmbedUnimplementedProviderServer()
}

// UnimplementedProviderServer must be embedded to have forward compatible implementations.
type UnimplementedProviderServer struct {
}

func (UnimplementedProviderServer) GetClient(context.Context, *GetClientReq) (*GetClientResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetClient not implemented")
}
func (UnimplementedProviderServer) CreateClient(context.Context, *CreateClientReq) (*CreateClientResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateClient not implemented")
}
func (UnimplementedProviderServer) UpdateClient(context.Context, *UpdateClientReq) (*UpdateClientResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateClient not implemented")
}
func (UnimplementedProviderServer) DeleteClient(context.Context, *DeleteClientReq) (*DeleteClientResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteClient not implemented")
}
func (UnimplementedProviderServer) CreatePassword(context.Context, *CreatePasswordReq) (*CreatePasswordResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreatePassword not implemented")
}
func (UnimplementedProviderServer) UpdatePassword(context.Context, *UpdatePasswordReq) (*UpdatePasswordResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdatePassword not implemented")
}
func (UnimplementedProviderServer) DeletePassword(context.Context, *DeletePasswordReq) (*DeletePasswordResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeletePassword not implemented")
}
func (UnimplementedProviderServer) ListPasswords(context.Context, *ListPasswordReq) (*ListPasswordResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListPasswords not implemented")
}
func (UnimplementedProviderServer) GetVersion(context.Context, *VersionReq) (*VersionResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetVersion not implemented")
}
func (UnimplementedProviderServer) ListRefresh(context.Context, *ListRefreshReq) (*ListRefreshResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListRefresh not implemented")
}
func (UnimplementedProviderServer) RevokeRefresh(context.Context, *RevokeRefreshReq) (*RevokeRefreshResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RevokeRefresh not implemented")
}
func (UnimplementedProviderServer) VerifyPassword(context.Context, *VerifyPasswordReq) (*VerifyPasswordResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyPassword not implemented")
}
func (UnimplementedProviderServer) mustEmbedUnimplementedProviderServer() {}

// UnsafeProviderServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ProviderServer will
// result in compilation errors.
type UnsafeProviderServer interface {
	mustEmbedUnimplementedProviderServer()
}

func RegisterProviderServer(s grpc.ServiceRegistrar, srv ProviderServer) {
	s.RegisterService(&Provider_ServiceDesc, srv)
}

func _Provider_GetClient_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetClientReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProviderServer).GetClient(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Provider_GetClient_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProviderServer).GetClient(ctx, req.(*GetClientReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Provider_CreateClient_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateClientReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProviderServer).CreateClient(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Provider_CreateClient_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProviderServer).CreateClient(ctx, req.(*CreateClientReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Provider_UpdateClient_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateClientReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProviderServer).UpdateClient(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Provider_UpdateClient_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProviderServer).UpdateClient(ctx, req.(*UpdateClientReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Provider_DeleteClient_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteClientReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProviderServer).DeleteClient(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Provider_DeleteClient_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProviderServer).DeleteClient(ctx, req.(*DeleteClientReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Provider_CreatePassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreatePasswordReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProviderServer).CreatePassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Provider_CreatePassword_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProviderServer).CreatePassword(ctx, req.(*CreatePasswordReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Provider_UpdatePassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdatePasswordReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProviderServer).UpdatePassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Provider_UpdatePassword_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProviderServer).UpdatePassword(ctx, req.(*UpdatePasswordReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Provider_DeletePassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeletePasswordReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProviderServer).DeletePassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Provider_DeletePassword_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProviderServer).DeletePassword(ctx, req.(*DeletePasswordReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Provider_ListPasswords_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListPasswordReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProviderServer).ListPasswords(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Provider_ListPasswords_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProviderServer).ListPasswords(ctx, req.(*ListPasswordReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Provider_GetVersion_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VersionReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProviderServer).GetVersion(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Provider_GetVersion_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProviderServer).GetVersion(ctx, req.(*VersionReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Provider_ListRefresh_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListRefreshReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProviderServer).ListRefresh(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Provider_ListRefresh_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProviderServer).ListRefresh(ctx, req.(*ListRefreshReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Provider_RevokeRefresh_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RevokeRefreshReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProviderServer).RevokeRefresh(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Provider_RevokeRefresh_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProviderServer).RevokeRefresh(ctx, req.(*RevokeRefreshReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Provider_VerifyPassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerifyPasswordReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProviderServer).VerifyPassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Provider_VerifyPassword_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProviderServer).VerifyPassword(ctx, req.(*VerifyPasswordReq))
	}
	return interceptor(ctx, in, info, handler)
}

// Provider_ServiceDesc is the grpc.ServiceDesc for provider service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Provider_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "api.Provider",
	HandlerType: (*ProviderServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetClient",
			Handler:    _Provider_GetClient_Handler,
		},
		{
			MethodName: "CreateClient",
			Handler:    _Provider_CreateClient_Handler,
		},
		{
			MethodName: "UpdateClient",
			Handler:    _Provider_UpdateClient_Handler,
		},
		{
			MethodName: "DeleteClient",
			Handler:    _Provider_DeleteClient_Handler,
		},
		{
			MethodName: "CreatePassword",
			Handler:    _Provider_CreatePassword_Handler,
		},
		{
			MethodName: "UpdatePassword",
			Handler:    _Provider_UpdatePassword_Handler,
		},
		{
			MethodName: "DeletePassword",
			Handler:    _Provider_DeletePassword_Handler,
		},
		{
			MethodName: "ListPasswords",
			Handler:    _Provider_ListPasswords_Handler,
		},
		{
			MethodName: "GetVersion",
			Handler:    _Provider_GetVersion_Handler,
		},
		{
			MethodName: "ListRefresh",
			Handler:    _Provider_ListRefresh_Handler,
		},
		{
			MethodName: "RevokeRefresh",
			Handler:    _Provider_RevokeRefresh_Handler,
		},
		{
			MethodName: "VerifyPassword",
			Handler:    _Provider_VerifyPassword_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/v2/api.proto",
}