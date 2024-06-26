// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v4.25.1
// source: verifier/verifier.proto

package verifier

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type KeyType int32

const (
	KeyType_TLS        KeyType = 0
	KeyType_Signature  KeyType = 1
	KeyType_Encryption KeyType = 2
	KeyType_AES        KeyType = 3
)

// Enum value maps for KeyType.
var (
	KeyType_name = map[int32]string{
		0: "TLS",
		1: "Signature",
		2: "Encryption",
		3: "AES",
	}
	KeyType_value = map[string]int32{
		"TLS":        0,
		"Signature":  1,
		"Encryption": 2,
		"AES":        3,
	}
)

func (x KeyType) Enum() *KeyType {
	p := new(KeyType)
	*p = x
	return p
}

func (x KeyType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (KeyType) Descriptor() protoreflect.EnumDescriptor {
	return file_verifier_verifier_proto_enumTypes[0].Descriptor()
}

func (KeyType) Type() protoreflect.EnumType {
	return &file_verifier_verifier_proto_enumTypes[0]
}

func (x KeyType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use KeyType.Descriptor instead.
func (KeyType) EnumDescriptor() ([]byte, []int) {
	return file_verifier_verifier_proto_rawDescGZIP(), []int{0}
}

type GetEKRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetEKRequest) Reset() {
	*x = GetEKRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_verifier_verifier_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetEKRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetEKRequest) ProtoMessage() {}

func (x *GetEKRequest) ProtoReflect() protoreflect.Message {
	mi := &file_verifier_verifier_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetEKRequest.ProtoReflect.Descriptor instead.
func (*GetEKRequest) Descriptor() ([]byte, []int) {
	return file_verifier_verifier_proto_rawDescGZIP(), []int{0}
}

type GetEKResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EkPub  []byte `protobuf:"bytes,1,opt,name=ekPub,proto3" json:"ekPub,omitempty"`
	EkCert []byte `protobuf:"bytes,2,opt,name=ekCert,proto3" json:"ekCert,omitempty"`
}

func (x *GetEKResponse) Reset() {
	*x = GetEKResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_verifier_verifier_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetEKResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetEKResponse) ProtoMessage() {}

func (x *GetEKResponse) ProtoReflect() protoreflect.Message {
	mi := &file_verifier_verifier_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetEKResponse.ProtoReflect.Descriptor instead.
func (*GetEKResponse) Descriptor() ([]byte, []int) {
	return file_verifier_verifier_proto_rawDescGZIP(), []int{1}
}

func (x *GetEKResponse) GetEkPub() []byte {
	if x != nil {
		return x.EkPub
	}
	return nil
}

func (x *GetEKResponse) GetEkCert() []byte {
	if x != nil {
		return x.EkCert
	}
	return nil
}

type GetAKRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetAKRequest) Reset() {
	*x = GetAKRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_verifier_verifier_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetAKRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAKRequest) ProtoMessage() {}

func (x *GetAKRequest) ProtoReflect() protoreflect.Message {
	mi := &file_verifier_verifier_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAKRequest.ProtoReflect.Descriptor instead.
func (*GetAKRequest) Descriptor() ([]byte, []int) {
	return file_verifier_verifier_proto_rawDescGZIP(), []int{2}
}

type GetAKResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AttestationParameters []byte `protobuf:"bytes,1,opt,name=attestation_parameters,json=attestationParameters,proto3" json:"attestation_parameters,omitempty"`
}

func (x *GetAKResponse) Reset() {
	*x = GetAKResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_verifier_verifier_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetAKResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAKResponse) ProtoMessage() {}

func (x *GetAKResponse) ProtoReflect() protoreflect.Message {
	mi := &file_verifier_verifier_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAKResponse.ProtoReflect.Descriptor instead.
func (*GetAKResponse) Descriptor() ([]byte, []int) {
	return file_verifier_verifier_proto_rawDescGZIP(), []int{3}
}

func (x *GetAKResponse) GetAttestationParameters() []byte {
	if x != nil {
		return x.AttestationParameters
	}
	return nil
}

type AttestRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EncryptedCredentials []byte `protobuf:"bytes,1,opt,name=encryptedCredentials,proto3" json:"encryptedCredentials,omitempty"`
}

func (x *AttestRequest) Reset() {
	*x = AttestRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_verifier_verifier_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttestRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttestRequest) ProtoMessage() {}

func (x *AttestRequest) ProtoReflect() protoreflect.Message {
	mi := &file_verifier_verifier_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttestRequest.ProtoReflect.Descriptor instead.
func (*AttestRequest) Descriptor() ([]byte, []int) {
	return file_verifier_verifier_proto_rawDescGZIP(), []int{4}
}

func (x *AttestRequest) GetEncryptedCredentials() []byte {
	if x != nil {
		return x.EncryptedCredentials
	}
	return nil
}

type AttestResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Secret []byte `protobuf:"bytes,1,opt,name=secret,proto3" json:"secret,omitempty"`
}

func (x *AttestResponse) Reset() {
	*x = AttestResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_verifier_verifier_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttestResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttestResponse) ProtoMessage() {}

func (x *AttestResponse) ProtoReflect() protoreflect.Message {
	mi := &file_verifier_verifier_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttestResponse.ProtoReflect.Descriptor instead.
func (*AttestResponse) Descriptor() ([]byte, []int) {
	return file_verifier_verifier_proto_rawDescGZIP(), []int{5}
}

func (x *AttestResponse) GetSecret() []byte {
	if x != nil {
		return x.Secret
	}
	return nil
}

type QuoteRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Nonce []byte `protobuf:"bytes,1,opt,name=nonce,proto3" json:"nonce,omitempty"`
}

func (x *QuoteRequest) Reset() {
	*x = QuoteRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_verifier_verifier_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QuoteRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QuoteRequest) ProtoMessage() {}

func (x *QuoteRequest) ProtoReflect() protoreflect.Message {
	mi := &file_verifier_verifier_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QuoteRequest.ProtoReflect.Descriptor instead.
func (*QuoteRequest) Descriptor() ([]byte, []int) {
	return file_verifier_verifier_proto_rawDescGZIP(), []int{6}
}

func (x *QuoteRequest) GetNonce() []byte {
	if x != nil {
		return x.Nonce
	}
	return nil
}

type QuoteResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PlatformAttestation []byte `protobuf:"bytes,1,opt,name=platformAttestation,proto3" json:"platformAttestation,omitempty"`
}

func (x *QuoteResponse) Reset() {
	*x = QuoteResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_verifier_verifier_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QuoteResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QuoteResponse) ProtoMessage() {}

func (x *QuoteResponse) ProtoReflect() protoreflect.Message {
	mi := &file_verifier_verifier_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QuoteResponse.ProtoReflect.Descriptor instead.
func (*QuoteResponse) Descriptor() ([]byte, []int) {
	return file_verifier_verifier_proto_rawDescGZIP(), []int{7}
}

func (x *QuoteResponse) GetPlatformAttestation() []byte {
	if x != nil {
		return x.PlatformAttestation
	}
	return nil
}

type GetAttestedKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Kid     string  `protobuf:"bytes,1,opt,name=kid,proto3" json:"kid,omitempty"`
	KeyType KeyType `protobuf:"varint,2,opt,name=key_type,json=keyType,proto3,enum=verifier.KeyType" json:"key_type,omitempty"`
}

func (x *GetAttestedKeyRequest) Reset() {
	*x = GetAttestedKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_verifier_verifier_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetAttestedKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAttestedKeyRequest) ProtoMessage() {}

func (x *GetAttestedKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_verifier_verifier_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAttestedKeyRequest.ProtoReflect.Descriptor instead.
func (*GetAttestedKeyRequest) Descriptor() ([]byte, []int) {
	return file_verifier_verifier_proto_rawDescGZIP(), []int{8}
}

func (x *GetAttestedKeyRequest) GetKid() string {
	if x != nil {
		return x.Kid
	}
	return ""
}

func (x *GetAttestedKeyRequest) GetKeyType() KeyType {
	if x != nil {
		return x.KeyType
	}
	return KeyType_TLS
}

type GetAttestedKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Certificate      []byte `protobuf:"bytes,1,opt,name=certificate,proto3" json:"certificate,omitempty"`
	KeyCertification []byte `protobuf:"bytes,2,opt,name=keyCertification,proto3" json:"keyCertification,omitempty"`
}

func (x *GetAttestedKeyResponse) Reset() {
	*x = GetAttestedKeyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_verifier_verifier_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetAttestedKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAttestedKeyResponse) ProtoMessage() {}

func (x *GetAttestedKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_verifier_verifier_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAttestedKeyResponse.ProtoReflect.Descriptor instead.
func (*GetAttestedKeyResponse) Descriptor() ([]byte, []int) {
	return file_verifier_verifier_proto_rawDescGZIP(), []int{9}
}

func (x *GetAttestedKeyResponse) GetCertificate() []byte {
	if x != nil {
		return x.Certificate
	}
	return nil
}

func (x *GetAttestedKeyResponse) GetKeyCertification() []byte {
	if x != nil {
		return x.KeyCertification
	}
	return nil
}

var File_verifier_verifier_proto protoreflect.FileDescriptor

var file_verifier_verifier_proto_rawDesc = []byte{
	0x0a, 0x17, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x2f, 0x76, 0x65, 0x72, 0x69, 0x66,
	0x69, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x08, 0x76, 0x65, 0x72, 0x69, 0x66,
	0x69, 0x65, 0x72, 0x22, 0x0e, 0x0a, 0x0c, 0x47, 0x65, 0x74, 0x45, 0x4b, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x22, 0x3d, 0x0a, 0x0d, 0x47, 0x65, 0x74, 0x45, 0x4b, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x6b, 0x50, 0x75, 0x62, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x05, 0x65, 0x6b, 0x50, 0x75, 0x62, 0x12, 0x16, 0x0a, 0x06, 0x65, 0x6b,
	0x43, 0x65, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x65, 0x6b, 0x43, 0x65,
	0x72, 0x74, 0x22, 0x0e, 0x0a, 0x0c, 0x47, 0x65, 0x74, 0x41, 0x4b, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x22, 0x46, 0x0a, 0x0d, 0x47, 0x65, 0x74, 0x41, 0x4b, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x35, 0x0a, 0x16, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x15, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73, 0x22, 0x43, 0x0a, 0x0d, 0x41, 0x74,
	0x74, 0x65, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x32, 0x0a, 0x14, 0x65,
	0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x61, 0x6c, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x14, 0x65, 0x6e, 0x63, 0x72, 0x79,
	0x70, 0x74, 0x65, 0x64, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x22,
	0x28, 0x0a, 0x0e, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x22, 0x24, 0x0a, 0x0c, 0x51, 0x75, 0x6f,
	0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x6e,
	0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x22,
	0x41, 0x0a, 0x0d, 0x51, 0x75, 0x6f, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x30, 0x0a, 0x13, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x41, 0x74, 0x74, 0x65,
	0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x13, 0x70,
	0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x22, 0x57, 0x0a, 0x15, 0x47, 0x65, 0x74, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x65,
	0x64, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x6b,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x69, 0x64, 0x12, 0x2c, 0x0a,
	0x08, 0x6b, 0x65, 0x79, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x11, 0x2e, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x2e, 0x4b, 0x65, 0x79, 0x54, 0x79,
	0x70, 0x65, 0x52, 0x07, 0x6b, 0x65, 0x79, 0x54, 0x79, 0x70, 0x65, 0x22, 0x66, 0x0a, 0x16, 0x47,
	0x65, 0x74, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x65, 0x64, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x63, 0x65, 0x72, 0x74,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x2a, 0x0a, 0x10, 0x6b, 0x65, 0x79, 0x43, 0x65,
	0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x10, 0x6b, 0x65, 0x79, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x2a, 0x3a, 0x0a, 0x07, 0x4b, 0x65, 0x79, 0x54, 0x79, 0x70, 0x65, 0x12, 0x07,
	0x0a, 0x03, 0x54, 0x4c, 0x53, 0x10, 0x00, 0x12, 0x0d, 0x0a, 0x09, 0x53, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x10, 0x01, 0x12, 0x0e, 0x0a, 0x0a, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x10, 0x02, 0x12, 0x07, 0x0a, 0x03, 0x41, 0x45, 0x53, 0x10, 0x03, 0x32,
	0xcf, 0x02, 0x0a, 0x08, 0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x12, 0x3a, 0x0a, 0x05,
	0x47, 0x65, 0x74, 0x45, 0x4b, 0x12, 0x16, 0x2e, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72,
	0x2e, 0x47, 0x65, 0x74, 0x45, 0x4b, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x17, 0x2e,
	0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x2e, 0x47, 0x65, 0x74, 0x45, 0x4b, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x3a, 0x0a, 0x05, 0x47, 0x65, 0x74, 0x41,
	0x4b, 0x12, 0x16, 0x2e, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x2e, 0x47, 0x65, 0x74,
	0x41, 0x4b, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x17, 0x2e, 0x76, 0x65, 0x72, 0x69,
	0x66, 0x69, 0x65, 0x72, 0x2e, 0x47, 0x65, 0x74, 0x41, 0x4b, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x00, 0x12, 0x3d, 0x0a, 0x06, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x12, 0x17,
	0x2e, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x2e, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x18, 0x2e, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69,
	0x65, 0x72, 0x2e, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x00, 0x12, 0x3a, 0x0a, 0x05, 0x51, 0x75, 0x6f, 0x74, 0x65, 0x12, 0x16, 0x2e, 0x76,
	0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x2e, 0x51, 0x75, 0x6f, 0x74, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x17, 0x2e, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x2e,
	0x51, 0x75, 0x6f, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12,
	0x50, 0x0a, 0x09, 0x47, 0x65, 0x74, 0x54, 0x4c, 0x53, 0x4b, 0x65, 0x79, 0x12, 0x1f, 0x2e, 0x76,
	0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x2e, 0x47, 0x65, 0x74, 0x41, 0x74, 0x74, 0x65, 0x73,
	0x74, 0x65, 0x64, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x20, 0x2e,
	0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x2e, 0x47, 0x65, 0x74, 0x41, 0x74, 0x74, 0x65,
	0x73, 0x74, 0x65, 0x64, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22,
	0x00, 0x42, 0x29, 0x5a, 0x27, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x73, 0x61, 0x6c, 0x72, 0x61, 0x73, 0x68, 0x69, 0x64, 0x31, 0x32, 0x33, 0x2f, 0x74, 0x6c, 0x73,
	0x5f, 0x61, 0x6b, 0x2f, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_verifier_verifier_proto_rawDescOnce sync.Once
	file_verifier_verifier_proto_rawDescData = file_verifier_verifier_proto_rawDesc
)

func file_verifier_verifier_proto_rawDescGZIP() []byte {
	file_verifier_verifier_proto_rawDescOnce.Do(func() {
		file_verifier_verifier_proto_rawDescData = protoimpl.X.CompressGZIP(file_verifier_verifier_proto_rawDescData)
	})
	return file_verifier_verifier_proto_rawDescData
}

var file_verifier_verifier_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_verifier_verifier_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_verifier_verifier_proto_goTypes = []interface{}{
	(KeyType)(0),                   // 0: verifier.KeyType
	(*GetEKRequest)(nil),           // 1: verifier.GetEKRequest
	(*GetEKResponse)(nil),          // 2: verifier.GetEKResponse
	(*GetAKRequest)(nil),           // 3: verifier.GetAKRequest
	(*GetAKResponse)(nil),          // 4: verifier.GetAKResponse
	(*AttestRequest)(nil),          // 5: verifier.AttestRequest
	(*AttestResponse)(nil),         // 6: verifier.AttestResponse
	(*QuoteRequest)(nil),           // 7: verifier.QuoteRequest
	(*QuoteResponse)(nil),          // 8: verifier.QuoteResponse
	(*GetAttestedKeyRequest)(nil),  // 9: verifier.GetAttestedKeyRequest
	(*GetAttestedKeyResponse)(nil), // 10: verifier.GetAttestedKeyResponse
}
var file_verifier_verifier_proto_depIdxs = []int32{
	0,  // 0: verifier.GetAttestedKeyRequest.key_type:type_name -> verifier.KeyType
	1,  // 1: verifier.Verifier.GetEK:input_type -> verifier.GetEKRequest
	3,  // 2: verifier.Verifier.GetAK:input_type -> verifier.GetAKRequest
	5,  // 3: verifier.Verifier.Attest:input_type -> verifier.AttestRequest
	7,  // 4: verifier.Verifier.Quote:input_type -> verifier.QuoteRequest
	9,  // 5: verifier.Verifier.GetTLSKey:input_type -> verifier.GetAttestedKeyRequest
	2,  // 6: verifier.Verifier.GetEK:output_type -> verifier.GetEKResponse
	4,  // 7: verifier.Verifier.GetAK:output_type -> verifier.GetAKResponse
	6,  // 8: verifier.Verifier.Attest:output_type -> verifier.AttestResponse
	8,  // 9: verifier.Verifier.Quote:output_type -> verifier.QuoteResponse
	10, // 10: verifier.Verifier.GetTLSKey:output_type -> verifier.GetAttestedKeyResponse
	6,  // [6:11] is the sub-list for method output_type
	1,  // [1:6] is the sub-list for method input_type
	1,  // [1:1] is the sub-list for extension type_name
	1,  // [1:1] is the sub-list for extension extendee
	0,  // [0:1] is the sub-list for field type_name
}

func init() { file_verifier_verifier_proto_init() }
func file_verifier_verifier_proto_init() {
	if File_verifier_verifier_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_verifier_verifier_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetEKRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_verifier_verifier_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetEKResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_verifier_verifier_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetAKRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_verifier_verifier_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetAKResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_verifier_verifier_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttestRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_verifier_verifier_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttestResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_verifier_verifier_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QuoteRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_verifier_verifier_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QuoteResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_verifier_verifier_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetAttestedKeyRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_verifier_verifier_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetAttestedKeyResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_verifier_verifier_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_verifier_verifier_proto_goTypes,
		DependencyIndexes: file_verifier_verifier_proto_depIdxs,
		EnumInfos:         file_verifier_verifier_proto_enumTypes,
		MessageInfos:      file_verifier_verifier_proto_msgTypes,
	}.Build()
	File_verifier_verifier_proto = out.File
	file_verifier_verifier_proto_rawDesc = nil
	file_verifier_verifier_proto_goTypes = nil
	file_verifier_verifier_proto_depIdxs = nil
}
