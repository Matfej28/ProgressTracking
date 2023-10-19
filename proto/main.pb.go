// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.21.1
// source: main.proto

package __

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

type RegistrationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Username        string `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
	Email           string `protobuf:"bytes,2,opt,name=email,proto3" json:"email,omitempty"`
	Password        string `protobuf:"bytes,3,opt,name=password,proto3" json:"password,omitempty"`
	ConfirmPassword string `protobuf:"bytes,4,opt,name=confirmPassword,proto3" json:"confirmPassword,omitempty"`
}

func (x *RegistrationRequest) Reset() {
	*x = RegistrationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_main_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RegistrationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegistrationRequest) ProtoMessage() {}

func (x *RegistrationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_main_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegistrationRequest.ProtoReflect.Descriptor instead.
func (*RegistrationRequest) Descriptor() ([]byte, []int) {
	return file_main_proto_rawDescGZIP(), []int{0}
}

func (x *RegistrationRequest) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *RegistrationRequest) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *RegistrationRequest) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

func (x *RegistrationRequest) GetConfirmPassword() string {
	if x != nil {
		return x.ConfirmPassword
	}
	return ""
}

type RegistrationResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Token string `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
}

func (x *RegistrationResponse) Reset() {
	*x = RegistrationResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_main_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RegistrationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegistrationResponse) ProtoMessage() {}

func (x *RegistrationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_main_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegistrationResponse.ProtoReflect.Descriptor instead.
func (*RegistrationResponse) Descriptor() ([]byte, []int) {
	return file_main_proto_rawDescGZIP(), []int{1}
}

func (x *RegistrationResponse) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

type LogInRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Email    string `protobuf:"bytes,1,opt,name=email,proto3" json:"email,omitempty"`
	Password string `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
}

func (x *LogInRequest) Reset() {
	*x = LogInRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_main_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LogInRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogInRequest) ProtoMessage() {}

func (x *LogInRequest) ProtoReflect() protoreflect.Message {
	mi := &file_main_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogInRequest.ProtoReflect.Descriptor instead.
func (*LogInRequest) Descriptor() ([]byte, []int) {
	return file_main_proto_rawDescGZIP(), []int{2}
}

func (x *LogInRequest) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *LogInRequest) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

type LogInResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Token string `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
}

func (x *LogInResponse) Reset() {
	*x = LogInResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_main_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LogInResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogInResponse) ProtoMessage() {}

func (x *LogInResponse) ProtoReflect() protoreflect.Message {
	mi := &file_main_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogInResponse.ProtoReflect.Descriptor instead.
func (*LogInResponse) Descriptor() ([]byte, []int) {
	return file_main_proto_rawDescGZIP(), []int{3}
}

func (x *LogInResponse) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

type GetRecordsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MuscleGroup *string   `protobuf:"bytes,1,opt,name=muscleGroup,proto3,oneof" json:"muscleGroup,omitempty"`
	Exercise    *string   `protobuf:"bytes,2,opt,name=exercise,proto3,oneof" json:"exercise,omitempty"`
	Reps        *RepRange `protobuf:"bytes,3,opt,name=reps,proto3,oneof" json:"reps,omitempty"`
}

func (x *GetRecordsRequest) Reset() {
	*x = GetRecordsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_main_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetRecordsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetRecordsRequest) ProtoMessage() {}

func (x *GetRecordsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_main_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetRecordsRequest.ProtoReflect.Descriptor instead.
func (*GetRecordsRequest) Descriptor() ([]byte, []int) {
	return file_main_proto_rawDescGZIP(), []int{4}
}

func (x *GetRecordsRequest) GetMuscleGroup() string {
	if x != nil && x.MuscleGroup != nil {
		return *x.MuscleGroup
	}
	return ""
}

func (x *GetRecordsRequest) GetExercise() string {
	if x != nil && x.Exercise != nil {
		return *x.Exercise
	}
	return ""
}

func (x *GetRecordsRequest) GetReps() *RepRange {
	if x != nil {
		return x.Reps
	}
	return nil
}

type GetRecordsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Record []*Record `protobuf:"bytes,1,rep,name=record,proto3" json:"record,omitempty"`
}

func (x *GetRecordsResponse) Reset() {
	*x = GetRecordsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_main_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetRecordsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetRecordsResponse) ProtoMessage() {}

func (x *GetRecordsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_main_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetRecordsResponse.ProtoReflect.Descriptor instead.
func (*GetRecordsResponse) Descriptor() ([]byte, []int) {
	return file_main_proto_rawDescGZIP(), []int{5}
}

func (x *GetRecordsResponse) GetRecord() []*Record {
	if x != nil {
		return x.Record
	}
	return nil
}

type UpdateRecordsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MuscleGroup string    `protobuf:"bytes,1,opt,name=muscleGroup,proto3" json:"muscleGroup,omitempty"`
	Exercise    string    `protobuf:"bytes,2,opt,name=exercise,proto3" json:"exercise,omitempty"`
	Reps        *RepRange `protobuf:"bytes,3,opt,name=reps,proto3" json:"reps,omitempty"`
	Sets        []*Set    `protobuf:"bytes,4,rep,name=sets,proto3" json:"sets,omitempty"`
}

func (x *UpdateRecordsRequest) Reset() {
	*x = UpdateRecordsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_main_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateRecordsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateRecordsRequest) ProtoMessage() {}

func (x *UpdateRecordsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_main_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateRecordsRequest.ProtoReflect.Descriptor instead.
func (*UpdateRecordsRequest) Descriptor() ([]byte, []int) {
	return file_main_proto_rawDescGZIP(), []int{6}
}

func (x *UpdateRecordsRequest) GetMuscleGroup() string {
	if x != nil {
		return x.MuscleGroup
	}
	return ""
}

func (x *UpdateRecordsRequest) GetExercise() string {
	if x != nil {
		return x.Exercise
	}
	return ""
}

func (x *UpdateRecordsRequest) GetReps() *RepRange {
	if x != nil {
		return x.Reps
	}
	return nil
}

func (x *UpdateRecordsRequest) GetSets() []*Set {
	if x != nil {
		return x.Sets
	}
	return nil
}

type UpdateRecordsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Record *Record `protobuf:"bytes,1,opt,name=record,proto3" json:"record,omitempty"`
}

func (x *UpdateRecordsResponse) Reset() {
	*x = UpdateRecordsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_main_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateRecordsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateRecordsResponse) ProtoMessage() {}

func (x *UpdateRecordsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_main_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateRecordsResponse.ProtoReflect.Descriptor instead.
func (*UpdateRecordsResponse) Descriptor() ([]byte, []int) {
	return file_main_proto_rawDescGZIP(), []int{7}
}

func (x *UpdateRecordsResponse) GetRecord() *Record {
	if x != nil {
		return x.Record
	}
	return nil
}

type Record struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MuscleGroup        string    `protobuf:"bytes,1,opt,name=muscleGroup,proto3" json:"muscleGroup,omitempty"`
	Exercise           string    `protobuf:"bytes,2,opt,name=exercise,proto3" json:"exercise,omitempty"`
	Reps               *RepRange `protobuf:"bytes,3,opt,name=reps,proto3" json:"reps,omitempty"`
	LastTraining       []*Set    `protobuf:"bytes,4,rep,name=lastTraining,proto3" json:"lastTraining,omitempty"`
	BeforeLastTraining []*Set    `protobuf:"bytes,5,rep,name=beforeLastTraining,proto3" json:"beforeLastTraining,omitempty"`
	Pr                 *Set      `protobuf:"bytes,6,opt,name=pr,proto3" json:"pr,omitempty"`
}

func (x *Record) Reset() {
	*x = Record{}
	if protoimpl.UnsafeEnabled {
		mi := &file_main_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Record) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Record) ProtoMessage() {}

func (x *Record) ProtoReflect() protoreflect.Message {
	mi := &file_main_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Record.ProtoReflect.Descriptor instead.
func (*Record) Descriptor() ([]byte, []int) {
	return file_main_proto_rawDescGZIP(), []int{8}
}

func (x *Record) GetMuscleGroup() string {
	if x != nil {
		return x.MuscleGroup
	}
	return ""
}

func (x *Record) GetExercise() string {
	if x != nil {
		return x.Exercise
	}
	return ""
}

func (x *Record) GetReps() *RepRange {
	if x != nil {
		return x.Reps
	}
	return nil
}

func (x *Record) GetLastTraining() []*Set {
	if x != nil {
		return x.LastTraining
	}
	return nil
}

func (x *Record) GetBeforeLastTraining() []*Set {
	if x != nil {
		return x.BeforeLastTraining
	}
	return nil
}

func (x *Record) GetPr() *Set {
	if x != nil {
		return x.Pr
	}
	return nil
}

type RepRange struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Min uint32 `protobuf:"varint,1,opt,name=min,proto3" json:"min,omitempty"`
	Max uint32 `protobuf:"varint,2,opt,name=max,proto3" json:"max,omitempty"`
}

func (x *RepRange) Reset() {
	*x = RepRange{}
	if protoimpl.UnsafeEnabled {
		mi := &file_main_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RepRange) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RepRange) ProtoMessage() {}

func (x *RepRange) ProtoReflect() protoreflect.Message {
	mi := &file_main_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RepRange.ProtoReflect.Descriptor instead.
func (*RepRange) Descriptor() ([]byte, []int) {
	return file_main_proto_rawDescGZIP(), []int{9}
}

func (x *RepRange) GetMin() uint32 {
	if x != nil {
		return x.Min
	}
	return 0
}

func (x *RepRange) GetMax() uint32 {
	if x != nil {
		return x.Max
	}
	return 0
}

type Set struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Reps   uint32  `protobuf:"varint,1,opt,name=reps,proto3" json:"reps,omitempty"`
	Weight float32 `protobuf:"fixed32,2,opt,name=weight,proto3" json:"weight,omitempty"`
}

func (x *Set) Reset() {
	*x = Set{}
	if protoimpl.UnsafeEnabled {
		mi := &file_main_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Set) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Set) ProtoMessage() {}

func (x *Set) ProtoReflect() protoreflect.Message {
	mi := &file_main_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Set.ProtoReflect.Descriptor instead.
func (*Set) Descriptor() ([]byte, []int) {
	return file_main_proto_rawDescGZIP(), []int{10}
}

func (x *Set) GetReps() uint32 {
	if x != nil {
		return x.Reps
	}
	return 0
}

func (x *Set) GetWeight() float32 {
	if x != nil {
		return x.Weight
	}
	return 0
}

var File_main_proto protoreflect.FileDescriptor

var file_main_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x10, 0x70, 0x72,
	0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x22, 0x8d,
	0x01, 0x0a, 0x13, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73,
	0x77, 0x6f, 0x72, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73,
	0x77, 0x6f, 0x72, 0x64, 0x12, 0x28, 0x0a, 0x0f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x50,
	0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x22, 0x2c,
	0x0a, 0x14, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x40, 0x0a, 0x0c,
	0x4c, 0x6f, 0x67, 0x49, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05,
	0x65, 0x6d, 0x61, 0x69, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x6d, 0x61,
	0x69, 0x6c, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x22, 0x25,
	0x0a, 0x0d, 0x4c, 0x6f, 0x67, 0x49, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0xb6, 0x01, 0x0a, 0x11, 0x47, 0x65, 0x74, 0x52, 0x65, 0x63,
	0x6f, 0x72, 0x64, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x25, 0x0a, 0x0b, 0x6d,
	0x75, 0x73, 0x63, 0x6c, 0x65, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x48, 0x00, 0x52, 0x0b, 0x6d, 0x75, 0x73, 0x63, 0x6c, 0x65, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x88,
	0x01, 0x01, 0x12, 0x1f, 0x0a, 0x08, 0x65, 0x78, 0x65, 0x72, 0x63, 0x69, 0x73, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x48, 0x01, 0x52, 0x08, 0x65, 0x78, 0x65, 0x72, 0x63, 0x69, 0x73, 0x65,
	0x88, 0x01, 0x01, 0x12, 0x33, 0x0a, 0x04, 0x72, 0x65, 0x70, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x54, 0x72, 0x61, 0x63,
	0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x52, 0x65, 0x70, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x48, 0x02, 0x52,
	0x04, 0x72, 0x65, 0x70, 0x73, 0x88, 0x01, 0x01, 0x42, 0x0e, 0x0a, 0x0c, 0x5f, 0x6d, 0x75, 0x73,
	0x63, 0x6c, 0x65, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x42, 0x0b, 0x0a, 0x09, 0x5f, 0x65, 0x78, 0x65,
	0x72, 0x63, 0x69, 0x73, 0x65, 0x42, 0x07, 0x0a, 0x05, 0x5f, 0x72, 0x65, 0x70, 0x73, 0x22, 0x46,
	0x0a, 0x12, 0x47, 0x65, 0x74, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x73, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x30, 0x0a, 0x06, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x54,
	0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x52, 0x06,
	0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x22, 0xaf, 0x01, 0x0a, 0x14, 0x55, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x20, 0x0a, 0x0b, 0x6d, 0x75, 0x73, 0x63, 0x6c, 0x65, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x6d, 0x75, 0x73, 0x63, 0x6c, 0x65, 0x47, 0x72, 0x6f, 0x75,
	0x70, 0x12, 0x1a, 0x0a, 0x08, 0x65, 0x78, 0x65, 0x72, 0x63, 0x69, 0x73, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x65, 0x78, 0x65, 0x72, 0x63, 0x69, 0x73, 0x65, 0x12, 0x2e, 0x0a,
	0x04, 0x72, 0x65, 0x70, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x70, 0x72,
	0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x52,
	0x65, 0x70, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x52, 0x04, 0x72, 0x65, 0x70, 0x73, 0x12, 0x29, 0x0a,
	0x04, 0x73, 0x65, 0x74, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x70, 0x72,
	0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x53,
	0x65, 0x74, 0x52, 0x04, 0x73, 0x65, 0x74, 0x73, 0x22, 0x49, 0x0a, 0x15, 0x55, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x30, 0x0a, 0x06, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x18, 0x2e, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x54, 0x72, 0x61, 0x63,
	0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x52, 0x06, 0x72, 0x65, 0x63,
	0x6f, 0x72, 0x64, 0x22, 0x9f, 0x02, 0x0a, 0x06, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x12, 0x20,
	0x0a, 0x0b, 0x6d, 0x75, 0x73, 0x63, 0x6c, 0x65, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0b, 0x6d, 0x75, 0x73, 0x63, 0x6c, 0x65, 0x47, 0x72, 0x6f, 0x75, 0x70,
	0x12, 0x1a, 0x0a, 0x08, 0x65, 0x78, 0x65, 0x72, 0x63, 0x69, 0x73, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x08, 0x65, 0x78, 0x65, 0x72, 0x63, 0x69, 0x73, 0x65, 0x12, 0x2e, 0x0a, 0x04,
	0x72, 0x65, 0x70, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x70, 0x72, 0x6f,
	0x67, 0x72, 0x65, 0x73, 0x73, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x52, 0x65,
	0x70, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x52, 0x04, 0x72, 0x65, 0x70, 0x73, 0x12, 0x39, 0x0a, 0x0c,
	0x6c, 0x61, 0x73, 0x74, 0x54, 0x72, 0x61, 0x69, 0x6e, 0x69, 0x6e, 0x67, 0x18, 0x04, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x15, 0x2e, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x54, 0x72, 0x61,
	0x63, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x53, 0x65, 0x74, 0x52, 0x0c, 0x6c, 0x61, 0x73, 0x74, 0x54,
	0x72, 0x61, 0x69, 0x6e, 0x69, 0x6e, 0x67, 0x12, 0x45, 0x0a, 0x12, 0x62, 0x65, 0x66, 0x6f, 0x72,
	0x65, 0x4c, 0x61, 0x73, 0x74, 0x54, 0x72, 0x61, 0x69, 0x6e, 0x69, 0x6e, 0x67, 0x18, 0x05, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x54, 0x72,
	0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x53, 0x65, 0x74, 0x52, 0x12, 0x62, 0x65, 0x66, 0x6f,
	0x72, 0x65, 0x4c, 0x61, 0x73, 0x74, 0x54, 0x72, 0x61, 0x69, 0x6e, 0x69, 0x6e, 0x67, 0x12, 0x25,
	0x0a, 0x02, 0x70, 0x72, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x70, 0x72, 0x6f,
	0x67, 0x72, 0x65, 0x73, 0x73, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x53, 0x65,
	0x74, 0x52, 0x02, 0x70, 0x72, 0x22, 0x2e, 0x0a, 0x08, 0x52, 0x65, 0x70, 0x52, 0x61, 0x6e, 0x67,
	0x65, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x69, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03,
	0x6d, 0x69, 0x6e, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x61, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x03, 0x6d, 0x61, 0x78, 0x22, 0x31, 0x0a, 0x03, 0x53, 0x65, 0x74, 0x12, 0x12, 0x0a, 0x04,
	0x72, 0x65, 0x70, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x72, 0x65, 0x70, 0x73,
	0x12, 0x16, 0x0a, 0x06, 0x77, 0x65, 0x69, 0x67, 0x68, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x02,
	0x52, 0x06, 0x77, 0x65, 0x69, 0x67, 0x68, 0x74, 0x32, 0xfe, 0x02, 0x0a, 0x10, 0x50, 0x72, 0x6f,
	0x67, 0x72, 0x65, 0x73, 0x73, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x12, 0x5f, 0x0a,
	0x0c, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x25, 0x2e,
	0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67,
	0x2e, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x26, 0x2e, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x54,
	0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x4a,
	0x0a, 0x05, 0x4c, 0x6f, 0x67, 0x49, 0x6e, 0x12, 0x1e, 0x2e, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65,
	0x73, 0x73, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x4c, 0x6f, 0x67, 0x49, 0x6e,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65,
	0x73, 0x73, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x4c, 0x6f, 0x67, 0x49, 0x6e,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x59, 0x0a, 0x0a, 0x47, 0x65,
	0x74, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x73, 0x12, 0x23, 0x2e, 0x70, 0x72, 0x6f, 0x67, 0x72,
	0x65, 0x73, 0x73, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x47, 0x65, 0x74, 0x52,
	0x65, 0x63, 0x6f, 0x72, 0x64, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x24, 0x2e,
	0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67,
	0x2e, 0x47, 0x65, 0x74, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x62, 0x0a, 0x0d, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52,
	0x65, 0x63, 0x6f, 0x72, 0x64, 0x73, 0x12, 0x26, 0x2e, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73,
	0x73, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65,
	0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x27,
	0x2e, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e,
	0x67, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x73, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x03, 0x5a, 0x01, 0x2e, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_main_proto_rawDescOnce sync.Once
	file_main_proto_rawDescData = file_main_proto_rawDesc
)

func file_main_proto_rawDescGZIP() []byte {
	file_main_proto_rawDescOnce.Do(func() {
		file_main_proto_rawDescData = protoimpl.X.CompressGZIP(file_main_proto_rawDescData)
	})
	return file_main_proto_rawDescData
}

var file_main_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_main_proto_goTypes = []interface{}{
	(*RegistrationRequest)(nil),   // 0: progressTracking.RegistrationRequest
	(*RegistrationResponse)(nil),  // 1: progressTracking.RegistrationResponse
	(*LogInRequest)(nil),          // 2: progressTracking.LogInRequest
	(*LogInResponse)(nil),         // 3: progressTracking.LogInResponse
	(*GetRecordsRequest)(nil),     // 4: progressTracking.GetRecordsRequest
	(*GetRecordsResponse)(nil),    // 5: progressTracking.GetRecordsResponse
	(*UpdateRecordsRequest)(nil),  // 6: progressTracking.UpdateRecordsRequest
	(*UpdateRecordsResponse)(nil), // 7: progressTracking.UpdateRecordsResponse
	(*Record)(nil),                // 8: progressTracking.Record
	(*RepRange)(nil),              // 9: progressTracking.RepRange
	(*Set)(nil),                   // 10: progressTracking.Set
}
var file_main_proto_depIdxs = []int32{
	9,  // 0: progressTracking.GetRecordsRequest.reps:type_name -> progressTracking.RepRange
	8,  // 1: progressTracking.GetRecordsResponse.record:type_name -> progressTracking.Record
	9,  // 2: progressTracking.UpdateRecordsRequest.reps:type_name -> progressTracking.RepRange
	10, // 3: progressTracking.UpdateRecordsRequest.sets:type_name -> progressTracking.Set
	8,  // 4: progressTracking.UpdateRecordsResponse.record:type_name -> progressTracking.Record
	9,  // 5: progressTracking.Record.reps:type_name -> progressTracking.RepRange
	10, // 6: progressTracking.Record.lastTraining:type_name -> progressTracking.Set
	10, // 7: progressTracking.Record.beforeLastTraining:type_name -> progressTracking.Set
	10, // 8: progressTracking.Record.pr:type_name -> progressTracking.Set
	0,  // 9: progressTracking.ProgressTracking.Registration:input_type -> progressTracking.RegistrationRequest
	2,  // 10: progressTracking.ProgressTracking.LogIn:input_type -> progressTracking.LogInRequest
	4,  // 11: progressTracking.ProgressTracking.GetRecords:input_type -> progressTracking.GetRecordsRequest
	6,  // 12: progressTracking.ProgressTracking.UpdateRecords:input_type -> progressTracking.UpdateRecordsRequest
	1,  // 13: progressTracking.ProgressTracking.Registration:output_type -> progressTracking.RegistrationResponse
	3,  // 14: progressTracking.ProgressTracking.LogIn:output_type -> progressTracking.LogInResponse
	5,  // 15: progressTracking.ProgressTracking.GetRecords:output_type -> progressTracking.GetRecordsResponse
	7,  // 16: progressTracking.ProgressTracking.UpdateRecords:output_type -> progressTracking.UpdateRecordsResponse
	13, // [13:17] is the sub-list for method output_type
	9,  // [9:13] is the sub-list for method input_type
	9,  // [9:9] is the sub-list for extension type_name
	9,  // [9:9] is the sub-list for extension extendee
	0,  // [0:9] is the sub-list for field type_name
}

func init() { file_main_proto_init() }
func file_main_proto_init() {
	if File_main_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_main_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RegistrationRequest); i {
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
		file_main_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RegistrationResponse); i {
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
		file_main_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LogInRequest); i {
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
		file_main_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LogInResponse); i {
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
		file_main_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetRecordsRequest); i {
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
		file_main_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetRecordsResponse); i {
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
		file_main_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateRecordsRequest); i {
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
		file_main_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateRecordsResponse); i {
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
		file_main_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Record); i {
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
		file_main_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RepRange); i {
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
		file_main_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Set); i {
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
	file_main_proto_msgTypes[4].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_main_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_main_proto_goTypes,
		DependencyIndexes: file_main_proto_depIdxs,
		MessageInfos:      file_main_proto_msgTypes,
	}.Build()
	File_main_proto = out.File
	file_main_proto_rawDesc = nil
	file_main_proto_goTypes = nil
	file_main_proto_depIdxs = nil
}
