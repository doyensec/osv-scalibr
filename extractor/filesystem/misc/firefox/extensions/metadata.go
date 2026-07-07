// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package extensions

import (
	"github.com/google/osv-scalibr/binary/proto/metadata"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadata.Register(ToStruct, ToProto)
}

// Metadata contains metadata for Firefox extensions.
type Metadata struct {
	Name         string
	Description  string
	Creator      string
	HomepageURL  string
	Type         string
	Location     string
	SourceURI    string
	InstallDate  int64
	UpdateDate   int64
	SignedState  int64
	Active       bool
	UserDisabled bool
	AppDisabled  bool
}

// ToProto converts the Metadata struct to a FirefoxExtensionsMetadata proto.
func ToProto(m *Metadata) *pb.FirefoxExtensionsMetadata {
	return &pb.FirefoxExtensionsMetadata{
		Name:         m.Name,
		Description:  m.Description,
		Creator:      m.Creator,
		HomepageUrl:  m.HomepageURL,
		Type:         m.Type,
		Location:     m.Location,
		SourceUri:    m.SourceURI,
		InstallDate:  m.InstallDate,
		UpdateDate:   m.UpdateDate,
		SignedState:  m.SignedState,
		Active:       m.Active,
		UserDisabled: m.UserDisabled,
		AppDisabled:  m.AppDisabled,
	}
}

// IsProtoable marks the struct as a metadata type.
func (m *Metadata) IsProtoable() {}

// ToStruct converts the FirefoxExtensionsMetadata proto to a Metadata struct.
func ToStruct(m *pb.FirefoxExtensionsMetadata) *Metadata {
	return &Metadata{
		Name:         m.GetName(),
		Description:  m.GetDescription(),
		Creator:      m.GetCreator(),
		HomepageURL:  m.GetHomepageUrl(),
		Type:         m.GetType(),
		Location:     m.GetLocation(),
		SourceURI:    m.GetSourceUri(),
		InstallDate:  m.GetInstallDate(),
		UpdateDate:   m.GetUpdateDate(),
		SignedState:  m.GetSignedState(),
		Active:       m.GetActive(),
		UserDisabled: m.GetUserDisabled(),
		AppDisabled:  m.GetAppDisabled(),
	}
}
