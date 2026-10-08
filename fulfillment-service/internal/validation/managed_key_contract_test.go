/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package validation

import (
	"time"

	"buf.build/go/protovalidate"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
	publicv1 "github.com/osac-project/osac/proto/gen/osac/public/v1"
)

var _ = Describe("ManagedKey contract", func() {
	var validator protovalidate.Validator

	BeforeEach(func() {
		var err error
		validator, err = protovalidate.New()
		Expect(err).ToNot(HaveOccurred())
	})

	It("accepts identities without confirmed material in both APIs", func() {
		Expect(validator.Validate(&privatev1.ManagedKey{})).To(Succeed())
		Expect(validator.Validate(&publicv1.ManagedKey{})).To(Succeed())
	})

	DescribeTable("validates material generations in both APIs",
		func(generation uint64, created *timestamppb.Timestamp, valid bool) {
			objects := []proto.Message{
				privatev1.ManagedKeyVersion_builder{Generation: generation, CreationTimestamp: created}.Build(),
				publicv1.ManagedKeyVersion_builder{Generation: generation, CreationTimestamp: created}.Build(),
			}
			for _, object := range objects {
				if valid {
					Expect(validator.Validate(object)).To(Succeed())
				} else {
					Expect(validator.Validate(object)).To(HaveOccurred())
				}
			}
		},
		Entry("confirmed generation", uint64(1), timestamppb.New(time.Unix(1, 0)), true),
		Entry("backend-neutral generation", uint64(5), timestamppb.New(time.Unix(1, 0)), true),
		Entry("zero generation", uint64(0), timestamppb.New(time.Unix(1, 0)), false),
		Entry("missing creation timestamp", uint64(1), (*timestamppb.Timestamp)(nil), false),
	)

	It("rejects undefined usage, state, and backend values", func() {
		for _, object := range []proto.Message{
			privatev1.ManagedKey_builder{Usage: privatev1.ManagedKeyUsage(99)}.Build(),
			publicv1.ManagedKey_builder{Usage: publicv1.ManagedKeyUsage(99)}.Build(),
			privatev1.ManagedKey_builder{State: privatev1.ManagedKeyState(99)}.Build(),
			publicv1.ManagedKey_builder{State: publicv1.ManagedKeyState(99)}.Build(),
			privatev1.ManagedKey_builder{Backend: privatev1.KeyBackend(99)}.Build(),
		} {
			Expect(validator.Validate(object)).To(HaveOccurred())
		}
	})

	It("exposes lifecycle metadata without backend coordinates or key material", func() {
		key := (&publicv1.ManagedKey{}).ProtoReflect().Descriptor()
		for _, field := range []protoreflect.Name{
			"id", "metadata", "usage", "state", "versions", "revocation_timestamp", "last_rotation_timestamp",
		} {
			Expect(key.Fields().ByName(field)).ToNot(BeNil())
		}
		for _, field := range []protoreflect.Name{"backend", "action_request", "active_version", "data"} {
			Expect(key.Fields().ByName(field)).To(BeNil())
		}
		version := key.Fields().ByName("versions").Message()
		Expect(version.Fields().Len()).To(Equal(2))
		Expect(version.Fields().ByName("generation")).ToNot(BeNil())
		Expect(version.Fields().ByName("creation_timestamp")).ToNot(BeNil())
		Expect(version.Fields().ByName("backend_object_id")).To(BeNil())
		Expect(version.Fields().ByName("backend_version_id")).To(BeNil())

		privateKey := (&privatev1.ManagedKey{}).ProtoReflect().Descriptor()
		Expect(privateKey.Fields().ByName("backend")).ToNot(BeNil())
		privateVersion := privateKey.Fields().ByName("versions").Message()
		Expect(privateVersion.Fields().ByName("backend_object_id")).ToNot(BeNil())
		Expect(privateVersion.Fields().ByName("backend_version_id")).ToNot(BeNil())
		for _, descriptor := range []protoreflect.MessageDescriptor{key, version, privateKey, privateVersion} {
			for i := 0; i < descriptor.Fields().Len(); i++ {
				Expect(descriptor.Fields().Get(i).Kind()).ToNot(Equal(protoreflect.BytesKind))
			}
		}

		event := (&publicv1.Event{}).ProtoReflect().Descriptor().Fields().ByName("managed_key")
		Expect(event).ToNot(BeNil())
		Expect(event.Message().FullName()).To(Equal(key.FullName()))
	})

	It("defines generation-independent ID/name references in both APIs", func() {
		for _, reference := range []proto.Message{&privatev1.ManagedKeyLocalReference{}, &publicv1.ManagedKeyLocalReference{}} {
			fields := reference.ProtoReflect().Descriptor().Fields()
			Expect(fields.Len()).To(Equal(2))
			Expect(fields.ByName("id").Kind()).To(Equal(protoreflect.StringKind))
			Expect(fields.ByName("name").Kind()).To(Equal(protoreflect.StringKind))
		}
	})

	It("keeps Signal private and leaves lifecycle actions outside the CRUD contract", func() {
		publicMethods := publicv1.File_osac_public_v1_managed_keys_service_proto.Services().ByName("ManagedKeys").Methods()
		for _, name := range []protoreflect.Name{"Create", "List", "Get", "Update", "Delete"} {
			Expect(publicMethods.ByName(name)).ToNot(BeNil())
		}
		for _, name := range []protoreflect.Name{"Signal", "Rotate", "Revoke", "Recover", "Encrypt", "Decrypt"} {
			Expect(publicMethods.ByName(name)).To(BeNil())
		}
		privateMethods := privatev1.File_osac_private_v1_managed_keys_service_proto.Services().ByName("ManagedKeys").Methods()
		Expect(privateMethods.ByName("Signal")).ToNot(BeNil())
	})
})
