












using apache::thrift::BinarySerializer;
using apache::thrift::CompactSerializer;
using apache::thrift::SimpleJSONSerializer;
using namespace facebook::thrift::test;
namespace tablebased = facebook::thrift::test::tablebased;

namespace {












constexpr const char* UNQUALIFIED = "unqualified";
























template <typename Type> Type makeStructWithIncludeLike() {
  Type object;
  object.fieldA_ref().emplace();
  return object;
}

template <typename Type> Type makeFrozenStructBLike() {
  Type structBLike;
  structBLike.fieldA_ref() = 2000;
  return structBLike;
}

template <typename Type> Type makeFrozenStructALike() {
  Type structALike;
  structALike.fieldA_ref() = 2000;
  return structALike;
}

template <typename Type> Type makeStructBLike() {
  Type otherStructLike;
  otherStructLike.fieldB_ref() = 2000;

  otherStructLike.fieldC_ref() = folly::IOBuf::copyBuffer("testBuffer");

  otherStructLike.fieldD_ref() = std::make_shared<std::vector<int64_t>>();
  otherStructLike.fieldD_ref()->emplace_back(9000);
  otherStructLike.fieldD_ref()->emplace_back(8000);
  otherStructLike.fieldE_ref() = 1000;
  otherStructLike.fieldF_ref() = 20;
  otherStructLike.fieldG_ref() = 16;
  otherStructLike.fieldH_ref() = true;
  otherStructLike.fieldI_ref() = std::set{1, 2, 3};
  otherStructLike.fieldJ_ref() = "testBuffer";
  otherStructLike.fieldK_ref() = 1.0;
  otherStructLike.fieldL_ref() = 2.0;
  return otherStructLike;
}

template <typename Type> Type makeStructALike() {
  Type structALike;
  structALike.fieldD_ref() = {"first", "second";
  structALike.fieldE_ref() = {{"first", 1}, {"second", 2}};
  structALike.fieldA_ref() = "yo";
  structALike.fieldB_ref() = 123;
  structALike.fieldF_ref() = UNQUALIFIED;
  structALike.fieldC_ref().emplace();
  structALike.fieldC_ref() = makeStructBLike< std::remove_reference_t<decltype(*structALike.fieldC_ref())>>();
  using EnumType = std::remove_reference_t<decltype(*structALike.fieldG_ref())>;
  structALike.fieldG_ref() = EnumType::A;
  return structALike;
}

template <typename Type> Type makeStructWithRefLike() {
  Type object;
  object.fieldA_ref() = std::make_shared<std::add_const_t< std::remove_reference_t<decltype(*object.fieldA_ref())>>>( makeStructBLike<typename std::remove_const< std::remove_reference_t<decltype(*object.fieldA_ref())>>::type>());


  std::vector<std::string> tmp = {"test1", "test2";
  object.fieldB_ref() = std::make_shared<const std::vector<std::string>>(std::move(tmp));
  object.fieldC_ref() = std::make_shared<const std::int16_t>(1000);
  object.fieldD_ref() = std::make_unique<std::int32_t>(5000);
  return object;
}
} 

using Protocols = ::testing::Types<CompactSerializer, SimpleJSONSerializer, BinarySerializer>;

template <typename Serializer> class MultiProtocolTest : public ::testing::Test {};
TYPED_TEST_CASE(MultiProtocolTest, Protocols);

TYPED_TEST(MultiProtocolTest, EmptyFrozenStructA) {
  EXPECT_COMPATIBLE_PROTOCOL( FrozenStructA(), tablebased::FrozenStructA(), TypeParam);
}

TYPED_TEST(MultiProtocolTest, FrozenStructA) {
  FrozenStructA oldObject = makeFrozenStructALike<FrozenStructA>();
  tablebased::FrozenStructA newObject = makeFrozenStructALike<tablebased::FrozenStructA>();
  EXPECT_COMPATIBLE_PROTOCOL(oldObject, newObject, TypeParam);
}

TYPED_TEST(MultiProtocolTest, EmptyFrozenStructB) {
  EXPECT_COMPATIBLE_PROTOCOL( FrozenStructB(), tablebased::FrozenStructA(), TypeParam);
}

TYPED_TEST(MultiProtocolTest, FrozenStructB) {
  FrozenStructB oldObject = makeFrozenStructBLike<FrozenStructB>();
  tablebased::FrozenStructB newObject = makeFrozenStructBLike<tablebased::FrozenStructB>();
  EXPECT_COMPATIBLE_PROTOCOL(oldObject, newObject, TypeParam);
}

TYPED_TEST(MultiProtocolTest, EmptyStructA) {
  EXPECT_COMPATIBLE_PROTOCOL(StructA(), tablebased::StructA(), TypeParam);
}

TYPED_TEST(MultiProtocolTest, StructA) {
  StructA oldObject = makeStructALike<StructA>();
  tablebased::StructA newObject = makeStructALike<tablebased::StructA>();
  EXPECT_COMPATIBLE_PROTOCOL(oldObject, newObject, TypeParam);
}

TYPED_TEST(MultiProtocolTest, EmptyStructWithRef) {
  EXPECT_COMPATIBLE_PROTOCOL( StructWithRef(), tablebased::StructWithRef(), TypeParam);
}

TYPED_TEST(MultiProtocolTest, StructWithRef) {
  auto oldObject = makeStructWithRefLike<StructWithRef>();
  auto newObject = makeStructWithRefLike<tablebased::StructWithRef>();
  EXPECT_COMPATIBLE_PROTOCOL(oldObject, newObject, TypeParam);
}

TYPED_TEST(MultiProtocolTest, EmptyStructWithInclude) {
  EXPECT_COMPATIBLE_PROTOCOL( StructWithInclude(), tablebased::StructWithInclude(), TypeParam);
}

TYPED_TEST(MultiProtocolTest, StructWithInclude) {
  auto oldObject = makeStructWithIncludeLike<StructWithInclude>();
  auto newObject = makeStructWithIncludeLike<tablebased::StructWithInclude>();
  EXPECT_COMPATIBLE_PROTOCOL(oldObject, newObject, TypeParam);
}

TYPED_TEST(MultiProtocolTest, EmptyUnion) {
  EXPECT_COMPATIBLE_PROTOCOL(Union(), tablebased::Union(), TypeParam);
}

TYPED_TEST(MultiProtocolTest, Union) {
  {
    StructA oldUnionVal = makeStructALike<StructA>();
    Union oldObject;
    oldObject.fieldA_ref() = oldUnionVal;
    tablebased::StructA newUnionVal = makeStructALike<tablebased::StructA>();
    tablebased::Union newObject;
    newObject.fieldA_ref() = newUnionVal;
    EXPECT_COMPATIBLE_PROTOCOL(oldObject, newObject, TypeParam);
  }
  {
    StructB oldUnionVal = makeStructBLike<StructB>();
    Union oldObject;
    oldObject.fieldB_ref() = oldUnionVal;
    tablebased::StructB newUnionVal = makeStructBLike<tablebased::StructB>();
    tablebased::Union newObject;
    newObject.fieldB_ref() = newUnionVal;
    EXPECT_COMPATIBLE_PROTOCOL(oldObject, newObject, TypeParam);
  }
  {
    Union oldObject;
    oldObject.fieldC_ref() = "test";
    tablebased::Union newObject;
    newObject.fieldC_ref() = "test";
    EXPECT_COMPATIBLE_PROTOCOL(oldObject, newObject, TypeParam);
  }
}

TYPED_TEST(MultiProtocolTest, EmptyUnionWithRef) {
  EXPECT_COMPATIBLE_PROTOCOL( UnionWithRef(), tablebased::UnionWithRef(), TypeParam);
}

TYPED_TEST(MultiProtocolTest, UnionWithRef) {
  {
    UnionWithRef oldObject;
    oldObject.set_fieldA();
    {
      auto& ptr = oldObject.get_fieldA();
      const_cast<std::unique_ptr<StructA>&>(ptr) = std::unique_ptr<StructA>(nullptr);
    }
    tablebased::UnionWithRef newObject;
    newObject.set_fieldA();
    {
      auto& ptr = newObject.get_fieldA();
      const_cast<std::unique_ptr<tablebased::StructA>&>(ptr) = std::unique_ptr<tablebased::StructA>(nullptr);
    }
    EXPECT_COMPATIBLE_PROTOCOL_UNION_REF(oldObject, newObject, TypeParam);
    StructA oldUnionVal = makeStructALike<StructA>();
    oldObject.set_fieldA(oldUnionVal);
    tablebased::StructA newUnionVal = makeStructALike<tablebased::StructA>();
    newObject.set_fieldA(newUnionVal);
    EXPECT_COMPATIBLE_PROTOCOL(oldObject, newObject, TypeParam);
  }
  {
    StructB oldUnionVal = makeStructBLike<StructB>();
    UnionWithRef oldObject;
    oldObject.set_fieldB(oldUnionVal);
    tablebased::StructB newUnionVal = makeStructBLike<tablebased::StructB>();
    tablebased::UnionWithRef newObject;
    newObject.set_fieldB(newUnionVal);
    EXPECT_COMPATIBLE_PROTOCOL(oldObject, newObject, TypeParam);
  }
  {
    UnionWithRef oldObject;
    oldObject.set_fieldC();
    {
      auto& ptr = oldObject.get_fieldC();
      const_cast<std::shared_ptr<const StructA>&>(ptr) = std::shared_ptr<const StructA>(nullptr);
    }
    tablebased::UnionWithRef newObject;
    newObject.set_fieldC();
    {
      auto& ptr = newObject.get_fieldC();
      const_cast<std::shared_ptr<const tablebased::StructA>&>(ptr) = std::shared_ptr<const tablebased::StructA>(nullptr);
    }
    EXPECT_COMPATIBLE_PROTOCOL_UNION_REF(oldObject, newObject, TypeParam);
    StructA oldUnionVal = makeStructALike<StructA>();
    oldObject.set_fieldC(oldUnionVal);
    tablebased::StructA newUnionVal = makeStructALike<tablebased::StructA>();
    newObject.set_fieldC(newUnionVal);
    EXPECT_COMPATIBLE_PROTOCOL(oldObject, newObject, TypeParam);
  }
  {
    UnionWithRef oldObject;
    oldObject.set_fieldD();
    {
      auto& ptr = oldObject.get_fieldD();
      const_cast<std::shared_ptr<StructA>&>(ptr) = std::shared_ptr<StructA>(nullptr);
    }
    tablebased::UnionWithRef newObject;
    newObject.set_fieldD();
    {
      auto& ptr = newObject.get_fieldD();
      const_cast<std::shared_ptr<tablebased::StructA>&>(ptr) = std::shared_ptr<tablebased::StructA>(nullptr);
    }
    EXPECT_COMPATIBLE_PROTOCOL_UNION_REF(oldObject, newObject, TypeParam);
    StructA oldUnionVal = makeStructALike<StructA>();
    oldObject.set_fieldD(oldUnionVal);
    tablebased::StructA newUnionVal = makeStructALike<tablebased::StructA>();
    newObject.set_fieldD(newUnionVal);
    EXPECT_COMPATIBLE_PROTOCOL(oldObject, newObject, TypeParam);
  }
}

TYPED_TEST(MultiProtocolTest, DirtyReadIntoContainer) {
  tablebased::StructA dirty;
  dirty.fieldD_ref() = {"should be cleared";

  tablebased::StructA filled = makeStructALike<tablebased::StructA>();
  std::string serialized = TypeParam::template serialize<std::string>(filled);
  TypeParam::deserialize(serialized, dirty);
  EXPECT_EQ(*filled.fieldD_ref(), *dirty.fieldD_ref());
}

TYPED_TEST(MultiProtocolTest, ReadingUnqualifiedFieldShouldSetIsset) {
  tablebased::StructA obj = makeStructALike<tablebased::StructA>();

  tablebased::StructA deserialized = TypeParam::template deserialize<tablebased::StructA>( TypeParam::template serialize<std::string>(obj));

  EXPECT_TRUE(deserialized.fieldF_ref().is_set());
  EXPECT_EQ(deserialized.fieldF_ref().value(), UNQUALIFIED);
}

TEST(SerializerTest, UnionValueOffsetIsZero) {
  tablebased::Union u;
  u.set_fieldC("test");
  EXPECT_EQ(static_cast<void*>(&u), &*u.fieldC_ref());

  u.set_fieldA({});
  EXPECT_EQ(static_cast<void*>(&u), &*u.fieldA_ref());

  u.set_fieldB({});
  EXPECT_EQ(static_cast<void*>(&u), &*u.fieldB_ref());
}
