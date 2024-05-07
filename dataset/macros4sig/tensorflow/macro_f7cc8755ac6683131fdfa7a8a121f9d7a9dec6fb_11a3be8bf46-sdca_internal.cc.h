


#include<new>

#include<stddef.h>
#include<utility>





#include<memory>


#include<type_traits>







#include<stdint.h>
#include<algorithm>











#include<unordered_map>



#include<ostream>


#include<sstream>

#include<array>




#include<functional>



#include<set>





#include<condition_variable>


#include<cstdint>
#include<complex>




#include<random>


#include<unordered_set>



#include<limits>





#include<vector>

#include<initializer_list>



#include<sys/time.h>
#include<atomic>









#include<stdarg.h>
#include<assert.h>



#include<map>
#include<limits.h>


#include<cmath>




#include<stdlib.h>


#include<chrono>

#include<cstddef>

#include<iterator>
#include<mutex>
#include<string>



#include<iosfwd>









#include<string.h>
#include<numeric>

#include<math.h>








#define REGISTER_DIRECT_COL_MAJOR_ACCESS(TENSOR_EXPR)                          \
  template <typename Scalar, typename StorageIndex, int Side, typename Device, \
            typename nocontract_t, typename contract_t, int packet_size,       \
            int Alignment>                                                     \
  struct DirectColMajorAccess<TensorContractionInputMapper<                    \
      Scalar, StorageIndex, Side, TensorEvaluator<TENSOR_EXPR, Device>,        \
      nocontract_t, contract_t, packet_size, true,    \
      false, Alignment>> {                             \
    enum { value = true };                                                     \
                                                                               \
    using DataMapper = TensorContractionInputMapper<                           \
        Scalar, StorageIndex, Side, TensorEvaluator<TENSOR_EXPR, Device>,      \
        nocontract_t, contract_t, packet_size, true,  \
        false, Alignment>;                             \
                                                                               \
    static bool block(const typename DataMapper::SubMapper& data_mapper,       \
                      const StorageIndex rows, const StorageIndex cols,        \
                      const StorageIndex num_kernels,                          \
                      ColMajorBlock<Scalar, StorageIndex>* block) {            \
      static_assert(DataMapper::DirectOffsets == true,                         \
                    "DataMapper must support direct offsets");                 \
                                                                               \
      const StorageIndex vert_offset = data_mapper.vert_offset();              \
      const StorageIndex horiz_offset = data_mapper.horiz_offset();            \
      const StorageIndex stride =                                              \
          Side == Lhs ? data_mapper.base_mapper().stride()                     \
                      : data_mapper.base_mapper().nocontract_strides()[0];     \
      const Scalar* data = data_mapper.base_mapper().tensor().data();          \
      data = Side == Lhs ? data : data + vert_offset + horiz_offset * stride;  \
                                                                               \
      const bool is_no_op_packing = stride == rows;                            \
      const StorageIndex addressable_mem = (stride * cols * sizeof(Scalar));   \
      const bool use_direct_access =                                           \
          is_no_op_packing || num_kernels == 1  ||              \
          ((num_kernels == 2) &&                                               \
           (addressable_mem < (256 << 10) ));                      \
                                                                               \
      if (use_direct_access) {                                                 \
        block->is_direct_access = true;                                        \
        block->raw_data = const_cast<Scalar*>(data);                           \
        block->stride = stride;                                                \
        block->transpose = 'N';                                                \
        return true;                                                           \
      }                                                                        \
      return false;                                                            \
    }                                                                          \
  }
#define REGISTER_TENSOR_CONTRACTION_KERNEL_NO_FALLBACK(RES_SCALAR, LHS_SCALAR, \
                                                       RHS_SCALAR)             \
                                                                               \
  template <typename StorageIndex, typename OutputMapper, typename LhsMapper,  \
            typename RhsMapper>                                                \
  struct TensorContractionKernel<RES_SCALAR, LHS_SCALAR, RHS_SCALAR,           \
                                 StorageIndex, OutputMapper, LhsMapper,        \
                                 RhsMapper> {                                  \
    TensorContractionKernel(StorageIndex m, StorageIndex k, StorageIndex n,    \
                            StorageIndex bm, StorageIndex bk, StorageIndex bn) \
        : m(m), k(k), n(n), bm(bm), bk(bk), bn(bn) {}                          \
                                                                               \
    enum { HasBeta = true };                                                   \
                                                                               \
    using ResScalar = RES_SCALAR;                                              \
    using LhsScalar = LHS_SCALAR;                                              \
    using RhsScalar = RHS_SCALAR;                                              \
                                                                               \
    using Traits = typename internal::gebp_traits<LhsScalar, RhsScalar>;       \
                                                                               \
    using LhsBlock = ColMajorBlock<LhsScalar, StorageIndex>;                   \
    using RhsBlock = ColMajorBlock<RhsScalar, StorageIndex>;                   \
                                                                               \
    using DirectLhsAccess = DirectColMajorAccess<LhsMapper>;                   \
    using DirectRhsAccess = DirectColMajorAccess<RhsMapper>;                   \
                                                                               \
                                    \
    typedef TensorContractionBlockMemAllocator<LhsScalar, RhsScalar>           \
        BlockMemAllocator;                                                     \
    typedef typename BlockMemAllocator::BlockMemHandle BlockMemHandle;         \
                                                                               \
    using LhsPacker =                                                          \
        gemm_pack_colmajor_block<LhsScalar, StorageIndex,                      \
                                 typename LhsMapper::SubMapper, ColMajor>;     \
    using RhsPacker =                                                          \
        gemm_pack_colmajor_block<RhsScalar, StorageIndex,                      \
                                 typename RhsMapper::SubMapper, ColMajor>;     \
                                                                               \
    using GemmKernelProviderType =                                             \
        GemmKernelProvider<ResScalar, LhsScalar, RhsScalar, StorageIndex,      \
                           OutputMapper>;                                      \
    static_assert(                                                             \
        GemmKernelProviderType::Defined,                                       \
        "Custom GEMM kernel is not registered for given scalar types");        \
    using GemmKernel = typename GemmKernelProviderType::GemmKernel;            \
                                                                               \
    template <typename Device>                                                 \
    EIGEN_DEVICE_FUNC BlockMemHandle allocate(Device& d, LhsBlock* lhs_block,  \
                                              RhsBlock* rhs_block) {           \
      return BlockMemAllocator::allocate(                                      \
          d, bm, bk, bn, &lhs_block->packed_data, &rhs_block->packed_data);    \
    }                                                                          \
                                                                               \
    template <typename Device>                                                 \
    EIGEN_DEVICE_FUNC BlockMemHandle                                           \
    allocateSlices(Device& d, const int num_lhs, const int num_rhs,            \
                   const int num_slices, std::vector<LhsBlock>* lhs_blocks,    \
                   std::vector<RhsBlock>* rhs_blocks) {                        \
      eigen_assert(num_slices > 0);                                            \
      std::vector<std::vector<LhsScalar*>> lhs_mem(num_slices);                \
      std::vector<std::vector<RhsScalar*>> rhs_mem(num_slices);                \
                                                                               \
      BlockMemHandle block_mem = BlockMemAllocator::allocateSlices(            \
          d, bm, bk, bn, num_lhs, num_rhs, num_slices, lhs_mem.data(),         \
          rhs_mem.data());                                                     \
                                                                               \
      for (Index x = 0; x < num_slices; x++) {                                 \
        if (num_lhs > 0) lhs_blocks[x].resize(num_lhs);                        \
        for (Index m = 0; m < num_lhs; m++) {                                  \
          lhs_blocks[x][m].packed_data = lhs_mem[x][m];                        \
        }                                                                      \
        if (num_rhs > 0) rhs_blocks[x].resize(num_rhs);                        \
        for (Index n = 0; n < num_rhs; n++) {                                  \
          rhs_blocks[x][n].packed_data = rhs_mem[x][n];                        \
        }                                                                      \
      }                                                                        \
                                                                               \
      return block_mem;                                                        \
    }                                                                          \
                                                                               \
    template <typename Device>                                                 \
    EIGEN_DEVICE_FUNC static void deallocate(Device& d,                        \
                                             BlockMemHandle handle) {          \
      BlockMemAllocator::deallocate(d, handle);                                \
    }                                                                          \
                                                                               \
    EIGEN_DEVICE_FUNC EIGEN_DONT_INLINE void packLhs(                          \
        LhsBlock* lhsBlock, const typename LhsMapper::SubMapper& data_mapper,  \
        const StorageIndex depth, const StorageIndex rows) {                   \
      const bool is_direct_access =                                            \
          DirectLhsAccess::value &&                                            \
          DirectLhsAccess::block(data_mapper, rows, depth,                     \
                                 bn > 0 ? divup(n, bn) : 0, lhsBlock);         \
                                                                               \
      if (!is_direct_access) {                                                 \
        lhsBlock->is_direct_access = false;                                    \
        LhsPacker()(lhsBlock->packed_data, data_mapper, rows, depth);          \
      }                                                                        \
    }                                                                          \
                                                                               \
    EIGEN_DEVICE_FUNC EIGEN_DONT_INLINE void packRhs(                          \
        RhsBlock* rhsBlock, const typename RhsMapper::SubMapper& data_mapper,  \
        const StorageIndex depth, const StorageIndex cols) {                   \
      const bool is_direct_access =                                            \
          DirectRhsAccess::value &&                                            \
          DirectRhsAccess::block(data_mapper, depth, cols,                     \
                                 bm > 0 ? divup(m, bm) : 0, rhsBlock);         \
                                                                               \
      if (!is_direct_access) {                                                 \
        rhsBlock->is_direct_access = false;                                    \
        RhsPacker()(rhsBlock->packed_data, data_mapper, depth, cols);          \
      }                                                                        \
    }                                                                          \
                                                                               \
    EIGEN_DEVICE_FUNC EIGEN_DONT_INLINE void invoke(                           \
        const OutputMapper& output_mapper, const LhsBlock& lhsBlock,           \
        const RhsBlock& rhsBlock, const StorageIndex rows,                     \
        const StorageIndex depth, const StorageIndex cols, const float alpha,  \
        const float beta) {                                                    \
      if ((DirectLhsAccess::value && lhsBlock.is_direct_access) &&             \
          (DirectRhsAccess::value && rhsBlock.is_direct_access)) {             \
        GemmKernel()(output_mapper, lhsBlock.raw_data, rhsBlock.raw_data,      \
                     rows, depth, cols, alpha, beta, lhsBlock.stride,  \
                     rhsBlock.stride,                                  \
                     lhsBlock.transpose,                        \
                     rhsBlock.transpose);                       \
                                                                               \
      } else if (DirectLhsAccess::value && lhsBlock.is_direct_access) {        \
        GemmKernel()(output_mapper, lhsBlock.raw_data, rhsBlock.packed_data,   \
                     rows, depth, cols, alpha, beta, lhsBlock.stride,  \
                     GemmKernel::kComputeStrideFromBlockDimensions,    \
                     lhsBlock.transpose, 'N');   \
                                                                               \
      } else if (DirectRhsAccess::value && rhsBlock.is_direct_access) {        \
        GemmKernel()(output_mapper, lhsBlock.packed_data, rhsBlock.raw_data,   \
                     rows, depth, cols, alpha, beta,                           \
                     GemmKernel::kComputeStrideFromBlockDimensions,    \
                     rhsBlock.stride, 'N',              \
                     rhsBlock.transpose);                       \
                                                                               \
      } else {                                                                 \
        GemmKernel()(output_mapper, lhsBlock.packed_data,                      \
                     rhsBlock.packed_data, rows, depth, cols, alpha, beta);    \
      }                                                                        \
    }                                                                          \
                                                                               \
   private:                                                                    \
     \
     \
     \
    const StorageIndex m;                                                      \
    const StorageIndex k;                                                      \
    const StorageIndex n;                                                      \
    const StorageIndex bm;                                                     \
    const StorageIndex bk;                                                     \
    const StorageIndex bn;                                                     \
  }
#define REGISTER_TENSOR_CONTRACTION_KERNEL_WITH_FALLBACK(                      \
    RES_SCALAR, LHS_SCALAR, RHS_SCALAR)                                        \
                                                                               \
  template <typename StorageIndex, typename OutputMapper, typename LhsMapper,  \
            typename RhsMapper>                                                \
  struct TensorContractionKernel<RES_SCALAR, LHS_SCALAR, RHS_SCALAR,           \
                                 StorageIndex, OutputMapper, LhsMapper,        \
                                 RhsMapper> {                                  \
    TensorContractionKernel(StorageIndex m, StorageIndex k, StorageIndex n,    \
                            StorageIndex bm, StorageIndex bk, StorageIndex bn) \
        : m(m), k(k), n(n), bm(bm), bk(bk), bn(bn) {}                          \
                                                                               \
    enum { HasBeta = true };                                                   \
                                                                               \
    using ResScalar = RES_SCALAR;                                              \
    using LhsScalar = LHS_SCALAR;                                              \
    using RhsScalar = RHS_SCALAR;                                              \
                                                                               \
    using Traits = typename internal::gebp_traits<LhsScalar, RhsScalar>;       \
                                                                               \
    using LhsBlock = ColMajorBlock<LhsScalar, StorageIndex>;                   \
    using RhsBlock = ColMajorBlock<RhsScalar, StorageIndex>;                   \
                                                                               \
    using DirectLhsAccess = DirectColMajorAccess<LhsMapper>;                   \
    using DirectRhsAccess = DirectColMajorAccess<RhsMapper>;                   \
                                                                               \
                                    \
    typedef TensorContractionBlockMemAllocator<LhsScalar, RhsScalar>           \
        BlockMemAllocator;                                                     \
    typedef typename BlockMemAllocator::BlockMemHandle BlockMemHandle;         \
                                                                               \
    using LhsPacker =                                                          \
        gemm_pack_colmajor_block<LhsScalar, StorageIndex,                      \
                                 typename LhsMapper::SubMapper, ColMajor>;     \
    using RhsPacker =                                                          \
        gemm_pack_colmajor_block<RhsScalar, StorageIndex,                      \
                                 typename RhsMapper::SubMapper, ColMajor>;     \
                                                                               \
    using GemmKernelProviderType =                                             \
        GemmKernelProvider<ResScalar, LhsScalar, RhsScalar, StorageIndex,      \
                           OutputMapper>;                                      \
    static_assert(                                                             \
        GemmKernelProviderType::Defined,                                       \
        "Custom GEMM kernel is not registered for given scalar types");        \
    using GemmKernel = typename GemmKernelProviderType::GemmKernel;            \
                                                                               \
     \
     \
    using EigenLhsPacker =                                                     \
        gemm_pack_lhs<LhsScalar, StorageIndex, typename LhsMapper::SubMapper,  \
                      Traits::mr, Traits::LhsProgress,                         \
                      typename Traits::LhsPacket4Packing, ColMajor>;           \
    using EigenRhsPacker =                                                     \
        gemm_pack_rhs<RhsScalar, StorageIndex, typename RhsMapper::SubMapper,  \
                      Traits::nr, ColMajor>;                                   \
    using GebpKernel =                                                         \
        gebp_kernel<LhsScalar, RhsScalar, StorageIndex, OutputMapper,          \
                    Traits::mr, Traits::nr,  false,            \
                     false>;                                   \
                                                                               \
    template <typename Device>                                                 \
    EIGEN_DEVICE_FUNC BlockMemHandle allocate(Device& d, LhsBlock* lhs_block,  \
                                              RhsBlock* rhs_block) {           \
      return BlockMemAllocator::allocate(                                      \
          d, bm, bk, bn, &lhs_block->packed_data, &rhs_block->packed_data);    \
    }                                                                          \
                                                                               \
    template <typename Device>                                                 \
    EIGEN_DEVICE_FUNC BlockMemHandle                                           \
    allocateSlices(Device& d, const int num_lhs, const int num_rhs,            \
                   const int num_slices, std::vector<LhsBlock>* lhs_blocks,    \
                   std::vector<RhsBlock>* rhs_blocks) {                        \
      eigen_assert(num_slices > 0);                                            \
      std::vector<std::vector<LhsScalar*>> lhs_mem(num_slices);                \
      std::vector<std::vector<RhsScalar*>> rhs_mem(num_slices);                \
                                                                               \
      BlockMemHandle block_mem = BlockMemAllocator::allocateSlices(            \
          d, bm, bk, bn, num_lhs, num_rhs, num_slices, lhs_mem.data(),         \
          rhs_mem.data());                                                     \
                                                                               \
      for (Index x = 0; x < num_slices; x++) {                                 \
        if (num_lhs > 0) lhs_blocks[x].resize(num_lhs);                        \
        for (Index m = 0; m < num_lhs; m++) {                                  \
          lhs_blocks[x][m].packed_data = lhs_mem[x][m];                        \
        }                                                                      \
        if (num_rhs > 0) rhs_blocks[x].resize(num_rhs);                        \
        for (Index n = 0; n < num_rhs; n++) {                                  \
          rhs_blocks[x][n].packed_data = rhs_mem[x][n];                        \
        }                                                                      \
      }                                                                        \
                                                                               \
      return block_mem;                                                        \
    }                                                                          \
                                                                               \
    template <typename Device>                                                 \
    EIGEN_DEVICE_FUNC static void deallocate(Device& d,                        \
                                             BlockMemHandle handle) {          \
      BlockMemAllocator::deallocate(d, handle);                                \
    }                                                                          \
                                                                               \
    EIGEN_DEVICE_FUNC EIGEN_DONT_INLINE void packLhs(                          \
        LhsBlock* lhsBlock, const typename LhsMapper::SubMapper& data_mapper,  \
        const StorageIndex depth, const StorageIndex rows) {                   \
      if (UseCustomContractionKernels()) {                                     \
        const bool is_direct_access =                                          \
            DirectLhsAccess::value &&                                          \
            DirectLhsAccess::block(data_mapper, rows, depth,                   \
                                   bn > 0 ? divup(n, bn) : 0, lhsBlock);       \
                                                                               \
        if (!is_direct_access) {                                               \
          lhsBlock->is_direct_access = false;                                  \
          LhsPacker()(lhsBlock->packed_data, data_mapper, rows, depth);        \
        }                                                                      \
      } else {                                                                 \
        lhsBlock->is_direct_access = false;                                    \
        EigenLhsPacker()(lhsBlock->packed_data, data_mapper, depth, rows,      \
                          0,  0);                          \
      }                                                                        \
    }                                                                          \
                                                                               \
    EIGEN_DEVICE_FUNC EIGEN_DONT_INLINE void packRhs(                          \
        RhsBlock* rhsBlock, const typename RhsMapper::SubMapper& data_mapper,  \
        const StorageIndex depth, const StorageIndex cols) {                   \
      if (UseCustomContractionKernels()) {                                     \
        const bool is_direct_access =                                          \
            DirectRhsAccess::value &&                                          \
            DirectRhsAccess::block(data_mapper, depth, cols,                   \
                                   bm > 0 ? divup(m, bm) : 0, rhsBlock);       \
                                                                               \
        if (!is_direct_access) {                                               \
          rhsBlock->is_direct_access = false;                                  \
          RhsPacker()(rhsBlock->packed_data, data_mapper, depth, cols);        \
        }                                                                      \
      } else {                                                                 \
        rhsBlock->is_direct_access = false;                                    \
        EigenRhsPacker()(rhsBlock->packed_data, data_mapper, depth, cols);     \
      }                                                                        \
    }                                                                          \
                                                                               \
    EIGEN_DEVICE_FUNC EIGEN_DONT_INLINE void invoke(                           \
        const OutputMapper& output_mapper, const LhsBlock& lhsBlock,           \
        const RhsBlock& rhsBlock, const StorageIndex rows,                     \
        const StorageIndex depth, const StorageIndex cols, const float alpha,  \
        const float beta) {                                                    \
      if (UseCustomContractionKernels()) {                                     \
        if ((DirectLhsAccess::value && lhsBlock.is_direct_access) &&           \
            (DirectRhsAccess::value && rhsBlock.is_direct_access)) {           \
          GemmKernel()(output_mapper, lhsBlock.raw_data, rhsBlock.raw_data,    \
                       rows, depth, cols, alpha, beta,                         \
                       lhsBlock.stride, rhsBlock.stride,       \
                       lhsBlock.transpose,                      \
                       rhsBlock.transpose);                     \
                                                                               \
        } else if (DirectLhsAccess::value && lhsBlock.is_direct_access) {      \
          GemmKernel()(output_mapper, lhsBlock.raw_data, rhsBlock.packed_data, \
                       rows, depth, cols, alpha, beta,                         \
                       lhsBlock.stride,                                \
                       GemmKernel::kComputeStrideFromBlockDimensions,  \
                       lhsBlock.transpose, 'N'); \
                                                                               \
        } else if (DirectRhsAccess::value && rhsBlock.is_direct_access) {      \
          GemmKernel()(output_mapper, lhsBlock.packed_data, rhsBlock.raw_data, \
                       rows, depth, cols, alpha, beta,                         \
                       GemmKernel::kComputeStrideFromBlockDimensions,  \
                       rhsBlock.stride, 'N',            \
                       rhsBlock.transpose);                     \
                                                                               \
        } else {                                                               \
          GemmKernel()(output_mapper, lhsBlock.packed_data,                    \
                       rhsBlock.packed_data, rows, depth, cols, alpha, beta);  \
        }                                                                      \
      } else {                                                                 \
         \
         \
         \
         \
         \
        if (beta == 0.0) {                                                     \
          for (StorageIndex col = 0; col < cols; ++col) {                      \
            ResScalar* output_base = &output_mapper(0, col);                   \
            typedef Array<ResScalar, Dynamic, 1> OutputRow;                    \
            typedef Map<OutputRow, 0, InnerStride<1>> OutputRowMap;            \
            OutputRowMap(output_base, rows).setZero();                         \
          }                                                                    \
        }                                                                      \
                                                                               \
        GebpKernel()(                                                          \
            output_mapper, lhsBlock.packed_data, rhsBlock.packed_data, rows,   \
            depth, cols, alpha,                                                \
             GemmKernel::kComputeStrideFromBlockDimensions,         \
             GemmKernel::kComputeStrideFromBlockDimensions,         \
             0,  0);                                     \
      }                                                                        \
    }                                                                          \
                                                                               \
   private:                                                                    \
     \
     \
     \
    const StorageIndex m;                                                      \
    const StorageIndex k;                                                      \
    const StorageIndex n;                                                      \
    const StorageIndex bm;                                                     \
    const StorageIndex bk;                                                     \
    const StorageIndex bn;                                                     \
  }
#define SIMPLE_TENSOR const Tensor<Scalar, 2, Eigen::ColMajor, StorageIndex>

#define TENSOR_MAP_COLMAJOR                                               \
  const TensorMap<Tensor<const Scalar, 2, Eigen::ColMajor, StorageIndex>, \
                  Eigen::Aligned>
#define TENSOR_MAP_CONST_COLMAJOR                                   \
  const TensorMap<Tensor<Scalar, 2, Eigen::ColMajor, StorageIndex>, \
                  Eigen::Aligned>
#define TENSOR_MAP_CONST_ROWMAJOR                                   \
  const TensorMap<Tensor<Scalar, 2, Eigen::RowMajor, StorageIndex>, \
                  Eigen::Aligned>
#define TENSOR_MAP_ROWMAJOR                                               \
  const TensorMap<Tensor<const Scalar, 2, Eigen::RowMajor, StorageIndex>, \
                  Eigen::Aligned>
#define TENSOR_RESHAPE                                                        \
  const TensorReshapingOp<                                                    \
      const Eigen::DSizes<StorageIndex, 2>,                                   \
      const TensorMap<Tensor<const Scalar, 4, Eigen::RowMajor, StorageIndex>, \
                      Eigen::Aligned>>


#define TF_ANNOTATE_BENIGN_RACE(ptr, description) \
  do {                                            \
  } while (0)
#define TF_ANNOTATE_MEMORY_IS_INITIALIZED(ptr, bytes) \
  do {                                                \
  } while (0)




















#define TF_TSTRING_LITTLE_ENDIAN 1
#define TF_le32toh(x) TF_swap32(x)


#define TF_CORD_SUPPORT 1


#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#define __ORDER_BIG_ENDIAN__ 0x10e1
#define __ORDER_LITTLE_ENDIAN__ 0x4d2
#define PHILOX_DEVICE_FUNC __host__ __device__
#define PHILOX_DEVICE_INLINE PHILOX_DEVICE_FUNC PHILOX_INLINE
#define PHILOX_INLINE __inline__



#define CHECK(condition)              \
  if (TF_PREDICT_FALSE(!(condition))) \
  LOG(FATAL) << "Check failed: " #condition " "
#define CHECK_EQ(val1, val2) CHECK_OP(Check_EQ, ==, val1, val2)
#define CHECK_GE(val1, val2) CHECK_OP(Check_GE, >=, val1, val2)
#define CHECK_GT(val1, val2) CHECK_OP(Check_GT, >, val1, val2)
#define CHECK_LE(val1, val2) CHECK_OP(Check_LE, <=, val1, val2)
#define CHECK_LT(val1, val2) CHECK_OP(Check_LT, <, val1, val2)
#define CHECK_NE(val1, val2) CHECK_OP(Check_NE, !=, val1, val2)
#define CHECK_NOTNULL(val)                                 \
  ::tensorflow::internal::CheckNotNull("__FILE__", "__LINE__", \
                                       "'" #val "' Must be non NULL", (val))
#define CHECK_OP(name, op, val1, val2) CHECK_OP_LOG(name, op, val1, val2)
#define CHECK_OP_LOG(name, op, val1, val2)                     \
  while (::tensorflow::internal::CheckOpString _result{        \
      ::tensorflow::internal::name##Impl(                      \
          ::tensorflow::internal::GetReferenceableValue(val1), \
          ::tensorflow::internal::GetReferenceableValue(val2), \
          #val1 " " #op " " #val2)})                           \
  ::tensorflow::internal::LogMessageFatal("__FILE__", "__LINE__") << *(_result.str_)
#define DCHECK(condition) CHECK(condition)
#define DCHECK_EQ(val1, val2) CHECK_EQ(val1, val2)
#define DCHECK_GE(val1, val2) CHECK_GE(val1, val2)
#define DCHECK_GT(val1, val2) CHECK_GT(val1, val2)
#define DCHECK_LE(val1, val2) CHECK_LE(val1, val2)
#define DCHECK_LT(val1, val2) CHECK_LT(val1, val2)
#define DCHECK_NE(val1, val2) CHECK_NE(val1, val2)
#define DVLOG VLOG
#define LOG(severity) _TF_LOG_##severity
#define LOGGING_INTERNAL_STATEFUL_CONDITION(kind, condition, arg)   \
  for (bool logging_internal_stateful_condition_do_log(condition);  \
       logging_internal_stateful_condition_do_log;                  \
       logging_internal_stateful_condition_do_log = false)          \
    for (static ::tensorflow::internal::Log##kind##State            \
             logging_internal_stateful_condition_state;             \
         logging_internal_stateful_condition_do_log &&              \
         logging_internal_stateful_condition_state.ShouldLog(arg);  \
         logging_internal_stateful_condition_do_log = false)        \
      for (const uint32_t COUNTER ABSL_ATTRIBUTE_UNUSED =           \
               logging_internal_stateful_condition_state.counter(); \
           logging_internal_stateful_condition_do_log;              \
           logging_internal_stateful_condition_do_log = false)
#define LOG_EVERY_N(severity, n)                       \
  LOGGING_INTERNAL_STATEFUL_CONDITION(EveryN, true, n) \
  LOG(severity)
#define LOG_EVERY_N_SEC(severity, n_seconds)                      \
  LOGGING_INTERNAL_STATEFUL_CONDITION(EveryNSec, true, n_seconds) \
  LOG(severity)
#define LOG_EVERY_POW_2(severity)                         \
  LOGGING_INTERNAL_STATEFUL_CONDITION(EveryPow2, true, 0) \
  LOG(severity)
#define LOG_FIRST_N(severity, n)                       \
  LOGGING_INTERNAL_STATEFUL_CONDITION(FirstN, true, n) \
  LOG(severity)
#define QCHECK(condition) CHECK(condition)
#define QCHECK_EQ(x, y) CHECK_EQ(x, y)
#define QCHECK_GE(x, y) CHECK_GE(x, y)
#define QCHECK_GT(x, y) CHECK_GT(x, y)
#define QCHECK_LE(x, y) CHECK_LE(x, y)
#define QCHECK_LT(x, y) CHECK_LT(x, y)
#define QCHECK_NE(x, y) CHECK_NE(x, y)

#define TF_DEFINE_CHECK_OP_IMPL(name, op)                                 \
  template <typename T1, typename T2>                                     \
  inline string* name##Impl(const T1& v1, const T2& v2,                   \
                            const char* exprtext) {                       \
    if (TF_PREDICT_TRUE(v1 op v2))                                        \
      return NULL;                                                        \
    else                                                                  \
      return ::tensorflow::internal::MakeCheckOpString(v1, v2, exprtext); \
  }                                                                       \
  inline string* name##Impl(int v1, int v2, const char* exprtext) {       \
    return name##Impl<int, int>(v1, v2, exprtext);                        \
  }                                                                       \
  inline string* name##Impl(const size_t v1, const int v2,                \
                            const char* exprtext) {                       \
    if (TF_PREDICT_FALSE(v2 < 0)) {                                       \
      return ::tensorflow::internal::MakeCheckOpString(v1, v2, exprtext); \
    }                                                                     \
    return name##Impl<size_t, size_t>(v1, v2, exprtext);                  \
  }                                                                       \
  inline string* name##Impl(const int v1, const size_t v2,                \
                            const char* exprtext) {                       \
    if (TF_PREDICT_FALSE(v2 >= std::numeric_limits<int>::max())) {        \
      return ::tensorflow::internal::MakeCheckOpString(v1, v2, exprtext); \
    }                                                                     \
    const size_t uval = (size_t)((unsigned)v2);                           \
    return name##Impl<size_t, size_t>(v1, uval, exprtext);                \
  }
#define VLOG(level)                                              \
  TF_PREDICT_TRUE(!VLOG_IS_ON(level))                            \
  ? (void)0                                                      \
  : ::tensorflow::internal::Voidifier() &                        \
          ::tensorflow::internal::LogMessage("__FILE__", "__LINE__", \
                                             tensorflow::INFO)
#define VLOG_IS_ON(lvl) ((lvl) <= 0)
#define _TF_LOG_ERROR \
  ::tensorflow::internal::LogMessage("__FILE__", "__LINE__", ::tensorflow::ERROR)
#define _TF_LOG_FATAL \
  ::tensorflow::internal::LogMessageFatal("__FILE__", "__LINE__")
#define _TF_LOG_INFO \
  ::tensorflow::internal::LogMessage("__FILE__", "__LINE__", ::tensorflow::INFO)
#define _TF_LOG_QFATAL _TF_LOG_FATAL
#define _TF_LOG_WARNING \
  ::tensorflow::internal::LogMessage("__FILE__", "__LINE__", ::tensorflow::WARNING)
#define LANG_CXX11 1

#define TF_ARRAYSIZE(a)         \
  ((sizeof(a) / sizeof(*(a))) / \
   static_cast<size_t>(!(sizeof(a) % sizeof(*(a)))))
#define TF_ATTRIBUTE_ALWAYS_INLINE __attribute__((always_inline))
#define TF_ATTRIBUTE_ANNOTATE(str) [[clang::annotate(str)]]
#define TF_ATTRIBUTE_COLD __attribute__((cold))
#define TF_ATTRIBUTE_NOINLINE __attribute__((noinline))
#define TF_ATTRIBUTE_NORETURN __attribute__((noreturn))
#define TF_ATTRIBUTE_UNUSED __attribute__((unused))
#define TF_ATTRIBUTE_WEAK __attribute__((weak))
#define TF_CONST_INIT [[clang::require_constant_initialization]]
#define TF_DISALLOW_COPY_AND_ASSIGN(TypeName) \
  TypeName(const TypeName&) = delete;         \
  void operator=(const TypeName&) = delete
#define TF_EXPORT __declspec(dllexport)
#define TF_FALLTHROUGH_INTENDED [[clang::fallthrough]]  
#define TF_HAS_BUILTIN(x) __has_builtin(x)
#define TF_HAS_CPP_ATTRIBUTE(n) __has_cpp_attribute(n)
#define TF_MUST_USE_RESULT __attribute__((warn_unused_result))
#define TF_PACKED __attribute__((packed))
#define TF_PREDICT_FALSE(x) (__builtin_expect(x, 0))
#define TF_PREDICT_TRUE(x) (__builtin_expect(!!(x), 1))
#define TF_PRINTF_ATTRIBUTE(string_index, first_to_check) \
  __attribute__((__format__(__printf__, string_index, first_to_check)))
#define TF_SCANF_ATTRIBUTE(string_index, first_to_check) \
  __attribute__((__format__(__scanf__, string_index, first_to_check)))
#define TF_UNUSED_VARIABLE(x) \
  tensorflow::internal::remove_unused_variable_compiler_warning(x)











#define REGISTER_FILE_SYSTEM(scheme, factory)                             \
  REGISTER_FILE_SYSTEM_ENV(::tensorflow::Env::Default(), scheme, factory, \
                           false);
#define REGISTER_FILE_SYSTEM_ENV(env, scheme, factory, modular) \
  REGISTER_FILE_SYSTEM_UNIQ_HELPER(__COUNTER__, env, scheme, factory, modular)
#define REGISTER_FILE_SYSTEM_UNIQ(ctr, env, scheme, factory, modular)        \
  static ::tensorflow::register_file_system::Register<factory>               \
      register_ff##ctr TF_ATTRIBUTE_UNUSED =                                 \
          ::tensorflow::register_file_system::Register<factory>(env, scheme, \
                                                                modular)
#define REGISTER_FILE_SYSTEM_UNIQ_HELPER(ctr, env, scheme, factory, modular) \
  REGISTER_FILE_SYSTEM_UNIQ(ctr, env, scheme, factory, modular)
#define REGISTER_LEGACY_FILE_SYSTEM(scheme, factory) \
  REGISTER_FILE_SYSTEM_ENV(::tensorflow::Env::Default(), scheme, factory, true);


#define TF_CHECK_OK(val) TF_DO_CHECK_OK(val, FATAL)
#define TF_DCHECK_OK(val) TF_CHECK_OK(val)
#define TF_DO_CHECK_OK(val, level)                                \
  while (auto _result = ::tensorflow::TfCheckOpHelper(val, #val)) \
  LOG(level) << *(_result)
#define TF_QCHECK_OK(val) TF_DO_CHECK_OK(val, QFATAL)




#define mutex_lock(x) static_assert(0, "mutex_lock_decl_missing_var_name");
#define tf_shared_lock(x) \
  static_assert(0, "tf_shared_lock_decl_missing_var_name");


#define GUARDED_VAR  

#define TF_ACQUIRE(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(acquire_capability(__VA_ARGS__))
#define TF_ACQUIRED_AFTER(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(acquired_after(__VA_ARGS__))
#define TF_ACQUIRED_BEFORE(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(acquired_before(__VA_ARGS__))
#define TF_ACQUIRE_SHARED(...)             \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE( \
      acquire_shared_capability(__VA_ARGS__))
#define TF_ASSERT_EXCLUSIVE_LOCK(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(assert_exclusive_lock(__VA_ARGS__))
#define TF_ASSERT_SHARED_LOCK(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(assert_shared_lock(__VA_ARGS__))
#define TF_EXCLUSIVE_LOCKS_REQUIRED(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(exclusive_locks_required(__VA_ARGS__))
#define TF_EXCLUSIVE_LOCK_FUNCTION(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(exclusive_lock_function(__VA_ARGS__))
#define TF_EXCLUSIVE_TRYLOCK_FUNCTION(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE( \
      exclusive_trylock_function(__VA_ARGS__))
#define TF_GUARDED_BY(x) TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(guarded_by(x))
#define TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(x) __attribute__((x))
#define TF_LOCKABLE TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(lockable)
#define TF_LOCKS_EXCLUDED(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(locks_excluded(__VA_ARGS__))
#define TF_LOCK_RETURNED(x) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(lock_returned(x))
#define TF_NO_THREAD_SAFETY_ANALYSIS \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(no_thread_safety_analysis)
#define TF_PT_GUARDED_BY(x) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(pt_guarded_by(x))
#define TF_PT_GUARDED_VAR  
#define TF_RELEASE(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(release_capability(__VA_ARGS__))
#define TF_SCOPED_LOCKABLE \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(scoped_lockable)
#define TF_SHARED_LOCKS_REQUIRED(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(shared_locks_required(__VA_ARGS__))
#define TF_SHARED_LOCK_FUNCTION(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(shared_lock_function(__VA_ARGS__))
#define TF_SHARED_TRYLOCK_FUNCTION(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(shared_trylock_function(__VA_ARGS__))
#define TF_TS_UNCHECKED(x) ""
#define TF_UNLOCK_FUNCTION(...) \
  TF_INTERNAL_THREAD_ANNOTATION_ATTRIBUTE(unlock_function(__VA_ARGS__))

#define TF_USE_FILESYSTEM_METHODS_WITH_NO_TRANSACTION_SUPPORT \
  using FileSystem::NewRandomAccessFile;                      \
  using FileSystem::NewWritableFile;                          \
  using FileSystem::NewAppendableFile;                        \
  using FileSystem::NewReadOnlyMemoryRegionFromFile;          \
  using FileSystem::FileExists;                               \
  using FileSystem::GetChildren;                              \
  using FileSystem::GetMatchingPaths;                         \
  using FileSystem::Stat;                                     \
  using FileSystem::DeleteFile;                               \
  using FileSystem::RecursivelyCreateDir;                     \
  using FileSystem::DeleteDir;                                \
  using FileSystem::DeleteRecursively;                        \
  using FileSystem::GetFileSize;                              \
  using FileSystem::RenameFile;                               \
  using FileSystem::CopyFile;                                 \
  using FileSystem::IsDirectory;                              \
  using FileSystem::FlushCaches

#define DECLARE_ERROR(FUNC, CONST)                                       \
  template <typename... Args>                                            \
  ::tensorflow::Status FUNC(Args... args) {                              \
    return ::tensorflow::Status(                                         \
        ::tensorflow::error::CONST,                                      \
        ::tensorflow::strings::StrCat(                                   \
            ::tensorflow::errors::internal::PrepareForStrCat(args)...)); \
  }                                                                      \
  inline bool Is##FUNC(const ::tensorflow::Status& status) {             \
    return status.code() == ::tensorflow::error::CONST;                  \
  }

#define TF_RETURN_IF_ERROR(...)                          \
  do {                                                   \
    ::tensorflow::Status _status = (__VA_ARGS__);        \
    if (TF_PREDICT_FALSE(!_status.ok())) return _status; \
  } while (0)
#define TF_RETURN_WITH_CONTEXT_IF_ERROR(expr, ...)                  \
  do {                                                              \
    ::tensorflow::Status _status = (expr);                          \
    if (TF_PREDICT_FALSE(!_status.ok())) {                          \
      ::tensorflow::errors::AppendToMessage(&_status, __VA_ARGS__); \
      return _status;                                               \
    }                                                               \
  } while (0)





#define REGISTER_KERNEL_BUILDER(kernel_builder, ...) \
  TF_ATTRIBUTE_ANNOTATE("tf:kernel")                 \
  REGISTER_KERNEL_BUILDER_IMPL(kernel_builder, false, __VA_ARGS__)
#define REGISTER_KERNEL_BUILDER_IMPL(kernel_builder, is_system_kernel, ...) \
  TF_EXTRACT_KERNEL_NAME(REGISTER_KERNEL_BUILDER_IMPL_2, kernel_builder,    \
                         is_system_kernel, __VA_ARGS__)
#define REGISTER_KERNEL_BUILDER_IMPL_2(op_name, kernel_builder_expr, \
                                       is_system_kernel, ...)        \
  TF_NEW_ID_FOR_INIT(REGISTER_KERNEL_BUILDER_IMPL_3, op_name,        \
                     kernel_builder_expr, is_system_kernel, __VA_ARGS__)
#define REGISTER_KERNEL_BUILDER_IMPL_3(ctr, op_name, kernel_builder_expr,   \
                                       is_system_kernel, ...)               \
  static ::tensorflow::InitOnStartupMarker const register_kernel_##ctr      \
      TF_ATTRIBUTE_UNUSED =                                                 \
          TF_INIT_ON_STARTUP_IF(is_system_kernel ||                         \
                                (SHOULD_REGISTER_OP_KERNEL(#__VA_ARGS__) && \
                                 SHOULD_REGISTER_OP(op_name)))              \
          << ([](::tensorflow::KernelDef const* kernel_def) {               \
               ::tensorflow::kernel_factory::OpKernelRegistrar registrar(   \
                   kernel_def, #__VA_ARGS__,                                \
                   [](::tensorflow::OpKernelConstruction* context)          \
                       -> ::tensorflow::OpKernel* {                         \
                     return new __VA_ARGS__(context);                       \
                   });                                                      \
               (void)registrar;                                             \
               return ::tensorflow::InitOnStartupMarker{};                  \
             })(kernel_builder_expr.Build());
#define REGISTER_SYSTEM_KERNEL_BUILDER(kernel_builder, ...) \
  TF_ATTRIBUTE_ANNOTATE("tf:kernel")                        \
  TF_ATTRIBUTE_ANNOTATE("tf:kernel:system")                 \
  REGISTER_KERNEL_BUILDER_IMPL(kernel_builder, true, __VA_ARGS__)

#define TF_EXTRACT_KERNEL_NAME(m, kernel_builder, ...)                    \
  TF_EXTRACT_KERNEL_NAME_IMPL(m, TF_EXTRACT_KERNEL_NAME_##kernel_builder, \
                              __VA_ARGS__)
#define TF_EXTRACT_KERNEL_NAME_IMPL(m, ...) m(__VA_ARGS__)
#define TF_EXTRACT_KERNEL_NAME_Name(name_str) \
  name_str, ::tensorflow::register_kernel::Name(name_str)




#define TF_LIB_GTL_ALIGNED_CHAR_ARRAY(T, Size)                          \
  typename tensorflow::gtl::internal::AlignType<TF_LIB_GTL_ALIGN_OF(T), \
                                                sizeof(T) * Size>::result
#define TF_LIB_GTL_ALIGNTYPE_TEMPLATE(X)                     \
  template <int size>                                        \
  struct AlignType<X, size> {                                \
    typedef TF_LIB_GTL_ALIGN_ATTRIBUTE(X) char result[size]; \
  }
#define TF_LIB_GTL_ALIGN_ATTRIBUTE(X) __declspec(align(X))
#define TF_LIB_GTL_ALIGN_OF(T) __alignof(T)





#define MATCH_TYPE_AND_ENUM(TYPE, ENUM)                 \
  template <>                                           \
  struct DataTypeToEnum<TYPE> {                         \
    static DataType v() { return ENUM; }                \
    static DataType ref() { return MakeRefType(ENUM); } \
    static constexpr DataType value = ENUM;             \
  };                                                    \
  template <>                                           \
  struct IsValidDataType<TYPE> {                        \
    static constexpr bool value = true;                 \
  };                                                    \
  template <>                                           \
  struct EnumToDataType<ENUM> {                         \
    typedef TYPE Type;                                  \
  }

























#define SHOULD_REGISTER_OP(op) true
#define SHOULD_REGISTER_OP_GRADIENT true
#define SHOULD_REGISTER_OP_KERNEL(clz) true

#define TF_INIT_ON_STARTUP_IF(cond)                \
  (::std::integral_constant<bool, !(cond)>::value) \
      ? ::tensorflow::InitOnStartupMarker{}        \
      : ::tensorflow::InitOnStartupMarker {}
#define TF_NEW_ID_FOR_INIT(m, ...) \
  TF_NEW_ID_FOR_INIT_1(m, __COUNTER__, __VA_ARGS__)
#define TF_NEW_ID_FOR_INIT_1(m, c, ...) TF_NEW_ID_FOR_INIT_2(m, c, __VA_ARGS__)
#define TF_NEW_ID_FOR_INIT_2(m, c, ...) m(c, __VA_ARGS__)
#define OP_REQUIRES(CTX, EXP, STATUS)                     \
  do {                                                    \
    if (!TF_PREDICT_TRUE(EXP)) {                          \
      CheckNotInComputeAsync((CTX), "OP_REQUIRES_ASYNC"); \
      (CTX)->CtxFailure("__FILE__", "__LINE__", (STATUS));    \
      return;                                             \
    }                                                     \
  } while (0)
#define OP_REQUIRES_ASYNC(CTX, EXP, STATUS, CALLBACK)  \
  do {                                                 \
    if (!TF_PREDICT_TRUE(EXP)) {                       \
      (CTX)->CtxFailure("__FILE__", "__LINE__", (STATUS)); \
      (CALLBACK)();                                    \
      return;                                          \
    }                                                  \
  } while (0)
#define OP_REQUIRES_OK(CTX, ...)                             \
  do {                                                       \
    ::tensorflow::Status _s(__VA_ARGS__);                    \
    if (!TF_PREDICT_TRUE(_s.ok())) {                         \
      CheckNotInComputeAsync((CTX), "OP_REQUIRES_OK_ASYNC"); \
      (CTX)->CtxFailureWithWarning("__FILE__", "__LINE__", _s);  \
      return;                                                \
    }                                                        \
  } while (0)
#define OP_REQUIRES_OK_ASYNC(CTX, STATUS, CALLBACK)         \
  do {                                                      \
    const ::tensorflow::Status& _s(STATUS);                 \
    if (!TF_PREDICT_TRUE(_s.ok())) {                        \
      (CTX)->CtxFailureWithWarning("__FILE__", "__LINE__", _s); \
      (CALLBACK)();                                         \
      return;                                               \
    }                                                       \
  } while (0)
#define OP_REQUIRES_OK_OR_SET_PAYLOAD(CTX, PAYLOAD_KEY, PAYLOAD_VALUE, STATUS) \
  do {                                                                         \
    if (!TF_PREDICT_TRUE(STATUS.ok())) {                                       \
      CheckNotInComputeAsync((CTX), "OP_REQUIRES_OK_ASYNC");                   \
      if (!PAYLOAD_VALUE.empty()) {                                            \
        STATUS.SetPayload(PAYLOAD_KEY, PAYLOAD_VALUE);                         \
      }                                                                        \
      (CTX)->CtxFailureWithWarning("__FILE__", "__LINE__", STATUS);                \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define REGISTER_OP(name)        \
  TF_ATTRIBUTE_ANNOTATE("tf:op") \
  TF_NEW_ID_FOR_INIT(REGISTER_OP_IMPL, name, false)
#define REGISTER_OP_IMPL(ctr, name, is_system_op)                         \
  static ::tensorflow::InitOnStartupMarker const register_op##ctr         \
      TF_ATTRIBUTE_UNUSED =                                               \
          TF_INIT_ON_STARTUP_IF(is_system_op || SHOULD_REGISTER_OP(name)) \
          << ::tensorflow::register_op::OpDefBuilderWrapper(name)
#define REGISTER_SYSTEM_OP(name)        \
  TF_ATTRIBUTE_ANNOTATE("tf:op")        \
  TF_ATTRIBUTE_ANNOTATE("tf:op:system") \
  TF_NEW_ID_FOR_INIT(REGISTER_OP_IMPL, name, true)



















