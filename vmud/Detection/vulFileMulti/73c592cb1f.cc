







namespace Envoy {
namespace Extensions {
namespace Compression {
namespace Gzip {
namespace Compressor {
namespace Fuzz {






DEFINE_FUZZER(const uint8_t* buf, size_t len) {

  FuzzedDataProvider provider(buf, len);
  ZlibCompressorImpl compressor;
  Stats::IsolatedStoreImpl stats_store;
  Decompressor::ZlibDecompressorImpl decompressor{stats_store, "test";

  
  
  const ZlibCompressorImpl::CompressionLevel compression_levels[] = {
      ZlibCompressorImpl::CompressionLevel::Best, ZlibCompressorImpl::CompressionLevel::Speed, ZlibCompressorImpl::CompressionLevel::Standard, };


  const ZlibCompressorImpl::CompressionLevel target_compression_level = provider.PickValueInArray(compression_levels);

  
  
  const ZlibCompressorImpl::CompressionStrategy compression_strategies[] = {
      ZlibCompressorImpl::CompressionStrategy::Filtered, ZlibCompressorImpl::CompressionStrategy::Huffman, ZlibCompressorImpl::CompressionStrategy::Rle, ZlibCompressorImpl::CompressionStrategy::Standard, };



  const ZlibCompressorImpl::CompressionStrategy target_compression_strategy = provider.PickValueInArray(compression_strategies);

  
  
  const int64_t target_window_bits = provider.ConsumeIntegralInRange(9, 15);

  
  
  const uint64_t target_memory_level = provider.ConsumeIntegralInRange(1, 9);

  compressor.init(target_compression_level, target_compression_strategy, target_window_bits, target_memory_level);
  decompressor.init(target_window_bits);

  bool provider_empty = provider.remaining_bytes() == 0;
  Buffer::OwnedImpl full_input;
  Buffer::OwnedImpl full_output;
  while (!provider_empty) {
    const std::string next_data = provider.ConsumeRandomLengthString(provider.remaining_bytes());
    ENVOY_LOG_MISC(debug, "Processing {} bytes", next_data.size());
    full_input.add(next_data);
    Buffer::OwnedImpl buffer{next_data.data(), next_data.size()};
    provider_empty = provider.remaining_bytes() == 0;
    compressor.compress(buffer, provider_empty ? Envoy::Compression::Compressor::State::Finish : Envoy::Compression::Compressor::State::Flush);
    decompressor.decompress(buffer, full_output);
  }
  RELEASE_ASSERT(full_input.toString() == full_output.toString(), "");
  RELEASE_ASSERT(compressor.checksum() == decompressor.checksum(), "");
}

} 
} 
} 
} 
} 
} 
