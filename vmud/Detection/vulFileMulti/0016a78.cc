
















unsigned int get_nprocs_conf(){
  int numProcessors = 0;
  size_t size = sizeof(numProcessors);
  int returnCode = sysctlbyname("hw.ncpu", &numProcessors, &size, NULL, 0);
  if( returnCode != 0 ) return 1;
  else return (unsigned int)numProcessors;
}








using namespace std;


void KakaduImage::openImage()
{
  string filename = getFileName( currentX, currentY );

  
  updateTimestamp( filename );

  
  kdu_customize_warnings(&pretty_cout);
  kdu_customize_errors(&pretty_cerr);


  Timer timer;
  timer.start();


  
  try{
    src.open( filename.c_str(), true );
    if( jpx_input.open( &src, false ) != 1 ) throw 1;
  }
  catch (...){
    throw file_error( "Kakadu :: Unable to open '"+filename+"'"); 
  }


  
  try{
    jpx_stream = jpx_input.access_codestream(0);
    if( !jpx_stream.exists() ) throw 1;
  }
  catch (...){
    throw file_error( "Kakadu :: No codestream in file '"+filename+"'"); 
  }


  
  input = NULL;
  input = jpx_stream.open_stream();

  
  codestream.create(input);
  if( !codestream.exists() ) throw file_error( "Kakadu :: Unable to create codestream for '"+filename+"'"); 

  
  

  
  switch( kdu_readmode ) {
    case KDU_FUSSY:
      codestream.set_fussy();
      break;
    case KDU_RESILIENT:
      codestream.set_resilient();
      break;
    case KDU_FAST:
    default:
      codestream.set_fast();
  }

  codestream.set_persistent();
  

  
  if( bpc == 0 ) loadImageInfo( currentX, currentY );


  logfile << "Kakadu :: openImage() :: " << timer.getTime() << " microseconds" << endl;


}


void KakaduImage::loadImageInfo( int seq, int ang )
{
  jp2_channels j2k_channels;
  jp2_palette j2k_palette;
  jp2_resolution j2k_resolution;
  jp2_colour j2k_colour;
  kdu_coords layer_size;
  jpx_layer_source jpx_layer;

  

  siz_params *siz = codestream.access_siz();
  int pcap_value = 0;
  siz->get( Scap, 0, 0, pcap_value );
  if( pcap_value & 0x00020000 ) logfile << "Kakadu :: HTJ2K codestream" << endl;


  
  try{
    jpx_layer = jpx_input.access_layer(0);
  }
  catch( ... ){
    throw file_error( "Kakadu :: Core Exception Caught During Metadata Extraction"); 
  }

  j2k_channels = jpx_layer.access_channels();
  j2k_resolution = jpx_layer.access_resolution();
  j2k_colour = jpx_layer.access_colour(0);
  layer_size = jpx_layer.get_layer_size();

  image_widths.push_back(layer_size.x);
  image_heights.push_back(layer_size.y);
  channels = codestream.get_num_components();
  numResolutions = codestream.get_min_dwt_levels();
  bpc = codestream.get_bit_depth(0,true);

  
  dpi_y = j2k_resolution.get_resolution( false );
  if( dpi_y > 0.0 ){
    dpi_y /= 100.0;          
    float aspect = j2k_resolution.get_aspect_ratio( false );
    dpi_x = dpi_y * aspect;
    dpi_units = 2;           
  }
  else dpi_y = 0.0;

  unsigned int w = layer_size.x;
  unsigned int h = layer_size.y;


  logfile << "Kakadu :: DWT Levels: " << numResolutions << endl;
  logfile << "Kakadu :: Pixel Resolution : " << w << "x" << h << endl;
  logfile << "Kakadu :: Capture Resolution : " << dpi_x << "x" << dpi_y << " pixels/cm" << endl;


  
  
  
  for( unsigned int c=1; c<numResolutions; c++ ){
    
    
    
    
    
    w = floor( w/2.0 );
    h = floor( h/2.0 );
    image_widths.push_back(w);
    image_heights.push_back(h);

    logfile << "Kakadu :: Resolution : " << w << "x" << h << endl;

  }

  
  
  
  
  unsigned int n = 1;
  w = image_widths[0];
  h = image_heights[0];
  while( (w>tile_width) || (h>tile_height) ){
    n++;
    w = floor( w/2.0 );
    h = floor( h/2.0 );
    if( n > numResolutions ){
      image_widths.push_back(w);
      image_heights.push_back(h);
    }
  }

  if( n > numResolutions ){

    logfile << "Kakadu :: Warning! Insufficient resolution levels in JPEG2000 stream. Will generate " << n-numResolutions << " extra levels dynamically -" << endl << "Kakadu :: However, you are advised to regenerate the file with at least " << n << " levels" << endl;

  }

  if( n > numResolutions ) virtual_levels = n-numResolutions-1;
  numResolutions = n;


  
  int cmp, plt, stream_id,format=0;

  
  j2k_channels.get_colour_mapping(0,cmp,plt,stream_id,format);

  j2k_channels.get_colour_mapping(0,cmp,plt,stream_id);


  j2k_palette = jpx_stream.access_palette();

  if( j2k_palette.exists() && j2k_palette.get_num_luts()>0 ){
    int entries = j2k_palette.get_num_entries();
    float *lt = new float[entries];
    j2k_palette.get_lut(0,lt);    
    
    for( int n=0; n<entries; n++ ){
      lut.push_back((int)((lt[n]+0.5)*255));
    }
    delete[] lt;

    logfile << "Kakadu :: Palette with " << j2k_palette.get_num_luts() << " LUT and " << entries << " entries/LUT with values " << lut[0] << "," << lut[1] << endl;

  }


  
  int icc_length = 0;
  const char* icc = (const char*) j2k_colour.get_icc_profile( &icc_length );
  if( icc_length > 0 ) metadata["icc"] = string( icc, icc_length );


  
  if( channels == 1 ){
    colourspace = (bpc==1)? BINARY : GREYSCALE;
  }
  else{
    jp2_colour_space cs = j2k_colour.get_space();
    if( cs == JP2_sRGB_SPACE || cs == JP2_iccRGB_SPACE || cs == JP2_esRGB_SPACE || cs == JP2_CIELab_SPACE ) colourspace = sRGB;
    
    else {

    	logfile << "WARNING : colour space not found, setting sRGB colour space value" << endl;

    	colourspace = sRGB;
    }
  }


  
  kdu_tile kt = codestream.open_tile(kdu_coords(0,0),NULL);
  quality_layers = codestream.get_max_tile_layers();

  string cs;
  switch( j2k_colour.get_space() ){
    case JP2_sRGB_SPACE:
      cs = "JP2_sRGB_SPACE";
      break;
    case JP2_sLUM_SPACE:
      cs =  "JP2_sLUM_SPACE";
      break;
    case JP2_CIELab_SPACE:
      cs = "JP2_CIELab_SPACE";
      break;
    default:
      cs = j2k_colour.get_space();
      break;
  }
  logfile << "Kakadu :: " << bpc << " bit data" << endl << "Kakadu :: " << channels << " channels" << endl << "Kakadu :: colour space: " << cs << endl << "Kakadu :: " << quality_layers << " quality layers detected" << endl;



  kt.close();

  
  if( bpc == 1 ) channels = 1;

  
  
  for( unsigned int i=0; i<channels; i++ ){
    min.push_back( 0.0 );
    if( bpc > 8 && bpc <= 16 ) max.push_back( 65535.0 );
    else max.push_back( 255.0 );
  }

  isSet = true;
}



void KakaduImage::closeImage()
{

  Timer timer;
  timer.start();


  
  if( codestream.exists() ) codestream.destroy();

  
  src.close();
  jpx_input.close();


  logfile << "Kakadu :: closeImage() :: " << timer.getTime() << " microseconds" << endl;

}



RawTile KakaduImage::getTile( int seq, int ang, unsigned int res, int layers, unsigned int tile )
{

  
  unsigned obpc = bpc;
  if( bpc <= 16 && bpc > 8 ) obpc = 16;
  else if( bpc <= 8 ) obpc = 8;


  Timer timer;
  timer.start();


  if( res > numResolutions ){
    ostringstream tile_no;
    tile_no << "Kakadu :: Asked for non-existent resolution: " << res;
    throw file_error( tile_no.str() );
  }

  int vipsres = ( numResolutions - 1 ) - res;

  unsigned int tw = tile_width;
  unsigned int th = tile_height;


  
  unsigned int rem_x = image_widths[vipsres] % tile_width;
  unsigned int rem_y = image_heights[vipsres] % tile_height;


  
  unsigned int ntlx = (image_widths[vipsres] / tw) + (rem_x == 0 ? 0 : 1);
  unsigned int ntly = (image_heights[vipsres] / th) + (rem_y == 0 ? 0 : 1);

  if( tile >= ntlx*ntly ){
    ostringstream tile_no;
    tile_no << "Kakadu :: Asked for non-existent tile: " << tile;
    throw file_error( tile_no.str() );
  }

  
  if( ( tile % ntlx == ntlx - 1 ) && ( rem_x != 0 ) ) {
    tw = rem_x;
  }

  
  if( ( tile / ntlx == ntly - 1 ) && rem_y != 0 ) {
    th = rem_y;
  }


  
  int xoffset = (tile % ntlx) * tile_width;
  int yoffset = (unsigned int) floor((double)(tile/ntlx)) * tile_height;


  logfile << "Kakadu :: Tile size: " << tw << "x" << th << "@" << channels << endl;



  
  RawTile rawtile( tile, res, seq, ang, tw, th, channels, obpc );


  
  if( obpc == 16 ) rawtile.data = new unsigned short[tw*th*channels];
  else if( obpc == 8 ) rawtile.data = new unsigned char[tw*th*channels];
  else throw file_error( "Kakadu :: Unsupported number of bits" );

  rawtile.dataLength = tw*th*channels*(obpc/8);
  rawtile.filename = getImagePath();
  rawtile.timestamp = timestamp;

  
  process( res, layers, xoffset, yoffset, tw, th, rawtile.data );



  logfile << "Kakadu :: bytes parsed: " << codestream.get_total_bytes(true) << endl;
  logfile << "Kakadu :: getTile() :: " << timer.getTime() << " microseconds" << endl;


  return rawtile;

}



RawTile KakaduImage::getRegion( int seq, int ang, unsigned int res, int layers, int x, int y, unsigned int w, unsigned int h )
{
  
  unsigned int obpc = bpc;
  if( bpc <= 16 && bpc > 8 ) obpc = 16;
  else if( bpc <= 8 ) obpc = 8;


  Timer timer;
  timer.start();


  RawTile rawtile( 0, res, seq, ang, w, h, channels, obpc );

  if( obpc == 16 ) rawtile.data = new unsigned short[w*h*channels];
  else if( obpc == 8 ) rawtile.data = new unsigned char[w*h*channels];
  else throw file_error( "Kakadu :: Unsupported number of bits" );

  rawtile.dataLength = w*h*channels*(obpc/8);
  rawtile.filename = getImagePath();
  rawtile.timestamp = timestamp;

  process( res, layers, x, y, w, h, rawtile.data );


  logfile << "Kakadu :: getRegion() :: " << timer.getTime() << " microseconds" << endl;


  return rawtile;

}



void KakaduImage::process( unsigned int res, int layers, int xoffset, int yoffset, unsigned int tw, unsigned int th, void *d )
{

  
  unsigned int obpc = bpc;
  if( bpc <= 16 && bpc > 8 ) obpc = 16;
  else if( bpc <= 8 ) obpc = 8;

  int vipsres = ( numResolutions - 1 ) - res;

  
  if( res < virtual_levels ){
    unsigned int factor = 1 << (virtual_levels-res);
    xoffset *= factor;
    yoffset *= factor;
    tw *= factor;
    th *= factor;
    vipsres = numResolutions - 1 - virtual_levels;

  logfile << "Kakadu :: using smallest existing resolution " << virtual_levels << endl;

  }

  
  
  if( layers < 0 ) layers = quality_layers;
  else if( layers == 0 ) layers = ceil( quality_layers/2.0 );

  
  if( layers < 1 ) layers = 1;


  
  kdu_dims image_dims, canvas_dims;
  canvas_dims.pos = kdu_coords( xoffset, yoffset );
  canvas_dims.size = kdu_coords( tw, th );

  
  if( !codestream.exists() ) throw file_error( "Kakadu :: Malformed JPEG2000 - unable to access codestream");

  
  
  codestream.apply_input_restrictions( 0,0,vipsres,layers,&canvas_dims,KDU_WANT_OUTPUT_COMPONENTS );
  codestream.map_region( 0, canvas_dims, image_dims, true );


  

  int num_threads = get_nprocs_conf();

  int num_threads = 0;



  kdu_thread_env env, *env_ref = NULL;
  if( num_threads > 0 ){
    env.create();
    for (int nt=0; nt < num_threads; nt++){
      
      if( !env.add_thread() ) num_threads = nt;
    }
    env_ref = &env;
  }




  logfile << "Kakadu :: decompressor init with " << num_threads << " threads" << endl;
  logfile << "Kakadu :: decoding " << layers << " quality layers" << endl;



  
  void *buffer = NULL;
  void *stripe_buffer = NULL;
  int *stripe_heights = NULL;

  try{

    
    codestream.apply_input_restrictions( 0, channels, vipsres, layers, &image_dims, KDU_WANT_OUTPUT_COMPONENTS );

    decompressor.start( codestream, false, true, env_ref, NULL );

    stripe_heights = new int[channels];
    codestream.get_dims(0,comp_dims,true);


    logfile << "Kakadu :: decompressor starting" << endl;

    logfile << "Kakadu :: requested region on high resolution canvas: position: " << image_dims.pos.x << "x" << image_dims.pos.y << ". size: " << image_dims.size.x << "x" << image_dims.size.y << endl;


    logfile << "Kakadu :: mapped resolution region size: " << comp_dims.size.x << "x" << comp_dims.size.y << endl;
    logfile << "Kakadu :: About to pull stripes" << endl;


    
    if( comp_dims.size.x <= 0 || comp_dims.size.y <= 0 ){

      logfile << "Kakadu :: Error: region of zero size requested" << endl;

      throw 1;
    }

    int index = 0;
    bool continues = true;

    
    
    decompressor.get_recommended_stripe_heights( comp_dims.size.y, 1024, stripe_heights, NULL );


    logfile << "Kakadu :: Allocating memory for stripe height " << stripe_heights[0] << endl;


    

    if( obpc == 16 ){
      stripe_buffer = new kdu_uint16[tw*stripe_heights[0]*channels];
      buffer = new unsigned short[tw*th*channels];
    }
    else if( obpc == 8 ){
      stripe_buffer = new kdu_byte[tw*stripe_heights[0]*channels];
      buffer = new unsigned char[tw*th*channels];
    }

    
    int previous_stripe_heights = stripe_heights[0];


    while( continues ){


      decompressor.get_recommended_stripe_heights( comp_dims.size.y, 1024, stripe_heights, NULL );


      
      if( stripe_heights[0] > previous_stripe_heights ){

	
	delete_buffer( stripe_buffer );
	if( obpc == 16 ){
	  stripe_buffer = new kdu_uint16[tw*stripe_heights[0]*channels];
	}
	else if( obpc == 8 ){
	  stripe_buffer = new kdu_byte[tw*stripe_heights[0]*channels];
	}


	logfile << "Kakadu :: Stripe height increase: re-allocating memory for height " << stripe_heights[0] << endl;

      }

      
      if( stripe_heights[0] == 0 ){

	logfile << "Kakadu :: Error: Zero stripe height" << endl;

	throw 1;
      }


      if( obpc == 16 ){
	
	bool s[3] = {false,false,false};
	continues = decompressor.pull_stripe( (kdu_int16*) stripe_buffer, stripe_heights, NULL, NULL, NULL, NULL, s );
      }
      else if( obpc == 8 ){
	continues = decompressor.pull_stripe( (kdu_byte*) stripe_buffer, stripe_heights, NULL, NULL, NULL );
      }



      logfile << "Kakadu :: stripe pulled" << endl;


      
      void *b1, *b2;
      if( obpc == 16 ){
	b1 = &( ((kdu_uint16*)stripe_buffer)[0] );
	b2 = &( ((unsigned short*)buffer)[index] );
      }
      else{ 
	b1 = &( ((kdu_byte*)stripe_buffer)[0] );
	b2 = &( ((unsigned char*)buffer)[index] );

	
	if( bpc == 1 ){

	  unsigned int k = tw * stripe_heights[0] * channels;

	  
	  if( !lut.empty() && lut[0]>lut[1] ){
	    for( unsigned int n=0; n<k; n++ ){
	      ((kdu_byte*)stripe_buffer)[n] =  ~(-((kdu_byte*)stripe_buffer)[n] >> 8);
	    }
	  }
	  else{
	    for( unsigned int n=0; n<k; n++ ){
	      ((kdu_byte*)stripe_buffer)[n] =  (-((kdu_byte*)stripe_buffer)[n] >> 8);
	    }
	  }
	}
      }

      memcpy( b2, b1, tw * stripe_heights[0] * channels * (obpc/8) );

      
      index += tw * stripe_heights[0] * channels;


      logfile << "Kakadu :: stripe complete with height " << stripe_heights[0] << endl;


    }


    if( !decompressor.finish() ){
      throw file_error( "Kakadu :: Error indicated by finish()" );
    }


    
    if( res < virtual_levels ){


      logfile << "Kakadu :: resizing tile to virtual resolution with factor " << (1 << (virtual_levels-res)) << endl;


      unsigned int n = 0;
      unsigned int factor = 1 << (virtual_levels-res);
      for( unsigned int j=0; j<th; j+=factor ){
	for( unsigned int i=0; i<tw; i+=factor ){
	  for( unsigned int k=0; k<channels; k++ ){
	    
	    if( obpc==16 ){
	      ((unsigned short*)d)[n++] = ((unsigned short*)buffer)[j*tw*channels + i*channels + k];
	    }
	    else if( obpc==8 ){
	      ((unsigned char*)d)[n++] = ((unsigned char*)buffer)[j*tw*channels + i*channels + k];
	    }
	  }
	}
      }
    }
    else memcpy( d, buffer, tw*th*channels * (obpc/8) );

    
    delete_buffer( buffer );


    logfile << "Kakadu :: decompressor completed" << endl;



  }
  catch (...){
    
    decompressor.finish();
    if( env.exists() ) env.destroy();
    delete_buffer( stripe_buffer );
    delete_buffer( buffer );
    if( stripe_heights ) delete[] stripe_heights;
    throw file_error( "Kakadu :: Core Exception Caught"); 
  }


  
  if( env.exists() ) env.destroy();

  
  delete_buffer( stripe_buffer );
  if( stripe_heights ){
    delete[] stripe_heights;
    stripe_heights = NULL;
  }

}



void KakaduImage::delete_buffer( void* buffer ){
  if( buffer ){
    if( bpc <= 16 && bpc > 8 ) delete[] (kdu_uint16*) buffer;
    else if( bpc<=8 ) delete[] (kdu_byte*) buffer;
  }


}
