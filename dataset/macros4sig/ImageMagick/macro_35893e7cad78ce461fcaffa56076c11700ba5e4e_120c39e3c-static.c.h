
#include<stdarg.h>

#include<ctype.h>

#include<float.h>


#include<errno.h>


#include<signal.h>

#include<fcntl.h>
#include<limits.h>




#include<time.h>



#include<math.h>
#include<stdio.h>
#include<locale.h>

#include<assert.h>



#define MagickCoderAlias(coder,alias)  { alias, coder },
#define MagickCoderExports(coder) \
extern ModuleExport size_t \
  Register ## coder ## Image(void); \
extern ModuleExport void \
  Unregister ## coder ## Image(void);
#define MagickCoderHeader(coder,offset,magic)  { coder, offset, \
  (const unsigned char *) (magic), sizeof(magic)-1 },






#define OpaqueAlpha  ((Quantum) QuantumRange)
#define TransparentAlpha  ((Quantum) 0)



#define MaxPixelChannels  64


#define BesselFilter  JincFilter
#define HanningFilter HannFilter

#define WelshFilter   WelchFilter














#define MagickMaxBufferExtent  81920
#define MagickMinBufferExtent  16384
#define MagickYCBCRAliases \
  MagickCoderAlias("YCbCr", "YCbCrA")





#define MagickXTRNAliases \
  MagickCoderAlias("XTRN", "XTRNARRAY")



#define MagickXPMAliases \
  MagickCoderAlias("XPM", "PICON") \
  MagickCoderAlias("XPM", "PM")
#define MagickXPMHeaders \
  MagickCoderHeader("XPM", 1, "* XPM *")

#define MagickXCFHeaders \
  MagickCoderHeader("XCF", 0, "gimp xcf")
#define MagickXCAliases \
  MagickCoderAlias("XC", "CANVAS")




#define MagickXBMHeaders \
  MagickCoderHeader("XBM", 0, "#define")

#define MagickWPGHeaders \
  MagickCoderHeader("WPG", 0, "\377WPC")



#define MagickWEBPHeaders \
  MagickCoderHeader("WEBP", 8, "WEBP")



#define MagickVIPSHeaders \
  MagickCoderHeader("VIPS", 0, "\010\362\246\266") \
  MagickCoderHeader("VIPS", 0, "\266\246\362\010")
#define MagickVIFFAliases \
  MagickCoderAlias("VIFF", "XV")
#define MagickVIFFHeaders \
  MagickCoderHeader("VIFF", 0, "\253\001")
#define MagickVIDEOAliases \
  MagickCoderAlias("VIDEO", "3GP") \
  MagickCoderAlias("VIDEO", "3G2") \
  MagickCoderAlias("VIDEO", "APNG") \
  MagickCoderAlias("VIDEO", "AVI") \
  MagickCoderAlias("VIDEO", "FLV") \
  MagickCoderAlias("VIDEO", "MKV") \
  MagickCoderAlias("VIDEO", "MOV") \
  MagickCoderAlias("VIDEO", "MPEG") \
  MagickCoderAlias("VIDEO", "MPG") \
  MagickCoderAlias("VIDEO", "MP4") \
  MagickCoderAlias("VIDEO", "M2V") \
  MagickCoderAlias("VIDEO", "M4V") \
  MagickCoderAlias("VIDEO", "WEBM") \
  MagickCoderAlias("VIDEO", "WMV")
#define MagickVIDEOHeaders \
  MagickCoderHeader("VIDEO", 0, "\000\000\001\263") \
  MagickCoderHeader("VIDEO", 0, "RIFF")



#define MagickVICARHeaders \
  MagickCoderHeader("VICAR", 0, "LBLSIZE") \
  MagickCoderHeader("VICAR", 0, "NJPL1I") \
  MagickCoderHeader("VICAR", 0, "PDS_VERSION_ID")
#define MagickUYVYAliases \
  MagickCoderAlias("UYVY", "PAL")

#define MagickURLAliases \
  MagickCoderAlias("URL", "HTTP") \
  MagickCoderAlias("URL", "HTTPS") \
  MagickCoderAlias("URL", "FTP") \
  MagickCoderAlias("URL", "FILE")



#define MagickTXTAliases \
  MagickCoderAlias("TXT", "SPARSE-COLOR") \
  MagickCoderAlias("TXT", "TEXT")
#define MagickTXTHeaders \
  MagickCoderHeader("TXT", 0, MagickTXTID)
#define MagickTXTID  "# ImageMagick pixel enumeration:"
#define MagickTTFAliases \
  MagickCoderAlias("TTF", "DFONT") \
  MagickCoderAlias("TTF", "PFA") \
  MagickCoderAlias("TTF", "PFB") \
  MagickCoderAlias("TTF", "OTF") \
  MagickCoderAlias("TTF", "TTC")
#define MagickTTFHeaders \
  MagickCoderHeader("TTF", 0, "\000\001\000\000\000") \
  MagickCoderHeader("PFA", 0, "%!PS-AdobeFont-1.0") \
  MagickCoderHeader("PFB", 6, "%!PS-AdobeFont-1.0")
#define MagickTIM2Aliases \
  MagickCoderAlias("TIM2","TM2")
#define MagickTIM2Headers \
  MagickCoderHeader("TM2", 0, "TIM2")




#define MagickTIFFAliases \
  MagickCoderAlias("TIFF", "GROUP4") \
  MagickCoderAlias("TIFF", "PTIF") \
  MagickCoderAlias("TIFF", "TIF") \
  MagickCoderAlias("TIFF", "TIFF64")
#define MagickTIFFHeaders \
  MagickCoderHeader("TIFF", 0, "\115\115\000\052") \
  MagickCoderHeader("TIFF", 0, "\111\111\052\000") \
  MagickCoderHeader("TIFF64", 0, "\115\115\000\053\000\010\000\000") \
  MagickCoderHeader("TIFF64", 0, "\111\111\053\000\010\000\000\000")


#define MagickTGAAliases \
  MagickCoderAlias("TGA", "ICB") \
  MagickCoderAlias("TGA", "VDA") \
  MagickCoderAlias("TGA", "VST")

#define MagickSVGAliases \
  MagickCoderAlias("SVG", "SVGZ") \
  MagickCoderAlias("SVG", "RSVG") \
  MagickCoderAlias("SVG", "MSVG")
#define MagickSVGHeaders \
  MagickCoderHeader("SVG", 1, "?XML") \
  MagickCoderHeader("SVG", 1, "?xml") \
  MagickCoderHeader("SVG", 1, "SVG") \
  MagickCoderHeader("SVG", 1, "svg")
#define MagickSUNAliases \
  MagickCoderAlias("SUN", "RAS")
#define MagickSUNHeaders \
  MagickCoderHeader("SUN", 0, "\131\246\152\225")


#define MagickSIXELAliases \
  MagickCoderAlias("SIXEL", "SIX")


#define MagickSGIHeaders \
  MagickCoderHeader("SGI", 0, "\001\332")

#define MagickSFWHeaders \
  MagickCoderHeader("SFW", 0, "SFW94")

#define MagickSCTHeaders \
  MagickCoderHeader("SCT", 0, "CT")





#define MagickRLEHeaders \
  MagickCoderHeader("RLE", 0, "\122\314")




#define MagickRGBAliases \
  MagickCoderAlias("RGB", "RGBA") \
  MagickCoderAlias("RGB", "RGBO") \
  MagickCoderAlias("RGB", "RGB565")

#define MagickRAWAliases \
  MagickCoderAlias("RAW", "R") \
  MagickCoderAlias("RAW", "C") \
  MagickCoderAlias("RAW", "G") \
  MagickCoderAlias("RAW", "M") \
  MagickCoderAlias("RAW", "B") \
  MagickCoderAlias("RAW", "Y") \
  MagickCoderAlias("RAW", "A") \
  MagickCoderAlias("RAW", "O") \
  MagickCoderAlias("RAW", "K")


#define MagickPWPHeaders \
  MagickCoderHeader("PWP", 0, "SFW95")
#define MagickPSDAliases \
  MagickCoderAlias("PSD", "PSB")
#define MagickPSDHeaders \
  MagickCoderHeader("PSB", 0, "8BPB") \
  MagickCoderHeader("PSD", 0, "8BPS")
#define MagickPSAliases \
  MagickCoderAlias("PS", "EPI") \
  MagickCoderAlias("PS", "EPS") \
  MagickCoderAlias("PS", "EPSF") \
  MagickCoderAlias("PS", "EPSI")
#define MagickPSHeaders \
  MagickCoderHeader("PS", 0, "%!") \
  MagickCoderHeader("PS", 0, "\004%!") \
  MagickCoderHeader("PS", 0, "\305\320\323\306")
#define MagickPS3Aliases \
  MagickCoderAlias("PS3", "EPS3")

#define MagickPS2Aliases \
  MagickCoderAlias("PS2", "EPS2")

#define MagickPNMAliases \
  MagickCoderAlias("PNM", "PAM") \
  MagickCoderAlias("PNM", "PBM") \
  MagickCoderAlias("PNM", "PFM") \
  MagickCoderAlias("PNM", "PHM") \
  MagickCoderAlias("PNM", "PGM") \
  MagickCoderAlias("PNM", "PPM")
#define MagickPNMHeaders \
  MagickCoderHeader("PBM", 0, "P1") \
  MagickCoderHeader("PGM", 0, "P2") \
  MagickCoderHeader("PPM", 0, "P3") \
  MagickCoderHeader("PBM", 0, "P4") \
  MagickCoderHeader("PGM", 0, "P5") \
  MagickCoderHeader("PPM", 0, "P6") \
  MagickCoderHeader("PAM", 0, "P7") \
  MagickCoderHeader("PFM", 0, "PF") \
  MagickCoderHeader("PFM", 0, "Pf") \
  MagickCoderHeader("PHM", 0, "PH") \
  MagickCoderHeader("PHM", 0, "Ph")
#define MagickPNGAliases \
  MagickCoderAlias("PNG", "MNG") \
  MagickCoderAlias("PNG", "PNG8") \
  MagickCoderAlias("PNG", "PNG24") \
  MagickCoderAlias("PNG", "PNG32") \
  MagickCoderAlias("PNG", "PNG48") \
  MagickCoderAlias("PNG", "PNG64") \
  MagickCoderAlias("PNG", "PNG00") \
  MagickCoderAlias("PNG", "JNG")
#define MagickPNGHeaders \
  MagickCoderHeader("PNG", 0, "\211PNG\r\n\032\n") \
  MagickCoderHeader("JNG", 0, "\213JNG\r\n\032\n") \
  MagickCoderHeader("MNG", 0, "\212MNG\r\n\032\n")
#define MagickPLASMAAliases \
  MagickCoderAlias("PLASMA", "FRACTAL")



#define MagickPICTAliases \
  MagickCoderAlias("PICT", "PCT")


#define MagickPGXHeaders \
  MagickCoderHeader("PGX", 0, "\050\107\020\115\046") \
  MagickCoderHeader("PGX", 0, "PG ML") \
  MagickCoderHeader("PGX", 0, "PG LM")

#define MagickPESHeaders \
  MagickCoderHeader("PES", 0, "#PES")
#define MagickPDFAliases \
  MagickCoderAlias("PDF", "AI") \
  MagickCoderAlias("PDF", "EPDF") \
  MagickCoderAlias("PDF", "PDFA") \
  MagickCoderAlias("PDF", "POCKETMOD")
#define MagickPDFHeaders \
  MagickCoderHeader("PDF", 0, "%PDF-")

#define MagickPDBHeaders \
  MagickCoderHeader("PDB", 60, "vIMGView")
#define MagickPCXAliases \
  MagickCoderAlias("PCX", "DCX")
#define MagickPCXHeaders \
  MagickCoderHeader("PCX", 0, "\012\002") \
  MagickCoderHeader("PCX", 0, "\012\005") \
  MagickCoderHeader("DCX", 0, "\261\150\336\72")

#define MagickPCLHeaders \
  MagickCoderHeader("PCL", 0, "\033E\033")
#define MagickPCDAliases \
  MagickCoderAlias("PCD", "PCDS")
#define MagickPCDHeaders \
  MagickCoderHeader("PCD", 2048, "PCD_")


















#define MagickMPRAliases \
  MagickCoderAlias("MPR", "MPRI")

#define MagickMPCAliases \
  MagickCoderAlias("MPC", "CACHE")
#define MagickMPCHeaders \
  MagickCoderHeader("MPC", 0, "id=MagickCache")



#define MagickMIFFHeaders \
  MagickCoderHeader("MIFF", 0, "Id=ImageMagick") \
  MagickCoderHeader("MIFF", 0, "id=ImageMagick")
#define MagickMETAAliases \
  MagickCoderAlias("META", "8BIM") \
  MagickCoderAlias("META", "8BIMTEXT") \
  MagickCoderAlias("META", "8BIMWTEXT") \
  MagickCoderAlias("META", "APP1") \
  MagickCoderAlias("META", "APP1JPEG") \
  MagickCoderAlias("META", "EXIF") \
  MagickCoderAlias("META", "XMP") \
  MagickCoderAlias("META", "ICM") \
  MagickCoderAlias("META", "ICC") \
  MagickCoderAlias("META", "IPTC") \
  MagickCoderAlias("META", "IPTCTEXT") \
  MagickCoderAlias("META", "IPTCWTEXT")
#define MagickMETAHeaders \
  MagickCoderHeader("8BIMWTEXT", 0, "8\000B\000I\000M\000#") \
  MagickCoderHeader("8BIMTEXT", 0, "8BIM#") \
  MagickCoderHeader("8BIM", 0, "8BIM") \
  MagickCoderHeader("IPTCWTEXT", 0, "\062\000#\000\060\000=\000\042\000&\000#\000\060\000;\000&\000#\000\062\000;\000\042\000") \
  MagickCoderHeader("IPTCTEXT", 0, "2#0=\042&#0;&#2;\042") \
  MagickCoderHeader("IPTC", 0, "\034\002")



#define MagickMATHeaders \
  MagickCoderHeader("MAT", 0, "MATLAB 5.0 MAT-file,")




#define MagickMAGICKAliases \
  MagickCoderAlias("MAGICK", "GRANITE") \
  MagickCoderAlias("MAGICK", "H") \
  MagickCoderAlias("MAGICK", "LOGO") \
  MagickCoderAlias("MAGICK", "NETSCAPE") \
  MagickCoderAlias("MAGICK", "ROSE") \
  MagickCoderAlias("MAGICK", "WIZARD")








#define MagickJXLHeaders \
  MagickCoderHeader("JXL", 0, "\xff\x0a") \
  MagickCoderHeader("JXL", 0, "\x00\x00\x00\x0c\x4a\x58\x4c\x20\x0d\x0a\x87\x0a")


#define MagickJPEGAliases \
  MagickCoderAlias("JPEG", "JPE") \
  MagickCoderAlias("JPEG", "JPG") \
  MagickCoderAlias("JPEG", "JPS") \
  MagickCoderAlias("JPEG", "PJPEG")
#define MagickJPEGHeaders \
  MagickCoderHeader("JPEG", 0, "\377\330\377")
#define MagickJP2Aliases \
  MagickCoderAlias("JP2", "J2C") \
  MagickCoderAlias("JP2", "J2K") \
  MagickCoderAlias("JP2", "JPM") \
  MagickCoderAlias("JP2", "JPT") \
  MagickCoderAlias("JP2", "JPC")
#define MagickJP2Headers \
  MagickCoderHeader("JP2", 0, "\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a") \
  MagickCoderHeader("JPC", 0, "\x0d\x0a\x87\x0a") \
  MagickCoderHeader("J2K", 0, "\xff\x4f\xff\x51")


#define MagickJBIGAliases \
  MagickCoderAlias("JBIG", "BIE") \
  MagickCoderAlias("JBIG", "JBG")


#define MagickIPLHeaders \
  MagickCoderHeader("IPL", 0, "data")
#define MagickINLINEAliases \
  MagickCoderAlias("INLINE", "DATA")



#define MagickICONAliases \
  MagickCoderAlias("ICON", "CUR") \
  MagickCoderAlias("ICON", "ICO")

#define MagickHTMLAliases \
  MagickCoderAlias("HTML", "HTM") \
  MagickCoderAlias("HTML", "SHTML")





#define MagickHEICAliases \
  MagickCoderAlias("HEIC", "AVIF") \
  MagickCoderAlias("HEIC", "HEIF")
#define MagickHEICHeaders \
  MagickCoderHeader("AVIF", 4, "ftypavif") \
  MagickCoderHeader("HEIC", 4, "ftypheic") \
  MagickCoderHeader("HEIC", 4, "ftypheix") \
  MagickCoderHeader("HEIC", 4, "ftypmif1")

#define MagickHDRHeaders \
  MagickCoderHeader("HDR", 0, "#?RADIANCE") \
  MagickCoderHeader("HDR", 0, "#?RGBE")


#define MagickGRAYAliases \
  MagickCoderAlias("GRAY", "GRAYA")

#define MagickGRADIENTAliases \
  MagickCoderAlias("GRADIENT", "RADIAL-GRADIENT")

#define MagickGIFAliases \
  MagickCoderAlias("GIF", "GIF87")
#define MagickGIFHeaders \
  MagickCoderHeader("GIF", 0, "GIF8")



#define MagickFLIFHeaders \
  MagickCoderHeader("FLIF", 0, "FLIF")

#define MagickFL32Headers \
  MagickCoderHeader("FL32", 0, "FL32")
#define MagickFITSAliases \
  MagickCoderAlias("FITS", "FTS")
#define MagickFITSHeaders \
  MagickCoderHeader("FITS", 0, "IT0") \
  MagickCoderHeader("FITS", 0, "SIMPLE")
#define MagickFAXAliases \
  MagickCoderAlias("FAX", "G3") \
  MagickCoderAlias("FAX", "G4")
#define MagickFAXHeaders \
  MagickCoderHeader("FAX", 0, "DFAX")
#define MagickFARBFELDAliases \
  MagickCoderAlias("FARBFELD", "FF")
#define MagickFARBFELDHeaders \
  MagickCoderHeader("FARBFELD", 0, "farbfeld")

#define MagickEXRHeaders \
  MagickCoderHeader("EXR", 0, "\166\057\061\001")
#define MagickEPTAliases \
  MagickCoderAlias("EPT", "EPT2") \
  MagickCoderAlias("EPT", "EPT3")
#define MagickEPTHeaders \
  MagickCoderHeader("EPT", 0, "\305\320\323\306")
#define MagickEMFAliases \
  MagickCoderAlias("EMF", "WMF")
#define MagickEMFHeaders \
  MagickCoderHeader("EMF", 40, "\040\105\115\106\000\000\001\000") \
  MagickCoderHeader("WMF", 0, "\327\315\306\232") \
  MagickCoderHeader("WMF", 0, "\001\000\011\000")

#define MagickDPXHeaders \
  MagickCoderHeader("DPX", 0, "SDPX") \
  MagickCoderHeader("DPX", 0, "XPDS")


#define MagickDOTAliases \
  MagickCoderAlias("DOT", "GV")
#define MagickDOTHeaders \
  MagickCoderHeader("DOT", 0, "digraph")
#define MagickDNGAliases \
  MagickCoderAlias("DNG", "3FR") \
  MagickCoderAlias("DNG", "ARW") \
  MagickCoderAlias("DNG", "CR2") \
  MagickCoderAlias("DNG", "CR3") \
  MagickCoderAlias("DNG", "CRW") \
  MagickCoderAlias("DNG", "DCR") \
  MagickCoderAlias("DNG", "DCRAW") \
  MagickCoderAlias("DNG", "ERF") \
  MagickCoderAlias("DNG", "IIQ") \
  MagickCoderAlias("DNG", "KDC") \
  MagickCoderAlias("DNG", "K25") \
  MagickCoderAlias("DNG", "MEF") \
  MagickCoderAlias("DNG", "MRW") \
  MagickCoderAlias("DNG", "NEF") \
  MagickCoderAlias("DNG", "NRW") \
  MagickCoderAlias("DNG", "ORF") \
  MagickCoderAlias("DNG", "PEF") \
  MagickCoderAlias("DNG", "RAF") \
  MagickCoderAlias("DNG", "RAW") \
  MagickCoderAlias("DNG", "RMF") \
  MagickCoderAlias("DNG", "RW2") \
  MagickCoderAlias("DNG", "SRF") \
  MagickCoderAlias("DNG", "SR2") \
  MagickCoderAlias("DNG", "X3F")
#define MagickDNGHeaders \
  MagickCoderHeader("CR2", 0, "\115\115\000\052\000\020\000\000\122\103\002") \
  MagickCoderHeader("CR2", 0, "\111\111\052\000\020\000\000\000\103\122\002") \
  MagickCoderHeader("CRW", 0, "II\x1a\x00\x00\x00HEAPCCDR") \
  MagickCoderHeader("ORF", 0, "IIRO\x08\x00\x00\x00") \
  MagickCoderHeader("MRW", 0, "\x00MRM") \
  MagickCoderHeader("RAF", 0, "FUJIFILMCCD-RAW ")

#define MagickDJVUHeaders \
  MagickCoderHeader("DJVU", 0, "AT&TFORM")
#define MagickDIBAliases \
  MagickCoderAlias("DIB", "ICODIB")
#define MagickDIBHeaders \
  MagickCoderHeader("DIB", 0, "\050\000")


#define MagickDDSAliases \
  MagickCoderAlias("DDS", "DXT1") \
  MagickCoderAlias("DDS", "DXT5")
#define MagickDDSHeaders \
  MagickCoderHeader("DDS", 0, "DDS ")

#define MagickDCMHeaders \
  MagickCoderHeader("DCM", 128, "DICM")




#define MagickCMYKAliases \
  MagickCoderAlias("CMYK", "CMYKA")








#define MagickCINHeaders \
  MagickCoderHeader("CIN", 0, "\200\052\137\327")


#define MagickCALSAliases \
  MagickCoderAlias("CALS", "CAL")
#define MagickCALSHeaders \
  MagickCoderHeader("CALS", 0, "srcdocid:") \
  MagickCoderHeader("CALS", 8, "rorient:") \
  MagickCoderHeader("CALS", 9, "rorient:") \
  MagickCoderHeader("CALS", 21, "version: MIL-STD-1840")
#define MagickBRAILLEAliases \
  MagickCoderAlias("BRAILLE", "BRF") \
  MagickCoderAlias("BRAILLE", "UBRL") \
  MagickCoderAlias("BRAILLE", "UBRL6") \
  MagickCoderAlias("BRAILLE", "ISOBRL") \
  MagickCoderAlias("BRAILLE", "ISOBRL6")

#define MagickBMPAliases \
  MagickCoderAlias("BMP", "BMP2") \
  MagickCoderAlias("BMP", "BMP3")
#define MagickBMPHeaders \
  MagickCoderHeader("BMP", 0, "BA") \
  MagickCoderHeader("BMP", 0, "BM") \
  MagickCoderHeader("BMP", 0, "CI") \
  MagickCoderHeader("BMP", 0, "CP") \
  MagickCoderHeader("BMP", 0, "IC") \
  MagickCoderHeader("BMP", 0, "IP")
#define MagickBGRAliases \
  MagickCoderAlias("BGR", "BGRA") \
  MagickCoderAlias("BGR", "BGRO")












#define MagickImageCoderSignature  ((size_t) \
  (((MagickLibInterface) << 8) | MAGICKCORE_QUANTUM_DEPTH))
#define MagickImageFilterSignature  ((size_t) \
  (((MagickLibInterface) << 8) | MAGICKCORE_QUANTUM_DEPTH))

#define ThrowBinaryException(severity,tag,context) \
{ \
  (void) ThrowMagickException(exception,GetMagickModule(),severity, \
    tag == (const char *) NULL ? "unknown" : tag,"`%s'",context); \
  return(MagickFalse); \
}
#define ThrowFatalException(severity,tag) \
{ \
  char \
    *fatal_message; \
 \
  ExceptionInfo \
    *fatal_exception; \
 \
  fatal_exception=AcquireExceptionInfo(); \
  fatal_message=GetExceptionMessage(errno); \
  (void) ThrowMagickException(fatal_exception,GetMagickModule(),severity, \
    tag == (const char *) NULL ? "unknown" : tag,"`%s'",fatal_message); \
  fatal_message=DestroyString(fatal_message); \
  CatchException(fatal_exception); \
  (void) DestroyExceptionInfo(fatal_exception); \
  MagickCoreTerminus(); \
  _exit((int) (severity-FatalErrorException)+1); \
}
#define ThrowFileException(exception,severity,tag,context) \
{ \
  char \
    *file_message; \
 \
  file_message=GetExceptionMessage(errno); \
  (void) ThrowMagickException(exception,GetMagickModule(),severity, \
    tag == (const char *) NULL ? "unknown" : tag,"'%s': %s",context, \
    file_message); \
  file_message=DestroyString(file_message); \
}
#define ThrowImageException(severity,tag) \
{ \
  (void) ThrowMagickException(exception,GetMagickModule(),severity, \
    tag == (const char *) NULL ? "unknown" : tag,"`%s'",image->filename); \
  return((Image *) NULL); \
}
#define ThrowReaderException(severity,tag) \
{ \
  (void) ThrowMagickException(exception,GetMagickModule(),severity,  \
    tag == (const char *) NULL ? "unknown" : tag,"`%s'",image_info->filename); \
  if ((image) != (Image *) NULL) \
    { \
      (void) CloseBlob(image); \
      image=DestroyImageList(image); \
    } \
  return((Image *) NULL); \
}
#define ThrowWriterException(severity,tag) \
{ \
  (void) ThrowMagickException(exception,GetMagickModule(),severity,  \
    tag == (const char *) NULL ? "unknown" : tag,"`%s'",image->filename); \
  if (image_info->adjoin != MagickFalse) \
    while (image->previous != (Image *) NULL) \
      image=image->previous; \
  (void) CloseBlob(image); \
  return(MagickFalse); \
}

# define magick_module  _module   
# define GetMagickModule()  "__FILE__",__func__,(unsigned long) "__LINE__"

#define MagickLogFilename  "log.xml"

#   define DirectoryListSeparator  ';'
#   define DirectorySeparator  "\\"
# define DisableMSCWarning(nr) __pragma(warning(push)) \
  __pragma(warning(disable:nr))
#  define EditorOptions  ""
#  define Exit  exit
#  define HAVE_STRERROR
#    define HAVE_TIFFCONF_H
#  define IsBasenameSeparator(c) \
  (((c) == ']') || ((c) == ':') || ((c) == '/') ? MagickTrue : MagickFalse)
# define MAGICKCORE_BUILD_MODULES
# define MAGICKCORE_CONFIG_H
#define MAGICKCORE_IMPLEMENTATION  1
#  define MAGICKCORE_LIBRARY_PATH  "sys$login:"
#  define MAGICKCORE_MODULES_SUPPORT
#  define MAGICKCORE_OPENCL_SUPPORT  1
#  define MAGICKCORE_OPENMP_SUPPORT  1
#  define MAGICKCORE_SHARE_PATH  "sys$login:"

#  define MAGICKCORE_WINDOWS_SUPPORT
#define MAGICK_SSIZE_MAX  (SSIZE_MAX)
#define MAGICK_SSIZE_MIN  (-(SSIZE_MAX)-1)
#define MagickMaxRecursionDepth  600
#   define NAMLEN(dirent) (dirent)->d_namlen
#define O_BINARY  0x00
#define PATH_MAX  4096
# define PreferencesDefaults  "~\."
#  define ProcessPendingEvents(text)
#  define ReadCommandlLine(argc,argv)
# define RestoreMSCWarning __pragma(warning(pop))
#  define STDC
#define STDIN_FILENO  0x00
#  define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#  define S_ISREG(mode) (((mode) & S_IFMT) == S_IFREG)
# define S_MODE (S_IRUSR | S_IWUSR)
#  define SetNotifyHandlers \
    SetErrorHandler(NTErrorHandler); \
    SetWarningHandler(NTWarningHandler)
#define Swap(x,y) ((x)^=(y), (y)^=(x), (x)^=(y))
#  define X11_APPLICATION_PATH  "decw$system_defaults:"
#    define X11_PREFERENCES_PATH  "~\\."

# define _FILE_OFFSET_BITS MAGICKCORE__FILE_OFFSET_BITS
# define const  _magickcore_const
#   define dirent direct
# define inline  _magickcore_inline
#  define magick_restrict restrict

#define MagickCoreSignature  0xabacadabUL
#        define MagickExport __attribute__ ((dllimport))
#  define MagickPathExtent  4096  
#  define MagickPrivate
#define MagickTimeExtent  26
#define MaxTextExtent  MagickPathExtent
#      define ModuleExport __attribute__ ((dllexport))
#    define _MAGICKDLL_
#  define _MAGICKLIB_
#  define magick_aligned(x,y)  x __attribute__((aligned(y)))
#  define magick_alloc_size(x)  __attribute__((__alloc_size__(x)))
#  define magick_alloc_sizes(x,y)  __attribute__((__alloc_size__(x,y)))
#  define magick_attribute  __attribute__
#  define magick_cold_spot  __attribute__((__cold__))
#  define magick_hot_spot  __attribute__((__hot__))
#  define magick_unused(x)  magick_unused_ ## x __attribute__((unused))
#define MAGICKCORE_ABI_SUFFIX  "Q" MAGICKCORE_STRING_XQUOTE(MAGICKCORE_QUANTUM_DEPTH)
#define MAGICKCORE_ALIGN_DOWN(n, power_of_2) \
  ((n) & ~MAGICKCORE_BITS_BELOW(power_of_2))
#define MAGICKCORE_ALIGN_UP(n, power_of_2) \
  MAGICKCORE_ALIGN_DOWN((n) + MAGICKCORE_MAX_ALIGNMENT_PADDING(power_of_2),power_of_2)
#define MAGICKCORE_BITS_BELOW(power_of_2) \
  ((power_of_2)-1)
#  define MAGICKCORE_CODER_PATH "sys$login:"
# define MAGICKCORE_CODER_RELATIVE_PATH MAGICKCORE_MODULES_RELATIVE_PATH MAGICKCORE_DIR_SEPARATOR MAGICKCORE_CODER_DIRNAME
# define MAGICKCORE_DIAGNOSTIC_IGNORE_MAYBE_UNINITIALIZED() \
   _Pragma("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define MAGICKCORE_DIAGNOSTIC_POP() \
   _Pragma("GCC diagnostic pop")
# define MAGICKCORE_DIAGNOSTIC_PUSH() \
   _Pragma("GCC diagnostic push")
#  define MAGICKCORE_FILTER_PATH  "sys$login:"
# define MAGICKCORE_FILTER_RELATIVE_PATH MAGICKCORE_MODULES_RELATIVE_PATH MAGICKCORE_DIR_SEPARATOR MAGICKCORE_FILTER_DIRNAME
# define MAGICKCORE_HDRI_ENABLE MAGICKCORE_HDRI_ENABLE_OBSOLETE_IN_H
# define MAGICKCORE_HDRI_SUPPORT 1
#define MAGICKCORE_IS_NOT_ALIGNED(n, power_of_2) \
  ((n) & MAGICKCORE_BITS_BELOW(power_of_2))
#define MAGICKCORE_IS_NOT_POWER_OF_2(n) \
  MAGICKCORE_IS_NOT_ALIGNED((n), (n))

#define MAGICKCORE_MAX_ALIGNMENT_PADDING(power_of_2) \
  MAGICKCORE_BITS_BELOW(power_of_2)
# define MAGICKCORE_MODULES_DIRNAME MAGICKCORE_MODULES_BASEDIRNAME "-" MAGICKCORE_ABI_SUFFIX
#  define MAGICKCORE_MODULES_PATH MAGICKCORE_LIBRARY_PATH MAGICKCORE_DIR_SEPARATOR MAGICKCORE_MODULES_DIRNAME
#define MAGICKCORE_MODULES_RELATIVE_PATH MAGICKCORE_LIBRARY_RELATIVE_PATH MAGICKCORE_DIR_SEPARATOR MAGICKCORE_MODULES_DIRNAME
# define MAGICKCORE_QUANTUM_DEPTH MAGICKCORE_QUANTUM_DEPTH_OBSOLETE_IN_H
# define MAGICKCORE_SHAREARCH_DIRNAME MAGICKCORE_SHAREARCH_BASEDIRNAME "-" MAGICKCORE_ABI_SUFFIX
#  define MAGICKCORE_SHAREARCH_PATH MAGICKCORE_LIBRARY_PATH MAGICKCORE_DIR_SEPARATOR MAGICKCORE_SHAREARCH_DIRNAME MAGICKCORE_DIR_SEPARATOR
#define MAGICKCORE_SHAREARCH_RELATIVE_PATH MAGICKCORE_LIBRARY_RELATIVE_PATH MAGICKCORE_DIR_SEPARATOR MAGICKCORE_SHAREARCH_DIRNAME
#define MAGICKCORE_STRING_QUOTE(str) #str
#define MAGICKCORE_STRING_XQUOTE(str) MAGICKCORE_STRING_QUOTE(str)
#  define MAGICK_COMPILER_WARNING(w) _Pragma(MAGICKCORE_STRING_QUOTE(GCC warning w))
#  define __CYGWIN__  __CYGWIN32__
#  define __has_builtin(x) 0
