#    define PDFIO_DEBUG(...)		fprintf(stderr, __VA_ARGS__)
#    define PDFIO_DEBUG_ARRAY(array)	_pdfioArrayDebug(array, stderr)
#    define PDFIO_DEBUG_DICT(dict)	_pdfioDictDebug(dict, stderr)
#    define PDFIO_DEBUG_VALUE(value)	_pdfioValueDebug(value, stderr)
#  define PDFIO_PRIVATE_H
#    define _CRT_SECURE_NO_WARNINGS
#    define _PDFIO_INTERNAL
#    define _PDFIO_NONNULL(...)	__attribute__ ((nonnull(__VA_ARGS__)))
#    define _PDFIO_NORETURN
#    define _PDFIO_PRIVATE
