#include<cstdint>


#include<atomic>
#include<poll.h>

#include<string.h>



#include<errno.h>


#include<stdint.h>



#include<sys/types.h>

#include<functional>


#include<set>






#include<map>

#include<netinet/in.h>




#include<sys/ioctl.h>
#include<vector>

#include<unistd.h>
#include<sys/socket.h>

#include<debug/map>




		#define STEAMNETWORKINGSOCKETS_SNP_PARANOIA 2
#define BSteamNetworkingIdentityToProtobuf( identity, msg, field_identity_string, field_identity_legacy_binary, field_legacy_steam_id, errMsg ) ( \
		( (identity).GetSteamID64() ? (void)(msg).set_ ## field_legacy_steam_id( (identity).GetSteamID64() ) : (void)0 ), \
		BSteamNetworkingIdentityToProtobufInternal( identity, (msg).mutable_ ## field_identity_string(), (msg).mutable_ ## field_identity_legacy_binary(), errMsg ) \
	)
#define DEFINE_CONNECTON_DEFAULT_CONFIGVAL( type, name, ... ) \
	ConnectionConfigDefaultValue<type> g_ConfigDefault_##name( k_ESteamNetworkingConfig_##name, #name, V_offsetof(ConnectionConfig, m_##name), __VA_ARGS__ )
#define DEFINE_GLOBAL_CONFIGVAL( type, name, ... ) \
	GlobalConfigValue<type> g_Config_##name( k_ESteamNetworkingConfig_##name, #name, __VA_ARGS__ )

#define SteamNetworkingIdentityFromProtobuf( identity, msg, field_identity_string, field_identity_legacy_binary, field_legacy_steam_id, errMsg ) \
	( \
		(msg).has_ ##field_identity_string() ? ( SteamNetworkingIdentity_ParseString( &(identity), sizeof(identity), (msg).field_identity_string().c_str() ) ? +1 : ( V_strcpy_safe( errMsg, "Failed to parse string" ), -1 ) ) \
		: (msg).has_ ##field_identity_legacy_binary() ? ( BSteamNetworkingIdentityFromLegacyBinaryProtobuf( identity, (msg).field_identity_legacy_binary(), errMsg ) ? +1 : -1 ) \
		: (msg).has_ ##field_legacy_steam_id() ? ( BSteamNetworkingIdentityFromLegacySteamID( identity, (msg).field_legacy_steam_id(), errMsg ) ? +1 : -1 ) \
		: ( V_strcpy_safe( errMsg, "No identity data" ), 0 ) \
	)
#define SteamNetworkingIdentityToProtobuf( identity, msg, field_identity_string, field_identity_legacy_binary, field_legacy_steam_id ) \
	{ SteamDatagramErrMsg identityToProtobufErrMsg; \
		if ( !BSteamNetworkingIdentityToProtobuf( identity, msg, field_identity_string, field_identity_legacy_binary, field_legacy_steam_id, identityToProtobufErrMsg ) ) { \
			AssertMsg2( false, "Failed to serialize identity to %s message.  %s", msg.GetTypeName().c_str(), identityToProtobufErrMsg ); \
		} \
	}
#define V_offsetof(class, field) (int)((intptr_t)&((class *)(0+sizeof(intptr_t)))->field - sizeof(intptr_t))
		#define closesocket close
		#define ioctlsocket ioctl
		#define likely(x) __builtin_expect (!!(x), 1)
		#define unlikely(x) __builtin_expect (!!(x), 0)

#define STEAMNETWORKINGUTILS_INTERFACE_VERSION "SteamNetworkingUtils003"



#define DLL_CLASS_EXPORT PLAT_DECL_EXPORT
#define DLL_CLASS_IMPORT PLAT_DECL_IMPORT
#define DLL_EXPORT extern
#define DLL_GLOBAL_EXPORT PLAT_DECL_EXPORT
#define DLL_GLOBAL_IMPORT extern PLAT_DECL_IMPORT
#define DLL_IMPORT extern

	    #define FORCEINLINE          inline __attribute__ ((always_inline))
    	#define FORCEINLINE_TEMPLATE inline

#define NOALIAS __declspec(noalias)
#define OVERRIDE override
#define PLAT_DECL_EXPORT __declspec( dllexport )
#define PLAT_DECL_IMPORT __declspec( dllimport )


#define STATIC_TEMPLATE_INLINE static
		#define  STDCALL
#define UNALIGNED __unaligned

		#define  __stdcall			__attribute__ ((__stdcall__))
    #define COMPILER_CLANG 1
		#define COMPILER_GCC 1
		#define COMPILER_MSVC64 1
		#define COMPILER_SNC 1
		#define IsARM() true
		#define IsAndroid() true
		#define IsLinux() true
		#define IsOSX() true



#define VALVE_BIG_ENDIAN 1
			#define VALVE_EXPLICIT_CONVERSION_OP 1
			#define VALVE_INITIALIZER_LIST_SUPPORT 1
#define VALVE_LITTLE_ENDIAN 1
			#define VALVE_RVALUE_REFS 1


#define SpewBug( ... ) SpewTypeDefaultGroup( k_ESteamNetworkingSocketsDebugOutputType_Bug, __VA_ARGS__ )
#define SpewBugGroup( nGroup, ... ) SpewTypeGroup( k_ESteamNetworkingSocketsDebugOutputType_Bug, (nGroup), __VA_ARGS__ )
#define SpewDebug( ... ) SpewTypeDefaultGroup( k_ESteamNetworkingSocketsDebugOutputType_Debug, __VA_ARGS__ )
#define SpewDebugGroup( nGroup, ... ) SpewTypeGroup( k_ESteamNetworkingSocketsDebugOutputType_Debug, (nGroup), __VA_ARGS__ )
#define SpewError( ... ) SpewTypeDefaultGroup( k_ESteamNetworkingSocketsDebugOutputType_Error, __VA_ARGS__ )
#define SpewErrorGroup( nGroup, ... ) SpewTypeGroup( k_ESteamNetworkingSocketsDebugOutputType_Error, (nGroup), __VA_ARGS__ )
#define SpewImportant( ... ) SpewTypeDefaultGroup( k_ESteamNetworkingSocketsDebugOutputType_Important, __VA_ARGS__ )
#define SpewImportantGroup( nGroup, ... ) SpewTypeGroup( k_ESteamNetworkingSocketsDebugOutputType_Important, (nGroup), __VA_ARGS__ )
#define SpewMsg( ... ) SpewTypeDefaultGroup( k_ESteamNetworkingSocketsDebugOutputType_Msg, __VA_ARGS__ )
#define SpewMsgGroup( nGroup, ... ) SpewTypeGroup( k_ESteamNetworkingSocketsDebugOutputType_Msg, (nGroup), __VA_ARGS__ )
#define SpewTypeDefaultGroup( eType, ... ) SpewTypeGroup( eType, g_eDefaultGroupSpewLevel, __VA_ARGS__ )
#define SpewTypeDefaultGroupRateLimited( usecNow, eType, ... ) ( ( (eType) <= g_eDefaultGroupSpewLevel && BRateLimitSpew( usecNow ) ) ? ReallySpewType( (eType), __VA_ARGS__ ) : (void)0 )
#define SpewTypeGroup( eType, nGroup, ... ) ( ( (eType) <= (nGroup) ) ? ReallySpewType( (eType), __VA_ARGS__ ) : (void)0 )
#define SpewVerbose( ... ) SpewTypeDefaultGroup( k_ESteamNetworkingSocketsDebugOutputType_Verbose, __VA_ARGS__ )
#define SpewVerboseGroup( nGroup, ... ) SpewTypeGroup( k_ESteamNetworkingSocketsDebugOutputType_Verbose, (nGroup), __VA_ARGS__ )
#define SpewWarning( ... ) SpewTypeDefaultGroup( k_ESteamNetworkingSocketsDebugOutputType_Warning, __VA_ARGS__ )
#define SpewWarningGroup( nGroup, ... ) SpewTypeGroup( k_ESteamNetworkingSocketsDebugOutputType_Warning, (nGroup), __VA_ARGS__ )
#define SpewWarningRateLimited( usecNow, ... ) SpewTypeDefaultGroupRateLimited( usecNow, k_ESteamNetworkingSocketsDebugOutputType_Warning, __VA_ARGS__ )


