
#include<iterator>

#include<cstdio>


#include<climits>

#include<memory>



#include<deque>







#include<cctype>
#include<cinttypes>



#include<zlib.h>
#include<ctime>
#include<math.h>

#include<cstdlib>




#include<cstdint>
#include<chrono>
#include<type_traits>

#include<algorithm>

#include<set>
#include<list>
#include<cstdarg>
#include<stdexcept>


#include<sys/types.h>

#include<stdint.h>


#include<vector>



#include<bitset>
#include<cstring>
#include<map>
#include<unordered_set>
#include<string>
#define CRAWL "Dungeon Crawl Stone Soup"
#define OUTS(x) utf8_to_mb(x).c_str()
#define OUTW(x) utf8_to_16(x).c_str()
#define CASE_ESCAPE case ESCAPE: case CONTROL('G'): case -1:
#define TAG_UNFOUND -20404
#define DEF_BITFIELD(fieldT, ...) \
    typedef enum_bitfield<__VA_ARGS__> fieldT; \
    EXPANDMACRO(DEF_BITFIELD_OPERATORS(fieldT, __VA_ARGS__, ))
#define DEF_BITFIELD_OPERATORS(fieldT, flagT, ...) \
    inline constexpr fieldT operator|(flagT a, flagT b)  { return fieldT(a) | b; } \
    inline constexpr fieldT operator|(flagT a, fieldT b) { return fieldT(a) | b; } \
    inline constexpr fieldT operator&(flagT a, flagT b)  { return fieldT(a) & b; } \
    inline constexpr fieldT operator&(flagT a, fieldT b) { return fieldT(a) & b; } \
    inline constexpr fieldT operator^(flagT a, flagT b)  { return fieldT(a) ^ b; } \
    inline constexpr fieldT operator^(flagT a, fieldT b) { return fieldT(a) ^ b; } \
    inline constexpr fieldT operator~(flagT a) { return ~fieldT(a); } \
    COMPILE_CHECK(is_enum<flagT>::value)
#define EXPANDMACRO(x) x
#define crawl_state (*real_crawl_state)
#define ACROBAT_AMULET_ACTIVE "acrobat_amulet_active"
#define BARBS_MOVE_KEY "moved_with_barbs_status"
#define EMERGENCY_FLIGHT_KEY "emergency_flight"
#define FORCE_MAPPABLE_KEY "force_mappable"
#define FROZEN_RAMPARTS_KEY "frozen_ramparts_position"
#define FROZEN_RAMPARTS_RADIUS 3
#define HORROR_LVL_EXTREME  3
#define HORROR_LVL_OVERWHELMING  5
#define HORROR_PENALTY_KEY "horror_penalty"
#define ICY_ARMOUR_KEY "ozocubu's_armour_pow"
#define MANA_REGEN_AMULET_ACTIVE "mana_regen_amulet_active"
#define NOXIOUS_BOG_KEY "noxious_bog_pow"
#define PARALYSED_BY_KEY "paralysed_by"
#define PETRIFIED_BY_KEY "petrified_by"
#define POWERED_BY_DEATH_KEY "powered_by_death_strength"
#define REGEN_AMULET_ACTIVE "regen_amulet_active"
#define SAP_MAGIC_KEY "sap_magic_amount"
#define SEVERE_CONTAM_LEVEL 3
#define SONG_OF_SLAYING_KEY "song_of_slaying_bonus"
#define TEMP_WATERWALK_KEY "temp_waterwalk"
#define TRANSFORM_POW_KEY "transform_pow"
#define you (*real_you)
#define HERD_COMFORT_RANGE 6
#define mrd(res, lev) (resists_t)((res) * ((lev) & 7))
#define BIT(x) ((uint64_t)1<<(x))
#define ACQUIRE_ITEMS_KEY "acquire_items" 
#define ACQUIRE_KEY "acquired" 
#define HEPLIAKLQANA_ALLY_GENDER_KEY "hepliaklqana_ally_gender"
#define HEPLIAKLQANA_ALLY_NAME_KEY "hepliaklqana_ally_name"
#define HEPLIAKLQANA_ALLY_TYPE_KEY "hepliaklqana_ally_type"
#define MON_GENDER_KEY "mon_gender"
#define PLACE_LIMIT 5   
#define NUM_FIXED_BOOKS      (MAX_FIXED_BOOK + 1)
#define NUM_NORMAL_BOOKS     (MAX_NORMAL_BOOK + 1)
#define LONGSIZE (sizeof(unsigned long)*8)
#define ULONG_MAX ((unsigned long)(-1))
#define ANDROID_ASSETS "ANDROID_ASSETS"
#define ARRAYSZ(x) (sizeof(x) / sizeof(x[0]))
#define AUTOMATIC_HIT           1500
#define BOUNDARY_BORDER         1
#define COLFLAG_CURSES_BRIGHTEN          0x0008
#define COLFLAG_FEATURE_ITEM             0x2000
#define COLFLAG_FRIENDLY_MONSTER         0x0100
#define COLFLAG_ITEM_HEAP                0x1000
#define COLFLAG_MASK                     0xFF00
#define COLFLAG_MAYSTAB                  0x0800
#define COLFLAG_NEUTRAL_MONSTER          0x0200
#define COLFLAG_REVERSE                  0x8000
#define COLFLAG_TRAP_ITEM                0x4000
#define COLFLAG_WILLSTAB                 0x0400
#define CONTROL(xxx)          ((xxx) - 'A' + 1)
#define ENDOFPACK 52
#define ENV_SHOW_DIAMETER (ENV_SHOW_OFFSET * 2 + 1)
#define ENV_SHOW_OFFSET LOS_MAX_RANGE
#define ESCAPE '\x1b'           
     #define FALSE 0
  #define FEATURE_MIMIC_CHANCE 1
#define GDM 105
#define GXM 80
#define GYM 70
#define ITEM_IN_INVENTORY (coord_def(-1, -1))
#define ITEM_IN_MONSTER_INVENTORY (coord_def(-2, -2))
#define ITEM_IN_SHOP 32767
#define KEY_MACRO_DISABLE_MORE -1
#define KEY_MACRO_ENABLE_MORE  -2
#define KEY_MACRO_MORE_PROTECT -10
#define LOS_DEFAULT_RANGE 7
#define LOS_MAX_RANGE LOS_RADIUS
#define LOS_RADIUS 8
#define MAX_BRANCH_DEPTH 27
#define MAX_ITEMS 2000
#define MAX_MONSTER_HP 10000
#define MAX_MONS_ALLOC 20
#define MAX_NUM_ATTACKS 4
#define MAX_RANDOM_SHOPS  5
#define MAX_SUBTYPES   60
#define MAX_UNRANDARTS 150
#define MIN_COLS  79
#define MIN_LINES 24
#define MSG_MIN_HEIGHT  5
#define NON_ITEM 27000
#define PAN_MONS_ALLOC 10
#define PCOLOUR(desc) ((desc) % PDC_NCOLOURS)
#define PDESCQ(qualifier, colour) (((qualifier) * PDC_NCOLOURS) + (colour))
#define PDESCS(colour) (colour)
#define PI 3.14159265359f
#define POT_MAGIC_MP (10 + random2avg(28, 3))
#define PQUAL(desc)   ((desc) / PDC_NCOLOURS)
#define RANDOM_ELEMENT(x) (x[random2(ARRAYSZ(x))])

#define TORNADO_RADIUS 5
     #define TRUE 1
#define VAULTS_ENTRY_RUNES 1
#define VIEW_BASE_WIDTH 33
#define VIEW_MIN_HEIGHT ENV_SHOW_DIAMETER
#define VIEW_MIN_WIDTH  ENV_SHOW_DIAMETER
#define VORTEX_RADIUS 3
#define X_BOUND_1               (-1 + BOUNDARY_BORDER)
#define X_BOUND_2               (GXM - BOUNDARY_BORDER)
#define X_WIDTH                 (X_BOUND_2 - X_BOUND_1 + 1)
#define Y_BOUND_1               (-1 + BOUNDARY_BORDER)
#define Y_BOUND_2               (GYM - BOUNDARY_BORDER)
#define Y_WIDTH                 (Y_BOUND_2 - Y_BOUND_1 + 1)
#define ZIG_ENTRY_RUNES 2
#define ZOT_ENTRY_RUNES 3
#define berserk_div(x) div_rand_round((x) * 2, 3)
#define berserk_mul(x) div_rand_round((x) * 3, 2)
#define grd    env.grid
#define haste_div(x) div_rand_round((x) * 2, 3)
#define haste_mul(x) div_rand_round((x) * 3, 2)
#define igrd   env.igrid
#define menv   env.mons
#define mgrd   env.mgrid
#define mitm   env.item
#define BEAM_STOP       1000        
#define IOOD_CASTER "iood_caster"
#define IOOD_DIST "iood_distance"
#define IOOD_FLAWED "iood_flawed"
#define IOOD_KC "iood_kc"
#define IOOD_MID "iood_mid"
#define IOOD_POW "iood_pow"
#define IOOD_REFLECTOR "iood_reflector"
#define IOOD_TPOS "iood_tpos"
#define IOOD_VX "iood_vx"
#define IOOD_VY "iood_vy"
#define IOOD_X "iood_x"
#define IOOD_Y "iood_y"
#define fail_check() if (fail) return spret::fail
    #define FNV64 1099511628211ULL
#define Options (*real_Options)
# define dprf(...) ((void)0)
#define TORPOR_SLOWED_KEY "torpor_slowed"
#define DEATH_NAME_LENGTH 10
#define MELT_ARMOUR_KEY "melt_armour"
#  define ASSERT_IN_BOUNDS(where)                                           \
     ASSERTM(in_bounds(where), "%s = (%d,%d)", #where, (where).x, (where).y)
#  define ASSERT_IN_BOUNDS_OR_ORIGIN(where)               \
     ASSERTM(in_bounds(where) || (where).origin(),        \
            "%s = (%d,%d)", #where, (where).x, (where).y)
#define DEVENT_METATABLE "dgn.devent"
#define ITEM_METATABLE "item.itemaccess"
#define MAPGRD_COL_METATABLE "dgn.mapgrdcol"
#define MAPGRD_METATABLE "dgn.mapgrd"
#define MAPMARK_METATABLE "dgn.mapmark"
#define MAP_METATABLE "dgn.mtmap"
#define MONS_METATABLE "monster.monsaccess"
#define clua (*real_clua)
#define unsafe_path_f(...) unsafe_path(make_stringf(__VA_ARGS__))
#define dlua (*real_dlua)
#define ASSERT_DLUA \
    do {                                                            \
        if (CLua::get_vm(ls).managed_vm)                            \
            luaL_error(ls, "Operation forbidden in end-user script");   \
    } while (false)
#define COORDS(c, p1, p2)                                \
    GETCOORD(c, p1, p2, in_bounds)
#define COORDSHOW(c, p1, p2) \
    GETCOORD(c, p1, p2, in_show_bounds)
#define DEVENT(ls, n, var) \
dgn_event *var = *(dgn_event **) luaL_checkudata(ls, n, DEVENT_METATABLE)
#define FEAT(f, pos) \
dungeon_feature_type f = check_lua_feature(ls, pos)
#define GETCOORD(c, p1, p2, boundfn)                      \
    coord_def c;                                          \
    c.x = luaL_safe_checkint(ls, p1);                          \
    c.y = luaL_safe_checkint(ls, p2);                          \
    if (!boundfn(c))                                        \
        luaL_error(                                          \
            ls,                                                 \
            make_stringf("Point (%d,%d) is out of bounds",      \
                         c.x, c.y).c_str());                    \
    else {};
#define LEVEL(br, pos)                                              \
    const char *branch_name = luaL_checkstring(ls, pos);            \
    branch_type br = branch_by_abbrevname(branch_name);             \
    if (br == NUM_BRANCHES)                                         \
        luaL_error(ls, "Expected branch name");
#define LINES(ls, n, var) \
map_lines &var = (*(map_def **) luaL_checkudata(ls, n, MAP_METATABLE))->map
#define LUAFN(name) static int name(lua_State *ls)
#define LUARET1(name, type, val) \
    static int name(lua_State *ls) \
    { \
        lua_push##type(ls, val); \
        return 1; \
    }
#define LUARET2(name, type, val1, val2)  \
    static int name(lua_State *ls) \
    { \
        lua_push##type(ls, val1); \
        lua_push##type(ls, val2); \
        return 2; \
    }
#define LUAWRAP(name, wrapexpr) \
    static int name(lua_State *ls) \
    {   \
        UNUSED(ls); \
        wrapexpr; \
        return 0; \
    }
#define LUA_ITEM(ls, name, n) \
item_def *item = *(item_def **) luaL_checkudata(ls, n, ITEM_METATABLE)
#define MAP(ls, n, var) \
map_def *var = *(map_def **) luaL_checkudata(ls, n, MAP_METATABLE)
#define MAPMARKER(ls, n, var) \
map_marker *var = *(map_marker **) luaL_checkudata(ls, n, MAPMARK_METATABLE)
#define PLUARET(type, val) \
    do { \
        lua_push##type(ls, val); \
        return 1; \
    } while (false)
#define luaL_safe_checkint(L,n)    ((int)luaL_safe_checkinteger(L, (n)))
#define luaL_safe_checklong(L,n)   ((long)luaL_safe_checkinteger(L, (n)))
    #define ALT_FILE_SEPARATOR '\\'
#define CLUA_MAX_MEMORY_USE (16 * 1024)
# define COMPILE_CHECK(expr) static_assert((expr), #expr)
#   define CRAWL_PRINTF_FORMAT __MINGW_PRINTF_FORMAT
    #define CURSES_SET_ESCDELAY 20











    #define DGL_CLEAR_SCREEN "\033[2J"



    #define DGL_MESSAGE_CHECK_INTERVAL 1








#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
    TypeName(const TypeName&) = delete;   \
    void operator=(const TypeName&) = delete
#define ENUM_INT64 : unsigned long long
    #define FILE_SEPARATOR '/'
# define GDB_PATH "/usr/local/bin/gdb"

#define IDLE_TIME_CLAMP  30
# define IMMUTABLE __attribute__ ((const))

        #define NDEBUG                  

# define NORETURN __attribute__ ((noreturn))
#define NUM_STORED_MESSAGES   1000
# define PRINTF(x, dfmt) const char *format dfmt, ...) \
                   __attribute__((format (CRAWL_PRINTF_FORMAT, x+1, x+2))
# define PURE __attribute__ ((pure))


#define SAVE_SUFFIX ".cs"
    #define SCORE_FILE_ENTRIES 1000
# define SIZE_MAX (std::numeric_limits<std::size_t>::max())
    #define TIME_FN gmtime




# define _WIN32_WINNT 0x501
#define DEF_ENUM_INC(T) \
    static inline T &operator++(T &x) { return x = static_cast<T>(x + 1); } \
    static inline T &operator--(T &x) { return x = static_cast<T>(x - 1); } \
    static inline T operator++(T &x, int) { T y = x; ++x; return y; } \
    static inline T operator--(T &x, int) { T y = x; --x; return y; } \
    COMPILE_CHECK(is_enum<T>::value)
#define MAX_NAME_LENGTH 30
#define MID_ANON_FRIEND   ((mid_t)0xffff0000)
#define MID_FIRST_NON_MONSTER MID_ANON_FRIEND
#define MID_NOBODY        ((mid_t)0x00000000)
#define MID_PLAYER        ((mid_t)0xffffffff)
#define MID_YOU_FAULTLESS ((mid_t)0xffff0001)
#define PRImidt PRIu32

#define bad_level_id_f(...) bad_level_id(make_stringf(__VA_ARGS__))
#define VEC_MAX_SIZE  0xFFFF

#define MAX_CHUNK_NAME_LENGTH 255

#define ASSERT(p)                                       \
    do {                                                \
        WARN_PUSH                                       \
        IGNORE_ASSERT_WARNINGS                          \
        if (!(p)) AssertFailed(#p, "__FILE__", "__LINE__"); \
        WARN_POP                                        \
    } while (false)
#define ASSERTM(p,text,...)                             \
    do {                                                \
        WARN_PUSH                                       \
        IGNORE_ASSERT_WARNINGS                          \
        if (!(p)) AssertFailed(#p, "__FILE__", "__LINE__", text, __VA_ARGS__); \
        WARN_POP                                        \
    } while (false)

#define ASSERT_LESS(x, xmax)                                                  \
  do {                                                                        \
    WARN_PUSH                                                                 \
    IGNORE_ASSERT_WARNINGS                                                    \
      if ((x) >= (xmax)) die("ASSERT failed: " #x " not less than " #xmax);   \
    WARN_POP                                                                  \
    } while (false)                                                           \

#define ASSERT_RANGE(x, xmin, xmax)                                           \
    do {                                                                      \
        WARN_PUSH                                                             \
        IGNORE_ASSERT_WARNINGS                                                \
        if ((x) < (xmin) || (x) >= (xmax))                                    \
        {                                                                     \
            die("ASSERT failed: " #x " of %" PRIdMAX " out of range " \
                #xmin " (%" PRIdMAX ") .. " \
                #xmax " (%" PRIdMAX ")",                                      \
                (intmax_t)(x), (intmax_t)(xmin), (intmax_t)(xmax));           \
        }                                                                     \
        WARN_POP                                                              \
    } while (false)
# define IGNORE_ASSERT_WARNINGS _Pragma("GCC diagnostic ignored \"-Wtautological-constant-out-of-range-compare\"")
# define WARN_POP  _Pragma("GCC diagnostic pop")
# define WARN_PUSH _Pragma("GCC diagnostic push")
#define die(...) die("__FILE__", "__LINE__", __VA_ARGS__)
#define TAG_CHR_FORMAT 0
#define TAG_MAJOR_VERSION 34
#define O_BINARY 0

































