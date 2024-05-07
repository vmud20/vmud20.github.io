#include<sys/types.h>

#include<stdint.h>

#include<string.h>

#include<stdlib.h>


#include<stdio.h>


#include<arpa/inet.h>
#include<stdarg.h>



#include<sys/param.h>
#include<errno.h>
#include<stddef.h>




#define DATUM(d) ((struct cil_symtab_datum *)(d))
#define FLAVOR(f) (NODE(f)->flavor)
#define NODE(n) ((struct cil_tree_node *)(DATUM(n)->nodes->head->data))



#define cil_list_for_each(item, list) \
	for (item = (list)->head; item != NULL; item = item->next)

#define CIL_MIN_DECLARATIVE 2000
#define CIL_MIN_OP_OPERANDS 1000

#define SEPOL_EEXIST         -EEXIST
#define SEPOL_ENOENT         -ENOENT
#define SEPOL_ENOMEM         -ENOMEM
#define SEPOL_ENOTSUP        -2  
#define SEPOL_ERANGE         -ERANGE
#define SEPOL_EREQ           -3  
#define SEPOL_ERR            -1
#define SEPOL_OK             0




#define CIL_AVRULE_ALLOWED     1
#define CIL_AVRULE_AUDITALLOW  2
#define CIL_AVRULE_AV         (AVRULE_ALLOWED | AVRULE_AUDITALLOW | AVRULE_DONTAUDIT | AVRULE_NEVERALLOW)
#define CIL_AVRULE_DONTAUDIT   8
#define CIL_AVRULE_NEVERALLOW 128
#define CIL_AVRULE_TYPE       (AVRULE_TRANSITION | AVRULE_MEMBER | AVRULE_CHANGE)
#define CIL_CONSTRAIN_KEYS "t1 t2 r1 r2 u1 u2"
#define CIL_CONSTRAIN_OPER "== != eq dom domby incomp not and or"

#define CIL_MAX_NAME_LENGTH 2048
#define CIL_MLSCONSTRAIN_KEYS CIL_MLS_LEVELS CIL_CONSTRAIN_KEYS
#define CIL_MLS_LEVELS "l1 l2 h1 h2" 
#define CIL_PERMS_PER_CLASS (sizeof(sepol_access_vector_t) * 8)
#define CIL_PERMX_KIND_IOCTL 1
#define CIL_TYPE_CHANGE     64
#define CIL_TYPE_MEMBER     32
#define CIL_TYPE_TRANSITION 16


#define ALLOW_UNKNOWN 	SEPOL_ALLOW_UNKNOWN
#define AVRULE_AV         (AVRULE_ALLOWED | AVRULE_AUDITALLOW | AVRULE_AUDITDENY | AVRULE_DONTAUDIT | AVRULE_NEVERALLOW)
#define AVRULE_OPTIONAL 1
#define AVRULE_TYPE       (AVRULE_TRANSITION | AVRULE_MEMBER | AVRULE_CHANGE)
#define AVRULE_XPERMS_ALLOWED 		AVTAB_XPERMS_ALLOWED
#define DEFAULT_GLBLUB 		7
#define ERRMSG_LEN 1024
#define EXTENDED_PERMS_LEN 8
#define IB_DEVICE_NAME_MAX 64
#define MOD_POLICYDB_VERSION_CONSTRAINT_NAMES  17
#define MOD_POLICYDB_VERSION_MAX MOD_POLICYDB_VERSION_GLBLUB
#define MOD_POLICYDB_VERSION_MIN MOD_POLICYDB_VERSION_BASE
#define MOD_POLICYDB_VERSION_RANGETRANS 	6
#define MOD_POLICYDB_VERSION_XPERMS_IOCTL  18
#define OBJECT_R "object_r"
#define OBJECT_R_VAL 1
#define OCON_FS    1	
#define OCON_FSUSE 5	
#define OCON_IBENDPORT 8	
#define OCON_IBPKEY 7	
#define OCON_ISID  0	
#define OCON_NETIF 3	
#define OCON_NODE  4	
#define OCON_NODE6 6	
#define OCON_NUM   9
#define OCON_PORT  2	
#define OCON_XEN_DEVICETREE 5    
#define OCON_XEN_IOPORT     2    
#define OCON_XEN_ISID  	    0    
#define OCON_XEN_PCIDEVICE  4    
#define OCON_XEN_PIRQ       1    
#define PERM_SYMTAB_SIZE 32
#define PF_LEN         2	
#define PF_USE_MEMORY  0
#define PF_USE_STDIO   1
#define POLICYDB_CONFIG_MLS    1
#define POLICYDB_ERROR       -1
#define POLICYDB_MAGIC SELINUX_MAGIC
#define POLICYDB_MOD_MAGIC SELINUX_MOD_MAGIC
#define POLICYDB_MOD_STRING "SE Linux Module"
#define POLICYDB_STRING "SE Linux"
#define POLICYDB_STRING_MAX_LENGTH 32
#define POLICYDB_SUCCESS      0
#define POLICYDB_UNSUPPORTED -2
#define POLICYDB_XEN_STRING "XenFlask"
#define POLICY_BASE SEPOL_POLICY_BASE
#define POLICY_KERN SEPOL_POLICY_KERN
#define POLICY_MOD SEPOL_POLICY_MOD
#define ROLE_ATTRIB 1		
#define ROLE_COMP 2
#define ROLE_ROLE 0		
#define ROLE_STAR 1
#define RULE_SELF 1
#define SCOPE_DECL 2
#define SCOPE_REQ  1
#define SYM_BOOLS   5
#define SYM_CATS    7
#define SYM_CLASSES 1
#define SYM_COMMONS 0
#define SYM_LEVELS  6
#define SYM_NUM     8
#define SYM_ROLES   2
#define SYM_TYPES   3
#define SYM_USERS   4
#define TYPE_ALIAS 2		
#define TYPE_ATTRIB 1		
#define TYPE_COMP 2
#define TYPE_FLAGS_EXPAND_ATTR (TYPE_FLAGS_EXPAND_ATTR_TRUE | \
				TYPE_FLAGS_EXPAND_ATTR_FALSE)
#define TYPE_STAR 1
#define TYPE_TYPE 0		

#define p_bool_val_to_name sym_val_to_name[SYM_BOOLS]
#define p_bools symtab[SYM_BOOLS]
#define p_bools_scope scope[SYM_BOOLS]
#define p_cat_scope scope[SYM_CATS]
#define p_cat_val_to_name sym_val_to_name[SYM_CATS]
#define p_cats symtab[SYM_CATS]
#define p_class_val_to_name sym_val_to_name[SYM_CLASSES]
#define p_classes symtab[SYM_CLASSES]
#define p_classes_scope scope[SYM_CLASSES]
#define p_common_val_to_name sym_val_to_name[SYM_COMMONS]
#define p_commons symtab[SYM_COMMONS]
#define p_levels symtab[SYM_LEVELS]
#define p_role_val_to_name sym_val_to_name[SYM_ROLES]
#define p_roles symtab[SYM_ROLES]
#define p_roles_scope scope[SYM_ROLES]
#define p_sens_scope scope[SYM_LEVELS]
#define p_sens_val_to_name sym_val_to_name[SYM_LEVELS]
#define p_type_val_to_name sym_val_to_name[SYM_TYPES]
#define p_types symtab[SYM_TYPES]
#define p_types_scope scope[SYM_TYPES]
#define p_user_val_to_name sym_val_to_name[SYM_USERS]
#define p_users symtab[SYM_USERS]
#define p_users_scope scope[SYM_USERS]
#define policydb_has_boundary_feature(p)			\
	(((p)->policy_type == POLICY_KERN			\
	  && p->policyvers >= POLICYDB_VERSION_BOUNDARY) ||	\
	 ((p)->policy_type != POLICY_KERN			\
	  && p->policyvers >= MOD_POLICYDB_VERSION_BOUNDARY))
#define xperm_clear(x, p) (p[x >> 5] &= ~(1 << (x & 0x1f)))
#define xperm_set(x, p) (p[x >> 5] |= (1 << (x & 0x1f)))
#define xperm_test(x, p) (1 & (p[x >> 5] >> (x & 0x1f)))
#define SIDTAB_HASH_BITS 7
#define SIDTAB_HASH_BUCKETS (1 << SIDTAB_HASH_BITS)
#define SIDTAB_HASH_MASK (SIDTAB_HASH_BUCKETS-1)
#define SIDTAB_SIZE SIDTAB_HASH_BUCKETS



#define mls_level_between(l1, l2, l3) \
(mls_level_dom((l1), (l2)) && mls_level_dom((l3), (l1)))
#define mls_level_incomp(l1, l2) \
(!mls_level_dom((l1), (l2)) && !mls_level_dom((l2), (l1)))
#define mls_range_contains(r1, r2) \
(mls_level_dom(&(r2).level[0], &(r1).level[0]) && \
 mls_level_dom(&(r1).level[1], &(r2).level[1]))
#define SELINUX_MAGIC 0xf97cff8c
#define SELINUX_MOD_MAGIC 0xf97cff8d
#define SEPOL_SECSID_NULL 0

#define MAPBIT  1ULL		
#define MAPSIZE (sizeof(MAPTYPE) * 8)	
#define MAPTYPE uint64_t	

#define ebitmap_for_each_bit(e, n, bit) \
	for (bit = ebitmap_start(e, &n); bit < ebitmap_length(e); bit = ebitmap_next(&n, bit)) \

#define ebitmap_for_each_positive_bit(e, n, bit) \
	ebitmap_for_each_bit(e, n, bit) if (ebitmap_node_get_bit(n, bit)) \

#define ebitmap_is_empty(e) (((e)->highbit) == 0)
#define ebitmap_length(e) ((e)->highbit)
#define ebitmap_startbit(e) ((e)->node ? (e)->node->startbit : 0)
#define ebitmap_startnode(e) ((e)->node)
#define CEXPR_DOM    3		
#define CEXPR_DOMBY  4		
#define CEXPR_EQ     1		
#define CEXPR_H1H2 256		
#define CEXPR_H1L2 128		
#define CEXPR_INCOMP 5		
#define CEXPR_L1H1 512		
#define CEXPR_L1H2 64		
#define CEXPR_L1L2 32		
#define CEXPR_L2H2 1024		
#define CEXPR_MAXDEPTH 5
#define CEXPR_NEQ    2		
#define CEXPR_ROLE 2		
#define CEXPR_TARGET 8		
#define CEXPR_TYPE 4		
#define CEXPR_USER 1		
#define CEXPR_XTARGET 16	

#define AVTAB_XPERMS		(AVTAB_XPERMS_ALLOWED | AVTAB_XPERMS_AUDITALLOW | AVTAB_XPERMS_DONTAUDIT)
#define MAX_AVTAB_HASH_BITS 20
#define MAX_AVTAB_HASH_BUCKETS (1 << MAX_AVTAB_HASH_BITS)
#define MAX_AVTAB_HASH_MASK (MAX_AVTAB_HASH_BUCKETS-1)
#define MAX_AVTAB_SIZE (MAX_AVTAB_HASH_BUCKETS << 1)

#define SEPOL_TARGET_SELINUX 0
#define SEPOL_TARGET_XEN     1


#define SECURITY_FS_USE_GENFS 4	
#define SECURITY_FS_USE_NONE  5	
#define SECURITY_FS_USE_TASK  3	
#define SECURITY_FS_USE_TRANS 2	
#define SECURITY_FS_USE_XATTR 1	
#define SEPOL_COMPUTEAV_BOUNDS 0x8U
#define SEPOL_COMPUTEAV_CONS   0x2U
#define SEPOL_COMPUTEAV_RBAC   0x4U
#define SEPOL_COMPUTEAV_TE     0x1U
#define SHOW_GRANTED 1






#define MAX_LOG_SIZE 512
#define COND_EXPR_MAXDEPTH 10
#define COND_MAX_BOOLS 5

