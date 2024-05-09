













static const struct bpf_verifier_ops * const bpf_verifier_ops[] = {





};




struct bpf_verifier_stack_elem {
	
	struct bpf_verifier_state st;
	int insn_idx;
	int prev_insn_idx;
	struct bpf_verifier_stack_elem *next;
};






struct bpf_call_arg_meta {
	struct bpf_map *map_ptr;
	bool raw_mode;
	bool pkt_access;
	int regno;
	int access_size;
};

static DEFINE_MUTEX(bpf_verifier_lock);


static __printf(2, 3) void verbose(struct bpf_verifier_env *env, const char *fmt, ...)
{
	struct bpf_verifer_log *log = &env->log;
	unsigned int n;
	va_list args;

	if (!log->level || !log->ubuf || bpf_verifier_log_full(log))
		return;

	va_start(args, fmt);
	n = vscnprintf(log->kbuf, BPF_VERIFIER_TMP_LOG_SIZE, fmt, args);
	va_end(args);

	WARN_ONCE(n >= BPF_VERIFIER_TMP_LOG_SIZE - 1, "verifier log line truncated - local buffer too short\n");

	n = min(log->len_total - log->len_used - 1, n);
	log->kbuf[n] = '\0';

	if (!copy_to_user(log->ubuf + log->len_used, log->kbuf, n + 1))
		log->len_used += n;
	else log->ubuf = NULL;
}

static bool type_is_pkt_pointer(enum bpf_reg_type type)
{
	return type == PTR_TO_PACKET || type == PTR_TO_PACKET_META;
}


static const char * const reg_type_str[] = {
	[NOT_INIT]		= "?", [SCALAR_VALUE]		= "inv", [PTR_TO_CTX]		= "ctx", [CONST_PTR_TO_MAP]	= "map_ptr", [PTR_TO_MAP_VALUE]	= "map_value", [PTR_TO_MAP_VALUE_OR_NULL] = "map_value_or_null", [PTR_TO_STACK]		= "fp", [PTR_TO_PACKET]		= "pkt", [PTR_TO_PACKET_META]	= "pkt_meta", [PTR_TO_PACKET_END]	= "pkt_end", };










static void print_verifier_state(struct bpf_verifier_env *env, struct bpf_verifier_state *state)
{
	struct bpf_reg_state *reg;
	enum bpf_reg_type t;
	int i;

	for (i = 0; i < MAX_BPF_REG; i++) {
		reg = &state->regs[i];
		t = reg->type;
		if (t == NOT_INIT)
			continue;
		verbose(env, " R%d=%s", i, reg_type_str[t]);
		if ((t == SCALAR_VALUE || t == PTR_TO_STACK) && tnum_is_const(reg->var_off)) {
			
			verbose(env, "%lld", reg->var_off.value + reg->off);
		} else {
			verbose(env, "(id=%d", reg->id);
			if (t != SCALAR_VALUE)
				verbose(env, ",off=%d", reg->off);
			if (type_is_pkt_pointer(t))
				verbose(env, ",r=%d", reg->range);
			else if (t == CONST_PTR_TO_MAP || t == PTR_TO_MAP_VALUE || t == PTR_TO_MAP_VALUE_OR_NULL)

				verbose(env, ",ks=%d,vs=%d", reg->map_ptr->key_size, reg->map_ptr->value_size);

			if (tnum_is_const(reg->var_off)) {
				
				verbose(env, ",imm=%llx", reg->var_off.value);
			} else {
				if (reg->smin_value != reg->umin_value && reg->smin_value != S64_MIN)
					verbose(env, ",smin_value=%lld", (long long)reg->smin_value);
				if (reg->smax_value != reg->umax_value && reg->smax_value != S64_MAX)
					verbose(env, ",smax_value=%lld", (long long)reg->smax_value);
				if (reg->umin_value != 0)
					verbose(env, ",umin_value=%llu", (unsigned long long)reg->umin_value);
				if (reg->umax_value != U64_MAX)
					verbose(env, ",umax_value=%llu", (unsigned long long)reg->umax_value);
				if (!tnum_is_unknown(reg->var_off)) {
					char tn_buf[48];

					tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
					verbose(env, ",var_off=%s", tn_buf);
				}
			}
			verbose(env, ")");
		}
	}
	for (i = 0; i < state->allocated_stack / BPF_REG_SIZE; i++) {
		if (state->stack[i].slot_type[0] == STACK_SPILL)
			verbose(env, " fp%d=%s", -MAX_BPF_STACK + i * BPF_REG_SIZE, reg_type_str[state->stack[i].spilled_ptr.type]);

	}
	verbose(env, "\n");
}

static int copy_stack_state(struct bpf_verifier_state *dst, const struct bpf_verifier_state *src)
{
	if (!src->stack)
		return 0;
	if (WARN_ON_ONCE(dst->allocated_stack < src->allocated_stack)) {
		
		memset(dst, 0, sizeof(*dst));
		return -EFAULT;
	}
	memcpy(dst->stack, src->stack, sizeof(*src->stack) * (src->allocated_stack / BPF_REG_SIZE));
	return 0;
}


static int realloc_verifier_state(struct bpf_verifier_state *state, int size, bool copy_old)
{
	u32 old_size = state->allocated_stack;
	struct bpf_stack_state *new_stack;
	int slot = size / BPF_REG_SIZE;

	if (size <= old_size || !size) {
		if (copy_old)
			return 0;
		state->allocated_stack = slot * BPF_REG_SIZE;
		if (!size && old_size) {
			kfree(state->stack);
			state->stack = NULL;
		}
		return 0;
	}
	new_stack = kmalloc_array(slot, sizeof(struct bpf_stack_state), GFP_KERNEL);
	if (!new_stack)
		return -ENOMEM;
	if (copy_old) {
		if (state->stack)
			memcpy(new_stack, state->stack, sizeof(*new_stack) * (old_size / BPF_REG_SIZE));
		memset(new_stack + old_size / BPF_REG_SIZE, 0, sizeof(*new_stack) * (size - old_size) / BPF_REG_SIZE);
	}
	state->allocated_stack = slot * BPF_REG_SIZE;
	kfree(state->stack);
	state->stack = new_stack;
	return 0;
}

static void free_verifier_state(struct bpf_verifier_state *state, bool free_self)
{
	kfree(state->stack);
	if (free_self)
		kfree(state);
}


static int copy_verifier_state(struct bpf_verifier_state *dst, const struct bpf_verifier_state *src)
{
	int err;

	err = realloc_verifier_state(dst, src->allocated_stack, false);
	if (err)
		return err;
	memcpy(dst, src, offsetof(struct bpf_verifier_state, allocated_stack));
	return copy_stack_state(dst, src);
}

static int pop_stack(struct bpf_verifier_env *env, int *prev_insn_idx, int *insn_idx)
{
	struct bpf_verifier_state *cur = env->cur_state;
	struct bpf_verifier_stack_elem *elem, *head = env->head;
	int err;

	if (env->head == NULL)
		return -ENOENT;

	if (cur) {
		err = copy_verifier_state(cur, &head->st);
		if (err)
			return err;
	}
	if (insn_idx)
		*insn_idx = head->insn_idx;
	if (prev_insn_idx)
		*prev_insn_idx = head->prev_insn_idx;
	elem = head->next;
	free_verifier_state(&head->st, false);
	kfree(head);
	env->head = elem;
	env->stack_size--;
	return 0;
}

static struct bpf_verifier_state *push_stack(struct bpf_verifier_env *env, int insn_idx, int prev_insn_idx)
{
	struct bpf_verifier_state *cur = env->cur_state;
	struct bpf_verifier_stack_elem *elem;
	int err;

	elem = kzalloc(sizeof(struct bpf_verifier_stack_elem), GFP_KERNEL);
	if (!elem)
		goto err;

	elem->insn_idx = insn_idx;
	elem->prev_insn_idx = prev_insn_idx;
	elem->next = env->head;
	env->head = elem;
	env->stack_size++;
	err = copy_verifier_state(&elem->st, cur);
	if (err)
		goto err;
	if (env->stack_size > BPF_COMPLEXITY_LIMIT_STACK) {
		verbose(env, "BPF program is too complex\n");
		goto err;
	}
	return &elem->st;
err:
	
	while (!pop_stack(env, NULL, NULL));
	return NULL;
}


static const int caller_saved[CALLER_SAVED_REGS] = {
	BPF_REG_0, BPF_REG_1, BPF_REG_2, BPF_REG_3, BPF_REG_4, BPF_REG_5 };

static void __mark_reg_not_init(struct bpf_reg_state *reg);


static void __mark_reg_known(struct bpf_reg_state *reg, u64 imm)
{
	reg->id = 0;
	reg->var_off = tnum_const(imm);
	reg->smin_value = (s64)imm;
	reg->smax_value = (s64)imm;
	reg->umin_value = imm;
	reg->umax_value = imm;
}


static void __mark_reg_known_zero(struct bpf_reg_state *reg)
{
	__mark_reg_known(reg, 0);
}

static void mark_reg_known_zero(struct bpf_verifier_env *env, struct bpf_reg_state *regs, u32 regno)
{
	if (WARN_ON(regno >= MAX_BPF_REG)) {
		verbose(env, "mark_reg_known_zero(regs, %u)\n", regno);
		
		for (regno = 0; regno < MAX_BPF_REG; regno++)
			__mark_reg_not_init(regs + regno);
		return;
	}
	__mark_reg_known_zero(regs + regno);
}

static bool reg_is_pkt_pointer(const struct bpf_reg_state *reg)
{
	return type_is_pkt_pointer(reg->type);
}

static bool reg_is_pkt_pointer_any(const struct bpf_reg_state *reg)
{
	return reg_is_pkt_pointer(reg) || reg->type == PTR_TO_PACKET_END;
}


static bool reg_is_init_pkt_pointer(const struct bpf_reg_state *reg, enum bpf_reg_type which)
{
	
	return reg->type == which && reg->id == 0 && reg->off == 0 && tnum_equals_const(reg->var_off, 0);


}


static void __update_reg_bounds(struct bpf_reg_state *reg)
{
	
	reg->smin_value = max_t(s64, reg->smin_value, reg->var_off.value | (reg->var_off.mask & S64_MIN));
	
	reg->smax_value = min_t(s64, reg->smax_value, reg->var_off.value | (reg->var_off.mask & S64_MAX));
	reg->umin_value = max(reg->umin_value, reg->var_off.value);
	reg->umax_value = min(reg->umax_value, reg->var_off.value | reg->var_off.mask);
}


static void __reg_deduce_bounds(struct bpf_reg_state *reg)
{
	
	if (reg->smin_value >= 0 || reg->smax_value < 0) {
		reg->smin_value = reg->umin_value = max_t(u64, reg->smin_value, reg->umin_value);
		reg->smax_value = reg->umax_value = min_t(u64, reg->smax_value, reg->umax_value);
		return;
	}
	
	if ((s64)reg->umax_value >= 0) {
		
		reg->smin_value = reg->umin_value;
		reg->smax_value = reg->umax_value = min_t(u64, reg->smax_value, reg->umax_value);
	} else if ((s64)reg->umin_value < 0) {
		
		reg->smin_value = reg->umin_value = max_t(u64, reg->smin_value, reg->umin_value);
		reg->smax_value = reg->umax_value;
	}
}


static void __reg_bound_offset(struct bpf_reg_state *reg)
{
	reg->var_off = tnum_intersect(reg->var_off, tnum_range(reg->umin_value, reg->umax_value));

}


static void __mark_reg_unbounded(struct bpf_reg_state *reg)
{
	reg->smin_value = S64_MIN;
	reg->smax_value = S64_MAX;
	reg->umin_value = 0;
	reg->umax_value = U64_MAX;
}


static void __mark_reg_unknown(struct bpf_reg_state *reg)
{
	reg->type = SCALAR_VALUE;
	reg->id = 0;
	reg->off = 0;
	reg->var_off = tnum_unknown;
	__mark_reg_unbounded(reg);
}

static void mark_reg_unknown(struct bpf_verifier_env *env, struct bpf_reg_state *regs, u32 regno)
{
	if (WARN_ON(regno >= MAX_BPF_REG)) {
		verbose(env, "mark_reg_unknown(regs, %u)\n", regno);
		
		for (regno = 0; regno < MAX_BPF_REG; regno++)
			__mark_reg_not_init(regs + regno);
		return;
	}
	__mark_reg_unknown(regs + regno);
}

static void __mark_reg_not_init(struct bpf_reg_state *reg)
{
	__mark_reg_unknown(reg);
	reg->type = NOT_INIT;
}

static void mark_reg_not_init(struct bpf_verifier_env *env, struct bpf_reg_state *regs, u32 regno)
{
	if (WARN_ON(regno >= MAX_BPF_REG)) {
		verbose(env, "mark_reg_not_init(regs, %u)\n", regno);
		
		for (regno = 0; regno < MAX_BPF_REG; regno++)
			__mark_reg_not_init(regs + regno);
		return;
	}
	__mark_reg_not_init(regs + regno);
}

static void init_reg_state(struct bpf_verifier_env *env, struct bpf_reg_state *regs)
{
	int i;

	for (i = 0; i < MAX_BPF_REG; i++) {
		mark_reg_not_init(env, regs, i);
		regs[i].live = REG_LIVE_NONE;
	}

	
	regs[BPF_REG_FP].type = PTR_TO_STACK;
	mark_reg_known_zero(env, regs, BPF_REG_FP);

	
	regs[BPF_REG_1].type = PTR_TO_CTX;
	mark_reg_known_zero(env, regs, BPF_REG_1);
}

enum reg_arg_type {
	SRC_OP,		 DST_OP, DST_OP_NO_MARK };



static void mark_reg_read(const struct bpf_verifier_state *state, u32 regno)
{
	struct bpf_verifier_state *parent = state->parent;

	if (regno == BPF_REG_FP)
		
		return;

	while (parent) {
		
		if (state->regs[regno].live & REG_LIVE_WRITTEN)
			break;
		
		parent->regs[regno].live |= REG_LIVE_READ;
		state = parent;
		parent = state->parent;
	}
}

static int check_reg_arg(struct bpf_verifier_env *env, u32 regno, enum reg_arg_type t)
{
	struct bpf_reg_state *regs = env->cur_state->regs;

	if (regno >= MAX_BPF_REG) {
		verbose(env, "R%d is invalid\n", regno);
		return -EINVAL;
	}

	if (t == SRC_OP) {
		
		if (regs[regno].type == NOT_INIT) {
			verbose(env, "R%d !read_ok\n", regno);
			return -EACCES;
		}
		mark_reg_read(env->cur_state, regno);
	} else {
		
		if (regno == BPF_REG_FP) {
			verbose(env, "frame pointer is read only\n");
			return -EACCES;
		}
		regs[regno].live |= REG_LIVE_WRITTEN;
		if (t == DST_OP)
			mark_reg_unknown(env, regs, regno);
	}
	return 0;
}

static bool is_spillable_regtype(enum bpf_reg_type type)
{
	switch (type) {
	case PTR_TO_MAP_VALUE:
	case PTR_TO_MAP_VALUE_OR_NULL:
	case PTR_TO_STACK:
	case PTR_TO_CTX:
	case PTR_TO_PACKET:
	case PTR_TO_PACKET_META:
	case PTR_TO_PACKET_END:
	case CONST_PTR_TO_MAP:
		return true;
	default:
		return false;
	}
}


static int check_stack_write(struct bpf_verifier_env *env, struct bpf_verifier_state *state, int off, int size, int value_regno)

{
	int i, slot = -off - 1, spi = slot / BPF_REG_SIZE, err;

	err = realloc_verifier_state(state, round_up(slot + 1, BPF_REG_SIZE), true);
	if (err)
		return err;
	
	if (!env->allow_ptr_leaks && state->stack[spi].slot_type[0] == STACK_SPILL && size != BPF_REG_SIZE) {

		verbose(env, "attempt to corrupt spilled pointer on stack\n");
		return -EACCES;
	}

	if (value_regno >= 0 && is_spillable_regtype(state->regs[value_regno].type)) {

		
		if (size != BPF_REG_SIZE) {
			verbose(env, "invalid size of register spill\n");
			return -EACCES;
		}

		
		state->stack[spi].spilled_ptr = state->regs[value_regno];
		state->stack[spi].spilled_ptr.live |= REG_LIVE_WRITTEN;

		for (i = 0; i < BPF_REG_SIZE; i++)
			state->stack[spi].slot_type[i] = STACK_SPILL;
	} else {
		
		state->stack[spi].spilled_ptr = (struct bpf_reg_state) {};

		for (i = 0; i < size; i++)
			state->stack[spi].slot_type[(slot - i) % BPF_REG_SIZE] = STACK_MISC;
	}
	return 0;
}

static void mark_stack_slot_read(const struct bpf_verifier_state *state, int slot)
{
	struct bpf_verifier_state *parent = state->parent;

	while (parent) {
		
		if (state->stack[slot].spilled_ptr.live & REG_LIVE_WRITTEN)
			break;
		
		parent->stack[slot].spilled_ptr.live |= REG_LIVE_READ;
		state = parent;
		parent = state->parent;
	}
}

static int check_stack_read(struct bpf_verifier_env *env, struct bpf_verifier_state *state, int off, int size, int value_regno)

{
	int i, slot = -off - 1, spi = slot / BPF_REG_SIZE;
	u8 *stype;

	if (state->allocated_stack <= slot) {
		verbose(env, "invalid read from stack off %d+0 size %d\n", off, size);
		return -EACCES;
	}
	stype = state->stack[spi].slot_type;

	if (stype[0] == STACK_SPILL) {
		if (size != BPF_REG_SIZE) {
			verbose(env, "invalid size of register spill\n");
			return -EACCES;
		}
		for (i = 1; i < BPF_REG_SIZE; i++) {
			if (stype[(slot - i) % BPF_REG_SIZE] != STACK_SPILL) {
				verbose(env, "corrupted spill memory\n");
				return -EACCES;
			}
		}

		if (value_regno >= 0) {
			
			state->regs[value_regno] = state->stack[spi].spilled_ptr;
			mark_stack_slot_read(state, spi);
		}
		return 0;
	} else {
		for (i = 0; i < size; i++) {
			if (stype[(slot - i) % BPF_REG_SIZE] != STACK_MISC) {
				verbose(env, "invalid read from stack off %d+%d size %d\n", off, i, size);
				return -EACCES;
			}
		}
		if (value_regno >= 0)
			
			mark_reg_unknown(env, state->regs, value_regno);
		return 0;
	}
}


static int __check_map_access(struct bpf_verifier_env *env, u32 regno, int off, int size, bool zero_size_allowed)
{
	struct bpf_reg_state *regs = cur_regs(env);
	struct bpf_map *map = regs[regno].map_ptr;

	if (off < 0 || size < 0 || (size == 0 && !zero_size_allowed) || off + size > map->value_size) {
		verbose(env, "invalid access to map value, value_size=%d off=%d size=%d\n", map->value_size, off, size);
		return -EACCES;
	}
	return 0;
}


static int check_map_access(struct bpf_verifier_env *env, u32 regno, int off, int size, bool zero_size_allowed)
{
	struct bpf_verifier_state *state = env->cur_state;
	struct bpf_reg_state *reg = &state->regs[regno];
	int err;

	
	if (env->log.level)
		print_verifier_state(env, state);
	
	if (reg->smin_value < 0) {
		verbose(env, "R%d min value is negative, either use unsigned index or do a if (index >=0) check.\n", regno);
		return -EACCES;
	}
	err = __check_map_access(env, regno, reg->smin_value + off, size, zero_size_allowed);
	if (err) {
		verbose(env, "R%d min value is outside of the array range\n", regno);
		return err;
	}

	
	if (reg->umax_value >= BPF_MAX_VAR_OFF) {
		verbose(env, "R%d unbounded memory access, make sure to bounds check any array access into a map\n", regno);
		return -EACCES;
	}
	err = __check_map_access(env, regno, reg->umax_value + off, size, zero_size_allowed);
	if (err)
		verbose(env, "R%d max value is outside of the array range\n", regno);
	return err;
}



static bool may_access_direct_pkt_data(struct bpf_verifier_env *env, const struct bpf_call_arg_meta *meta, enum bpf_access_type t)

{
	switch (env->prog->type) {
	case BPF_PROG_TYPE_LWT_IN:
	case BPF_PROG_TYPE_LWT_OUT:
		
		if (t == BPF_WRITE)
			return false;
		
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
	case BPF_PROG_TYPE_XDP:
	case BPF_PROG_TYPE_LWT_XMIT:
	case BPF_PROG_TYPE_SK_SKB:
		if (meta)
			return meta->pkt_access;

		env->seen_direct_write = true;
		return true;
	default:
		return false;
	}
}

static int __check_packet_access(struct bpf_verifier_env *env, u32 regno, int off, int size, bool zero_size_allowed)
{
	struct bpf_reg_state *regs = cur_regs(env);
	struct bpf_reg_state *reg = &regs[regno];

	if (off < 0 || size < 0 || (size == 0 && !zero_size_allowed) || (u64)off + size > reg->range) {
		verbose(env, "invalid access to packet, off=%d size=%d, R%d(id=%d,off=%d,r=%d)\n", off, size, regno, reg->id, reg->off, reg->range);
		return -EACCES;
	}
	return 0;
}

static int check_packet_access(struct bpf_verifier_env *env, u32 regno, int off, int size, bool zero_size_allowed)
{
	struct bpf_reg_state *regs = cur_regs(env);
	struct bpf_reg_state *reg = &regs[regno];
	int err;

	

	
	if (reg->smin_value < 0) {
		verbose(env, "R%d min value is negative, either use unsigned index or do a if (index >=0) check.\n", regno);
		return -EACCES;
	}
	err = __check_packet_access(env, regno, off, size, zero_size_allowed);
	if (err) {
		verbose(env, "R%d offset is outside of the packet\n", regno);
		return err;
	}
	return err;
}


static int check_ctx_access(struct bpf_verifier_env *env, int insn_idx, int off, int size, enum bpf_access_type t, enum bpf_reg_type *reg_type)
{
	struct bpf_insn_access_aux info = {
		.reg_type = *reg_type, };

	if (env->ops->is_valid_access && env->ops->is_valid_access(off, size, t, &info)) {
		
		*reg_type = info.reg_type;

		env->insn_aux_data[insn_idx].ctx_field_size = info.ctx_field_size;
		
		if (env->prog->aux->max_ctx_offset < off + size)
			env->prog->aux->max_ctx_offset = off + size;
		return 0;
	}

	verbose(env, "invalid bpf_context access off=%d size=%d\n", off, size);
	return -EACCES;
}

static bool __is_pointer_value(bool allow_ptr_leaks, const struct bpf_reg_state *reg)
{
	if (allow_ptr_leaks)
		return false;

	return reg->type != SCALAR_VALUE;
}

static bool is_pointer_value(struct bpf_verifier_env *env, int regno)
{
	return __is_pointer_value(env->allow_ptr_leaks, cur_regs(env) + regno);
}

static int check_pkt_ptr_alignment(struct bpf_verifier_env *env, const struct bpf_reg_state *reg, int off, int size, bool strict)

{
	struct tnum reg_off;
	int ip_align;

	
	if (!strict || size == 1)
		return 0;

	
	ip_align = 2;

	reg_off = tnum_add(reg->var_off, tnum_const(ip_align + reg->off + off));
	if (!tnum_is_aligned(reg_off, size)) {
		char tn_buf[48];

		tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
		verbose(env, "misaligned packet access off %d+%s+%d+%d size %d\n", ip_align, tn_buf, reg->off, off, size);

		return -EACCES;
	}

	return 0;
}

static int check_generic_ptr_alignment(struct bpf_verifier_env *env, const struct bpf_reg_state *reg, const char *pointer_desc, int off, int size, bool strict)


{
	struct tnum reg_off;

	
	if (!strict || size == 1)
		return 0;

	reg_off = tnum_add(reg->var_off, tnum_const(reg->off + off));
	if (!tnum_is_aligned(reg_off, size)) {
		char tn_buf[48];

		tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
		verbose(env, "misaligned %saccess off %s+%d+%d size %d\n", pointer_desc, tn_buf, reg->off, off, size);
		return -EACCES;
	}

	return 0;
}

static int check_ptr_alignment(struct bpf_verifier_env *env, const struct bpf_reg_state *reg, int off, int size)

{
	bool strict = env->strict_alignment;
	const char *pointer_desc = "";

	switch (reg->type) {
	case PTR_TO_PACKET:
	case PTR_TO_PACKET_META:
		
		return check_pkt_ptr_alignment(env, reg, off, size, strict);
	case PTR_TO_MAP_VALUE:
		pointer_desc = "value ";
		break;
	case PTR_TO_CTX:
		pointer_desc = "context ";
		break;
	case PTR_TO_STACK:
		pointer_desc = "stack ";
		break;
	default:
		break;
	}
	return check_generic_ptr_alignment(env, reg, pointer_desc, off, size, strict);
}


static int check_mem_access(struct bpf_verifier_env *env, int insn_idx, u32 regno, int off, int bpf_size, enum bpf_access_type t, int value_regno)

{
	struct bpf_verifier_state *state = env->cur_state;
	struct bpf_reg_state *regs = cur_regs(env);
	struct bpf_reg_state *reg = regs + regno;
	int size, err = 0;

	size = bpf_size_to_bytes(bpf_size);
	if (size < 0)
		return size;

	
	err = check_ptr_alignment(env, reg, off, size);
	if (err)
		return err;

	
	off += reg->off;

	if (reg->type == PTR_TO_MAP_VALUE) {
		if (t == BPF_WRITE && value_regno >= 0 && is_pointer_value(env, value_regno)) {
			verbose(env, "R%d leaks addr into map\n", value_regno);
			return -EACCES;
		}

		err = check_map_access(env, regno, off, size, false);
		if (!err && t == BPF_READ && value_regno >= 0)
			mark_reg_unknown(env, regs, value_regno);

	} else if (reg->type == PTR_TO_CTX) {
		enum bpf_reg_type reg_type = SCALAR_VALUE;

		if (t == BPF_WRITE && value_regno >= 0 && is_pointer_value(env, value_regno)) {
			verbose(env, "R%d leaks addr into ctx\n", value_regno);
			return -EACCES;
		}
		
		if (reg->off) {
			verbose(env, "dereference of modified ctx ptr R%d off=%d+%d, ctx+const is allowed, ctx+const+const is not\n", regno, reg->off, off - reg->off);

			return -EACCES;
		}
		if (!tnum_is_const(reg->var_off) || reg->var_off.value) {
			char tn_buf[48];

			tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
			verbose(env, "variable ctx access var_off=%s off=%d size=%d", tn_buf, off, size);

			return -EACCES;
		}
		err = check_ctx_access(env, insn_idx, off, size, t, &reg_type);
		if (!err && t == BPF_READ && value_regno >= 0) {
			
			if (reg_type == SCALAR_VALUE)
				mark_reg_unknown(env, regs, value_regno);
			else mark_reg_known_zero(env, regs, value_regno);

			regs[value_regno].id = 0;
			regs[value_regno].off = 0;
			regs[value_regno].range = 0;
			regs[value_regno].type = reg_type;
		}

	} else if (reg->type == PTR_TO_STACK) {
		
		if (!tnum_is_const(reg->var_off)) {
			char tn_buf[48];

			tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
			verbose(env, "variable stack access var_off=%s off=%d size=%d", tn_buf, off, size);
			return -EACCES;
		}
		off += reg->var_off.value;
		if (off >= 0 || off < -MAX_BPF_STACK) {
			verbose(env, "invalid stack off=%d size=%d\n", off, size);
			return -EACCES;
		}

		if (env->prog->aux->stack_depth < -off)
			env->prog->aux->stack_depth = -off;

		if (t == BPF_WRITE)
			err = check_stack_write(env, state, off, size, value_regno);
		else err = check_stack_read(env, state, off, size, value_regno);

	} else if (reg_is_pkt_pointer(reg)) {
		if (t == BPF_WRITE && !may_access_direct_pkt_data(env, NULL, t)) {
			verbose(env, "cannot write into packet\n");
			return -EACCES;
		}
		if (t == BPF_WRITE && value_regno >= 0 && is_pointer_value(env, value_regno)) {
			verbose(env, "R%d leaks addr into packet\n", value_regno);
			return -EACCES;
		}
		err = check_packet_access(env, regno, off, size, false);
		if (!err && t == BPF_READ && value_regno >= 0)
			mark_reg_unknown(env, regs, value_regno);
	} else {
		verbose(env, "R%d invalid mem access '%s'\n", regno, reg_type_str[reg->type]);
		return -EACCES;
	}

	if (!err && size < BPF_REG_SIZE && value_regno >= 0 && t == BPF_READ && regs[value_regno].type == SCALAR_VALUE) {
		
		regs[value_regno].var_off = tnum_cast(regs[value_regno].var_off, size);
		__update_reg_bounds(&regs[value_regno]);
	}
	return err;
}

static int check_xadd(struct bpf_verifier_env *env, int insn_idx, struct bpf_insn *insn)
{
	int err;

	if ((BPF_SIZE(insn->code) != BPF_W && BPF_SIZE(insn->code) != BPF_DW) || insn->imm != 0) {
		verbose(env, "BPF_XADD uses reserved fields\n");
		return -EINVAL;
	}

	
	err = check_reg_arg(env, insn->src_reg, SRC_OP);
	if (err)
		return err;

	
	err = check_reg_arg(env, insn->dst_reg, SRC_OP);
	if (err)
		return err;

	if (is_pointer_value(env, insn->src_reg)) {
		verbose(env, "R%d leaks addr into mem\n", insn->src_reg);
		return -EACCES;
	}

	
	err = check_mem_access(env, insn_idx, insn->dst_reg, insn->off, BPF_SIZE(insn->code), BPF_READ, -1);
	if (err)
		return err;

	
	return check_mem_access(env, insn_idx, insn->dst_reg, insn->off, BPF_SIZE(insn->code), BPF_WRITE, -1);
}


static bool register_is_null(struct bpf_reg_state reg)
{
	return reg.type == SCALAR_VALUE && tnum_equals_const(reg.var_off, 0);
}


static int check_stack_boundary(struct bpf_verifier_env *env, int regno, int access_size, bool zero_size_allowed, struct bpf_call_arg_meta *meta)

{
	struct bpf_verifier_state *state = env->cur_state;
	struct bpf_reg_state *regs = state->regs;
	int off, i, slot, spi;

	if (regs[regno].type != PTR_TO_STACK) {
		
		if (zero_size_allowed && access_size == 0 && register_is_null(regs[regno]))
			return 0;

		verbose(env, "R%d type=%s expected=%s\n", regno, reg_type_str[regs[regno].type], reg_type_str[PTR_TO_STACK]);

		return -EACCES;
	}

	
	if (!tnum_is_const(regs[regno].var_off)) {
		char tn_buf[48];

		tnum_strn(tn_buf, sizeof(tn_buf), regs[regno].var_off);
		verbose(env, "invalid variable stack read R%d var_off=%s\n", regno, tn_buf);
	}
	off = regs[regno].off + regs[regno].var_off.value;
	if (off >= 0 || off < -MAX_BPF_STACK || off + access_size > 0 || access_size < 0 || (access_size == 0 && !zero_size_allowed)) {
		verbose(env, "invalid stack type R%d off=%d access_size=%d\n", regno, off, access_size);
		return -EACCES;
	}

	if (env->prog->aux->stack_depth < -off)
		env->prog->aux->stack_depth = -off;

	if (meta && meta->raw_mode) {
		meta->access_size = access_size;
		meta->regno = regno;
		return 0;
	}

	for (i = 0; i < access_size; i++) {
		slot = -(off + i) - 1;
		spi = slot / BPF_REG_SIZE;
		if (state->allocated_stack <= slot || state->stack[spi].slot_type[slot % BPF_REG_SIZE] != STACK_MISC) {

			verbose(env, "invalid indirect read from stack off %d+%d size %d\n", off, i, access_size);
			return -EACCES;
		}
	}
	return 0;
}

static int check_helper_mem_access(struct bpf_verifier_env *env, int regno, int access_size, bool zero_size_allowed, struct bpf_call_arg_meta *meta)

{
	struct bpf_reg_state *regs = cur_regs(env), *reg = &regs[regno];

	switch (reg->type) {
	case PTR_TO_PACKET:
	case PTR_TO_PACKET_META:
		return check_packet_access(env, regno, reg->off, access_size, zero_size_allowed);
	case PTR_TO_MAP_VALUE:
		return check_map_access(env, regno, reg->off, access_size, zero_size_allowed);
	default: 
		return check_stack_boundary(env, regno, access_size, zero_size_allowed, meta);
	}
}

static int check_func_arg(struct bpf_verifier_env *env, u32 regno, enum bpf_arg_type arg_type, struct bpf_call_arg_meta *meta)

{
	struct bpf_reg_state *regs = cur_regs(env), *reg = &regs[regno];
	enum bpf_reg_type expected_type, type = reg->type;
	int err = 0;

	if (arg_type == ARG_DONTCARE)
		return 0;

	err = check_reg_arg(env, regno, SRC_OP);
	if (err)
		return err;

	if (arg_type == ARG_ANYTHING) {
		if (is_pointer_value(env, regno)) {
			verbose(env, "R%d leaks addr into helper function\n", regno);
			return -EACCES;
		}
		return 0;
	}

	if (type_is_pkt_pointer(type) && !may_access_direct_pkt_data(env, meta, BPF_READ)) {
		verbose(env, "helper access to the packet is not allowed\n");
		return -EACCES;
	}

	if (arg_type == ARG_PTR_TO_MAP_KEY || arg_type == ARG_PTR_TO_MAP_VALUE) {
		expected_type = PTR_TO_STACK;
		if (!type_is_pkt_pointer(type) && type != expected_type)
			goto err_type;
	} else if (arg_type == ARG_CONST_SIZE || arg_type == ARG_CONST_SIZE_OR_ZERO) {
		expected_type = SCALAR_VALUE;
		if (type != expected_type)
			goto err_type;
	} else if (arg_type == ARG_CONST_MAP_PTR) {
		expected_type = CONST_PTR_TO_MAP;
		if (type != expected_type)
			goto err_type;
	} else if (arg_type == ARG_PTR_TO_CTX) {
		expected_type = PTR_TO_CTX;
		if (type != expected_type)
			goto err_type;
	} else if (arg_type == ARG_PTR_TO_MEM || arg_type == ARG_PTR_TO_MEM_OR_NULL || arg_type == ARG_PTR_TO_UNINIT_MEM) {

		expected_type = PTR_TO_STACK;
		
		if (register_is_null(*reg) && arg_type == ARG_PTR_TO_MEM_OR_NULL)
			;
		else if (!type_is_pkt_pointer(type) && type != PTR_TO_MAP_VALUE && type != expected_type)

			goto err_type;
		meta->raw_mode = arg_type == ARG_PTR_TO_UNINIT_MEM;
	} else {
		verbose(env, "unsupported arg_type %d\n", arg_type);
		return -EFAULT;
	}

	if (arg_type == ARG_CONST_MAP_PTR) {
		
		meta->map_ptr = reg->map_ptr;
	} else if (arg_type == ARG_PTR_TO_MAP_KEY) {
		
		if (!meta->map_ptr) {
			
			verbose(env, "invalid map_ptr to access map->key\n");
			return -EACCES;
		}
		if (type_is_pkt_pointer(type))
			err = check_packet_access(env, regno, reg->off, meta->map_ptr->key_size, false);

		else err = check_stack_boundary(env, regno, meta->map_ptr->key_size, false, NULL);


	} else if (arg_type == ARG_PTR_TO_MAP_VALUE) {
		
		if (!meta->map_ptr) {
			
			verbose(env, "invalid map_ptr to access map->value\n");
			return -EACCES;
		}
		if (type_is_pkt_pointer(type))
			err = check_packet_access(env, regno, reg->off, meta->map_ptr->value_size, false);

		else err = check_stack_boundary(env, regno, meta->map_ptr->value_size, false, NULL);


	} else if (arg_type == ARG_CONST_SIZE || arg_type == ARG_CONST_SIZE_OR_ZERO) {
		bool zero_size_allowed = (arg_type == ARG_CONST_SIZE_OR_ZERO);

		
		if (regno == 0) {
			
			verbose(env, "ARG_CONST_SIZE cannot be first argument\n");
			return -EACCES;
		}

		

		if (!tnum_is_const(reg->var_off))
			
			meta = NULL;

		if (reg->smin_value < 0) {
			verbose(env, "R%d min value is negative, either use unsigned or 'var &= const'\n", regno);
			return -EACCES;
		}

		if (reg->umin_value == 0) {
			err = check_helper_mem_access(env, regno - 1, 0, zero_size_allowed, meta);

			if (err)
				return err;
		}

		if (reg->umax_value >= BPF_MAX_VAR_SIZ) {
			verbose(env, "R%d unbounded memory access, use 'var &= const' or 'if (var < const)'\n", regno);
			return -EACCES;
		}
		err = check_helper_mem_access(env, regno - 1, reg->umax_value, zero_size_allowed, meta);

	}

	return err;
err_type:
	verbose(env, "R%d type=%s expected=%s\n", regno, reg_type_str[type], reg_type_str[expected_type]);
	return -EACCES;
}

static int check_map_func_compatibility(struct bpf_verifier_env *env, struct bpf_map *map, int func_id)
{
	if (!map)
		return 0;

	
	switch (map->map_type) {
	case BPF_MAP_TYPE_PROG_ARRAY:
		if (func_id != BPF_FUNC_tail_call)
			goto error;
		break;
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		if (func_id != BPF_FUNC_perf_event_read && func_id != BPF_FUNC_perf_event_output && func_id != BPF_FUNC_perf_event_read_value)

			goto error;
		break;
	case BPF_MAP_TYPE_STACK_TRACE:
		if (func_id != BPF_FUNC_get_stackid)
			goto error;
		break;
	case BPF_MAP_TYPE_CGROUP_ARRAY:
		if (func_id != BPF_FUNC_skb_under_cgroup && func_id != BPF_FUNC_current_task_under_cgroup)
			goto error;
		break;
	
	case BPF_MAP_TYPE_DEVMAP:
		if (func_id != BPF_FUNC_redirect_map)
			goto error;
		break;
	
	case BPF_MAP_TYPE_CPUMAP:
		if (func_id != BPF_FUNC_redirect_map)
			goto error;
		break;
	case BPF_MAP_TYPE_ARRAY_OF_MAPS:
	case BPF_MAP_TYPE_HASH_OF_MAPS:
		if (func_id != BPF_FUNC_map_lookup_elem)
			goto error;
		break;
	case BPF_MAP_TYPE_SOCKMAP:
		if (func_id != BPF_FUNC_sk_redirect_map && func_id != BPF_FUNC_sock_map_update && func_id != BPF_FUNC_map_delete_elem)

			goto error;
		break;
	default:
		break;
	}

	
	switch (func_id) {
	case BPF_FUNC_tail_call:
		if (map->map_type != BPF_MAP_TYPE_PROG_ARRAY)
			goto error;
		break;
	case BPF_FUNC_perf_event_read:
	case BPF_FUNC_perf_event_output:
	case BPF_FUNC_perf_event_read_value:
		if (map->map_type != BPF_MAP_TYPE_PERF_EVENT_ARRAY)
			goto error;
		break;
	case BPF_FUNC_get_stackid:
		if (map->map_type != BPF_MAP_TYPE_STACK_TRACE)
			goto error;
		break;
	case BPF_FUNC_current_task_under_cgroup:
	case BPF_FUNC_skb_under_cgroup:
		if (map->map_type != BPF_MAP_TYPE_CGROUP_ARRAY)
			goto error;
		break;
	case BPF_FUNC_redirect_map:
		if (map->map_type != BPF_MAP_TYPE_DEVMAP && map->map_type != BPF_MAP_TYPE_CPUMAP)
			goto error;
		break;
	case BPF_FUNC_sk_redirect_map:
		if (map->map_type != BPF_MAP_TYPE_SOCKMAP)
			goto error;
		break;
	case BPF_FUNC_sock_map_update:
		if (map->map_type != BPF_MAP_TYPE_SOCKMAP)
			goto error;
		break;
	default:
		break;
	}

	return 0;
error:
	verbose(env, "cannot pass map_type %d into func %s#%d\n", map->map_type, func_id_name(func_id), func_id);
	return -EINVAL;
}

static int check_raw_mode(const struct bpf_func_proto *fn)
{
	int count = 0;

	if (fn->arg1_type == ARG_PTR_TO_UNINIT_MEM)
		count++;
	if (fn->arg2_type == ARG_PTR_TO_UNINIT_MEM)
		count++;
	if (fn->arg3_type == ARG_PTR_TO_UNINIT_MEM)
		count++;
	if (fn->arg4_type == ARG_PTR_TO_UNINIT_MEM)
		count++;
	if (fn->arg5_type == ARG_PTR_TO_UNINIT_MEM)
		count++;

	return count > 1 ? -EINVAL : 0;
}


static void clear_all_pkt_pointers(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *state = env->cur_state;
	struct bpf_reg_state *regs = state->regs, *reg;
	int i;

	for (i = 0; i < MAX_BPF_REG; i++)
		if (reg_is_pkt_pointer_any(&regs[i]))
			mark_reg_unknown(env, regs, i);

	for (i = 0; i < state->allocated_stack / BPF_REG_SIZE; i++) {
		if (state->stack[i].slot_type[0] != STACK_SPILL)
			continue;
		reg = &state->stack[i].spilled_ptr;
		if (reg_is_pkt_pointer_any(reg))
			__mark_reg_unknown(reg);
	}
}

static int check_call(struct bpf_verifier_env *env, int func_id, int insn_idx)
{
	const struct bpf_func_proto *fn = NULL;
	struct bpf_reg_state *regs;
	struct bpf_call_arg_meta meta;
	bool changes_data;
	int i, err;

	
	if (func_id < 0 || func_id >= __BPF_FUNC_MAX_ID) {
		verbose(env, "invalid func %s#%d\n", func_id_name(func_id), func_id);
		return -EINVAL;
	}

	if (env->ops->get_func_proto)
		fn = env->ops->get_func_proto(func_id);

	if (!fn) {
		verbose(env, "unknown func %s#%d\n", func_id_name(func_id), func_id);
		return -EINVAL;
	}

	
	if (!env->prog->gpl_compatible && fn->gpl_only) {
		verbose(env, "cannot call GPL only function from proprietary program\n");
		return -EINVAL;
	}

	
	changes_data = bpf_helper_changes_pkt_data(fn->func);
	if (changes_data && fn->arg1_type != ARG_PTR_TO_CTX) {
		verbose(env, "kernel subsystem misconfigured func %s#%d: r1 != ctx\n", func_id_name(func_id), func_id);
		return -EINVAL;
	}

	memset(&meta, 0, sizeof(meta));
	meta.pkt_access = fn->pkt_access;

	
	err = check_raw_mode(fn);
	if (err) {
		verbose(env, "kernel subsystem misconfigured func %s#%d\n", func_id_name(func_id), func_id);
		return err;
	}

	
	err = check_func_arg(env, BPF_REG_1, fn->arg1_type, &meta);
	if (err)
		return err;
	err = check_func_arg(env, BPF_REG_2, fn->arg2_type, &meta);
	if (err)
		return err;
	err = check_func_arg(env, BPF_REG_3, fn->arg3_type, &meta);
	if (err)
		return err;
	err = check_func_arg(env, BPF_REG_4, fn->arg4_type, &meta);
	if (err)
		return err;
	err = check_func_arg(env, BPF_REG_5, fn->arg5_type, &meta);
	if (err)
		return err;

	
	for (i = 0; i < meta.access_size; i++) {
		err = check_mem_access(env, insn_idx, meta.regno, i, BPF_B, BPF_WRITE, -1);
		if (err)
			return err;
	}

	regs = cur_regs(env);
	
	for (i = 0; i < CALLER_SAVED_REGS; i++) {
		mark_reg_not_init(env, regs, caller_saved[i]);
		check_reg_arg(env, caller_saved[i], DST_OP_NO_MARK);
	}

	
	if (fn->ret_type == RET_INTEGER) {
		
		mark_reg_unknown(env, regs, BPF_REG_0);
	} else if (fn->ret_type == RET_VOID) {
		regs[BPF_REG_0].type = NOT_INIT;
	} else if (fn->ret_type == RET_PTR_TO_MAP_VALUE_OR_NULL) {
		struct bpf_insn_aux_data *insn_aux;

		regs[BPF_REG_0].type = PTR_TO_MAP_VALUE_OR_NULL;
		
		mark_reg_known_zero(env, regs, BPF_REG_0);
		regs[BPF_REG_0].off = 0;
		
		if (meta.map_ptr == NULL) {
			verbose(env, "kernel subsystem misconfigured verifier\n");
			return -EINVAL;
		}
		regs[BPF_REG_0].map_ptr = meta.map_ptr;
		regs[BPF_REG_0].id = ++env->id_gen;
		insn_aux = &env->insn_aux_data[insn_idx];
		if (!insn_aux->map_ptr)
			insn_aux->map_ptr = meta.map_ptr;
		else if (insn_aux->map_ptr != meta.map_ptr)
			insn_aux->map_ptr = BPF_MAP_PTR_POISON;
	} else {
		verbose(env, "unknown return type %d of func %s#%d\n", fn->ret_type, func_id_name(func_id), func_id);
		return -EINVAL;
	}

	err = check_map_func_compatibility(env, meta.map_ptr, func_id);
	if (err)
		return err;

	if (changes_data)
		clear_all_pkt_pointers(env);
	return 0;
}

static void coerce_reg_to_32(struct bpf_reg_state *reg)
{
	
	reg->var_off = tnum_cast(reg->var_off, 4);
	
	__update_reg_bounds(reg);
}

static bool signed_add_overflows(s64 a, s64 b)
{
	
	s64 res = (s64)((u64)a + (u64)b);

	if (b < 0)
		return res > a;
	return res < a;
}

static bool signed_sub_overflows(s64 a, s64 b)
{
	
	s64 res = (s64)((u64)a - (u64)b);

	if (b < 0)
		return res < a;
	return res > a;
}


static int adjust_ptr_min_max_vals(struct bpf_verifier_env *env, struct bpf_insn *insn, const struct bpf_reg_state *ptr_reg, const struct bpf_reg_state *off_reg)


{
	struct bpf_reg_state *regs = cur_regs(env), *dst_reg;
	bool known = tnum_is_const(off_reg->var_off);
	s64 smin_val = off_reg->smin_value, smax_val = off_reg->smax_value, smin_ptr = ptr_reg->smin_value, smax_ptr = ptr_reg->smax_value;
	u64 umin_val = off_reg->umin_value, umax_val = off_reg->umax_value, umin_ptr = ptr_reg->umin_value, umax_ptr = ptr_reg->umax_value;
	u8 opcode = BPF_OP(insn->code);
	u32 dst = insn->dst_reg;

	dst_reg = &regs[dst];

	if (WARN_ON_ONCE(known && (smin_val != smax_val))) {
		print_verifier_state(env, env->cur_state);
		verbose(env, "verifier internal error: known but bad sbounds\n");
		return -EINVAL;
	}
	if (WARN_ON_ONCE(known && (umin_val != umax_val))) {
		print_verifier_state(env, env->cur_state);
		verbose(env, "verifier internal error: known but bad ubounds\n");
		return -EINVAL;
	}

	if (BPF_CLASS(insn->code) != BPF_ALU64) {
		
		if (!env->allow_ptr_leaks)
			verbose(env, "R%d 32-bit pointer arithmetic prohibited\n", dst);

		return -EACCES;
	}

	if (ptr_reg->type == PTR_TO_MAP_VALUE_OR_NULL) {
		if (!env->allow_ptr_leaks)
			verbose(env, "R%d pointer arithmetic on PTR_TO_MAP_VALUE_OR_NULL prohibited, null-check it first\n", dst);
		return -EACCES;
	}
	if (ptr_reg->type == CONST_PTR_TO_MAP) {
		if (!env->allow_ptr_leaks)
			verbose(env, "R%d pointer arithmetic on CONST_PTR_TO_MAP prohibited\n", dst);
		return -EACCES;
	}
	if (ptr_reg->type == PTR_TO_PACKET_END) {
		if (!env->allow_ptr_leaks)
			verbose(env, "R%d pointer arithmetic on PTR_TO_PACKET_END prohibited\n", dst);
		return -EACCES;
	}

	
	dst_reg->type = ptr_reg->type;
	dst_reg->id = ptr_reg->id;

	switch (opcode) {
	case BPF_ADD:
		
		if (known && (ptr_reg->off + smin_val == (s64)(s32)(ptr_reg->off + smin_val))) {
			
			dst_reg->smin_value = smin_ptr;
			dst_reg->smax_value = smax_ptr;
			dst_reg->umin_value = umin_ptr;
			dst_reg->umax_value = umax_ptr;
			dst_reg->var_off = ptr_reg->var_off;
			dst_reg->off = ptr_reg->off + smin_val;
			dst_reg->range = ptr_reg->range;
			break;
		}
		
		if (signed_add_overflows(smin_ptr, smin_val) || signed_add_overflows(smax_ptr, smax_val)) {
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			dst_reg->smin_value = smin_ptr + smin_val;
			dst_reg->smax_value = smax_ptr + smax_val;
		}
		if (umin_ptr + umin_val < umin_ptr || umax_ptr + umax_val < umax_ptr) {
			dst_reg->umin_value = 0;
			dst_reg->umax_value = U64_MAX;
		} else {
			dst_reg->umin_value = umin_ptr + umin_val;
			dst_reg->umax_value = umax_ptr + umax_val;
		}
		dst_reg->var_off = tnum_add(ptr_reg->var_off, off_reg->var_off);
		dst_reg->off = ptr_reg->off;
		if (reg_is_pkt_pointer(ptr_reg)) {
			dst_reg->id = ++env->id_gen;
			
			dst_reg->range = 0;
		}
		break;
	case BPF_SUB:
		if (dst_reg == off_reg) {
			
			if (!env->allow_ptr_leaks)
				verbose(env, "R%d tried to subtract pointer from scalar\n", dst);
			return -EACCES;
		}
		
		if (ptr_reg->type == PTR_TO_STACK) {
			if (!env->allow_ptr_leaks)
				verbose(env, "R%d subtraction from stack pointer prohibited\n", dst);
			return -EACCES;
		}
		if (known && (ptr_reg->off - smin_val == (s64)(s32)(ptr_reg->off - smin_val))) {
			
			dst_reg->smin_value = smin_ptr;
			dst_reg->smax_value = smax_ptr;
			dst_reg->umin_value = umin_ptr;
			dst_reg->umax_value = umax_ptr;
			dst_reg->var_off = ptr_reg->var_off;
			dst_reg->id = ptr_reg->id;
			dst_reg->off = ptr_reg->off - smin_val;
			dst_reg->range = ptr_reg->range;
			break;
		}
		
		if (signed_sub_overflows(smin_ptr, smax_val) || signed_sub_overflows(smax_ptr, smin_val)) {
			
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			dst_reg->smin_value = smin_ptr - smax_val;
			dst_reg->smax_value = smax_ptr - smin_val;
		}
		if (umin_ptr < umax_val) {
			
			dst_reg->umin_value = 0;
			dst_reg->umax_value = U64_MAX;
		} else {
			
			dst_reg->umin_value = umin_ptr - umax_val;
			dst_reg->umax_value = umax_ptr - umin_val;
		}
		dst_reg->var_off = tnum_sub(ptr_reg->var_off, off_reg->var_off);
		dst_reg->off = ptr_reg->off;
		if (reg_is_pkt_pointer(ptr_reg)) {
			dst_reg->id = ++env->id_gen;
			
			if (smin_val < 0)
				dst_reg->range = 0;
		}
		break;
	case BPF_AND:
	case BPF_OR:
	case BPF_XOR:
		
		if (!env->allow_ptr_leaks)
			verbose(env, "R%d bitwise operator %s on pointer prohibited\n", dst, bpf_alu_string[opcode >> 4]);
		return -EACCES;
	default:
		
		if (!env->allow_ptr_leaks)
			verbose(env, "R%d pointer arithmetic with %s operator prohibited\n", dst, bpf_alu_string[opcode >> 4]);
		return -EACCES;
	}

	__update_reg_bounds(dst_reg);
	__reg_deduce_bounds(dst_reg);
	__reg_bound_offset(dst_reg);
	return 0;
}

static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env, struct bpf_insn *insn, struct bpf_reg_state *dst_reg, struct bpf_reg_state src_reg)


{
	struct bpf_reg_state *regs = cur_regs(env);
	u8 opcode = BPF_OP(insn->code);
	bool src_known, dst_known;
	s64 smin_val, smax_val;
	u64 umin_val, umax_val;

	if (BPF_CLASS(insn->code) != BPF_ALU64) {
		
		coerce_reg_to_32(dst_reg);
		coerce_reg_to_32(&src_reg);
	}
	smin_val = src_reg.smin_value;
	smax_val = src_reg.smax_value;
	umin_val = src_reg.umin_value;
	umax_val = src_reg.umax_value;
	src_known = tnum_is_const(src_reg.var_off);
	dst_known = tnum_is_const(dst_reg->var_off);

	switch (opcode) {
	case BPF_ADD:
		if (signed_add_overflows(dst_reg->smin_value, smin_val) || signed_add_overflows(dst_reg->smax_value, smax_val)) {
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			dst_reg->smin_value += smin_val;
			dst_reg->smax_value += smax_val;
		}
		if (dst_reg->umin_value + umin_val < umin_val || dst_reg->umax_value + umax_val < umax_val) {
			dst_reg->umin_value = 0;
			dst_reg->umax_value = U64_MAX;
		} else {
			dst_reg->umin_value += umin_val;
			dst_reg->umax_value += umax_val;
		}
		dst_reg->var_off = tnum_add(dst_reg->var_off, src_reg.var_off);
		break;
	case BPF_SUB:
		if (signed_sub_overflows(dst_reg->smin_value, smax_val) || signed_sub_overflows(dst_reg->smax_value, smin_val)) {
			
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			dst_reg->smin_value -= smax_val;
			dst_reg->smax_value -= smin_val;
		}
		if (dst_reg->umin_value < umax_val) {
			
			dst_reg->umin_value = 0;
			dst_reg->umax_value = U64_MAX;
		} else {
			
			dst_reg->umin_value -= umax_val;
			dst_reg->umax_value -= umin_val;
		}
		dst_reg->var_off = tnum_sub(dst_reg->var_off, src_reg.var_off);
		break;
	case BPF_MUL:
		dst_reg->var_off = tnum_mul(dst_reg->var_off, src_reg.var_off);
		if (smin_val < 0 || dst_reg->smin_value < 0) {
			
			__mark_reg_unbounded(dst_reg);
			__update_reg_bounds(dst_reg);
			break;
		}
		
		if (umax_val > U32_MAX || dst_reg->umax_value > U32_MAX) {
			
			__mark_reg_unbounded(dst_reg);
			
			__update_reg_bounds(dst_reg);
			break;
		}
		dst_reg->umin_value *= umin_val;
		dst_reg->umax_value *= umax_val;
		if (dst_reg->umax_value > S64_MAX) {
			
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			dst_reg->smin_value = dst_reg->umin_value;
			dst_reg->smax_value = dst_reg->umax_value;
		}
		break;
	case BPF_AND:
		if (src_known && dst_known) {
			__mark_reg_known(dst_reg, dst_reg->var_off.value & src_reg.var_off.value);
			break;
		}
		
		dst_reg->var_off = tnum_and(dst_reg->var_off, src_reg.var_off);
		dst_reg->umin_value = dst_reg->var_off.value;
		dst_reg->umax_value = min(dst_reg->umax_value, umax_val);
		if (dst_reg->smin_value < 0 || smin_val < 0) {
			
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			
			dst_reg->smin_value = dst_reg->umin_value;
			dst_reg->smax_value = dst_reg->umax_value;
		}
		
		__update_reg_bounds(dst_reg);
		break;
	case BPF_OR:
		if (src_known && dst_known) {
			__mark_reg_known(dst_reg, dst_reg->var_off.value | src_reg.var_off.value);
			break;
		}
		
		dst_reg->var_off = tnum_or(dst_reg->var_off, src_reg.var_off);
		dst_reg->umin_value = max(dst_reg->umin_value, umin_val);
		dst_reg->umax_value = dst_reg->var_off.value | dst_reg->var_off.mask;
		if (dst_reg->smin_value < 0 || smin_val < 0) {
			
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			
			dst_reg->smin_value = dst_reg->umin_value;
			dst_reg->smax_value = dst_reg->umax_value;
		}
		
		__update_reg_bounds(dst_reg);
		break;
	case BPF_LSH:
		if (umax_val > 63) {
			
			mark_reg_unknown(env, regs, insn->dst_reg);
			break;
		}
		
		dst_reg->smin_value = S64_MIN;
		dst_reg->smax_value = S64_MAX;
		
		if (dst_reg->umax_value > 1ULL << (63 - umax_val)) {
			dst_reg->umin_value = 0;
			dst_reg->umax_value = U64_MAX;
		} else {
			dst_reg->umin_value <<= umin_val;
			dst_reg->umax_value <<= umax_val;
		}
		if (src_known)
			dst_reg->var_off = tnum_lshift(dst_reg->var_off, umin_val);
		else dst_reg->var_off = tnum_lshift(tnum_unknown, umin_val);
		
		__update_reg_bounds(dst_reg);
		break;
	case BPF_RSH:
		if (umax_val > 63) {
			
			mark_reg_unknown(env, regs, insn->dst_reg);
			break;
		}
		
		dst_reg->smin_value = S64_MIN;
		dst_reg->smax_value = S64_MAX;
		if (src_known)
			dst_reg->var_off = tnum_rshift(dst_reg->var_off, umin_val);
		else dst_reg->var_off = tnum_rshift(tnum_unknown, umin_val);
		dst_reg->umin_value >>= umax_val;
		dst_reg->umax_value >>= umin_val;
		
		__update_reg_bounds(dst_reg);
		break;
	default:
		mark_reg_unknown(env, regs, insn->dst_reg);
		break;
	}

	__reg_deduce_bounds(dst_reg);
	__reg_bound_offset(dst_reg);
	return 0;
}


static int adjust_reg_min_max_vals(struct bpf_verifier_env *env, struct bpf_insn *insn)
{
	struct bpf_reg_state *regs = cur_regs(env), *dst_reg, *src_reg;
	struct bpf_reg_state *ptr_reg = NULL, off_reg = {0};
	u8 opcode = BPF_OP(insn->code);
	int rc;

	dst_reg = &regs[insn->dst_reg];
	src_reg = NULL;
	if (dst_reg->type != SCALAR_VALUE)
		ptr_reg = dst_reg;
	if (BPF_SRC(insn->code) == BPF_X) {
		src_reg = &regs[insn->src_reg];
		if (src_reg->type != SCALAR_VALUE) {
			if (dst_reg->type != SCALAR_VALUE) {
				
				if (!env->allow_ptr_leaks) {
					verbose(env, "R%d pointer %s pointer prohibited\n", insn->dst_reg, bpf_alu_string[opcode >> 4]);

					return -EACCES;
				}
				mark_reg_unknown(env, regs, insn->dst_reg);
				return 0;
			} else {
				
				rc = adjust_ptr_min_max_vals(env, insn, src_reg, dst_reg);
				if (rc == -EACCES && env->allow_ptr_leaks) {
					
					__mark_reg_unknown(&off_reg);
					return adjust_scalar_min_max_vals( env, insn, dst_reg, off_reg);

				}
				return rc;
			}
		} else if (ptr_reg) {
			
			rc = adjust_ptr_min_max_vals(env, insn, dst_reg, src_reg);
			if (rc == -EACCES && env->allow_ptr_leaks) {
				
				__mark_reg_unknown(dst_reg);
				return adjust_scalar_min_max_vals( env, insn, dst_reg, *src_reg);
			}
			return rc;
		}
	} else {
		
		off_reg.type = SCALAR_VALUE;
		__mark_reg_known(&off_reg, insn->imm);
		src_reg = &off_reg;
		if (ptr_reg) { 
			rc = adjust_ptr_min_max_vals(env, insn, ptr_reg, src_reg);
			if (rc == -EACCES && env->allow_ptr_leaks) {
				
				__mark_reg_unknown(dst_reg);
				return adjust_scalar_min_max_vals( env, insn, dst_reg, off_reg);
			}
			return rc;
		}
	}

	
	if (WARN_ON_ONCE(ptr_reg)) {
		print_verifier_state(env, env->cur_state);
		verbose(env, "verifier internal error: unexpected ptr_reg\n");
		return -EINVAL;
	}
	if (WARN_ON(!src_reg)) {
		print_verifier_state(env, env->cur_state);
		verbose(env, "verifier internal error: no src_reg\n");
		return -EINVAL;
	}
	return adjust_scalar_min_max_vals(env, insn, dst_reg, *src_reg);
}


static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
{
	struct bpf_reg_state *regs = cur_regs(env);
	u8 opcode = BPF_OP(insn->code);
	int err;

	if (opcode == BPF_END || opcode == BPF_NEG) {
		if (opcode == BPF_NEG) {
			if (BPF_SRC(insn->code) != 0 || insn->src_reg != BPF_REG_0 || insn->off != 0 || insn->imm != 0) {

				verbose(env, "BPF_NEG uses reserved fields\n");
				return -EINVAL;
			}
		} else {
			if (insn->src_reg != BPF_REG_0 || insn->off != 0 || (insn->imm != 16 && insn->imm != 32 && insn->imm != 64) || BPF_CLASS(insn->code) == BPF_ALU64) {

				verbose(env, "BPF_END uses reserved fields\n");
				return -EINVAL;
			}
		}

		
		err = check_reg_arg(env, insn->dst_reg, SRC_OP);
		if (err)
			return err;

		if (is_pointer_value(env, insn->dst_reg)) {
			verbose(env, "R%d pointer arithmetic prohibited\n", insn->dst_reg);
			return -EACCES;
		}

		
		err = check_reg_arg(env, insn->dst_reg, DST_OP);
		if (err)
			return err;

	} else if (opcode == BPF_MOV) {

		if (BPF_SRC(insn->code) == BPF_X) {
			if (insn->imm != 0 || insn->off != 0) {
				verbose(env, "BPF_MOV uses reserved fields\n");
				return -EINVAL;
			}

			
			err = check_reg_arg(env, insn->src_reg, SRC_OP);
			if (err)
				return err;
		} else {
			if (insn->src_reg != BPF_REG_0 || insn->off != 0) {
				verbose(env, "BPF_MOV uses reserved fields\n");
				return -EINVAL;
			}
		}

		
		err = check_reg_arg(env, insn->dst_reg, DST_OP);
		if (err)
			return err;

		if (BPF_SRC(insn->code) == BPF_X) {
			if (BPF_CLASS(insn->code) == BPF_ALU64) {
				
				regs[insn->dst_reg] = regs[insn->src_reg];
				regs[insn->dst_reg].live |= REG_LIVE_WRITTEN;
			} else {
				
				if (is_pointer_value(env, insn->src_reg)) {
					verbose(env, "R%d partial copy of pointer\n", insn->src_reg);

					return -EACCES;
				}
				mark_reg_unknown(env, regs, insn->dst_reg);
				
				regs[insn->dst_reg].var_off = tnum_cast( regs[insn->dst_reg].var_off, 4);
				__update_reg_bounds(&regs[insn->dst_reg]);
			}
		} else {
			
			regs[insn->dst_reg].type = SCALAR_VALUE;
			if (BPF_CLASS(insn->code) == BPF_ALU64) {
				__mark_reg_known(regs + insn->dst_reg, insn->imm);
			} else {
				__mark_reg_known(regs + insn->dst_reg, (u32)insn->imm);
			}
		}

	} else if (opcode > BPF_END) {
		verbose(env, "invalid BPF_ALU opcode %x\n", opcode);
		return -EINVAL;

	} else {	

		if (BPF_SRC(insn->code) == BPF_X) {
			if (insn->imm != 0 || insn->off != 0) {
				verbose(env, "BPF_ALU uses reserved fields\n");
				return -EINVAL;
			}
			
			err = check_reg_arg(env, insn->src_reg, SRC_OP);
			if (err)
				return err;
		} else {
			if (insn->src_reg != BPF_REG_0 || insn->off != 0) {
				verbose(env, "BPF_ALU uses reserved fields\n");
				return -EINVAL;
			}
		}

		
		err = check_reg_arg(env, insn->dst_reg, SRC_OP);
		if (err)
			return err;

		if ((opcode == BPF_MOD || opcode == BPF_DIV) && BPF_SRC(insn->code) == BPF_K && insn->imm == 0) {
			verbose(env, "div by zero\n");
			return -EINVAL;
		}

		if ((opcode == BPF_LSH || opcode == BPF_RSH || opcode == BPF_ARSH) && BPF_SRC(insn->code) == BPF_K) {
			int size = BPF_CLASS(insn->code) == BPF_ALU64 ? 64 : 32;

			if (insn->imm < 0 || insn->imm >= size) {
				verbose(env, "invalid shift %d\n", insn->imm);
				return -EINVAL;
			}
		}

		
		err = check_reg_arg(env, insn->dst_reg, DST_OP_NO_MARK);
		if (err)
			return err;

		return adjust_reg_min_max_vals(env, insn);
	}

	return 0;
}

static void find_good_pkt_pointers(struct bpf_verifier_state *state, struct bpf_reg_state *dst_reg, enum bpf_reg_type type, bool range_right_open)


{
	struct bpf_reg_state *regs = state->regs, *reg;
	u16 new_range;
	int i;

	if (dst_reg->off < 0 || (dst_reg->off == 0 && range_right_open))
		
		return;

	if (dst_reg->umax_value > MAX_PACKET_OFF || dst_reg->umax_value + dst_reg->off > MAX_PACKET_OFF)
		
		return;

	new_range = dst_reg->off;
	if (range_right_open)
		new_range--;

	

	
	for (i = 0; i < MAX_BPF_REG; i++)
		if (regs[i].type == type && regs[i].id == dst_reg->id)
			
			regs[i].range = max(regs[i].range, new_range);

	for (i = 0; i < state->allocated_stack / BPF_REG_SIZE; i++) {
		if (state->stack[i].slot_type[0] != STACK_SPILL)
			continue;
		reg = &state->stack[i].spilled_ptr;
		if (reg->type == type && reg->id == dst_reg->id)
			reg->range = max(reg->range, new_range);
	}
}


static void reg_set_min_max(struct bpf_reg_state *true_reg, struct bpf_reg_state *false_reg, u64 val, u8 opcode)

{
	
	if (__is_pointer_value(false, false_reg))
		return;

	switch (opcode) {
	case BPF_JEQ:
		
		__mark_reg_known(true_reg, val);
		break;
	case BPF_JNE:
		
		__mark_reg_known(false_reg, val);
		break;
	case BPF_JGT:
		false_reg->umax_value = min(false_reg->umax_value, val);
		true_reg->umin_value = max(true_reg->umin_value, val + 1);
		break;
	case BPF_JSGT:
		false_reg->smax_value = min_t(s64, false_reg->smax_value, val);
		true_reg->smin_value = max_t(s64, true_reg->smin_value, val + 1);
		break;
	case BPF_JLT:
		false_reg->umin_value = max(false_reg->umin_value, val);
		true_reg->umax_value = min(true_reg->umax_value, val - 1);
		break;
	case BPF_JSLT:
		false_reg->smin_value = max_t(s64, false_reg->smin_value, val);
		true_reg->smax_value = min_t(s64, true_reg->smax_value, val - 1);
		break;
	case BPF_JGE:
		false_reg->umax_value = min(false_reg->umax_value, val - 1);
		true_reg->umin_value = max(true_reg->umin_value, val);
		break;
	case BPF_JSGE:
		false_reg->smax_value = min_t(s64, false_reg->smax_value, val - 1);
		true_reg->smin_value = max_t(s64, true_reg->smin_value, val);
		break;
	case BPF_JLE:
		false_reg->umin_value = max(false_reg->umin_value, val + 1);
		true_reg->umax_value = min(true_reg->umax_value, val);
		break;
	case BPF_JSLE:
		false_reg->smin_value = max_t(s64, false_reg->smin_value, val + 1);
		true_reg->smax_value = min_t(s64, true_reg->smax_value, val);
		break;
	default:
		break;
	}

	__reg_deduce_bounds(false_reg);
	__reg_deduce_bounds(true_reg);
	
	__reg_bound_offset(false_reg);
	__reg_bound_offset(true_reg);
	
	__update_reg_bounds(false_reg);
	__update_reg_bounds(true_reg);
}


static void reg_set_min_max_inv(struct bpf_reg_state *true_reg, struct bpf_reg_state *false_reg, u64 val, u8 opcode)

{
	if (__is_pointer_value(false, false_reg))
		return;

	switch (opcode) {
	case BPF_JEQ:
		
		__mark_reg_known(true_reg, val);
		break;
	case BPF_JNE:
		
		__mark_reg_known(false_reg, val);
		break;
	case BPF_JGT:
		true_reg->umax_value = min(true_reg->umax_value, val - 1);
		false_reg->umin_value = max(false_reg->umin_value, val);
		break;
	case BPF_JSGT:
		true_reg->smax_value = min_t(s64, true_reg->smax_value, val - 1);
		false_reg->smin_value = max_t(s64, false_reg->smin_value, val);
		break;
	case BPF_JLT:
		true_reg->umin_value = max(true_reg->umin_value, val + 1);
		false_reg->umax_value = min(false_reg->umax_value, val);
		break;
	case BPF_JSLT:
		true_reg->smin_value = max_t(s64, true_reg->smin_value, val + 1);
		false_reg->smax_value = min_t(s64, false_reg->smax_value, val);
		break;
	case BPF_JGE:
		true_reg->umax_value = min(true_reg->umax_value, val);
		false_reg->umin_value = max(false_reg->umin_value, val + 1);
		break;
	case BPF_JSGE:
		true_reg->smax_value = min_t(s64, true_reg->smax_value, val);
		false_reg->smin_value = max_t(s64, false_reg->smin_value, val + 1);
		break;
	case BPF_JLE:
		true_reg->umin_value = max(true_reg->umin_value, val);
		false_reg->umax_value = min(false_reg->umax_value, val - 1);
		break;
	case BPF_JSLE:
		true_reg->smin_value = max_t(s64, true_reg->smin_value, val);
		false_reg->smax_value = min_t(s64, false_reg->smax_value, val - 1);
		break;
	default:
		break;
	}

	__reg_deduce_bounds(false_reg);
	__reg_deduce_bounds(true_reg);
	
	__reg_bound_offset(false_reg);
	__reg_bound_offset(true_reg);
	
	__update_reg_bounds(false_reg);
	__update_reg_bounds(true_reg);
}


static void __reg_combine_min_max(struct bpf_reg_state *src_reg, struct bpf_reg_state *dst_reg)
{
	src_reg->umin_value = dst_reg->umin_value = max(src_reg->umin_value, dst_reg->umin_value);
	src_reg->umax_value = dst_reg->umax_value = min(src_reg->umax_value, dst_reg->umax_value);
	src_reg->smin_value = dst_reg->smin_value = max(src_reg->smin_value, dst_reg->smin_value);
	src_reg->smax_value = dst_reg->smax_value = min(src_reg->smax_value, dst_reg->smax_value);
	src_reg->var_off = dst_reg->var_off = tnum_intersect(src_reg->var_off, dst_reg->var_off);
	
	__update_reg_bounds(src_reg);
	__update_reg_bounds(dst_reg);
	
	__reg_deduce_bounds(src_reg);
	__reg_deduce_bounds(dst_reg);
	
	__reg_bound_offset(src_reg);
	__reg_bound_offset(dst_reg);
	
	__update_reg_bounds(src_reg);
	__update_reg_bounds(dst_reg);
}

static void reg_combine_min_max(struct bpf_reg_state *true_src, struct bpf_reg_state *true_dst, struct bpf_reg_state *false_src, struct bpf_reg_state *false_dst, u8 opcode)



{
	switch (opcode) {
	case BPF_JEQ:
		__reg_combine_min_max(true_src, true_dst);
		break;
	case BPF_JNE:
		__reg_combine_min_max(false_src, false_dst);
		break;
	}
}

static void mark_map_reg(struct bpf_reg_state *regs, u32 regno, u32 id, bool is_null)
{
	struct bpf_reg_state *reg = &regs[regno];

	if (reg->type == PTR_TO_MAP_VALUE_OR_NULL && reg->id == id) {
		
		if (WARN_ON_ONCE(reg->smin_value || reg->smax_value || !tnum_equals_const(reg->var_off, 0) || reg->off)) {

			__mark_reg_known_zero(reg);
			reg->off = 0;
		}
		if (is_null) {
			reg->type = SCALAR_VALUE;
		} else if (reg->map_ptr->inner_map_meta) {
			reg->type = CONST_PTR_TO_MAP;
			reg->map_ptr = reg->map_ptr->inner_map_meta;
		} else {
			reg->type = PTR_TO_MAP_VALUE;
		}
		
		reg->id = 0;
	}
}


static void mark_map_regs(struct bpf_verifier_state *state, u32 regno, bool is_null)
{
	struct bpf_reg_state *regs = state->regs;
	u32 id = regs[regno].id;
	int i;

	for (i = 0; i < MAX_BPF_REG; i++)
		mark_map_reg(regs, i, id, is_null);

	for (i = 0; i < state->allocated_stack / BPF_REG_SIZE; i++) {
		if (state->stack[i].slot_type[0] != STACK_SPILL)
			continue;
		mark_map_reg(&state->stack[i].spilled_ptr, 0, id, is_null);
	}
}

static bool try_match_pkt_pointers(const struct bpf_insn *insn, struct bpf_reg_state *dst_reg, struct bpf_reg_state *src_reg, struct bpf_verifier_state *this_branch, struct bpf_verifier_state *other_branch)



{
	if (BPF_SRC(insn->code) != BPF_X)
		return false;

	switch (BPF_OP(insn->code)) {
	case BPF_JGT:
		if ((dst_reg->type == PTR_TO_PACKET && src_reg->type == PTR_TO_PACKET_END) || (dst_reg->type == PTR_TO_PACKET_META && reg_is_init_pkt_pointer(src_reg, PTR_TO_PACKET))) {


			
			find_good_pkt_pointers(this_branch, dst_reg, dst_reg->type, false);
		} else if ((dst_reg->type == PTR_TO_PACKET_END && src_reg->type == PTR_TO_PACKET) || (reg_is_init_pkt_pointer(dst_reg, PTR_TO_PACKET) && src_reg->type == PTR_TO_PACKET_META)) {


			
			find_good_pkt_pointers(other_branch, src_reg, src_reg->type, true);
		} else {
			return false;
		}
		break;
	case BPF_JLT:
		if ((dst_reg->type == PTR_TO_PACKET && src_reg->type == PTR_TO_PACKET_END) || (dst_reg->type == PTR_TO_PACKET_META && reg_is_init_pkt_pointer(src_reg, PTR_TO_PACKET))) {


			
			find_good_pkt_pointers(other_branch, dst_reg, dst_reg->type, true);
		} else if ((dst_reg->type == PTR_TO_PACKET_END && src_reg->type == PTR_TO_PACKET) || (reg_is_init_pkt_pointer(dst_reg, PTR_TO_PACKET) && src_reg->type == PTR_TO_PACKET_META)) {


			
			find_good_pkt_pointers(this_branch, src_reg, src_reg->type, false);
		} else {
			return false;
		}
		break;
	case BPF_JGE:
		if ((dst_reg->type == PTR_TO_PACKET && src_reg->type == PTR_TO_PACKET_END) || (dst_reg->type == PTR_TO_PACKET_META && reg_is_init_pkt_pointer(src_reg, PTR_TO_PACKET))) {


			
			find_good_pkt_pointers(this_branch, dst_reg, dst_reg->type, true);
		} else if ((dst_reg->type == PTR_TO_PACKET_END && src_reg->type == PTR_TO_PACKET) || (reg_is_init_pkt_pointer(dst_reg, PTR_TO_PACKET) && src_reg->type == PTR_TO_PACKET_META)) {


			
			find_good_pkt_pointers(other_branch, src_reg, src_reg->type, false);
		} else {
			return false;
		}
		break;
	case BPF_JLE:
		if ((dst_reg->type == PTR_TO_PACKET && src_reg->type == PTR_TO_PACKET_END) || (dst_reg->type == PTR_TO_PACKET_META && reg_is_init_pkt_pointer(src_reg, PTR_TO_PACKET))) {


			
			find_good_pkt_pointers(other_branch, dst_reg, dst_reg->type, false);
		} else if ((dst_reg->type == PTR_TO_PACKET_END && src_reg->type == PTR_TO_PACKET) || (reg_is_init_pkt_pointer(dst_reg, PTR_TO_PACKET) && src_reg->type == PTR_TO_PACKET_META)) {


			
			find_good_pkt_pointers(this_branch, src_reg, src_reg->type, true);
		} else {
			return false;
		}
		break;
	default:
		return false;
	}

	return true;
}

static int check_cond_jmp_op(struct bpf_verifier_env *env, struct bpf_insn *insn, int *insn_idx)
{
	struct bpf_verifier_state *other_branch, *this_branch = env->cur_state;
	struct bpf_reg_state *regs = this_branch->regs, *dst_reg;
	u8 opcode = BPF_OP(insn->code);
	int err;

	if (opcode > BPF_JSLE) {
		verbose(env, "invalid BPF_JMP opcode %x\n", opcode);
		return -EINVAL;
	}

	if (BPF_SRC(insn->code) == BPF_X) {
		if (insn->imm != 0) {
			verbose(env, "BPF_JMP uses reserved fields\n");
			return -EINVAL;
		}

		
		err = check_reg_arg(env, insn->src_reg, SRC_OP);
		if (err)
			return err;

		if (is_pointer_value(env, insn->src_reg)) {
			verbose(env, "R%d pointer comparison prohibited\n", insn->src_reg);
			return -EACCES;
		}
	} else {
		if (insn->src_reg != BPF_REG_0) {
			verbose(env, "BPF_JMP uses reserved fields\n");
			return -EINVAL;
		}
	}

	
	err = check_reg_arg(env, insn->dst_reg, SRC_OP);
	if (err)
		return err;

	dst_reg = &regs[insn->dst_reg];

	
	if (BPF_SRC(insn->code) == BPF_K && (opcode == BPF_JEQ || opcode == BPF_JNE) && dst_reg->type == SCALAR_VALUE && tnum_equals_const(dst_reg->var_off, insn->imm)) {


		if (opcode == BPF_JEQ) {
			
			*insn_idx += insn->off;
			return 0;
		} else {
			
			return 0;
		}
	}

	other_branch = push_stack(env, *insn_idx + insn->off + 1, *insn_idx);
	if (!other_branch)
		return -EFAULT;

	
	if (BPF_SRC(insn->code) == BPF_X) {
		if (dst_reg->type == SCALAR_VALUE && regs[insn->src_reg].type == SCALAR_VALUE) {
			if (tnum_is_const(regs[insn->src_reg].var_off))
				reg_set_min_max(&other_branch->regs[insn->dst_reg], dst_reg, regs[insn->src_reg].var_off.value, opcode);

			else if (tnum_is_const(dst_reg->var_off))
				reg_set_min_max_inv(&other_branch->regs[insn->src_reg], &regs[insn->src_reg], dst_reg->var_off.value, opcode);

			else if (opcode == BPF_JEQ || opcode == BPF_JNE)
				
				reg_combine_min_max(&other_branch->regs[insn->src_reg], &other_branch->regs[insn->dst_reg], &regs[insn->src_reg], &regs[insn->dst_reg], opcode);


		}
	} else if (dst_reg->type == SCALAR_VALUE) {
		reg_set_min_max(&other_branch->regs[insn->dst_reg], dst_reg, insn->imm, opcode);
	}

	
	if (BPF_SRC(insn->code) == BPF_K && insn->imm == 0 && (opcode == BPF_JEQ || opcode == BPF_JNE) && dst_reg->type == PTR_TO_MAP_VALUE_OR_NULL) {

		
		mark_map_regs(this_branch, insn->dst_reg, opcode == BPF_JNE);
		mark_map_regs(other_branch, insn->dst_reg, opcode == BPF_JEQ);
	} else if (!try_match_pkt_pointers(insn, dst_reg, &regs[insn->src_reg], this_branch, other_branch) && is_pointer_value(env, insn->dst_reg)) {

		verbose(env, "R%d pointer comparison prohibited\n", insn->dst_reg);
		return -EACCES;
	}
	if (env->log.level)
		print_verifier_state(env, this_branch);
	return 0;
}


static struct bpf_map *ld_imm64_to_map_ptr(struct bpf_insn *insn)
{
	u64 imm64 = ((u64) (u32) insn[0].imm) | ((u64) (u32) insn[1].imm) << 32;

	return (struct bpf_map *) (unsigned long) imm64;
}


static int check_ld_imm(struct bpf_verifier_env *env, struct bpf_insn *insn)
{
	struct bpf_reg_state *regs = cur_regs(env);
	int err;

	if (BPF_SIZE(insn->code) != BPF_DW) {
		verbose(env, "invalid BPF_LD_IMM insn\n");
		return -EINVAL;
	}
	if (insn->off != 0) {
		verbose(env, "BPF_LD_IMM64 uses reserved fields\n");
		return -EINVAL;
	}

	err = check_reg_arg(env, insn->dst_reg, DST_OP);
	if (err)
		return err;

	if (insn->src_reg == 0) {
		u64 imm = ((u64)(insn + 1)->imm << 32) | (u32)insn->imm;

		regs[insn->dst_reg].type = SCALAR_VALUE;
		__mark_reg_known(&regs[insn->dst_reg], imm);
		return 0;
	}

	
	BUG_ON(insn->src_reg != BPF_PSEUDO_MAP_FD);

	regs[insn->dst_reg].type = CONST_PTR_TO_MAP;
	regs[insn->dst_reg].map_ptr = ld_imm64_to_map_ptr(insn);
	return 0;
}

static bool may_access_skb(enum bpf_prog_type type)
{
	switch (type) {
	case BPF_PROG_TYPE_SOCKET_FILTER:
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
		return true;
	default:
		return false;
	}
}


static int check_ld_abs(struct bpf_verifier_env *env, struct bpf_insn *insn)
{
	struct bpf_reg_state *regs = cur_regs(env);
	u8 mode = BPF_MODE(insn->code);
	int i, err;

	if (!may_access_skb(env->prog->type)) {
		verbose(env, "BPF_LD_[ABS|IND] instructions not allowed for this program type\n");
		return -EINVAL;
	}

	if (insn->dst_reg != BPF_REG_0 || insn->off != 0 || BPF_SIZE(insn->code) == BPF_DW || (mode == BPF_ABS && insn->src_reg != BPF_REG_0)) {

		verbose(env, "BPF_LD_[ABS|IND] uses reserved fields\n");
		return -EINVAL;
	}

	
	err = check_reg_arg(env, BPF_REG_6, SRC_OP);
	if (err)
		return err;

	if (regs[BPF_REG_6].type != PTR_TO_CTX) {
		verbose(env, "at the time of BPF_LD_ABS|IND R6 != pointer to skb\n");
		return -EINVAL;
	}

	if (mode == BPF_IND) {
		
		err = check_reg_arg(env, insn->src_reg, SRC_OP);
		if (err)
			return err;
	}

	
	for (i = 0; i < CALLER_SAVED_REGS; i++) {
		mark_reg_not_init(env, regs, caller_saved[i]);
		check_reg_arg(env, caller_saved[i], DST_OP_NO_MARK);
	}

	
	mark_reg_unknown(env, regs, BPF_REG_0);
	return 0;
}

static int check_return_code(struct bpf_verifier_env *env)
{
	struct bpf_reg_state *reg;
	struct tnum range = tnum_range(0, 1);

	switch (env->prog->type) {
	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_SOCK_OPS:
	case BPF_PROG_TYPE_CGROUP_DEVICE:
		break;
	default:
		return 0;
	}

	reg = cur_regs(env) + BPF_REG_0;
	if (reg->type != SCALAR_VALUE) {
		verbose(env, "At program exit the register R0 is not a known value (%s)\n", reg_type_str[reg->type]);
		return -EINVAL;
	}

	if (!tnum_in(range, reg->var_off)) {
		verbose(env, "At program exit the register R0 ");
		if (!tnum_is_unknown(reg->var_off)) {
			char tn_buf[48];

			tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
			verbose(env, "has value %s", tn_buf);
		} else {
			verbose(env, "has unknown scalar value");
		}
		verbose(env, " should have been 0 or 1\n");
		return -EINVAL;
	}
	return 0;
}



enum {
	DISCOVERED = 0x10, EXPLORED = 0x20, FALLTHROUGH = 1, BRANCH = 2, };






static int *insn_stack;	
static int cur_stack;	
static int *insn_state;


static int push_insn(int t, int w, int e, struct bpf_verifier_env *env)
{
	if (e == FALLTHROUGH && insn_state[t] >= (DISCOVERED | FALLTHROUGH))
		return 0;

	if (e == BRANCH && insn_state[t] >= (DISCOVERED | BRANCH))
		return 0;

	if (w < 0 || w >= env->prog->len) {
		verbose(env, "jump out of range from insn %d to %d\n", t, w);
		return -EINVAL;
	}

	if (e == BRANCH)
		
		env->explored_states[w] = STATE_LIST_MARK;

	if (insn_state[w] == 0) {
		
		insn_state[t] = DISCOVERED | e;
		insn_state[w] = DISCOVERED;
		if (cur_stack >= env->prog->len)
			return -E2BIG;
		insn_stack[cur_stack++] = w;
		return 1;
	} else if ((insn_state[w] & 0xF0) == DISCOVERED) {
		verbose(env, "back-edge from insn %d to %d\n", t, w);
		return -EINVAL;
	} else if (insn_state[w] == EXPLORED) {
		
		insn_state[t] = DISCOVERED | e;
	} else {
		verbose(env, "insn state internal bug\n");
		return -EFAULT;
	}
	return 0;
}


static int check_cfg(struct bpf_verifier_env *env)
{
	struct bpf_insn *insns = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	int ret = 0;
	int i, t;

	insn_state = kcalloc(insn_cnt, sizeof(int), GFP_KERNEL);
	if (!insn_state)
		return -ENOMEM;

	insn_stack = kcalloc(insn_cnt, sizeof(int), GFP_KERNEL);
	if (!insn_stack) {
		kfree(insn_state);
		return -ENOMEM;
	}

	insn_state[0] = DISCOVERED; 
	insn_stack[0] = 0; 
	cur_stack = 1;

peek_stack:
	if (cur_stack == 0)
		goto check_state;
	t = insn_stack[cur_stack - 1];

	if (BPF_CLASS(insns[t].code) == BPF_JMP) {
		u8 opcode = BPF_OP(insns[t].code);

		if (opcode == BPF_EXIT) {
			goto mark_explored;
		} else if (opcode == BPF_CALL) {
			ret = push_insn(t, t + 1, FALLTHROUGH, env);
			if (ret == 1)
				goto peek_stack;
			else if (ret < 0)
				goto err_free;
			if (t + 1 < insn_cnt)
				env->explored_states[t + 1] = STATE_LIST_MARK;
		} else if (opcode == BPF_JA) {
			if (BPF_SRC(insns[t].code) != BPF_K) {
				ret = -EINVAL;
				goto err_free;
			}
			
			ret = push_insn(t, t + insns[t].off + 1, FALLTHROUGH, env);
			if (ret == 1)
				goto peek_stack;
			else if (ret < 0)
				goto err_free;
			
			if (t + 1 < insn_cnt)
				env->explored_states[t + 1] = STATE_LIST_MARK;
		} else {
			
			env->explored_states[t] = STATE_LIST_MARK;
			ret = push_insn(t, t + 1, FALLTHROUGH, env);
			if (ret == 1)
				goto peek_stack;
			else if (ret < 0)
				goto err_free;

			ret = push_insn(t, t + insns[t].off + 1, BRANCH, env);
			if (ret == 1)
				goto peek_stack;
			else if (ret < 0)
				goto err_free;
		}
	} else {
		
		ret = push_insn(t, t + 1, FALLTHROUGH, env);
		if (ret == 1)
			goto peek_stack;
		else if (ret < 0)
			goto err_free;
	}

mark_explored:
	insn_state[t] = EXPLORED;
	if (cur_stack-- <= 0) {
		verbose(env, "pop stack internal bug\n");
		ret = -EFAULT;
		goto err_free;
	}
	goto peek_stack;

check_state:
	for (i = 0; i < insn_cnt; i++) {
		if (insn_state[i] != EXPLORED) {
			verbose(env, "unreachable insn %d\n", i);
			ret = -EINVAL;
			goto err_free;
		}
	}
	ret = 0; 

err_free:
	kfree(insn_state);
	kfree(insn_stack);
	return ret;
}


static bool range_within(struct bpf_reg_state *old, struct bpf_reg_state *cur)
{
	return old->umin_value <= cur->umin_value && old->umax_value >= cur->umax_value && old->smin_value <= cur->smin_value && old->smax_value >= cur->smax_value;


}



struct idpair {
	u32 old;
	u32 cur;
};


static bool check_ids(u32 old_id, u32 cur_id, struct idpair *idmap)
{
	unsigned int i;

	for (i = 0; i < ID_MAP_SIZE; i++) {
		if (!idmap[i].old) {
			
			idmap[i].old = old_id;
			idmap[i].cur = cur_id;
			return true;
		}
		if (idmap[i].old == old_id)
			return idmap[i].cur == cur_id;
	}
	
	WARN_ON_ONCE(1);
	return false;
}


static bool regsafe(struct bpf_reg_state *rold, struct bpf_reg_state *rcur, struct idpair *idmap)
{
	if (!(rold->live & REG_LIVE_READ))
		
		return true;

	if (memcmp(rold, rcur, offsetof(struct bpf_reg_state, live)) == 0)
		return true;

	if (rold->type == NOT_INIT)
		
		return true;
	if (rcur->type == NOT_INIT)
		return false;
	switch (rold->type) {
	case SCALAR_VALUE:
		if (rcur->type == SCALAR_VALUE) {
			
			return range_within(rold, rcur) && tnum_in(rold->var_off, rcur->var_off);
		} else {
			
			return rold->umin_value == 0 && rold->umax_value == U64_MAX && rold->smin_value == S64_MIN && rold->smax_value == S64_MAX && tnum_is_unknown(rold->var_off);



		}
	case PTR_TO_MAP_VALUE:
		
		return memcmp(rold, rcur, offsetof(struct bpf_reg_state, id)) == 0 && range_within(rold, rcur) && tnum_in(rold->var_off, rcur->var_off);

	case PTR_TO_MAP_VALUE_OR_NULL:
		
		if (rcur->type != PTR_TO_MAP_VALUE_OR_NULL)
			return false;
		if (memcmp(rold, rcur, offsetof(struct bpf_reg_state, id)))
			return false;
		
		return check_ids(rold->id, rcur->id, idmap);
	case PTR_TO_PACKET_META:
	case PTR_TO_PACKET:
		if (rcur->type != rold->type)
			return false;
		
		if (rold->range > rcur->range)
			return false;
		
		if (rold->off != rcur->off)
			return false;
		
		if (rold->id && !check_ids(rold->id, rcur->id, idmap))
			return false;
		
		return range_within(rold, rcur) && tnum_in(rold->var_off, rcur->var_off);
	case PTR_TO_CTX:
	case CONST_PTR_TO_MAP:
	case PTR_TO_STACK:
	case PTR_TO_PACKET_END:
		
	default:
		
		return false;
	}

	
	WARN_ON_ONCE(1);
	return false;
}

static bool stacksafe(struct bpf_verifier_state *old, struct bpf_verifier_state *cur, struct idpair *idmap)

{
	int i, spi;

	
	if (old->allocated_stack > cur->allocated_stack)
		return false;

	
	for (i = 0; i < old->allocated_stack; i++) {
		spi = i / BPF_REG_SIZE;

		if (old->stack[spi].slot_type[i % BPF_REG_SIZE] == STACK_INVALID)
			continue;
		if (old->stack[spi].slot_type[i % BPF_REG_SIZE] != cur->stack[spi].slot_type[i % BPF_REG_SIZE])
			
			return false;
		if (i % BPF_REG_SIZE)
			continue;
		if (old->stack[spi].slot_type[0] != STACK_SPILL)
			continue;
		if (!regsafe(&old->stack[spi].spilled_ptr, &cur->stack[spi].spilled_ptr, idmap))

			
			return false;
	}
	return true;
}


static bool states_equal(struct bpf_verifier_env *env, struct bpf_verifier_state *old, struct bpf_verifier_state *cur)

{
	struct idpair *idmap;
	bool ret = false;
	int i;

	idmap = kcalloc(ID_MAP_SIZE, sizeof(struct idpair), GFP_KERNEL);
	
	if (!idmap)
		return false;

	for (i = 0; i < MAX_BPF_REG; i++) {
		if (!regsafe(&old->regs[i], &cur->regs[i], idmap))
			goto out_free;
	}

	if (!stacksafe(old, cur, idmap))
		goto out_free;
	ret = true;
out_free:
	kfree(idmap);
	return ret;
}


static bool do_propagate_liveness(const struct bpf_verifier_state *state, struct bpf_verifier_state *parent)
{
	bool writes = parent == state->parent; 
	bool touched = false; 
	int i;

	if (!parent)
		return touched;
	
	BUILD_BUG_ON(BPF_REG_FP + 1 != MAX_BPF_REG);
	
	for (i = 0; i < BPF_REG_FP; i++) {
		if (parent->regs[i].live & REG_LIVE_READ)
			continue;
		if (writes && (state->regs[i].live & REG_LIVE_WRITTEN))
			continue;
		if (state->regs[i].live & REG_LIVE_READ) {
			parent->regs[i].live |= REG_LIVE_READ;
			touched = true;
		}
	}
	
	for (i = 0; i < state->allocated_stack / BPF_REG_SIZE && i < parent->allocated_stack / BPF_REG_SIZE; i++) {
		if (parent->stack[i].slot_type[0] != STACK_SPILL)
			continue;
		if (state->stack[i].slot_type[0] != STACK_SPILL)
			continue;
		if (parent->stack[i].spilled_ptr.live & REG_LIVE_READ)
			continue;
		if (writes && (state->stack[i].spilled_ptr.live & REG_LIVE_WRITTEN))
			continue;
		if (state->stack[i].spilled_ptr.live & REG_LIVE_READ) {
			parent->stack[i].spilled_ptr.live |= REG_LIVE_READ;
			touched = true;
		}
	}
	return touched;
}


static void propagate_liveness(const struct bpf_verifier_state *state, struct bpf_verifier_state *parent)
{
	while (do_propagate_liveness(state, parent)) {
		
		state = parent;
		parent = state->parent;
	}
}

static int is_state_visited(struct bpf_verifier_env *env, int insn_idx)
{
	struct bpf_verifier_state_list *new_sl;
	struct bpf_verifier_state_list *sl;
	struct bpf_verifier_state *cur = env->cur_state;
	int i, err;

	sl = env->explored_states[insn_idx];
	if (!sl)
		
		return 0;

	while (sl != STATE_LIST_MARK) {
		if (states_equal(env, &sl->state, cur)) {
			
			propagate_liveness(&sl->state, cur);
			return 1;
		}
		sl = sl->next;
	}

	
	new_sl = kzalloc(sizeof(struct bpf_verifier_state_list), GFP_KERNEL);
	if (!new_sl)
		return -ENOMEM;

	
	err = copy_verifier_state(&new_sl->state, cur);
	if (err) {
		free_verifier_state(&new_sl->state, false);
		kfree(new_sl);
		return err;
	}
	new_sl->next = env->explored_states[insn_idx];
	env->explored_states[insn_idx] = new_sl;
	
	cur->parent = &new_sl->state;
	
	for (i = 0; i < BPF_REG_FP; i++)
		cur->regs[i].live = REG_LIVE_NONE;
	for (i = 0; i < cur->allocated_stack / BPF_REG_SIZE; i++)
		if (cur->stack[i].slot_type[0] == STACK_SPILL)
			cur->stack[i].spilled_ptr.live = REG_LIVE_NONE;
	return 0;
}

static int ext_analyzer_insn_hook(struct bpf_verifier_env *env, int insn_idx, int prev_insn_idx)
{
	if (env->dev_ops && env->dev_ops->insn_hook)
		return env->dev_ops->insn_hook(env, insn_idx, prev_insn_idx);

	return 0;
}

static int do_check(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *state;
	struct bpf_insn *insns = env->prog->insnsi;
	struct bpf_reg_state *regs;
	int insn_cnt = env->prog->len;
	int insn_idx, prev_insn_idx = 0;
	int insn_processed = 0;
	bool do_print_state = false;

	state = kzalloc(sizeof(struct bpf_verifier_state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	env->cur_state = state;
	init_reg_state(env, state->regs);
	state->parent = NULL;
	insn_idx = 0;
	for (;;) {
		struct bpf_insn *insn;
		u8 class;
		int err;

		if (insn_idx >= insn_cnt) {
			verbose(env, "invalid insn idx %d insn_cnt %d\n", insn_idx, insn_cnt);
			return -EFAULT;
		}

		insn = &insns[insn_idx];
		class = BPF_CLASS(insn->code);

		if (++insn_processed > BPF_COMPLEXITY_LIMIT_INSNS) {
			verbose(env, "BPF program is too large. Processed %d insn\n", insn_processed);

			return -E2BIG;
		}

		err = is_state_visited(env, insn_idx);
		if (err < 0)
			return err;
		if (err == 1) {
			
			if (env->log.level) {
				if (do_print_state)
					verbose(env, "\nfrom %d to %d: safe\n", prev_insn_idx, insn_idx);
				else verbose(env, "%d: safe\n", insn_idx);
			}
			goto process_bpf_exit;
		}

		if (need_resched())
			cond_resched();

		if (env->log.level > 1 || (env->log.level && do_print_state)) {
			if (env->log.level > 1)
				verbose(env, "%d:", insn_idx);
			else verbose(env, "\nfrom %d to %d:", prev_insn_idx, insn_idx);

			print_verifier_state(env, state);
			do_print_state = false;
		}

		if (env->log.level) {
			verbose(env, "%d: ", insn_idx);
			print_bpf_insn(verbose, env, insn, env->allow_ptr_leaks);
		}

		err = ext_analyzer_insn_hook(env, insn_idx, prev_insn_idx);
		if (err)
			return err;

		regs = cur_regs(env);
		env->insn_aux_data[insn_idx].seen = true;
		if (class == BPF_ALU || class == BPF_ALU64) {
			err = check_alu_op(env, insn);
			if (err)
				return err;

		} else if (class == BPF_LDX) {
			enum bpf_reg_type *prev_src_type, src_reg_type;

			

			
			err = check_reg_arg(env, insn->src_reg, SRC_OP);
			if (err)
				return err;

			err = check_reg_arg(env, insn->dst_reg, DST_OP_NO_MARK);
			if (err)
				return err;

			src_reg_type = regs[insn->src_reg].type;

			
			err = check_mem_access(env, insn_idx, insn->src_reg, insn->off, BPF_SIZE(insn->code), BPF_READ, insn->dst_reg);

			if (err)
				return err;

			prev_src_type = &env->insn_aux_data[insn_idx].ptr_type;

			if (*prev_src_type == NOT_INIT) {
				
				*prev_src_type = src_reg_type;

			} else if (src_reg_type != *prev_src_type && (src_reg_type == PTR_TO_CTX || *prev_src_type == PTR_TO_CTX)) {

				
				verbose(env, "same insn cannot be used with different pointers\n");
				return -EINVAL;
			}

		} else if (class == BPF_STX) {
			enum bpf_reg_type *prev_dst_type, dst_reg_type;

			if (BPF_MODE(insn->code) == BPF_XADD) {
				err = check_xadd(env, insn_idx, insn);
				if (err)
					return err;
				insn_idx++;
				continue;
			}

			
			err = check_reg_arg(env, insn->src_reg, SRC_OP);
			if (err)
				return err;
			
			err = check_reg_arg(env, insn->dst_reg, SRC_OP);
			if (err)
				return err;

			dst_reg_type = regs[insn->dst_reg].type;

			
			err = check_mem_access(env, insn_idx, insn->dst_reg, insn->off, BPF_SIZE(insn->code), BPF_WRITE, insn->src_reg);

			if (err)
				return err;

			prev_dst_type = &env->insn_aux_data[insn_idx].ptr_type;

			if (*prev_dst_type == NOT_INIT) {
				*prev_dst_type = dst_reg_type;
			} else if (dst_reg_type != *prev_dst_type && (dst_reg_type == PTR_TO_CTX || *prev_dst_type == PTR_TO_CTX)) {

				verbose(env, "same insn cannot be used with different pointers\n");
				return -EINVAL;
			}

		} else if (class == BPF_ST) {
			if (BPF_MODE(insn->code) != BPF_MEM || insn->src_reg != BPF_REG_0) {
				verbose(env, "BPF_ST uses reserved fields\n");
				return -EINVAL;
			}
			
			err = check_reg_arg(env, insn->dst_reg, SRC_OP);
			if (err)
				return err;

			
			err = check_mem_access(env, insn_idx, insn->dst_reg, insn->off, BPF_SIZE(insn->code), BPF_WRITE, -1);

			if (err)
				return err;

		} else if (class == BPF_JMP) {
			u8 opcode = BPF_OP(insn->code);

			if (opcode == BPF_CALL) {
				if (BPF_SRC(insn->code) != BPF_K || insn->off != 0 || insn->src_reg != BPF_REG_0 || insn->dst_reg != BPF_REG_0) {


					verbose(env, "BPF_CALL uses reserved fields\n");
					return -EINVAL;
				}

				err = check_call(env, insn->imm, insn_idx);
				if (err)
					return err;

			} else if (opcode == BPF_JA) {
				if (BPF_SRC(insn->code) != BPF_K || insn->imm != 0 || insn->src_reg != BPF_REG_0 || insn->dst_reg != BPF_REG_0) {


					verbose(env, "BPF_JA uses reserved fields\n");
					return -EINVAL;
				}

				insn_idx += insn->off + 1;
				continue;

			} else if (opcode == BPF_EXIT) {
				if (BPF_SRC(insn->code) != BPF_K || insn->imm != 0 || insn->src_reg != BPF_REG_0 || insn->dst_reg != BPF_REG_0) {


					verbose(env, "BPF_EXIT uses reserved fields\n");
					return -EINVAL;
				}

				
				err = check_reg_arg(env, BPF_REG_0, SRC_OP);
				if (err)
					return err;

				if (is_pointer_value(env, BPF_REG_0)) {
					verbose(env, "R0 leaks addr as return value\n");
					return -EACCES;
				}

				err = check_return_code(env);
				if (err)
					return err;
process_bpf_exit:
				err = pop_stack(env, &prev_insn_idx, &insn_idx);
				if (err < 0) {
					if (err != -ENOENT)
						return err;
					break;
				} else {
					do_print_state = true;
					continue;
				}
			} else {
				err = check_cond_jmp_op(env, insn, &insn_idx);
				if (err)
					return err;
			}
		} else if (class == BPF_LD) {
			u8 mode = BPF_MODE(insn->code);

			if (mode == BPF_ABS || mode == BPF_IND) {
				err = check_ld_abs(env, insn);
				if (err)
					return err;

			} else if (mode == BPF_IMM) {
				err = check_ld_imm(env, insn);
				if (err)
					return err;

				insn_idx++;
				env->insn_aux_data[insn_idx].seen = true;
			} else {
				verbose(env, "invalid BPF_LD mode\n");
				return -EINVAL;
			}
		} else {
			verbose(env, "unknown insn class %d\n", class);
			return -EINVAL;
		}

		insn_idx++;
	}

	verbose(env, "processed %d insns, stack depth %d\n", insn_processed, env->prog->aux->stack_depth);
	return 0;
}

static int check_map_prealloc(struct bpf_map *map)
{
	return (map->map_type != BPF_MAP_TYPE_HASH && map->map_type != BPF_MAP_TYPE_PERCPU_HASH && map->map_type != BPF_MAP_TYPE_HASH_OF_MAPS) || !(map->map_flags & BPF_F_NO_PREALLOC);


}

static int check_map_prog_compatibility(struct bpf_verifier_env *env, struct bpf_map *map, struct bpf_prog *prog)


{
	
	if (prog->type == BPF_PROG_TYPE_PERF_EVENT) {
		if (!check_map_prealloc(map)) {
			verbose(env, "perf_event programs can only use preallocated hash map\n");
			return -EINVAL;
		}
		if (map->inner_map_meta && !check_map_prealloc(map->inner_map_meta)) {
			verbose(env, "perf_event programs can only use preallocated inner hash map\n");
			return -EINVAL;
		}
	}
	return 0;
}


static int replace_map_fd_with_map_ptr(struct bpf_verifier_env *env)
{
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	int i, j, err;

	err = bpf_prog_calc_tag(env->prog);
	if (err)
		return err;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (BPF_CLASS(insn->code) == BPF_LDX && (BPF_MODE(insn->code) != BPF_MEM || insn->imm != 0)) {
			verbose(env, "BPF_LDX uses reserved fields\n");
			return -EINVAL;
		}

		if (BPF_CLASS(insn->code) == BPF_STX && ((BPF_MODE(insn->code) != BPF_MEM && BPF_MODE(insn->code) != BPF_XADD) || insn->imm != 0)) {

			verbose(env, "BPF_STX uses reserved fields\n");
			return -EINVAL;
		}

		if (insn[0].code == (BPF_LD | BPF_IMM | BPF_DW)) {
			struct bpf_map *map;
			struct fd f;

			if (i == insn_cnt - 1 || insn[1].code != 0 || insn[1].dst_reg != 0 || insn[1].src_reg != 0 || insn[1].off != 0) {

				verbose(env, "invalid bpf_ld_imm64 insn\n");
				return -EINVAL;
			}

			if (insn->src_reg == 0)
				
				goto next_insn;

			if (insn->src_reg != BPF_PSEUDO_MAP_FD) {
				verbose(env, "unrecognized bpf_ld_imm64 insn\n");
				return -EINVAL;
			}

			f = fdget(insn->imm);
			map = __bpf_map_get(f);
			if (IS_ERR(map)) {
				verbose(env, "fd %d is not pointing to valid bpf_map\n", insn->imm);
				return PTR_ERR(map);
			}

			err = check_map_prog_compatibility(env, map, env->prog);
			if (err) {
				fdput(f);
				return err;
			}

			
			insn[0].imm = (u32) (unsigned long) map;
			insn[1].imm = ((u64) (unsigned long) map) >> 32;

			
			for (j = 0; j < env->used_map_cnt; j++)
				if (env->used_maps[j] == map) {
					fdput(f);
					goto next_insn;
				}

			if (env->used_map_cnt >= MAX_USED_MAPS) {
				fdput(f);
				return -E2BIG;
			}

			
			map = bpf_map_inc(map, false);
			if (IS_ERR(map)) {
				fdput(f);
				return PTR_ERR(map);
			}
			env->used_maps[env->used_map_cnt++] = map;

			fdput(f);
next_insn:
			insn++;
			i++;
		}
	}

	
	return 0;
}


static void release_maps(struct bpf_verifier_env *env)
{
	int i;

	for (i = 0; i < env->used_map_cnt; i++)
		bpf_map_put(env->used_maps[i]);
}


static void convert_pseudo_ld_imm64(struct bpf_verifier_env *env)
{
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	int i;

	for (i = 0; i < insn_cnt; i++, insn++)
		if (insn->code == (BPF_LD | BPF_IMM | BPF_DW))
			insn->src_reg = 0;
}


static int adjust_insn_aux_data(struct bpf_verifier_env *env, u32 prog_len, u32 off, u32 cnt)
{
	struct bpf_insn_aux_data *new_data, *old_data = env->insn_aux_data;
	int i;

	if (cnt == 1)
		return 0;
	new_data = vzalloc(sizeof(struct bpf_insn_aux_data) * prog_len);
	if (!new_data)
		return -ENOMEM;
	memcpy(new_data, old_data, sizeof(struct bpf_insn_aux_data) * off);
	memcpy(new_data + off + cnt - 1, old_data + off, sizeof(struct bpf_insn_aux_data) * (prog_len - off - cnt + 1));
	for (i = off; i < off + cnt - 1; i++)
		new_data[i].seen = true;
	env->insn_aux_data = new_data;
	vfree(old_data);
	return 0;
}

static struct bpf_prog *bpf_patch_insn_data(struct bpf_verifier_env *env, u32 off, const struct bpf_insn *patch, u32 len)
{
	struct bpf_prog *new_prog;

	new_prog = bpf_patch_insn_single(env->prog, off, patch, len);
	if (!new_prog)
		return NULL;
	if (adjust_insn_aux_data(env, new_prog->len, off, len))
		return NULL;
	return new_prog;
}


static void sanitize_dead_code(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	struct bpf_insn nop = BPF_MOV64_REG(BPF_REG_0, BPF_REG_0);
	struct bpf_insn *insn = env->prog->insnsi;
	const int insn_cnt = env->prog->len;
	int i;

	for (i = 0; i < insn_cnt; i++) {
		if (aux_data[i].seen)
			continue;
		memcpy(insn + i, &nop, sizeof(nop));
	}
}


static int convert_ctx_accesses(struct bpf_verifier_env *env)
{
	const struct bpf_verifier_ops *ops = env->ops;
	int i, cnt, size, ctx_field_size, delta = 0;
	const int insn_cnt = env->prog->len;
	struct bpf_insn insn_buf[16], *insn;
	struct bpf_prog *new_prog;
	enum bpf_access_type type;
	bool is_narrower_load;
	u32 target_size;

	if (ops->gen_prologue) {
		cnt = ops->gen_prologue(insn_buf, env->seen_direct_write, env->prog);
		if (cnt >= ARRAY_SIZE(insn_buf)) {
			verbose(env, "bpf verifier is misconfigured\n");
			return -EINVAL;
		} else if (cnt) {
			new_prog = bpf_patch_insn_data(env, 0, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			env->prog = new_prog;
			delta += cnt - 1;
		}
	}

	if (!ops->convert_ctx_access)
		return 0;

	insn = env->prog->insnsi + delta;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (insn->code == (BPF_LDX | BPF_MEM | BPF_B) || insn->code == (BPF_LDX | BPF_MEM | BPF_H) || insn->code == (BPF_LDX | BPF_MEM | BPF_W) || insn->code == (BPF_LDX | BPF_MEM | BPF_DW))


			type = BPF_READ;
		else if (insn->code == (BPF_STX | BPF_MEM | BPF_B) || insn->code == (BPF_STX | BPF_MEM | BPF_H) || insn->code == (BPF_STX | BPF_MEM | BPF_W) || insn->code == (BPF_STX | BPF_MEM | BPF_DW))


			type = BPF_WRITE;
		else continue;

		if (env->insn_aux_data[i + delta].ptr_type != PTR_TO_CTX)
			continue;

		ctx_field_size = env->insn_aux_data[i + delta].ctx_field_size;
		size = BPF_LDST_BYTES(insn);

		
		is_narrower_load = size < ctx_field_size;
		if (is_narrower_load) {
			u32 off = insn->off;
			u8 size_code;

			if (type == BPF_WRITE) {
				verbose(env, "bpf verifier narrow ctx access misconfigured\n");
				return -EINVAL;
			}

			size_code = BPF_H;
			if (ctx_field_size == 4)
				size_code = BPF_W;
			else if (ctx_field_size == 8)
				size_code = BPF_DW;

			insn->off = off & ~(ctx_field_size - 1);
			insn->code = BPF_LDX | BPF_MEM | size_code;
		}

		target_size = 0;
		cnt = ops->convert_ctx_access(type, insn, insn_buf, env->prog, &target_size);
		if (cnt == 0 || cnt >= ARRAY_SIZE(insn_buf) || (ctx_field_size && !target_size)) {
			verbose(env, "bpf verifier is misconfigured\n");
			return -EINVAL;
		}

		if (is_narrower_load && size < target_size) {
			if (ctx_field_size <= 4)
				insn_buf[cnt++] = BPF_ALU32_IMM(BPF_AND, insn->dst_reg, (1 << size * 8) - 1);
			else insn_buf[cnt++] = BPF_ALU64_IMM(BPF_AND, insn->dst_reg, (1 << size * 8) - 1);

		}

		new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
		if (!new_prog)
			return -ENOMEM;

		delta += cnt - 1;

		
		env->prog = new_prog;
		insn      = new_prog->insnsi + i + delta;
	}

	return 0;
}


static int fixup_bpf_calls(struct bpf_verifier_env *env)
{
	struct bpf_prog *prog = env->prog;
	struct bpf_insn *insn = prog->insnsi;
	const struct bpf_func_proto *fn;
	const int insn_cnt = prog->len;
	struct bpf_insn insn_buf[16];
	struct bpf_prog *new_prog;
	struct bpf_map *map_ptr;
	int i, cnt, delta = 0;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (insn->code != (BPF_JMP | BPF_CALL))
			continue;

		if (insn->imm == BPF_FUNC_get_route_realm)
			prog->dst_needed = 1;
		if (insn->imm == BPF_FUNC_get_prandom_u32)
			bpf_user_rnd_init_once();
		if (insn->imm == BPF_FUNC_tail_call) {
			
			prog->cb_access = 1;
			env->prog->aux->stack_depth = MAX_BPF_STACK;

			
			insn->imm = 0;
			insn->code = BPF_JMP | BPF_TAIL_CALL;
			continue;
		}

		
		if (ebpf_jit_enabled() && BITS_PER_LONG == 64 && insn->imm == BPF_FUNC_map_lookup_elem) {
			map_ptr = env->insn_aux_data[i + delta].map_ptr;
			if (map_ptr == BPF_MAP_PTR_POISON || !map_ptr->ops->map_gen_lookup)
				goto patch_call_imm;

			cnt = map_ptr->ops->map_gen_lookup(map_ptr, insn_buf);
			if (cnt == 0 || cnt >= ARRAY_SIZE(insn_buf)) {
				verbose(env, "bpf verifier is misconfigured\n");
				return -EINVAL;
			}

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta += cnt - 1;

			
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			continue;
		}

		if (insn->imm == BPF_FUNC_redirect_map) {
			
			u64 addr = (unsigned long)prog->aux;
			struct bpf_insn r4_ld[] = {
				BPF_LD_IMM64(BPF_REG_4, addr), *insn, };

			cnt = ARRAY_SIZE(r4_ld);

			new_prog = bpf_patch_insn_data(env, i + delta, r4_ld, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
		}
patch_call_imm:
		fn = env->ops->get_func_proto(insn->imm);
		
		if (!fn->func) {
			verbose(env, "kernel subsystem misconfigured func %s#%d\n", func_id_name(insn->imm), insn->imm);

			return -EFAULT;
		}
		insn->imm = fn->func - __bpf_call_base;
	}

	return 0;
}

static void free_states(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state_list *sl, *sln;
	int i;

	if (!env->explored_states)
		return;

	for (i = 0; i < env->prog->len; i++) {
		sl = env->explored_states[i];

		if (sl)
			while (sl != STATE_LIST_MARK) {
				sln = sl->next;
				free_verifier_state(&sl->state, false);
				kfree(sl);
				sl = sln;
			}
	}

	kfree(env->explored_states);
}

int bpf_check(struct bpf_prog **prog, union bpf_attr *attr)
{
	struct bpf_verifier_env *env;
	struct bpf_verifer_log *log;
	int ret = -EINVAL;

	
	if (ARRAY_SIZE(bpf_verifier_ops) == 0)
		return -EINVAL;

	
	env = kzalloc(sizeof(struct bpf_verifier_env), GFP_KERNEL);
	if (!env)
		return -ENOMEM;
	log = &env->log;

	env->insn_aux_data = vzalloc(sizeof(struct bpf_insn_aux_data) * (*prog)->len);
	ret = -ENOMEM;
	if (!env->insn_aux_data)
		goto err_free_env;
	env->prog = *prog;
	env->ops = bpf_verifier_ops[env->prog->type];

	
	mutex_lock(&bpf_verifier_lock);

	if (attr->log_level || attr->log_buf || attr->log_size) {
		
		log->level = attr->log_level;
		log->ubuf = (char __user *) (unsigned long) attr->log_buf;
		log->len_total = attr->log_size;

		ret = -EINVAL;
		
		if (log->len_total < 128 || log->len_total > UINT_MAX >> 8 || !log->level || !log->ubuf)
			goto err_unlock;
	}

	env->strict_alignment = !!(attr->prog_flags & BPF_F_STRICT_ALIGNMENT);
	if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
		env->strict_alignment = true;

	if (env->prog->aux->offload) {
		ret = bpf_prog_offload_verifier_prep(env);
		if (ret)
			goto err_unlock;
	}

	ret = replace_map_fd_with_map_ptr(env);
	if (ret < 0)
		goto skip_full_check;

	env->explored_states = kcalloc(env->prog->len, sizeof(struct bpf_verifier_state_list *), GFP_USER);

	ret = -ENOMEM;
	if (!env->explored_states)
		goto skip_full_check;

	ret = check_cfg(env);
	if (ret < 0)
		goto skip_full_check;

	env->allow_ptr_leaks = capable(CAP_SYS_ADMIN);

	ret = do_check(env);
	if (env->cur_state) {
		free_verifier_state(env->cur_state, true);
		env->cur_state = NULL;
	}

skip_full_check:
	while (!pop_stack(env, NULL, NULL));
	free_states(env);

	if (ret == 0)
		sanitize_dead_code(env);

	if (ret == 0)
		
		ret = convert_ctx_accesses(env);

	if (ret == 0)
		ret = fixup_bpf_calls(env);

	if (log->level && bpf_verifier_log_full(log))
		ret = -ENOSPC;
	if (log->level && !log->ubuf) {
		ret = -EFAULT;
		goto err_release_maps;
	}

	if (ret == 0 && env->used_map_cnt) {
		
		env->prog->aux->used_maps = kmalloc_array(env->used_map_cnt, sizeof(env->used_maps[0]), GFP_KERNEL);


		if (!env->prog->aux->used_maps) {
			ret = -ENOMEM;
			goto err_release_maps;
		}

		memcpy(env->prog->aux->used_maps, env->used_maps, sizeof(env->used_maps[0]) * env->used_map_cnt);
		env->prog->aux->used_map_cnt = env->used_map_cnt;

		
		convert_pseudo_ld_imm64(env);
	}

err_release_maps:
	if (!env->prog->aux->used_maps)
		
		release_maps(env);
	*prog = env->prog;
err_unlock:
	mutex_unlock(&bpf_verifier_lock);
	vfree(env->insn_aux_data);
err_free_env:
	kfree(env);
	return ret;
}
