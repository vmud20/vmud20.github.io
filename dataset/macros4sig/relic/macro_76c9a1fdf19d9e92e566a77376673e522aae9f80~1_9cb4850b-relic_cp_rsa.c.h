
#include<ctype.h>
#include<stdint.h>

#include<pthread.h>

#include<string.h>
#include<alloca.h>






#include<stdlib.h>

#include<malloc.h>

#include<stdio.h>
#include<setjmp.h>



#include<time.h>
#include<sys/time.h>

#include<math.h>

#include<omp.h>



#define rlc_thread 	__thread

#define RLC_MD_LEN					RLC_MD_LEN_SH224
#define md_map(H, M, L)			md_map_b2s160(H, M, L)
#define md_xmd(B, BL, I, IL, D, DL) 	md_xmd_sh224(B, BL, I, IL, D, DL)

#define RLC_PREFIX(F)			_RLC_PREFIX(LABEL, F)
#define _RLC_PREFIX(A, B)		__RLC_PREFIX(A, B)
#define __RLC_PREFIX(A, B)		A ## _ ## B
#define arch_clean 	RLC_PREFIX(arch_clean)
#define arch_copy_rom 	RLC_PREFIX(arch_copy_rom)
#define arch_cycles 	RLC_PREFIX(arch_cycles)
#define arch_init 	RLC_PREFIX(arch_init)
#define arch_lzcnt 	RLC_PREFIX(arch_lzcnt)
#define bench_after 	RLC_PREFIX(bench_after)
#define bench_before 	RLC_PREFIX(bench_before)
#define bench_compute 	RLC_PREFIX(bench_compute)
#define bench_overhead 	RLC_PREFIX(bench_overhead)
#define bench_print 	RLC_PREFIX(bench_print)
#define bench_reset 	RLC_PREFIX(bench_reset)
#define bench_total 	RLC_PREFIX(bench_total)
#define bn_abs 	RLC_PREFIX(bn_abs)
#define bn_add 	RLC_PREFIX(bn_add)
#define bn_add1_low 	RLC_PREFIX(bn_add1_low)
#define bn_add_dig 	RLC_PREFIX(bn_add_dig)
#define bn_addn_low 	RLC_PREFIX(bn_addn_low)
#define bn_bits 	RLC_PREFIX(bn_bits)
#define bn_clean 	RLC_PREFIX(bn_clean)
#define bn_cmp 	RLC_PREFIX(bn_cmp)
#define bn_cmp1_low 	RLC_PREFIX(bn_cmp1_low)
#define bn_cmp_abs 	RLC_PREFIX(bn_cmp_abs)
#define bn_cmp_dig 	RLC_PREFIX(bn_cmp_dig)
#define bn_cmpn_low 	RLC_PREFIX(bn_cmpn_low)
#define bn_copy 	RLC_PREFIX(bn_copy)
#define bn_dbl 	RLC_PREFIX(bn_dbl)
#define bn_div 	RLC_PREFIX(bn_div)
#define bn_div1_low 	RLC_PREFIX(bn_div1_low)
#define bn_div_dig 	RLC_PREFIX(bn_div_dig)
#define bn_div_rem 	RLC_PREFIX(bn_div_rem)
#define bn_div_rem_dig 	RLC_PREFIX(bn_div_rem_dig)
#define bn_divn_low 	RLC_PREFIX(bn_divn_low)
#define bn_factor 	RLC_PREFIX(bn_factor)
#define bn_gcd_basic 	RLC_PREFIX(bn_gcd_basic)
#define bn_gcd_dig 	RLC_PREFIX(bn_gcd_dig)
#define bn_gcd_ext_basic 	RLC_PREFIX(bn_gcd_ext_basic)
#define bn_gcd_ext_dig 	RLC_PREFIX(bn_gcd_ext_dig)
#define bn_gcd_ext_lehme 	RLC_PREFIX(bn_gcd_ext_lehme)
#define bn_gcd_ext_mid 	RLC_PREFIX(bn_gcd_ext_mid)
#define bn_gcd_ext_stein 	RLC_PREFIX(bn_gcd_ext_stein)
#define bn_gcd_lehme 	RLC_PREFIX(bn_gcd_lehme)
#define bn_gcd_stein 	RLC_PREFIX(bn_gcd_stein)
#define bn_gen_prime_basic 	RLC_PREFIX(bn_gen_prime_basic)
#define bn_gen_prime_safep 	RLC_PREFIX(bn_gen_prime_safep)
#define bn_gen_prime_stron 	RLC_PREFIX(bn_gen_prime_stron)
#define bn_get_bit 	RLC_PREFIX(bn_get_bit)
#define bn_get_dig 	RLC_PREFIX(bn_get_dig)
#define bn_get_prime 	RLC_PREFIX(bn_get_prime)
#define bn_grow 	RLC_PREFIX(bn_grow)
#define bn_ham 	RLC_PREFIX(bn_ham)
#define bn_hlv 	RLC_PREFIX(bn_hlv)
#define bn_init 	RLC_PREFIX(bn_init)
#define bn_is_even 	RLC_PREFIX(bn_is_even)
#define bn_is_factor 	RLC_PREFIX(bn_is_factor)
#define bn_is_prime 	RLC_PREFIX(bn_is_prime)
#define bn_is_prime_basic 	RLC_PREFIX(bn_is_prime_basic)
#define bn_is_prime_rabin 	RLC_PREFIX(bn_is_prime_rabin)
#define bn_is_prime_solov 	RLC_PREFIX(bn_is_prime_solov)
#define bn_is_zero 	RLC_PREFIX(bn_is_zero)
#define bn_lcm 	RLC_PREFIX(bn_lcm)
#define bn_lsh 	RLC_PREFIX(bn_lsh)
#define bn_lsh1_low 	RLC_PREFIX(bn_lsh1_low)
#define bn_lshb_low 	RLC_PREFIX(bn_lshb_low)
#define bn_lshd_low 	RLC_PREFIX(bn_lshd_low)
#define bn_mod_2b 	RLC_PREFIX(bn_mod_2b)
#define bn_mod_barrt 	RLC_PREFIX(bn_mod_barrt)
#define bn_mod_basic 	RLC_PREFIX(bn_mod_basic)
#define bn_mod_dig 	RLC_PREFIX(bn_mod_dig)
#define bn_mod_inv 	RLC_PREFIX(bn_mod_inv)
#define bn_mod_monty_back 	RLC_PREFIX(bn_mod_monty_back)
#define bn_mod_monty_basic 	RLC_PREFIX(bn_mod_monty_basic)
#define bn_mod_monty_comba 	RLC_PREFIX(bn_mod_monty_comba)
#define bn_mod_monty_conv 	RLC_PREFIX(bn_mod_monty_conv)
#define bn_mod_pmers 	RLC_PREFIX(bn_mod_pmers)
#define bn_mod_pre_barrt 	RLC_PREFIX(bn_mod_pre_barrt)
#define bn_mod_pre_monty 	RLC_PREFIX(bn_mod_pre_monty)
#define bn_mod_pre_pmers 	RLC_PREFIX(bn_mod_pre_pmers)
#define bn_modn_low 	RLC_PREFIX(bn_modn_low)
#define bn_mul1_low 	RLC_PREFIX(bn_mul1_low)
#define bn_mul_basic 	RLC_PREFIX(bn_mul_basic)
#define bn_mul_comba 	RLC_PREFIX(bn_mul_comba)
#define bn_mul_dig 	RLC_PREFIX(bn_mul_dig)
#define bn_mul_karat 	RLC_PREFIX(bn_mul_karat)
#define bn_mula_low 	RLC_PREFIX(bn_mula_low)
#define bn_muld_low 	RLC_PREFIX(bn_muld_low)
#define bn_muln_low 	RLC_PREFIX(bn_muln_low)
#define bn_mxp_basic 	RLC_PREFIX(bn_mxp_basic)
#define bn_mxp_dig 	RLC_PREFIX(bn_mxp_dig)
#define bn_mxp_monty 	RLC_PREFIX(bn_mxp_monty)
#define bn_mxp_slide 	RLC_PREFIX(bn_mxp_slide)
#define bn_neg 	RLC_PREFIX(bn_neg)
#define bn_print 	RLC_PREFIX(bn_print)
#define bn_rand 	RLC_PREFIX(bn_rand)
#define bn_rand_mod 	RLC_PREFIX(bn_rand_mod)
#define bn_read_bin 	RLC_PREFIX(bn_read_bin)
#define bn_read_raw 	RLC_PREFIX(bn_read_raw)
#define bn_read_str 	RLC_PREFIX(bn_read_str)
#define bn_rec_glv 	RLC_PREFIX(bn_rec_glv)
#define bn_rec_jsf 	RLC_PREFIX(bn_rec_jsf)
#define bn_rec_naf 	RLC_PREFIX(bn_rec_naf)
#define bn_rec_reg 	RLC_PREFIX(bn_rec_reg)
#define bn_rec_rtnaf 	RLC_PREFIX(bn_rec_rtnaf)
#define bn_rec_slw 	RLC_PREFIX(bn_rec_slw)
#define bn_rec_tnaf 	RLC_PREFIX(bn_rec_tnaf)
#define bn_rec_tnaf_get 	RLC_PREFIX(bn_rec_tnaf_get)
#define bn_rec_tnaf_mod 	RLC_PREFIX(bn_rec_tnaf_mod)
#define bn_rec_win 	RLC_PREFIX(bn_rec_win)
#define bn_rsh 	RLC_PREFIX(bn_rsh)
#define bn_rsh1_low 	RLC_PREFIX(bn_rsh1_low)
#define bn_rshb_low 	RLC_PREFIX(bn_rshb_low)
#define bn_rshd_low 	RLC_PREFIX(bn_rshd_low)
#define bn_set_2b 	RLC_PREFIX(bn_set_2b)
#define bn_set_bit 	RLC_PREFIX(bn_set_bit)
#define bn_set_dig 	RLC_PREFIX(bn_set_dig)
#define bn_sign 	RLC_PREFIX(bn_sign)
#define bn_size_bin 	RLC_PREFIX(bn_size_bin)
#define bn_size_raw 	RLC_PREFIX(bn_size_raw)
#define bn_size_str 	RLC_PREFIX(bn_size_str)
#define bn_smb_jac 	RLC_PREFIX(bn_smb_jac)
#define bn_smb_leg 	RLC_PREFIX(bn_smb_leg)
#define bn_sqr_basic 	RLC_PREFIX(bn_sqr_basic)
#define bn_sqr_comba 	RLC_PREFIX(bn_sqr_comba)
#define bn_sqr_karat 	RLC_PREFIX(bn_sqr_karat)
#define bn_sqra_low 	RLC_PREFIX(bn_sqra_low)
#define bn_sqrn_low 	RLC_PREFIX(bn_sqrn_low)
#define bn_srt 	RLC_PREFIX(bn_srt)
#define bn_st     	RLC_PREFIX(bn_st)
#define bn_sub 	RLC_PREFIX(bn_sub)
#define bn_sub1_low 	RLC_PREFIX(bn_sub1_low)
#define bn_sub_dig 	RLC_PREFIX(bn_sub_dig)
#define bn_subn_low 	RLC_PREFIX(bn_subn_low)
#define bn_t      	RLC_PREFIX(bn_t)
#define bn_trim 	RLC_PREFIX(bn_trim)
#define bn_write_bin 	RLC_PREFIX(bn_write_bin)
#define bn_write_raw 	RLC_PREFIX(bn_write_raw)
#define bn_write_str 	RLC_PREFIX(bn_write_str)
#define bn_zero 	RLC_PREFIX(bn_zero)
#define conf_print    RLC_PREFIX(conf_print)
#define core_clean 	RLC_PREFIX(core_clean)
#define core_ctx      RLC_PREFIX(core_ctx)
#define core_get 	RLC_PREFIX(core_get)
#define core_init 	RLC_PREFIX(core_init)
#define core_set 	RLC_PREFIX(core_set)
#define cp_bbs_gen 	RLC_PREFIX(cp_bbs_gen)
#define cp_bbs_sig 	RLC_PREFIX(cp_bbs_sig)
#define cp_bbs_ver 	RLC_PREFIX(cp_bbs_ver)
#define cp_bdpe_dec 	RLC_PREFIX(cp_bdpe_dec)
#define cp_bdpe_enc 	RLC_PREFIX(cp_bdpe_enc)
#define cp_bdpe_gen 	RLC_PREFIX(cp_bdpe_gen)
#define cp_bgn_add 	RLC_PREFIX(cp_bgn_add)
#define cp_bgn_dec 	RLC_PREFIX(cp_bgn_dec)
#define cp_bgn_dec1 	RLC_PREFIX(cp_bgn_dec1)
#define cp_bgn_dec2 	RLC_PREFIX(cp_bgn_dec2)
#define cp_bgn_enc1 	RLC_PREFIX(cp_bgn_enc1)
#define cp_bgn_enc2 	RLC_PREFIX(cp_bgn_enc2)
#define cp_bgn_gen 	RLC_PREFIX(cp_bgn_gen)
#define cp_bgn_mul 	RLC_PREFIX(cp_bgn_mul)
#define cp_bls_gen 	RLC_PREFIX(cp_bls_gen)
#define cp_bls_sig 	RLC_PREFIX(cp_bls_sig)
#define cp_bls_ver 	RLC_PREFIX(cp_bls_ver)
#define cp_clb_gen 	RLC_PREFIX(cp_clb_gen)
#define cp_clb_sig 	RLC_PREFIX(cp_clb_sig)
#define cp_clb_ver 	RLC_PREFIX(cp_clb_ver)
#define cp_cli_gen 	RLC_PREFIX(cp_cli_gen)
#define cp_cli_sig 	RLC_PREFIX(cp_cli_sig)
#define cp_cli_ver 	RLC_PREFIX(cp_cli_ver)
#define cp_cls_gen 	RLC_PREFIX(cp_cls_gen)
#define cp_cls_sig 	RLC_PREFIX(cp_cls_sig)
#define cp_cls_ver 	RLC_PREFIX(cp_cls_ver)
#define cp_cmlhs_evl 	RLC_PREFIX(cp_cmlhs_evl)
#define cp_cmlhs_fun 	RLC_PREFIX(cp_cmlhs_fun)
#define cp_cmlhs_gen 	RLC_PREFIX(cp_cmlhs_gen)
#define cp_cmlhs_init 	RLC_PREFIX(cp_cmlhs_init)
#define cp_cmlhs_sig 	RLC_PREFIX(cp_cmlhs_sig)
#define cp_cmlhs_ver 	RLC_PREFIX(cp_cmlhs_ver)
#define cp_ecdh_gen 	RLC_PREFIX(cp_ecdh_gen)
#define cp_ecdh_key 	RLC_PREFIX(cp_ecdh_key)
#define cp_ecdsa_gen 	RLC_PREFIX(cp_ecdsa_gen)
#define cp_ecdsa_sig 	RLC_PREFIX(cp_ecdsa_sig)
#define cp_ecdsa_ver 	RLC_PREFIX(cp_ecdsa_ver)
#define cp_ecies_dec 	RLC_PREFIX(cp_ecies_dec)
#define cp_ecies_enc 	RLC_PREFIX(cp_ecies_enc)
#define cp_ecies_gen 	RLC_PREFIX(cp_ecies_gen)
#define cp_ecmqv_gen 	RLC_PREFIX(cp_ecmqv_gen)
#define cp_ecmqv_key 	RLC_PREFIX(cp_ecmqv_key)
#define cp_ecss_gen 	RLC_PREFIX(cp_ecss_gen)
#define cp_ecss_sig 	RLC_PREFIX(cp_ecss_sig)
#define cp_ecss_ver 	RLC_PREFIX(cp_ecss_ver)
#define cp_ghpe_dec 	RLC_PREFIX(cp_ghpe_dec)
#define cp_ghpe_enc 	RLC_PREFIX(cp_ghpe_enc)
#define cp_ghpe_gen 	RLC_PREFIX(cp_ghpe_gen)
#define cp_ibe_dec 	RLC_PREFIX(cp_ibe_dec)
#define cp_ibe_enc 	RLC_PREFIX(cp_ibe_enc)
#define cp_ibe_gen 	RLC_PREFIX(cp_ibe_gen)
#define cp_ibe_gen_prv 	RLC_PREFIX(cp_ibe_gen_prv)
#define cp_mklhs_evl 	RLC_PREFIX(cp_mklhs_evl)
#define cp_mklhs_fun 	RLC_PREFIX(cp_mklhs_fun)
#define cp_mklhs_gen 	RLC_PREFIX(cp_mklhs_gen)
#define cp_mklhs_off 	RLC_PREFIX(cp_mklhs_off)
#define cp_mklhs_onv 	RLC_PREFIX(cp_mklhs_onv)
#define cp_mklhs_sig 	RLC_PREFIX(cp_mklhs_sig)
#define cp_mklhs_ver 	RLC_PREFIX(cp_mklhs_ver)
#define cp_phpe_dec 	RLC_PREFIX(cp_phpe_dec)
#define cp_phpe_enc 	RLC_PREFIX(cp_phpe_enc)
#define cp_phpe_gen 	RLC_PREFIX(cp_phpe_gen)
#define cp_psb_gen 	RLC_PREFIX(cp_psb_gen)
#define cp_psb_sig 	RLC_PREFIX(cp_psb_sig)
#define cp_psb_ver 	RLC_PREFIX(cp_psb_ver)
#define cp_pss_gen 	RLC_PREFIX(cp_pss_gen)
#define cp_pss_sig 	RLC_PREFIX(cp_pss_sig)
#define cp_pss_ver 	RLC_PREFIX(cp_pss_ver)
#define cp_rabin_dec 	RLC_PREFIX(cp_rabin_dec)
#define cp_rabin_enc 	RLC_PREFIX(cp_rabin_enc)
#define cp_rabin_gen 	RLC_PREFIX(cp_rabin_gen)
#define cp_rsa_dec 	RLC_PREFIX(cp_rsa_dec)
#define cp_rsa_enc 	RLC_PREFIX(cp_rsa_enc)
#define cp_rsa_gen 	RLC_PREFIX(cp_rsa_gen)
#define cp_rsa_sig 	RLC_PREFIX(cp_rsa_sig)
#define cp_rsa_ver 	RLC_PREFIX(cp_rsa_ver)
#define cp_sokaka_gen 	RLC_PREFIX(cp_sokaka_gen)
#define cp_sokaka_gen_prv 	RLC_PREFIX(cp_sokaka_gen_prv)
#define cp_sokaka_key 	RLC_PREFIX(cp_sokaka_key)
#define cp_vbnn_gen 	RLC_PREFIX(cp_vbnn_gen)
#define cp_vbnn_gen_prv 	RLC_PREFIX(cp_vbnn_gen_prv)
#define cp_vbnn_sig 	RLC_PREFIX(cp_vbnn_sig)
#define cp_vbnn_ver 	RLC_PREFIX(cp_vbnn_ver)
#define cp_zss_gen 	RLC_PREFIX(cp_zss_gen)
#define cp_zss_sig 	RLC_PREFIX(cp_zss_sig)
#define cp_zss_ver 	RLC_PREFIX(cp_zss_ver)
#define crt_t		RLC_PREFIX(crt_t)
#define dv12_t         RLC_PREFIX(dv12_t)
#define dv18_t         RLC_PREFIX(dv18_t)
#define dv24_t         RLC_PREFIX(dv24_t)
#define dv2_t         RLC_PREFIX(dv2_t)
#define dv3_t         RLC_PREFIX(dv3_t)
#define dv48_t         RLC_PREFIX(dv48_t)
#define dv54_t         RLC_PREFIX(dv54_t)
#define dv6_t         RLC_PREFIX(dv6_t)
#define dv8_t         RLC_PREFIX(dv8_t)
#define dv9_t         RLC_PREFIX(dv9_t)
#define dv_cmp 	RLC_PREFIX(dv_cmp)
#define dv_cmp_const 	RLC_PREFIX(dv_cmp_const)
#define dv_copy 	RLC_PREFIX(dv_copy)
#define dv_copy_cond 	RLC_PREFIX(dv_copy_cond)
#define dv_free_dynam 	RLC_PREFIX(dv_free_dynam)
#define dv_new_dynam 	RLC_PREFIX(dv_new_dynam)
#define dv_print 	RLC_PREFIX(dv_print)
#define dv_swap_cond 	RLC_PREFIX(dv_swap_cond)
#define dv_t          RLC_PREFIX(dv_t)
#define dv_zero 	RLC_PREFIX(dv_zero)
#define eb_add_basic 	RLC_PREFIX(eb_add_basic)
#define eb_add_projc 	RLC_PREFIX(eb_add_projc)
#define eb_cmp 	RLC_PREFIX(eb_cmp)
#define eb_copy 	RLC_PREFIX(eb_copy)
#define eb_curve_clean 	RLC_PREFIX(eb_curve_clean)
#define eb_curve_get_a 	RLC_PREFIX(eb_curve_get_a)
#define eb_curve_get_b 	RLC_PREFIX(eb_curve_get_b)
#define eb_curve_get_cof 	RLC_PREFIX(eb_curve_get_cof)
#define eb_curve_get_gen 	RLC_PREFIX(eb_curve_get_gen)
#define eb_curve_get_ord 	RLC_PREFIX(eb_curve_get_ord)
#define eb_curve_get_tab 	RLC_PREFIX(eb_curve_get_tab)
#define eb_curve_init 	RLC_PREFIX(eb_curve_init)
#define eb_curve_is_kbltz 	RLC_PREFIX(eb_curve_is_kbltz)
#define eb_curve_opt_a 	RLC_PREFIX(eb_curve_opt_a)
#define eb_curve_opt_b 	RLC_PREFIX(eb_curve_opt_b)
#define eb_curve_set 	RLC_PREFIX(eb_curve_set)
#define eb_dbl_basic 	RLC_PREFIX(eb_dbl_basic)
#define eb_dbl_projc 	RLC_PREFIX(eb_dbl_projc)
#define eb_frb_basic 	RLC_PREFIX(eb_frb_basic)
#define eb_frb_projc 	RLC_PREFIX(eb_frb_projc)
#define eb_hlv 	RLC_PREFIX(eb_hlv)
#define eb_is_infty 	RLC_PREFIX(eb_is_infty)
#define eb_map 	RLC_PREFIX(eb_map)
#define eb_mul_basic 	RLC_PREFIX(eb_mul_basic)
#define eb_mul_dig 	RLC_PREFIX(eb_mul_dig)
#define eb_mul_fix_basic 	RLC_PREFIX(eb_mul_fix_basic)
#define eb_mul_fix_combd 	RLC_PREFIX(eb_mul_fix_combd)
#define eb_mul_fix_combs 	RLC_PREFIX(eb_mul_fix_combs)
#define eb_mul_fix_lwnaf 	RLC_PREFIX(eb_mul_fix_lwnaf)
#define eb_mul_fix_nafwi 	RLC_PREFIX(eb_mul_fix_nafwi)
#define eb_mul_fix_yaowi 	RLC_PREFIX(eb_mul_fix_yaowi)
#define eb_mul_gen 	RLC_PREFIX(eb_mul_gen)
#define eb_mul_halve 	RLC_PREFIX(eb_mul_halve)
#define eb_mul_lodah 	RLC_PREFIX(eb_mul_lodah)
#define eb_mul_lwnaf 	RLC_PREFIX(eb_mul_lwnaf)
#define eb_mul_pre_basic 	RLC_PREFIX(eb_mul_pre_basic)
#define eb_mul_pre_combd 	RLC_PREFIX(eb_mul_pre_combd)
#define eb_mul_pre_combs 	RLC_PREFIX(eb_mul_pre_combs)
#define eb_mul_pre_lwnaf 	RLC_PREFIX(eb_mul_pre_lwnaf)
#define eb_mul_pre_nafwi 	RLC_PREFIX(eb_mul_pre_nafwi)
#define eb_mul_pre_yaowi 	RLC_PREFIX(eb_mul_pre_yaowi)
#define eb_mul_rwnaf 	RLC_PREFIX(eb_mul_rwnaf)
#define eb_mul_sim_basic 	RLC_PREFIX(eb_mul_sim_basic)
#define eb_mul_sim_gen 	RLC_PREFIX(eb_mul_sim_gen)
#define eb_mul_sim_inter 	RLC_PREFIX(eb_mul_sim_inter)
#define eb_mul_sim_joint 	RLC_PREFIX(eb_mul_sim_joint)
#define eb_mul_sim_trick 	RLC_PREFIX(eb_mul_sim_trick)
#define eb_neg_basic 	RLC_PREFIX(eb_neg_basic)
#define eb_neg_projc 	RLC_PREFIX(eb_neg_projc)
#define eb_norm 	RLC_PREFIX(eb_norm)
#define eb_norm_sim 	RLC_PREFIX(eb_norm_sim)
#define eb_on_curve 	RLC_PREFIX(eb_on_curve)
#define eb_param_get 	RLC_PREFIX(eb_param_get)
#define eb_param_level 	RLC_PREFIX(eb_param_level)
#define eb_param_print 	RLC_PREFIX(eb_param_print)
#define eb_param_set 	RLC_PREFIX(eb_param_set)
#define eb_param_set_any 	RLC_PREFIX(eb_param_set_any)
#define eb_param_set_any_kbltz 	RLC_PREFIX(eb_param_set_any_kbltz)
#define eb_param_set_any_plain 	RLC_PREFIX(eb_param_set_any_plain)
#define eb_pck 	RLC_PREFIX(eb_pck)
#define eb_print 	RLC_PREFIX(eb_print)
#define eb_rand 	RLC_PREFIX(eb_rand)
#define eb_read_bin 	RLC_PREFIX(eb_read_bin)
#define eb_rhs 	RLC_PREFIX(eb_rhs)
#define eb_set_infty 	RLC_PREFIX(eb_set_infty)
#define eb_size_bin 	RLC_PREFIX(eb_size_bin)
#define eb_st         RLC_PREFIX(eb_st)
#define eb_sub_basic 	RLC_PREFIX(eb_sub_basic)
#define eb_sub_projc 	RLC_PREFIX(eb_sub_projc)
#define eb_t          RLC_PREFIX(eb_t)
#define eb_tab 	RLC_PREFIX(eb_tab)
#define eb_upk 	RLC_PREFIX(eb_upk)
#define eb_write_bin 	RLC_PREFIX(eb_write_bin)
#define ed_add_basic 	RLC_PREFIX(ed_add_basic)
#define ed_add_extnd 	RLC_PREFIX(ed_add_extnd)
#define ed_add_projc 	RLC_PREFIX(ed_add_projc)
#define ed_cmp 	RLC_PREFIX(ed_cmp)
#define ed_copy 	RLC_PREFIX(ed_copy)
#define ed_curve_clean 	RLC_PREFIX(ed_curve_clean)
#define ed_curve_get_cof 	RLC_PREFIX(ed_curve_get_cof)
#define ed_curve_get_gen 	RLC_PREFIX(ed_curve_get_gen)
#define ed_curve_get_ord 	RLC_PREFIX(ed_curve_get_ord)
#define ed_curve_get_tab 	RLC_PREFIX(ed_curve_get_tab)
#define ed_curve_init 	RLC_PREFIX(ed_curve_init)
#define ed_dbl_basic 	RLC_PREFIX(ed_dbl_basic)
#define ed_dbl_extnd 	RLC_PREFIX(ed_dbl_extnd)
#define ed_dbl_projc 	RLC_PREFIX(ed_dbl_projc)
#define ed_is_infty 	RLC_PREFIX(ed_is_infty)
#define ed_map 	RLC_PREFIX(ed_map)
#define ed_map_dst 	RLC_PREFIX(ed_map_dst)
#define ed_mul_basic 	RLC_PREFIX(ed_mul_basic)
#define ed_mul_dig 	RLC_PREFIX(ed_mul_dig)
#define ed_mul_fix_basic 	RLC_PREFIX(ed_mul_fix_basic)
#define ed_mul_fix_combd 	RLC_PREFIX(ed_mul_fix_combd)
#define ed_mul_fix_combs 	RLC_PREFIX(ed_mul_fix_combs)
#define ed_mul_fix_lwnaf 	RLC_PREFIX(ed_mul_fix_lwnaf)
#define ed_mul_fix_lwnaf_mixed 	RLC_PREFIX(ed_mul_fix_lwnaf_mixed)
#define ed_mul_fix_nafwi 	RLC_PREFIX(ed_mul_fix_nafwi)
#define ed_mul_fix_yaowi 	RLC_PREFIX(ed_mul_fix_yaowi)
#define ed_mul_gen 	RLC_PREFIX(ed_mul_gen)
#define ed_mul_lwnaf 	RLC_PREFIX(ed_mul_lwnaf)
#define ed_mul_lwreg 	RLC_PREFIX(ed_mul_lwreg)
#define ed_mul_monty 	RLC_PREFIX(ed_mul_monty)
#define ed_mul_pre_basic 	RLC_PREFIX(ed_mul_pre_basic)
#define ed_mul_pre_combd 	RLC_PREFIX(ed_mul_pre_combd)
#define ed_mul_pre_combs 	RLC_PREFIX(ed_mul_pre_combs)
#define ed_mul_pre_lwnaf 	RLC_PREFIX(ed_mul_pre_lwnaf)
#define ed_mul_pre_nafwi 	RLC_PREFIX(ed_mul_pre_nafwi)
#define ed_mul_pre_yaowi 	RLC_PREFIX(ed_mul_pre_yaowi)
#define ed_mul_sim_basic 	RLC_PREFIX(ed_mul_sim_basic)
#define ed_mul_sim_gen 	RLC_PREFIX(ed_mul_sim_gen)
#define ed_mul_sim_inter 	RLC_PREFIX(ed_mul_sim_inter)
#define ed_mul_sim_joint 	RLC_PREFIX(ed_mul_sim_joint)
#define ed_mul_sim_trick 	RLC_PREFIX(ed_mul_sim_trick)
#define ed_mul_slide 	RLC_PREFIX(ed_mul_slide)
#define ed_neg_basic 	RLC_PREFIX(ed_neg_basic)
#define ed_neg_projc 	RLC_PREFIX(ed_neg_projc)
#define ed_norm 	RLC_PREFIX(ed_norm)
#define ed_norm_sim 	RLC_PREFIX(ed_norm_sim)
#define ed_on_curve 	RLC_PREFIX(ed_on_curve)
#define ed_param_get 	RLC_PREFIX(ed_param_get)
#define ed_param_level 	RLC_PREFIX(ed_param_level)
#define ed_param_print 	RLC_PREFIX(ed_param_print)
#define ed_param_set 	RLC_PREFIX(ed_param_set)
#define ed_param_set_any 	RLC_PREFIX(ed_param_set_any)
#define ed_pck 	RLC_PREFIX(ed_pck)
#define ed_print 	RLC_PREFIX(ed_print)
#define ed_projc_to_extnd 	RLC_PREFIX(ed_projc_to_extnd)
#define ed_rand 	RLC_PREFIX(ed_rand)
#define ed_read_bin 	RLC_PREFIX(ed_read_bin)
#define ed_rhs 	RLC_PREFIX(ed_rhs)
#define ed_set_infty 	RLC_PREFIX(ed_set_infty)
#define ed_size_bin 	RLC_PREFIX(ed_size_bin)
#define ed_st         RLC_PREFIX(ed_st)
#define ed_sub_basic 	RLC_PREFIX(ed_sub_basic)
#define ed_sub_extnd 	RLC_PREFIX(ed_sub_extnd)
#define ed_sub_projc 	RLC_PREFIX(ed_sub_projc)
#define ed_t          RLC_PREFIX(ed_t)
#define ed_tab 	RLC_PREFIX(ed_tab)
#define ed_upk 	RLC_PREFIX(ed_upk)
#define ed_write_bin 	RLC_PREFIX(ed_write_bin)
#define ep2_add_basic 	RLC_PREFIX(ep2_add_basic)
#define ep2_add_projc 	RLC_PREFIX(ep2_add_projc)
#define ep2_add_slp_basic 	RLC_PREFIX(ep2_add_slp_basic)
#define ep2_cmp 	RLC_PREFIX(ep2_cmp)
#define ep2_copy 	RLC_PREFIX(ep2_copy)
#define ep2_curve_clean 	RLC_PREFIX(ep2_curve_clean)
#define ep2_curve_get_a 	RLC_PREFIX(ep2_curve_get_a)
#define ep2_curve_get_b 	RLC_PREFIX(ep2_curve_get_b)
#define ep2_curve_get_cof 	RLC_PREFIX(ep2_curve_get_cof)
#define ep2_curve_get_gen 	RLC_PREFIX(ep2_curve_get_gen)
#define ep2_curve_get_iso 	RLC_PREFIX(ep2_curve_get_iso)
#define ep2_curve_get_ord 	RLC_PREFIX(ep2_curve_get_ord)
#define ep2_curve_get_tab 	RLC_PREFIX(ep2_curve_get_tab)
#define ep2_curve_get_vs 	RLC_PREFIX(ep2_curve_get_vs)
#define ep2_curve_init 	RLC_PREFIX(ep2_curve_init)
#define ep2_curve_is_ctmap 	RLC_PREFIX(ep2_curve_is_ctmap)
#define ep2_curve_is_twist 	RLC_PREFIX(ep2_curve_is_twist)
#define ep2_curve_opt_a 	RLC_PREFIX(ep2_curve_opt_a)
#define ep2_curve_opt_b 	RLC_PREFIX(ep2_curve_opt_b)
#define ep2_curve_set 	RLC_PREFIX(ep2_curve_set)
#define ep2_curve_set_twist 	RLC_PREFIX(ep2_curve_set_twist)
#define ep2_dbl_basic 	RLC_PREFIX(ep2_dbl_basic)
#define ep2_dbl_projc 	RLC_PREFIX(ep2_dbl_projc)
#define ep2_dbl_slp_basic 	RLC_PREFIX(ep2_dbl_slp_basic)
#define ep2_frb 	RLC_PREFIX(ep2_frb)
#define ep2_is_infty 	RLC_PREFIX(ep2_is_infty)
#define ep2_map 	RLC_PREFIX(ep2_map)
#define ep2_map_dst 	RLC_PREFIX(ep2_map_dst)
#define ep2_mul_basic 	RLC_PREFIX(ep2_mul_basic)
#define ep2_mul_dig 	RLC_PREFIX(ep2_mul_dig)
#define ep2_mul_fix_basic 	RLC_PREFIX(ep2_mul_fix_basic)
#define ep2_mul_fix_combd 	RLC_PREFIX(ep2_mul_fix_combd)
#define ep2_mul_fix_combs 	RLC_PREFIX(ep2_mul_fix_combs)
#define ep2_mul_fix_lwnaf 	RLC_PREFIX(ep2_mul_fix_lwnaf)
#define ep2_mul_fix_nafwi 	RLC_PREFIX(ep2_mul_fix_nafwi)
#define ep2_mul_fix_yaowi 	RLC_PREFIX(ep2_mul_fix_yaowi)
#define ep2_mul_gen 	RLC_PREFIX(ep2_mul_gen)
#define ep2_mul_lwnaf 	RLC_PREFIX(ep2_mul_lwnaf)
#define ep2_mul_lwreg 	RLC_PREFIX(ep2_mul_lwreg)
#define ep2_mul_monty 	RLC_PREFIX(ep2_mul_monty)
#define ep2_mul_pre_basic 	RLC_PREFIX(ep2_mul_pre_basic)
#define ep2_mul_pre_combd 	RLC_PREFIX(ep2_mul_pre_combd)
#define ep2_mul_pre_combs 	RLC_PREFIX(ep2_mul_pre_combs)
#define ep2_mul_pre_lwnaf 	RLC_PREFIX(ep2_mul_pre_lwnaf)
#define ep2_mul_pre_nafwi 	RLC_PREFIX(ep2_mul_pre_nafwi)
#define ep2_mul_pre_yaowi 	RLC_PREFIX(ep2_mul_pre_yaowi)
#define ep2_mul_sim_basic 	RLC_PREFIX(ep2_mul_sim_basic)
#define ep2_mul_sim_dig 	RLC_PREFIX(ep2_mul_sim_dig)
#define ep2_mul_sim_gen 	RLC_PREFIX(ep2_mul_sim_gen)
#define ep2_mul_sim_inter 	RLC_PREFIX(ep2_mul_sim_inter)
#define ep2_mul_sim_joint 	RLC_PREFIX(ep2_mul_sim_joint)
#define ep2_mul_sim_trick 	RLC_PREFIX(ep2_mul_sim_trick)
#define ep2_mul_slide 	RLC_PREFIX(ep2_mul_slide)
#define ep2_neg 	RLC_PREFIX(ep2_neg)
#define ep2_norm 	RLC_PREFIX(ep2_norm)
#define ep2_norm_sim 	RLC_PREFIX(ep2_norm_sim)
#define ep2_on_curve 	RLC_PREFIX(ep2_on_curve)
#define ep2_pck 	RLC_PREFIX(ep2_pck)
#define ep2_print 	RLC_PREFIX(ep2_print)
#define ep2_rand 	RLC_PREFIX(ep2_rand)
#define ep2_read_bin 	RLC_PREFIX(ep2_read_bin)
#define ep2_rhs 	RLC_PREFIX(ep2_rhs)
#define ep2_set_infty 	RLC_PREFIX(ep2_set_infty)
#define ep2_size_bin 	RLC_PREFIX(ep2_size_bin)
#define ep2_st        RLC_PREFIX(ep2_st)
 #define ep2_sub 	RLC_PREFIX(ep2_sub)
#define ep2_t         RLC_PREFIX(ep2_t)
#define ep2_tab 	RLC_PREFIX(ep2_tab)
#define ep2_upk 	RLC_PREFIX(ep2_upk)
#define ep2_write_bin 	RLC_PREFIX(ep2_write_bin)
#define ep_add_basic 	RLC_PREFIX(ep_add_basic)
#define ep_add_jacob 	RLC_PREFIX(ep_add_jacob)
#define ep_add_projc 	RLC_PREFIX(ep_add_projc)
#define ep_add_slp_basic 	RLC_PREFIX(ep_add_slp_basic)
#define ep_cmp 	RLC_PREFIX(ep_cmp)
#define ep_copy 	RLC_PREFIX(ep_copy)
#define ep_curve_clean 	RLC_PREFIX(ep_curve_clean)
#define ep_curve_get_a 	RLC_PREFIX(ep_curve_get_a)
#define ep_curve_get_b 	RLC_PREFIX(ep_curve_get_b)
#define ep_curve_get_b3 	RLC_PREFIX(ep_curve_get_b3)
#define ep_curve_get_beta 	RLC_PREFIX(ep_curve_get_beta)
#define ep_curve_get_cof 	RLC_PREFIX(ep_curve_get_cof)
#define ep_curve_get_gen 	RLC_PREFIX(ep_curve_get_gen)
#define ep_curve_get_iso 	RLC_PREFIX(ep_curve_get_iso)
#define ep_curve_get_ord 	RLC_PREFIX(ep_curve_get_ord)
#define ep_curve_get_tab 	RLC_PREFIX(ep_curve_get_tab)
#define ep_curve_get_v1 	RLC_PREFIX(ep_curve_get_v1)
#define ep_curve_get_v2 	RLC_PREFIX(ep_curve_get_v2)
#define ep_curve_init 	RLC_PREFIX(ep_curve_init)
#define ep_curve_is_ctmap 	RLC_PREFIX(ep_curve_is_ctmap)
#define ep_curve_is_endom 	RLC_PREFIX(ep_curve_is_endom)
#define ep_curve_is_pairf 	RLC_PREFIX(ep_curve_is_pairf)
#define ep_curve_is_super 	RLC_PREFIX(ep_curve_is_super)
#define ep_curve_mul_a 	RLC_PREFIX(ep_curve_mul_a)
#define ep_curve_mul_b 	RLC_PREFIX(ep_curve_mul_b)
#define ep_curve_mul_b3 	RLC_PREFIX(ep_curve_mul_b3)
#define ep_curve_opt_a 	RLC_PREFIX(ep_curve_opt_a)
#define ep_curve_opt_b 	RLC_PREFIX(ep_curve_opt_b)
#define ep_curve_opt_b3 	RLC_PREFIX(ep_curve_opt_b3)
#define ep_curve_set_endom 	RLC_PREFIX(ep_curve_set_endom)
#define ep_curve_set_plain 	RLC_PREFIX(ep_curve_set_plain)
#define ep_curve_set_super 	RLC_PREFIX(ep_curve_set_super)
#define ep_dbl_basic 	RLC_PREFIX(ep_dbl_basic)
#define ep_dbl_jacob 	RLC_PREFIX(ep_dbl_jacob)
#define ep_dbl_projc 	RLC_PREFIX(ep_dbl_projc)
#define ep_dbl_slp_basic 	RLC_PREFIX(ep_dbl_slp_basic)
#define ep_is_infty 	RLC_PREFIX(ep_is_infty)
#define ep_map 	RLC_PREFIX(ep_map)
#define ep_map_dst 	RLC_PREFIX(ep_map_dst)
#define ep_mul_basic 	RLC_PREFIX(ep_mul_basic)
#define ep_mul_dig 	RLC_PREFIX(ep_mul_dig)
#define ep_mul_fix_basic 	RLC_PREFIX(ep_mul_fix_basic)
#define ep_mul_fix_combd 	RLC_PREFIX(ep_mul_fix_combd)
#define ep_mul_fix_combs 	RLC_PREFIX(ep_mul_fix_combs)
#define ep_mul_fix_lwnaf 	RLC_PREFIX(ep_mul_fix_lwnaf)
#define ep_mul_fix_nafwi 	RLC_PREFIX(ep_mul_fix_nafwi)
#define ep_mul_fix_yaowi 	RLC_PREFIX(ep_mul_fix_yaowi)
#define ep_mul_gen 	RLC_PREFIX(ep_mul_gen)
#define ep_mul_lwnaf 	RLC_PREFIX(ep_mul_lwnaf)
#define ep_mul_lwreg 	RLC_PREFIX(ep_mul_lwreg)
#define ep_mul_monty 	RLC_PREFIX(ep_mul_monty)
#define ep_mul_pre_basic 	RLC_PREFIX(ep_mul_pre_basic)
#define ep_mul_pre_combd 	RLC_PREFIX(ep_mul_pre_combd)
#define ep_mul_pre_combs 	RLC_PREFIX(ep_mul_pre_combs)
#define ep_mul_pre_lwnaf 	RLC_PREFIX(ep_mul_pre_lwnaf)
#define ep_mul_pre_nafwi 	RLC_PREFIX(ep_mul_pre_nafwi)
#define ep_mul_pre_yaowi 	RLC_PREFIX(ep_mul_pre_yaowi)
#define ep_mul_sim_basic 	RLC_PREFIX(ep_mul_sim_basic)
#define ep_mul_sim_dig 	RLC_PREFIX(ep_mul_sim_dig)
#define ep_mul_sim_gen 	RLC_PREFIX(ep_mul_sim_gen)
#define ep_mul_sim_inter 	RLC_PREFIX(ep_mul_sim_inter)
#define ep_mul_sim_joint 	RLC_PREFIX(ep_mul_sim_joint)
#define ep_mul_sim_trick 	RLC_PREFIX(ep_mul_sim_trick)
#define ep_mul_slide 	RLC_PREFIX(ep_mul_slide)
#define ep_neg 	RLC_PREFIX(ep_neg)
#define ep_norm 	RLC_PREFIX(ep_norm)
#define ep_norm_sim 	RLC_PREFIX(ep_norm_sim)
#define ep_on_curve 	RLC_PREFIX(ep_on_curve)
#define ep_param_embed 	RLC_PREFIX(ep_param_embed)
#define ep_param_get 	RLC_PREFIX(ep_param_get)
#define ep_param_level 	RLC_PREFIX(ep_param_level)
#define ep_param_print 	RLC_PREFIX(ep_param_print)
#define ep_param_set 	RLC_PREFIX(ep_param_set)
#define ep_param_set_any 	RLC_PREFIX(ep_param_set_any)
#define ep_param_set_any_endom 	RLC_PREFIX(ep_param_set_any_endom)
#define ep_param_set_any_pairf 	RLC_PREFIX(ep_param_set_any_pairf)
#define ep_param_set_any_plain 	RLC_PREFIX(ep_param_set_any_plain)
#define ep_param_set_any_super 	RLC_PREFIX(ep_param_set_any_super)
#define ep_pck 	RLC_PREFIX(ep_pck)
#define ep_print 	RLC_PREFIX(ep_print)
#define ep_rand 	RLC_PREFIX(ep_rand)
#define ep_read_bin 	RLC_PREFIX(ep_read_bin)
#define ep_rhs 	RLC_PREFIX(ep_rhs)
#define ep_set_infty 	RLC_PREFIX(ep_set_infty)
#define ep_size_bin 	RLC_PREFIX(ep_size_bin)
#define ep_st         RLC_PREFIX(ep_st)
#define ep_sub 	RLC_PREFIX(ep_sub)
#define ep_t          RLC_PREFIX(ep_t)
#define ep_tab 	RLC_PREFIX(ep_tab)
#define ep_upk 	RLC_PREFIX(ep_upk)
#define ep_write_bin 	RLC_PREFIX(ep_write_bin)
#define err_full_msg 	RLC_PREFIX(err_full_msg)
#define err_get_code 	RLC_PREFIX(err_get_code)
#define err_get_msg 	RLC_PREFIX(err_get_msg)
#define err_simple_msg 	RLC_PREFIX(err_simple_msg)
#define fb2_inv 	RLC_PREFIX(fb2_inv)
#define fb2_mul 	RLC_PREFIX(fb2_mul)
 #define fb2_mul_nor 	RLC_PREFIX(fb2_mul_nor)
#define fb2_slv 	RLC_PREFIX(fb2_slv)
#define fb2_sqr 	RLC_PREFIX(fb2_sqr)
#define fb_add 	RLC_PREFIX(fb_add)
#define fb_add1_low 	RLC_PREFIX(fb_add1_low)
#define fb_add_dig 	RLC_PREFIX(fb_add_dig)
#define fb_addd_low 	RLC_PREFIX(fb_addd_low)
#define fb_addn_low 	RLC_PREFIX(fb_addn_low)
#define fb_bits 	RLC_PREFIX(fb_bits)
#define fb_cmp 	RLC_PREFIX(fb_cmp)
#define fb_cmp_dig 	RLC_PREFIX(fb_cmp_dig)
#define fb_copy 	RLC_PREFIX(fb_copy)
#define fb_exp_2b 	RLC_PREFIX(fb_exp_2b)
#define fb_exp_basic 	RLC_PREFIX(fb_exp_basic)
#define fb_exp_monty 	RLC_PREFIX(fb_exp_monty)
#define fb_exp_slide 	RLC_PREFIX(fb_exp_slide)
#define fb_get_bit 	RLC_PREFIX(fb_get_bit)
#define fb_inv_almos 	RLC_PREFIX(fb_inv_almos)
#define fb_inv_basic 	RLC_PREFIX(fb_inv_basic)
#define fb_inv_binar 	RLC_PREFIX(fb_inv_binar)
#define fb_inv_bruch 	RLC_PREFIX(fb_inv_bruch)
#define fb_inv_ctaia 	RLC_PREFIX(fb_inv_ctaia)
#define fb_inv_exgcd 	RLC_PREFIX(fb_inv_exgcd)
#define fb_inv_itoht 	RLC_PREFIX(fb_inv_itoht)
#define fb_inv_lower 	RLC_PREFIX(fb_inv_lower)
#define fb_inv_sim 	RLC_PREFIX(fb_inv_sim)
#define fb_invn_low 	RLC_PREFIX(fb_invn_low)
#define fb_is_zero 	RLC_PREFIX(fb_is_zero)
#define fb_itr_basic 	RLC_PREFIX(fb_itr_basic)
#define fb_itr_pre_quick 	RLC_PREFIX(fb_itr_pre_quick)
#define fb_itr_quick 	RLC_PREFIX(fb_itr_quick)
#define fb_itrn_low 	RLC_PREFIX(fb_itrn_low)
#define fb_lsh 	RLC_PREFIX(fb_lsh)
#define fb_lsh1_low 	RLC_PREFIX(fb_lsh1_low)
#define fb_lsha_low 	RLC_PREFIX(fb_lsha_low)
#define fb_lshb_low 	RLC_PREFIX(fb_lshb_low)
#define fb_lshd_low 	RLC_PREFIX(fb_lshd_low)
#define fb_mul1_low 	RLC_PREFIX(fb_mul1_low)
#define fb_mul_basic 	RLC_PREFIX(fb_mul_basic)
#define fb_mul_dig 	RLC_PREFIX(fb_mul_dig)
#define fb_mul_integ 	RLC_PREFIX(fb_mul_integ)
#define fb_mul_karat 	RLC_PREFIX(fb_mul_karat)
#define fb_mul_lodah 	RLC_PREFIX(fb_mul_lodah)
#define fb_muld_low 	RLC_PREFIX(fb_muld_low)
#define fb_mulm_low 	RLC_PREFIX(fb_mulm_low)
#define fb_muln_low 	RLC_PREFIX(fb_muln_low)
#define fb_neg 	RLC_PREFIX(fb_neg)
#define fb_param_print 	RLC_PREFIX(fb_param_print)
#define fb_param_set 	RLC_PREFIX(fb_param_set)
#define fb_param_set_any 	RLC_PREFIX(fb_param_set_any)
#define fb_poly_add 	RLC_PREFIX(fb_poly_add)
#define fb_poly_clean 	RLC_PREFIX(fb_poly_clean)
#define fb_poly_get 	RLC_PREFIX(fb_poly_get)
#define fb_poly_get_chain 	RLC_PREFIX(fb_poly_get_chain)
#define fb_poly_get_rdc 	RLC_PREFIX(fb_poly_get_rdc)
#define fb_poly_get_slv 	RLC_PREFIX(fb_poly_get_slv)
#define fb_poly_get_srz 	RLC_PREFIX(fb_poly_get_srz)
#define fb_poly_get_trc 	RLC_PREFIX(fb_poly_get_trc)
#define fb_poly_init 	RLC_PREFIX(fb_poly_init)
#define fb_poly_set_dense 	RLC_PREFIX(fb_poly_set_dense)
#define fb_poly_set_penta 	RLC_PREFIX(fb_poly_set_penta)
#define fb_poly_set_trino 	RLC_PREFIX(fb_poly_set_trino)
#define fb_poly_tab_sqr 	RLC_PREFIX(fb_poly_tab_sqr)
#define fb_poly_tab_srz 	RLC_PREFIX(fb_poly_tab_srz)
#define fb_print 	RLC_PREFIX(fb_print)
#define fb_rand 	RLC_PREFIX(fb_rand)
#define fb_rdc1_low 	RLC_PREFIX(fb_rdc1_low)
#define fb_rdc_basic 	RLC_PREFIX(fb_rdc_basic)
#define fb_rdc_quick 	RLC_PREFIX(fb_rdc_quick)
#define fb_rdcn_low 	RLC_PREFIX(fb_rdcn_low)
#define fb_read_bin 	RLC_PREFIX(fb_read_bin)
#define fb_read_str 	RLC_PREFIX(fb_read_str)
#define fb_rsh 	RLC_PREFIX(fb_rsh)
#define fb_rsh1_low 	RLC_PREFIX(fb_rsh1_low)
#define fb_rshb_low 	RLC_PREFIX(fb_rshb_low)
#define fb_rshd_low 	RLC_PREFIX(fb_rshd_low)
#define fb_set_bit 	RLC_PREFIX(fb_set_bit)
#define fb_set_dig 	RLC_PREFIX(fb_set_dig)
#define fb_size_str 	RLC_PREFIX(fb_size_str)
#define fb_slv_basic 	RLC_PREFIX(fb_slv_basic)
#define fb_slv_quick 	RLC_PREFIX(fb_slv_quick)
#define fb_slvn_low 	RLC_PREFIX(fb_slvn_low)
#define fb_sqr_basic 	RLC_PREFIX(fb_sqr_basic)
#define fb_sqr_integ 	RLC_PREFIX(fb_sqr_integ)
#define fb_sqr_quick 	RLC_PREFIX(fb_sqr_quick)
#define fb_sqrl_low 	RLC_PREFIX(fb_sqrl_low)
#define fb_sqrm_low 	RLC_PREFIX(fb_sqrm_low)
#define fb_sqrn_low 	RLC_PREFIX(fb_sqrn_low)
#define fb_srt_basic 	RLC_PREFIX(fb_srt_basic)
#define fb_srt_quick 	RLC_PREFIX(fb_srt_quick)
#define fb_srtn_low 	RLC_PREFIX(fb_srtn_low)
#define fb_trc_basic 	RLC_PREFIX(fb_trc_basic)
#define fb_trc_quick 	RLC_PREFIX(fb_trc_quick)
#define fb_trcn_low 	RLC_PREFIX(fb_trcn_low)
#define fb_write_bin 	RLC_PREFIX(fb_write_bin)
#define fb_write_str 	RLC_PREFIX(fb_write_str)
#define fb_zero 	RLC_PREFIX(fb_zero)
#define first_ctx     RLC_PREFIX(first_ctx)
#define fp12_add 	RLC_PREFIX(fp12_add)
#define fp12_back_cyc 	RLC_PREFIX(fp12_back_cyc)
#define fp12_back_cyc_sim 	RLC_PREFIX(fp12_back_cyc_sim)
#define fp12_cmp 	RLC_PREFIX(fp12_cmp)
#define fp12_cmp_dig 	RLC_PREFIX(fp12_cmp_dig)
#define fp12_conv_cyc 	RLC_PREFIX(fp12_conv_cyc)
#define fp12_copy 	RLC_PREFIX(fp12_copy)
#define fp12_dbl 	RLC_PREFIX(fp12_dbl)
#define fp12_exp 	RLC_PREFIX(fp12_exp)
#define fp12_exp_cyc 	RLC_PREFIX(fp12_exp_cyc)
#define fp12_exp_cyc_sps 	RLC_PREFIX(fp12_exp_cyc_sps)
#define fp12_exp_dig 	RLC_PREFIX(fp12_exp_dig)
#define fp12_frb 	RLC_PREFIX(fp12_frb)
#define fp12_inv 	RLC_PREFIX(fp12_inv)
#define fp12_inv_cyc 	RLC_PREFIX(fp12_inv_cyc)
#define fp12_is_zero 	RLC_PREFIX(fp12_is_zero)
#define fp12_mul_art 	RLC_PREFIX(fp12_mul_art)
#define fp12_mul_basic 	RLC_PREFIX(fp12_mul_basic)
#define fp12_mul_dxs_basic 	RLC_PREFIX(fp12_mul_dxs_basic)
#define fp12_mul_dxs_lazyr 	RLC_PREFIX(fp12_mul_dxs_lazyr)
#define fp12_mul_lazyr 	RLC_PREFIX(fp12_mul_lazyr)
#define fp12_mul_unr 	RLC_PREFIX(fp12_mul_unr)
#define fp12_neg 	RLC_PREFIX(fp12_neg)
#define fp12_pck 	RLC_PREFIX(fp12_pck)
#define fp12_print 	RLC_PREFIX(fp12_print)
#define fp12_rand 	RLC_PREFIX(fp12_rand)
#define fp12_read_bin 	RLC_PREFIX(fp12_read_bin)
#define fp12_set_dig 	RLC_PREFIX(fp12_set_dig)
#define fp12_size_bin 	RLC_PREFIX(fp12_size_bin)
#define fp12_sqr_basic 	RLC_PREFIX(fp12_sqr_basic)
#define fp12_sqr_cyc_basic 	RLC_PREFIX(fp12_sqr_cyc_basic)
#define fp12_sqr_cyc_lazyr 	RLC_PREFIX(fp12_sqr_cyc_lazyr)
#define fp12_sqr_lazyr 	RLC_PREFIX(fp12_sqr_lazyr)
#define fp12_sqr_pck_basic 	RLC_PREFIX(fp12_sqr_pck_basic)
#define fp12_sqr_pck_lazyr 	RLC_PREFIX(fp12_sqr_pck_lazyr)
#define fp12_sqr_unr 	RLC_PREFIX(fp12_sqr_unr)
#define fp12_st        RLC_PREFIX(fp12_st)
#define fp12_sub 	RLC_PREFIX(fp12_sub)
#define fp12_t         RLC_PREFIX(fp12_t)
#define fp12_test_cyc 	RLC_PREFIX(fp12_test_cyc)
#define fp12_upk 	RLC_PREFIX(fp12_upk)
#define fp12_write_bin 	RLC_PREFIX(fp12_write_bin)
#define fp12_zero 	RLC_PREFIX(fp12_zero)
#define fp18_add 	RLC_PREFIX(fp18_add)
#define fp18_cmp 	RLC_PREFIX(fp18_cmp)
#define fp18_cmp_dig 	RLC_PREFIX(fp18_cmp_dig)
#define fp18_conv_cyc 	RLC_PREFIX(fp18_conv_cyc)
#define fp18_copy 	RLC_PREFIX(fp18_copy)
#define fp18_dbl 	RLC_PREFIX(fp18_dbl)
#define fp18_exp 	RLC_PREFIX(fp18_exp)
#define fp18_frb 	RLC_PREFIX(fp18_frb)
#define fp18_inv 	RLC_PREFIX(fp18_inv)
#define fp18_inv_cyc 	RLC_PREFIX(fp18_inv_cyc)
#define fp18_is_zero 	RLC_PREFIX(fp18_is_zero)
#define fp18_mul_art 	RLC_PREFIX(fp18_mul_art)
#define fp18_mul_basic 	RLC_PREFIX(fp18_mul_basic)
#define fp18_mul_dxs_basic 	RLC_PREFIX(fp18_mul_dxs_basic)
#define fp18_mul_dxs_lazyr 	RLC_PREFIX(fp18_mul_dxs_lazyr)
#define fp18_mul_lazyr 	RLC_PREFIX(fp18_mul_lazyr)
#define fp18_mul_unr 	RLC_PREFIX(fp18_mul_unr)
#define fp18_neg 	RLC_PREFIX(fp18_neg)
#define fp18_print 	RLC_PREFIX(fp18_print)
#define fp18_rand 	RLC_PREFIX(fp18_rand)
#define fp18_read_bin 	RLC_PREFIX(fp18_read_bin)
#define fp18_set_dig 	RLC_PREFIX(fp18_set_dig)
#define fp18_size_bin 	RLC_PREFIX(fp18_size_bin)
#define fp18_sqr_basic 	RLC_PREFIX(fp18_sqr_basic)
#define fp18_sqr_lazyr 	RLC_PREFIX(fp18_sqr_lazyr)
#define fp18_sqr_unr 	RLC_PREFIX(fp18_sqr_unr)
#define fp18_st        RLC_PREFIX(fp18_st)
#define fp18_sub 	RLC_PREFIX(fp18_sub)
#define fp18_t         RLC_PREFIX(fp18_t)
#define fp18_write_bin 	RLC_PREFIX(fp18_write_bin)
#define fp18_zero 	RLC_PREFIX(fp18_zero)
#define fp24_add 	RLC_PREFIX(fp24_add)
#define fp24_cmp 	RLC_PREFIX(fp24_cmp)
#define fp24_cmp_dig 	RLC_PREFIX(fp24_cmp_dig)
#define fp24_copy 	RLC_PREFIX(fp24_copy)
#define fp24_dbl 	RLC_PREFIX(fp24_dbl)
#define fp24_exp 	RLC_PREFIX(fp24_exp)
#define fp24_frb 	RLC_PREFIX(fp24_frb)
#define fp24_inv 	RLC_PREFIX(fp24_inv)
#define fp24_is_zero 	RLC_PREFIX(fp24_is_zero)
#define fp24_mul_art 	RLC_PREFIX(fp24_mul_art)
#define fp24_mul_basic 	RLC_PREFIX(fp24_mul_basic)
#define fp24_mul_dxs 	RLC_PREFIX(fp24_mul_dxs)
#define fp24_mul_lazyr 	RLC_PREFIX(fp24_mul_lazyr)
#define fp24_mul_unr 	RLC_PREFIX(fp24_mul_unr)
#define fp24_neg 	RLC_PREFIX(fp24_neg)
#define fp24_print 	RLC_PREFIX(fp24_print)
#define fp24_rand 	RLC_PREFIX(fp24_rand)
#define fp24_read_bin 	RLC_PREFIX(fp24_read_bin)
#define fp24_set_dig 	RLC_PREFIX(fp24_set_dig)
#define fp24_size_bin 	RLC_PREFIX(fp24_size_bin)
#define fp24_sqr_basic 	RLC_PREFIX(fp24_sqr_basic)
#define fp24_sqr_lazyr 	RLC_PREFIX(fp24_sqr_lazyr)
#define fp24_sqr_unr 	RLC_PREFIX(fp24_sqr_unr)
#define fp24_st        RLC_PREFIX(fp24_st)
#define fp24_sub 	RLC_PREFIX(fp24_sub)
#define fp24_t         RLC_PREFIX(fp24_t)
#define fp24_write_bin 	RLC_PREFIX(fp24_write_bin)
#define fp24_zero 	RLC_PREFIX(fp24_zero)
#define fp2_add_basic 	RLC_PREFIX(fp2_add_basic)
#define fp2_add_dig 	RLC_PREFIX(fp2_add_dig)
#define fp2_add_integ 	RLC_PREFIX(fp2_add_integ)
#define fp2_addc_low 	RLC_PREFIX(fp2_addc_low)
#define fp2_addd_low 	RLC_PREFIX(fp2_addd_low)
#define fp2_addm_low 	RLC_PREFIX(fp2_addm_low)
#define fp2_addn_low 	RLC_PREFIX(fp2_addn_low)
#define fp2_cmp 	RLC_PREFIX(fp2_cmp)
#define fp2_cmp_dig 	RLC_PREFIX(fp2_cmp_dig)
#define fp2_conv_cyc 	RLC_PREFIX(fp2_conv_cyc)
#define fp2_copy 	RLC_PREFIX(fp2_copy)
#define fp2_dbl_basic 	RLC_PREFIX(fp2_dbl_basic)
#define fp2_dbl_integ 	RLC_PREFIX(fp2_dbl_integ)
#define fp2_dblm_low 	RLC_PREFIX(fp2_dblm_low)
#define fp2_dbln_low 	RLC_PREFIX(fp2_dbln_low)
#define fp2_exp 	RLC_PREFIX(fp2_exp)
#define fp2_exp_cyc 	RLC_PREFIX(fp2_exp_cyc)
#define fp2_exp_dig 	RLC_PREFIX(fp2_exp_dig)
#define fp2_field_get_qnr 	RLC_PREFIX(fp2_field_get_qnr)
#define fp2_field_init 	RLC_PREFIX(fp2_field_init)
#define fp2_frb 	RLC_PREFIX(fp2_frb)
#define fp2_inv 	RLC_PREFIX(fp2_inv)
#define fp2_inv_cyc 	RLC_PREFIX(fp2_inv_cyc)
#define fp2_inv_sim 	RLC_PREFIX(fp2_inv_sim)
#define fp2_is_zero 	RLC_PREFIX(fp2_is_zero)
#define fp2_mul_art 	RLC_PREFIX(fp2_mul_art)
#define fp2_mul_basic 	RLC_PREFIX(fp2_mul_basic)
#define fp2_mul_dig 	RLC_PREFIX(fp2_mul_dig)
#define fp2_mul_frb 	RLC_PREFIX(fp2_mul_frb)
#define fp2_mul_integ 	RLC_PREFIX(fp2_mul_integ)
#define fp2_mul_nor_basic 	RLC_PREFIX(fp2_mul_nor_basic)
#define fp2_mul_nor_integ 	RLC_PREFIX(fp2_mul_nor_integ)
#define fp2_mulc_low 	RLC_PREFIX(fp2_mulc_low)
#define fp2_mulm_low 	RLC_PREFIX(fp2_mulm_low)
#define fp2_muln_low 	RLC_PREFIX(fp2_muln_low)
#define fp2_neg 	RLC_PREFIX(fp2_neg)
#define fp2_nord_low 	RLC_PREFIX(fp2_nord_low)
#define fp2_norh_low 	RLC_PREFIX(fp2_norh_low)
#define fp2_norm_low 	RLC_PREFIX(fp2_norm_low)
#define fp2_pck 	RLC_PREFIX(fp2_pck)
#define fp2_print 	RLC_PREFIX(fp2_print)
#define fp2_rand 	RLC_PREFIX(fp2_rand)
#define fp2_rdcn_low 	RLC_PREFIX(fp2_rdcn_low)
#define fp2_read_bin 	RLC_PREFIX(fp2_read_bin)
#define fp2_set_dig 	RLC_PREFIX(fp2_set_dig)
#define fp2_size_bin 	RLC_PREFIX(fp2_size_bin)
#define fp2_sqr_basic 	RLC_PREFIX(fp2_sqr_basic)
#define fp2_sqr_integ 	RLC_PREFIX(fp2_sqr_integ)
#define fp2_sqrm_low 	RLC_PREFIX(fp2_sqrm_low)
#define fp2_sqrn_low 	RLC_PREFIX(fp2_sqrn_low)
#define fp2_srt 	RLC_PREFIX(fp2_srt)
#define fp2_st        RLC_PREFIX(fp2_st)
#define fp2_sub_basic 	RLC_PREFIX(fp2_sub_basic)
#define fp2_sub_dig 	RLC_PREFIX(fp2_sub_dig)
#define fp2_sub_integ 	RLC_PREFIX(fp2_sub_integ)
#define fp2_subc_low 	RLC_PREFIX(fp2_subc_low)
#define fp2_subd_low 	RLC_PREFIX(fp2_subd_low)
#define fp2_subm_low 	RLC_PREFIX(fp2_subm_low)
#define fp2_subn_low 	RLC_PREFIX(fp2_subn_low)
#define fp2_t         RLC_PREFIX(fp2_t)
#define fp2_test_cyc 	RLC_PREFIX(fp2_test_cyc)
#define fp2_upk 	RLC_PREFIX(fp2_upk)
#define fp2_write_bin 	RLC_PREFIX(fp2_write_bin)
#define fp2_zero 	RLC_PREFIX(fp2_zero)
#define fp3_add_basic 	RLC_PREFIX(fp3_add_basic)
#define fp3_add_integ 	RLC_PREFIX(fp3_add_integ)
#define fp3_addc_low 	RLC_PREFIX(fp3_addc_low)
#define fp3_addd_low 	RLC_PREFIX(fp3_addd_low)
#define fp3_addm_low 	RLC_PREFIX(fp3_addm_low)
#define fp3_addn_low 	RLC_PREFIX(fp3_addn_low)
#define fp3_cmp 	RLC_PREFIX(fp3_cmp)
#define fp3_cmp_dig 	RLC_PREFIX(fp3_cmp_dig)
#define fp3_copy 	RLC_PREFIX(fp3_copy)
#define fp3_dbl_basic 	RLC_PREFIX(fp3_dbl_basic)
#define fp3_dbl_integ 	RLC_PREFIX(fp3_dbl_integ)
#define fp3_dblm_low 	RLC_PREFIX(fp3_dblm_low)
#define fp3_dbln_low 	RLC_PREFIX(fp3_dbln_low)
#define fp3_exp 	RLC_PREFIX(fp3_exp)
#define fp3_field_init 	RLC_PREFIX(fp3_field_init)
#define fp3_frb 	RLC_PREFIX(fp3_frb)
#define fp3_inv 	RLC_PREFIX(fp3_inv)
#define fp3_inv_sim 	RLC_PREFIX(fp3_inv_sim)
#define fp3_is_zero 	RLC_PREFIX(fp3_is_zero)
#define fp3_mul_basic 	RLC_PREFIX(fp3_mul_basic)
#define fp3_mul_frb 	RLC_PREFIX(fp3_mul_frb)
#define fp3_mul_integ 	RLC_PREFIX(fp3_mul_integ)
#define fp3_mul_nor 	RLC_PREFIX(fp3_mul_nor)
#define fp3_mulc_low 	RLC_PREFIX(fp3_mulc_low)
#define fp3_mulm_low 	RLC_PREFIX(fp3_mulm_low)
#define fp3_muln_low 	RLC_PREFIX(fp3_muln_low)
#define fp3_neg 	RLC_PREFIX(fp3_neg)
#define fp3_nord_low 	RLC_PREFIX(fp3_nord_low)
#define fp3_print 	RLC_PREFIX(fp3_print)
#define fp3_rand 	RLC_PREFIX(fp3_rand)
#define fp3_rdcn_low 	RLC_PREFIX(fp3_rdcn_low)
#define fp3_read_bin 	RLC_PREFIX(fp3_read_bin)
#define fp3_set_dig 	RLC_PREFIX(fp3_set_dig)
#define fp3_size_bin 	RLC_PREFIX(fp3_size_bin)
#define fp3_sqr_basic 	RLC_PREFIX(fp3_sqr_basic)
#define fp3_sqr_integ 	RLC_PREFIX(fp3_sqr_integ)
#define fp3_sqrm_low 	RLC_PREFIX(fp3_sqrm_low)
#define fp3_sqrn_low 	RLC_PREFIX(fp3_sqrn_low)
#define fp3_srt 	RLC_PREFIX(fp3_srt)
#define fp3_st        RLC_PREFIX(fp3_st)
#define fp3_sub_basic 	RLC_PREFIX(fp3_sub_basic)
#define fp3_sub_integ 	RLC_PREFIX(fp3_sub_integ)
#define fp3_subc_low 	RLC_PREFIX(fp3_subc_low)
#define fp3_subd_low 	RLC_PREFIX(fp3_subd_low)
#define fp3_subm_low 	RLC_PREFIX(fp3_subm_low)
#define fp3_subn_low 	RLC_PREFIX(fp3_subn_low)
#define fp3_t         RLC_PREFIX(fp3_t)
#define fp3_write_bin 	RLC_PREFIX(fp3_write_bin)
#define fp3_zero 	RLC_PREFIX(fp3_zero)
#define fp48_add 	RLC_PREFIX(fp48_add)
#define fp48_back_cyc 	RLC_PREFIX(fp48_back_cyc)
#define fp48_back_cyc_sim 	RLC_PREFIX(fp48_back_cyc_sim)
#define fp48_cmp 	RLC_PREFIX(fp48_cmp)
#define fp48_cmp_dig 	RLC_PREFIX(fp48_cmp_dig)
#define fp48_conv_cyc 	RLC_PREFIX(fp48_conv_cyc)
#define fp48_copy 	RLC_PREFIX(fp48_copy)
#define fp48_dbl 	RLC_PREFIX(fp48_dbl)
#define fp48_exp 	RLC_PREFIX(fp48_exp)
#define fp48_exp_cyc 	RLC_PREFIX(fp48_exp_cyc)
#define fp48_exp_cyc_sps 	RLC_PREFIX(fp48_exp_cyc_sps)
#define fp48_exp_dig 	RLC_PREFIX(fp48_exp_dig)
#define fp48_frb 	RLC_PREFIX(fp48_frb)
#define fp48_inv 	RLC_PREFIX(fp48_inv)
#define fp48_inv_cyc 	RLC_PREFIX(fp48_inv_cyc)
#define fp48_is_zero 	RLC_PREFIX(fp48_is_zero)
#define fp48_mul_art 	RLC_PREFIX(fp48_mul_art)
#define fp48_mul_basic 	RLC_PREFIX(fp48_mul_basic)
#define fp48_mul_dxs 	RLC_PREFIX(fp48_mul_dxs)
#define fp48_mul_lazyr 	RLC_PREFIX(fp48_mul_lazyr)
#define fp48_mul_unr 	RLC_PREFIX(fp48_mul_unr)
#define fp48_neg 	RLC_PREFIX(fp48_neg)
#define fp48_pck 	RLC_PREFIX(fp48_pck)
#define fp48_print 	RLC_PREFIX(fp48_print)
#define fp48_rand 	RLC_PREFIX(fp48_rand)
#define fp48_read_bin 	RLC_PREFIX(fp48_read_bin)
#define fp48_set_dig 	RLC_PREFIX(fp48_set_dig)
#define fp48_size_bin 	RLC_PREFIX(fp48_size_bin)
#define fp48_sqr_basic 	RLC_PREFIX(fp48_sqr_basic)
#define fp48_sqr_cyc_basic 	RLC_PREFIX(fp48_sqr_cyc_basic)
#define fp48_sqr_cyc_lazyr 	RLC_PREFIX(fp48_sqr_cyc_lazyr)
#define fp48_sqr_lazyr 	RLC_PREFIX(fp48_sqr_lazyr)
#define fp48_sqr_pck_basic 	RLC_PREFIX(fp48_sqr_pck_basic)
#define fp48_sqr_pck_lazyr 	RLC_PREFIX(fp48_sqr_pck_lazyr)
#define fp48_sqr_unr 	RLC_PREFIX(fp48_sqr_unr)
#define fp48_st        RLC_PREFIX(fp48_st)
#define fp48_sub 	RLC_PREFIX(fp48_sub)
#define fp48_t         RLC_PREFIX(fp48_t)
#define fp48_test_cyc 	RLC_PREFIX(fp48_test_cyc)
#define fp48_upk 	RLC_PREFIX(fp48_upk)
#define fp48_write_bin 	RLC_PREFIX(fp48_write_bin)
#define fp48_zero 	RLC_PREFIX(fp48_zero)
#define fp4_add 	RLC_PREFIX(fp4_add)
#define fp4_cmp 	RLC_PREFIX(fp4_cmp)
#define fp4_cmp_dig 	RLC_PREFIX(fp4_cmp_dig)
#define fp4_copy 	RLC_PREFIX(fp4_copy)
#define fp4_dbl 	RLC_PREFIX(fp4_dbl)
#define fp4_exp 	RLC_PREFIX(fp4_exp)
#define fp4_frb 	RLC_PREFIX(fp4_frb)
#define fp4_inv 	RLC_PREFIX(fp4_inv)
#define fp4_inv_cyc 	RLC_PREFIX(fp4_inv_cyc)
#define fp4_is_zero 	RLC_PREFIX(fp4_is_zero)
#define fp4_mul_art 	RLC_PREFIX(fp4_mul_art)
#define fp4_mul_basic 	RLC_PREFIX(fp4_mul_basic)
#define fp4_mul_dxs 	RLC_PREFIX(fp4_mul_dxs)
#define fp4_mul_lazyr 	RLC_PREFIX(fp4_mul_lazyr)
#define fp4_mul_unr 	RLC_PREFIX(fp4_mul_unr)
#define fp4_neg 	RLC_PREFIX(fp4_neg)
#define fp4_print 	RLC_PREFIX(fp4_print)
#define fp4_rand 	RLC_PREFIX(fp4_rand)
#define fp4_read_bin 	RLC_PREFIX(fp4_read_bin)
#define fp4_set_dig 	RLC_PREFIX(fp4_set_dig)
#define fp4_size_bin 	RLC_PREFIX(fp4_size_bin)
#define fp4_sqr_basic 	RLC_PREFIX(fp4_sqr_basic)
#define fp4_sqr_lazyr 	RLC_PREFIX(fp4_sqr_lazyr)
#define fp4_sqr_unr 	RLC_PREFIX(fp4_sqr_unr)
#define fp4_sub 	RLC_PREFIX(fp4_sub)
#define fp4_write_bin 	RLC_PREFIX(fp4_write_bin)
#define fp4_zero 	RLC_PREFIX(fp4_zero)
#define fp54_add 	RLC_PREFIX(fp54_add)
#define fp54_back_cyc 	RLC_PREFIX(fp54_back_cyc)
#define fp54_back_cyc_sim 	RLC_PREFIX(fp54_back_cyc_sim)
#define fp54_cmp 	RLC_PREFIX(fp54_cmp)
#define fp54_cmp_dig 	RLC_PREFIX(fp54_cmp_dig)
#define fp54_conv_cyc 	RLC_PREFIX(fp54_conv_cyc)
#define fp54_copy 	RLC_PREFIX(fp54_copy)
#define fp54_dbl 	RLC_PREFIX(fp54_dbl)
#define fp54_exp 	RLC_PREFIX(fp54_exp)
#define fp54_exp_cyc 	RLC_PREFIX(fp54_exp_cyc)
#define fp54_exp_cyc_sps 	RLC_PREFIX(fp54_exp_cyc_sps)
#define fp54_exp_dig 	RLC_PREFIX(fp54_exp_dig)
#define fp54_frb 	RLC_PREFIX(fp54_frb)
#define fp54_inv 	RLC_PREFIX(fp54_inv)
#define fp54_inv_cyc 	RLC_PREFIX(fp54_inv_cyc)
#define fp54_is_zero 	RLC_PREFIX(fp54_is_zero)
#define fp54_mul_art 	RLC_PREFIX(fp54_mul_art)
#define fp54_mul_basic 	RLC_PREFIX(fp54_mul_basic)
#define fp54_mul_dxs 	RLC_PREFIX(fp54_mul_dxs)
#define fp54_mul_lazyr 	RLC_PREFIX(fp54_mul_lazyr)
#define fp54_mul_unr 	RLC_PREFIX(fp54_mul_unr)
#define fp54_neg 	RLC_PREFIX(fp54_neg)
#define fp54_pck 	RLC_PREFIX(fp54_pck)
#define fp54_print 	RLC_PREFIX(fp54_print)
#define fp54_rand 	RLC_PREFIX(fp54_rand)
#define fp54_read_bin 	RLC_PREFIX(fp54_read_bin)
#define fp54_set_dig 	RLC_PREFIX(fp54_set_dig)
#define fp54_size_bin 	RLC_PREFIX(fp54_size_bin)
#define fp54_sqr_basic 	RLC_PREFIX(fp54_sqr_basic)
#define fp54_sqr_cyc_basic 	RLC_PREFIX(fp54_sqr_cyc_basic)
#define fp54_sqr_cyc_lazyr 	RLC_PREFIX(fp54_sqr_cyc_lazyr)
#define fp54_sqr_lazyr 	RLC_PREFIX(fp54_sqr_lazyr)
#define fp54_sqr_pck_basic 	RLC_PREFIX(fp54_sqr_pck_basic)
#define fp54_sqr_pck_lazyr 	RLC_PREFIX(fp54_sqr_pck_lazyr)
#define fp54_sqr_unr 	RLC_PREFIX(fp54_sqr_unr)
#define fp54_st        RLC_PREFIX(fp54_st)
#define fp54_sub 	RLC_PREFIX(fp54_sub)
#define fp54_t         RLC_PREFIX(fp54_t)
#define fp54_test_cyc 	RLC_PREFIX(fp54_test_cyc)
#define fp54_upk 	RLC_PREFIX(fp54_upk)
#define fp54_write_bin 	RLC_PREFIX(fp54_write_bin)
#define fp54_zero 	RLC_PREFIX(fp54_zero)
#define fp6_add 	RLC_PREFIX(fp6_add)
#define fp6_cmp 	RLC_PREFIX(fp6_cmp)
#define fp6_cmp_dig 	RLC_PREFIX(fp6_cmp_dig)
#define fp6_copy 	RLC_PREFIX(fp6_copy)
#define fp6_dbl 	RLC_PREFIX(fp6_dbl)
#define fp6_exp 	RLC_PREFIX(fp6_exp)
#define fp6_frb 	RLC_PREFIX(fp6_frb)
#define fp6_inv 	RLC_PREFIX(fp6_inv)
#define fp6_is_zero 	RLC_PREFIX(fp6_is_zero)
#define fp6_mul_art 	RLC_PREFIX(fp6_mul_art)
#define fp6_mul_basic 	RLC_PREFIX(fp6_mul_basic)
#define fp6_mul_dxs 	RLC_PREFIX(fp6_mul_dxs)
#define fp6_mul_lazyr 	RLC_PREFIX(fp6_mul_lazyr)
#define fp6_mul_unr 	RLC_PREFIX(fp6_mul_unr)
#define fp6_neg 	RLC_PREFIX(fp6_neg)
#define fp6_print 	RLC_PREFIX(fp6_print)
#define fp6_rand 	RLC_PREFIX(fp6_rand)
#define fp6_read_bin 	RLC_PREFIX(fp6_read_bin)
#define fp6_set_dig 	RLC_PREFIX(fp6_set_dig)
#define fp6_size_bin 	RLC_PREFIX(fp6_size_bin)
#define fp6_sqr_basic 	RLC_PREFIX(fp6_sqr_basic)
#define fp6_sqr_lazyr 	RLC_PREFIX(fp6_sqr_lazyr)
#define fp6_sqr_unr 	RLC_PREFIX(fp6_sqr_unr)
#define fp6_st        RLC_PREFIX(fp6_st)
#define fp6_sub 	RLC_PREFIX(fp6_sub)
#define fp6_t         RLC_PREFIX(fp6_t)
#define fp6_write_bin 	RLC_PREFIX(fp6_write_bin)
#define fp6_zero 	RLC_PREFIX(fp6_zero)
#define fp8_add 	RLC_PREFIX(fp8_add)
#define fp8_cmp 	RLC_PREFIX(fp8_cmp)
#define fp8_cmp_dig 	RLC_PREFIX(fp8_cmp_dig)
#define fp8_conv_cyc 	RLC_PREFIX(fp8_conv_cyc)
#define fp8_copy 	RLC_PREFIX(fp8_copy)
#define fp8_dbl 	RLC_PREFIX(fp8_dbl)
#define fp8_exp 	RLC_PREFIX(fp8_exp)
#define fp8_exp_cyc 	RLC_PREFIX(fp8_exp_cyc)
#define fp8_frb 	RLC_PREFIX(fp8_frb)
#define fp8_inv 	RLC_PREFIX(fp8_inv)
#define fp8_inv_cyc 	RLC_PREFIX(fp8_inv_cyc)
#define fp8_inv_sim 	RLC_PREFIX(fp8_inv_sim)
#define fp8_is_zero 	RLC_PREFIX(fp8_is_zero)
#define fp8_mul_art 	RLC_PREFIX(fp8_mul_art)
#define fp8_mul_basic 	RLC_PREFIX(fp8_mul_basic)
#define fp8_mul_dxs 	RLC_PREFIX(fp8_mul_dxs)
#define fp8_mul_lazyr 	RLC_PREFIX(fp8_mul_lazyr)
#define fp8_mul_unr 	RLC_PREFIX(fp8_mul_unr)
#define fp8_neg 	RLC_PREFIX(fp8_neg)
#define fp8_print 	RLC_PREFIX(fp8_print)
#define fp8_rand 	RLC_PREFIX(fp8_rand)
#define fp8_read_bin 	RLC_PREFIX(fp8_read_bin)
#define fp8_set_dig 	RLC_PREFIX(fp8_set_dig)
#define fp8_size_bin 	RLC_PREFIX(fp8_size_bin)
#define fp8_sqr_basic 	RLC_PREFIX(fp8_sqr_basic)
#define fp8_sqr_cyc 	RLC_PREFIX(fp8_sqr_cyc)
#define fp8_sqr_lazyr 	RLC_PREFIX(fp8_sqr_lazyr)
#define fp8_sqr_unr 	RLC_PREFIX(fp8_sqr_unr)
#define fp8_st        RLC_PREFIX(fp8_st)
#define fp8_sub 	RLC_PREFIX(fp8_sub)
#define fp8_t         RLC_PREFIX(fp8_t)
#define fp8_test_cyc 	RLC_PREFIX(fp8_test_cyc)
#define fp8_write_bin 	RLC_PREFIX(fp8_write_bin)
#define fp8_zero 	RLC_PREFIX(fp8_zero)
#define fp9_add 	RLC_PREFIX(fp9_add)
#define fp9_cmp 	RLC_PREFIX(fp9_cmp)
#define fp9_cmp_dig 	RLC_PREFIX(fp9_cmp_dig)
#define fp9_copy 	RLC_PREFIX(fp9_copy)
#define fp9_dbl 	RLC_PREFIX(fp9_dbl)
#define fp9_exp 	RLC_PREFIX(fp9_exp)
#define fp9_frb 	RLC_PREFIX(fp9_frb)
#define fp9_inv 	RLC_PREFIX(fp9_inv)
#define fp9_inv_sim 	RLC_PREFIX(fp9_inv_sim)
#define fp9_is_zero 	RLC_PREFIX(fp9_is_zero)
#define fp9_mul_art 	RLC_PREFIX(fp9_mul_art)
#define fp9_mul_basic 	RLC_PREFIX(fp9_mul_basic)
#define fp9_mul_dxs 	RLC_PREFIX(fp9_mul_dxs)
#define fp9_mul_lazyr 	RLC_PREFIX(fp9_mul_lazyr)
#define fp9_mul_unr 	RLC_PREFIX(fp9_mul_unr)
#define fp9_neg 	RLC_PREFIX(fp9_neg)
#define fp9_print 	RLC_PREFIX(fp9_print)
#define fp9_rand 	RLC_PREFIX(fp9_rand)
#define fp9_read_bin 	RLC_PREFIX(fp9_read_bin)
#define fp9_set_dig 	RLC_PREFIX(fp9_set_dig)
#define fp9_size_bin 	RLC_PREFIX(fp9_size_bin)
#define fp9_sqr_basic 	RLC_PREFIX(fp9_sqr_basic)
#define fp9_sqr_lazyr 	RLC_PREFIX(fp9_sqr_lazyr)
#define fp9_sqr_unr 	RLC_PREFIX(fp9_sqr_unr)
#define fp9_st        RLC_PREFIX(fp9_st)
#define fp9_sub 	RLC_PREFIX(fp9_sub)
#define fp9_t         RLC_PREFIX(fp9_t)
#define fp9_write_bin 	RLC_PREFIX(fp9_write_bin)
#define fp9_zero 	RLC_PREFIX(fp9_zero)
#define fp_add1_low 	RLC_PREFIX(fp_add1_low)
#define fp_add_basic 	RLC_PREFIX(fp_add_basic)
#define fp_add_dig 	RLC_PREFIX(fp_add_dig)
#define fp_add_integ 	RLC_PREFIX(fp_add_integ)
#define fp_addc_low 	RLC_PREFIX(fp_addc_low)
#define fp_addd_low 	RLC_PREFIX(fp_addd_low)
#define fp_addm_low 	RLC_PREFIX(fp_addm_low)
#define fp_addn_low 	RLC_PREFIX(fp_addn_low)
#define fp_bits 	RLC_PREFIX(fp_bits)
#define fp_cmp 	RLC_PREFIX(fp_cmp)
#define fp_cmp_dig 	RLC_PREFIX(fp_cmp_dig)
#define fp_copy 	RLC_PREFIX(fp_copy)
#define fp_dbl_basic 	RLC_PREFIX(fp_dbl_basic)
#define fp_dbl_integ 	RLC_PREFIX(fp_dbl_integ)
#define fp_dblm_low 	RLC_PREFIX(fp_dblm_low)
#define fp_dbln_low 	RLC_PREFIX(fp_dbln_low)
#define fp_exp_basic 	RLC_PREFIX(fp_exp_basic)
#define fp_exp_monty 	RLC_PREFIX(fp_exp_monty)
#define fp_exp_slide 	RLC_PREFIX(fp_exp_slide)
#define fp_get_bit 	RLC_PREFIX(fp_get_bit)
#define fp_hlv_basic 	RLC_PREFIX(fp_hlv_basic)
#define fp_hlv_integ 	RLC_PREFIX(fp_hlv_integ)
#define fp_hlvd_low 	RLC_PREFIX(fp_hlvd_low)
#define fp_hlvm_low 	RLC_PREFIX(fp_hlvm_low)
#define fp_inv_basic 	RLC_PREFIX(fp_inv_basic)
#define fp_inv_binar 	RLC_PREFIX(fp_inv_binar)
#define fp_inv_divst 	RLC_PREFIX(fp_inv_divst)
#define fp_inv_exgcd 	RLC_PREFIX(fp_inv_exgcd)
#define fp_inv_lower 	RLC_PREFIX(fp_inv_lower)
#define fp_inv_monty 	RLC_PREFIX(fp_inv_monty)
#define fp_inv_sim 	RLC_PREFIX(fp_inv_sim)
#define fp_invm_low 	RLC_PREFIX(fp_invm_low)
#define fp_is_even 	RLC_PREFIX(fp_is_even)
#define fp_is_zero 	RLC_PREFIX(fp_is_zero)
#define fp_lsh 	RLC_PREFIX(fp_lsh)
#define fp_lsh1_low 	RLC_PREFIX(fp_lsh1_low)
#define fp_lshb_low 	RLC_PREFIX(fp_lshb_low)
#define fp_lshd_low 	RLC_PREFIX(fp_lshd_low)
#define fp_mul1_low 	RLC_PREFIX(fp_mul1_low)
#define fp_mul_basic 	RLC_PREFIX(fp_mul_basic)
#define fp_mul_comba 	RLC_PREFIX(fp_mul_comba)
#define fp_mul_dig 	RLC_PREFIX(fp_mul_dig)
#define fp_mul_integ 	RLC_PREFIX(fp_mul_integ)
#define fp_mul_karat 	RLC_PREFIX(fp_mul_karat)
#define fp_mula_low 	RLC_PREFIX(fp_mula_low)
#define fp_mulm_low 	RLC_PREFIX(fp_mulm_low)
#define fp_muln_low 	RLC_PREFIX(fp_muln_low)
#define fp_neg_basic 	RLC_PREFIX(fp_neg_basic)
#define fp_neg_integ 	RLC_PREFIX(fp_neg_integ)
#define fp_negm_low 	RLC_PREFIX(fp_negm_low)
#define fp_param_get 	RLC_PREFIX(fp_param_get)
#define fp_param_get_sps 	RLC_PREFIX(fp_param_get_sps)
#define fp_param_print 	RLC_PREFIX(fp_param_print)
#define fp_param_set 	RLC_PREFIX(fp_param_set)
#define fp_param_set_any 	RLC_PREFIX(fp_param_set_any)
#define fp_param_set_any_dense 	RLC_PREFIX(fp_param_set_any_dense)
#define fp_param_set_any_pmers 	RLC_PREFIX(fp_param_set_any_pmers)
#define fp_param_set_any_tower 	RLC_PREFIX(fp_param_set_any_tower)
#define fp_prime_back 	RLC_PREFIX(fp_prime_back)
#define fp_prime_calc 	RLC_PREFIX(fp_prime_calc)
#define fp_prime_clean 	RLC_PREFIX(fp_prime_clean)
#define fp_prime_conv 	RLC_PREFIX(fp_prime_conv)
#define fp_prime_conv_dig 	RLC_PREFIX(fp_prime_conv_dig)
#define fp_prime_get 	RLC_PREFIX(fp_prime_get)
#define fp_prime_get_2ad 	RLC_PREFIX(fp_prime_get_2ad)
#define fp_prime_get_cnr 	RLC_PREFIX(fp_prime_get_cnr)
#define fp_prime_get_conv 	RLC_PREFIX(fp_prime_get_conv)
#define fp_prime_get_mod8 	RLC_PREFIX(fp_prime_get_mod8)
#define fp_prime_get_par 	RLC_PREFIX(fp_prime_get_par)
#define fp_prime_get_par_sps 	RLC_PREFIX(fp_prime_get_par_sps)
#define fp_prime_get_qnr 	RLC_PREFIX(fp_prime_get_qnr)
#define fp_prime_get_rdc 	RLC_PREFIX(fp_prime_get_rdc)
#define fp_prime_get_sps 	RLC_PREFIX(fp_prime_get_sps)
#define fp_prime_init 	RLC_PREFIX(fp_prime_init)
#define fp_prime_set_dense 	RLC_PREFIX(fp_prime_set_dense)
#define fp_prime_set_pairf 	RLC_PREFIX(fp_prime_set_pairf)
#define fp_prime_set_pmers 	RLC_PREFIX(fp_prime_set_pmers)
#define fp_print 	RLC_PREFIX(fp_print)
#define fp_rand 	RLC_PREFIX(fp_rand)
#define fp_rdc_basic 	RLC_PREFIX(fp_rdc_basic)
#define fp_rdc_monty_basic 	RLC_PREFIX(fp_rdc_monty_basic)
#define fp_rdc_monty_comba 	RLC_PREFIX(fp_rdc_monty_comba)
#define fp_rdc_quick 	RLC_PREFIX(fp_rdc_quick)
#define fp_rdcn_low 	RLC_PREFIX(fp_rdcn_low)
#define fp_rdcs_low 	RLC_PREFIX(fp_rdcs_low)
#define fp_read_bin 	RLC_PREFIX(fp_read_bin)
#define fp_read_str 	RLC_PREFIX(fp_read_str)
#define fp_rsh 	RLC_PREFIX(fp_rsh)
#define fp_rsh1_low 	RLC_PREFIX(fp_rsh1_low)
#define fp_rshb_low 	RLC_PREFIX(fp_rshb_low)
#define fp_rshd_low 	RLC_PREFIX(fp_rshd_low)
#define fp_set_bit 	RLC_PREFIX(fp_set_bit)
#define fp_set_dig 	RLC_PREFIX(fp_set_dig)
#define fp_size_str 	RLC_PREFIX(fp_size_str)
#define fp_sqr_basic 	RLC_PREFIX(fp_sqr_basic)
#define fp_sqr_comba 	RLC_PREFIX(fp_sqr_comba)
#define fp_sqr_integ 	RLC_PREFIX(fp_sqr_integ)
#define fp_sqr_karat 	RLC_PREFIX(fp_sqr_karat)
#define fp_sqrm_low 	RLC_PREFIX(fp_sqrm_low)
#define fp_sqrn_low 	RLC_PREFIX(fp_sqrn_low)
#define fp_srt 	RLC_PREFIX(fp_srt)
#define fp_st	        RLC_PREFIX(fp_st)
#define fp_sub1_low 	RLC_PREFIX(fp_sub1_low)
#define fp_sub_basic 	RLC_PREFIX(fp_sub_basic)
#define fp_sub_dig 	RLC_PREFIX(fp_sub_dig)
#define fp_sub_integ 	RLC_PREFIX(fp_sub_integ)
#define fp_subc_low 	RLC_PREFIX(fp_subc_low)
#define fp_subd_low 	RLC_PREFIX(fp_subd_low)
#define fp_subm_low 	RLC_PREFIX(fp_subm_low)
#define fp_subn_low 	RLC_PREFIX(fp_subn_low)
#define fp_t          RLC_PREFIX(fp_t)
#define fp_write_bin 	RLC_PREFIX(fp_write_bin)
#define fp_write_str 	RLC_PREFIX(fp_write_str)
#define fp_zero 	RLC_PREFIX(fp_zero)
#define md_hmac 	RLC_PREFIX(md_hmac)
#define md_kdf 	RLC_PREFIX(md_kdf)
#define md_map_b2s160 	RLC_PREFIX(md_map_b2s160)
#define md_map_b2s256 	RLC_PREFIX(md_map_b2s256)
#define md_map_sh224 	RLC_PREFIX(md_map_sh224)
#define md_map_sh256 	RLC_PREFIX(md_map_sh256)
#define md_map_sh384 	RLC_PREFIX(md_map_sh384)
#define md_map_sh512 	RLC_PREFIX(md_map_sh512)
#define md_mgf 	RLC_PREFIX(md_mgf)
#define md_xmd_sh224 	RLC_PREFIX(md_xmd_sh224)
#define md_xmd_sh256 	RLC_PREFIX(md_xmd_sh256)
#define md_xmd_sh384 	RLC_PREFIX(md_xmd_sh384)
#define md_xmd_sh512 	RLC_PREFIX(md_xmd_sh512)
#define pp_add_k12_basic 	RLC_PREFIX(pp_add_k12_basic)
#define pp_add_k12_projc_basic 	RLC_PREFIX(pp_add_k12_projc_basic)
#define pp_add_k12_projc_lazyr 	RLC_PREFIX(pp_add_k12_projc_lazyr)
#define pp_add_k2_basic 	RLC_PREFIX(pp_add_k2_basic)
#define pp_add_k2_projc_basic 	RLC_PREFIX(pp_add_k2_projc_basic)
#define pp_add_k2_projc_lazyr 	RLC_PREFIX(pp_add_k2_projc_lazyr)
#define pp_add_k48_basic 	RLC_PREFIX(pp_add_k48_basic)
#define pp_add_k48_projc 	RLC_PREFIX(pp_add_k48_projc)
#define pp_add_k54_basic 	RLC_PREFIX(pp_add_k54_basic)
#define pp_add_k54_projc 	RLC_PREFIX(pp_add_k54_projc)
#define pp_add_k8_basic 	RLC_PREFIX(pp_add_k8_basic)
#define pp_add_k8_projc_basic 	RLC_PREFIX(pp_add_k8_projc_basic)
#define pp_add_k8_projc_lazyr 	RLC_PREFIX(pp_add_k8_projc_lazyr)
#define pp_add_lit_k12 	RLC_PREFIX(pp_add_lit_k12)
#define pp_dbl_k12_basic 	RLC_PREFIX(pp_dbl_k12_basic)
#define pp_dbl_k12_projc_basic 	RLC_PREFIX(pp_dbl_k12_projc_basic)
#define pp_dbl_k12_projc_lazyr 	RLC_PREFIX(pp_dbl_k12_projc_lazyr)
#define pp_dbl_k2_basic 	RLC_PREFIX(pp_dbl_k2_basic)
#define pp_dbl_k2_projc_basic 	RLC_PREFIX(pp_dbl_k2_projc_basic)
#define pp_dbl_k2_projc_lazyr 	RLC_PREFIX(pp_dbl_k2_projc_lazyr)
#define pp_dbl_k48_basic 	RLC_PREFIX(pp_dbl_k48_basic)
#define pp_dbl_k48_projc 	RLC_PREFIX(pp_dbl_k48_projc)
#define pp_dbl_k54_basic 	RLC_PREFIX(pp_dbl_k54_basic)
#define pp_dbl_k54_projc 	RLC_PREFIX(pp_dbl_k54_projc)
#define pp_dbl_k8_basic 	RLC_PREFIX(pp_dbl_k8_basic)
#define pp_dbl_k8_projc_basic 	RLC_PREFIX(pp_dbl_k8_projc_basic)
#define pp_dbl_k8_projc_lazyr 	RLC_PREFIX(pp_dbl_k8_projc_lazyr)
#define pp_dbl_lit_k12 	RLC_PREFIX(pp_dbl_lit_k12)
#define pp_exp_k12 	RLC_PREFIX(pp_exp_k12)
#define pp_exp_k2 	RLC_PREFIX(pp_exp_k2)
#define pp_exp_k48 	RLC_PREFIX(pp_exp_k48)
#define pp_exp_k54 	RLC_PREFIX(pp_exp_k54)
#define pp_exp_k8 	RLC_PREFIX(pp_exp_k8)
#define pp_map_clean 	RLC_PREFIX(pp_map_clean)
#define pp_map_init 	RLC_PREFIX(pp_map_init)
#define pp_map_k48 	RLC_PREFIX(pp_map_k48)
#define pp_map_k54 	RLC_PREFIX(pp_map_k54)
#define pp_map_oatep_k12 	RLC_PREFIX(pp_map_oatep_k12)
#define pp_map_oatep_k8 	RLC_PREFIX(pp_map_oatep_k8)
#define pp_map_sim_oatep_k12 	RLC_PREFIX(pp_map_sim_oatep_k12)
#define pp_map_sim_tatep_k12 	RLC_PREFIX(pp_map_sim_tatep_k12)
#define pp_map_sim_tatep_k2 	RLC_PREFIX(pp_map_sim_tatep_k2)
#define pp_map_sim_weilp_k12 	RLC_PREFIX(pp_map_sim_weilp_k12)
#define pp_map_sim_weilp_k2 	RLC_PREFIX(pp_map_sim_weilp_k2)
#define pp_map_tatep_k12 	RLC_PREFIX(pp_map_tatep_k12)
#define pp_map_tatep_k2 	RLC_PREFIX(pp_map_tatep_k2)
#define pp_map_weilp_k12 	RLC_PREFIX(pp_map_weilp_k12)
#define pp_map_weilp_k2 	RLC_PREFIX(pp_map_weilp_k2)
#define pp_norm_k12 	RLC_PREFIX(pp_norm_k12)
#define pp_norm_k2 	RLC_PREFIX(pp_norm_k2)
#define pp_norm_k8 	RLC_PREFIX(pp_norm_k8)
#define rand_bytes 	RLC_PREFIX(rand_bytes)
#define rand_clean 	RLC_PREFIX(rand_clean)
#define rand_init 	RLC_PREFIX(rand_init)
#define rand_seed 	RLC_PREFIX(rand_seed)
#define rsa_t		RLC_PREFIX(rsa_t)
#define test_fail 	RLC_PREFIX(test_fail)
#define test_pass 	RLC_PREFIX(test_pass)
#define util_bits_dig 	RLC_PREFIX(util_bits_dig)
#define util_cmp_const 	RLC_PREFIX(util_cmp_const)
#define util_conv_big 	RLC_PREFIX(util_conv_big)
#define util_conv_char 	RLC_PREFIX(util_conv_char)
#define util_conv_endian 	RLC_PREFIX(util_conv_endian)
#define util_conv_little 	RLC_PREFIX(util_conv_little)
#define util_print_dig 	RLC_PREFIX(util_print_dig)
#define util_printf 	RLC_PREFIX(util_printf)
#define RLC_ALIGN(A)														\
	((unsigned int)(A) + RLC_PAD((unsigned int)(A)));						\

#define RLC_PAD(A)		((A) % ALIGN == 0 ? 0 : ALIGN - ((A) % ALIGN))

#define rlc_align 		__attribute__ ((aligned (ALIGN)))

#define bdpe_free(A)														\
	if (A != NULL) {														\
		bn_free((A)->n);													\
		bn_free((A)->y);													\
		bn_free((A)->p);													\
		bn_free((A)->q);													\
		(A)->t = 0;															\
		free(A);															\
		A = NULL;															\
	}
#define bdpe_new(A)															\
	A = (bdpe_t)calloc(1, sizeof(bdpe_st));									\
	if (A == NULL) {														\
		RLC_THROW(ERR_NO_MEMORY);											\
	}																		\
	bn_new((A)->n);															\
	bn_new((A)->y);															\
	bn_new((A)->p);															\
	bn_new((A)->q);															\
	(A)->t = 0;																\

#define bdpe_null(A)			
#define bgn_free(A)															\
	if (A != NULL) {														\
		bn_free((A)->x);													\
		bn_free((A)->y);													\
		bn_free((A)->z);													\
		g1_free((A)->gx);													\
		g1_free((A)->gy);													\
		g1_free((A)->gz);													\
		g2_free((A)->hx);													\
		g2_free((A)->hy);													\
		g2_free((A)->hz);													\
		free(A);															\
		A = NULL;															\
	}
#define bgn_new(A)															\
	A = (bgn_t)calloc(1, sizeof(bgn_st));									\
	if (A == NULL) {														\
		RLC_THROW(ERR_NO_MEMORY);											\
	}																		\
	bn_new((A)->x);															\
	bn_new((A)->y);															\
	bn_new((A)->z);															\
	g1_new((A)->gx);														\
	g1_new((A)->gy);														\
	g1_new((A)->gz);														\
	g2_new((A)->hx);														\
	g2_new((A)->hy);														\
	g2_new((A)->hz);														\

#define bgn_null(A)				
#define crt_free(A)															\
	if (A != NULL) {														\
		bn_free((A)->n);													\
		bn_free((A)->dp);													\
		bn_free((A)->dq);													\
		bn_free((A)->p);													\
		bn_free((A)->q);													\
		bn_free((A)->qi);													\
		free(A);															\
		A = NULL;															\
	}
#define crt_new(A)															\
	A = (crt_t)calloc(1, sizeof(crt_st));									\
	if (A == NULL) {														\
		RLC_THROW(ERR_NO_MEMORY);											\
	}																		\
	bn_new((A)->n);															\
	bn_new((A)->dp);														\
	bn_new((A)->dq);														\
	bn_new((A)->p);															\
	bn_new((A)->q);															\
	bn_new((A)->qi);														\

#define crt_null(A)				
#define phpe_free(A)		crt_free(A)
#define phpe_new(A)			crt_new(A)
#define phpe_null(A)		
#define rabin_free(A)		crt_free(A)
#define rabin_new(A)		crt_new(A)
#define rabin_null(A)		
#define rsa_free(A)															\
	if (A != NULL) {														\
		bn_free((A)->d);													\
		bn_free((A)->e);													\
		crt_free((A)->crt);													\
		free(A);															\
		A = NULL;															\
	}
#define rsa_new(A)															\
	A = (rsa_t)calloc(1, sizeof(_rsa_st));									\
	if (A == NULL) {														\
		RLC_THROW(ERR_NO_MEMORY);											\
	}																		\
	bn_null((A)->d);														\
	bn_null((A)->e);														\
	bn_new((A)->d);															\
	bn_new((A)->e);															\
	crt_new((A)->crt);														\

#define rsa_null(A)				
#define sokaka_free(A)														\
	if (A != NULL) {														\
		g1_free((A)->s1);													\
		g2_free((A)->s2);													\
		free(A);															\
		A = NULL;															\
	}
#define sokaka_new(A)														\
	A = (sokaka_t)calloc(1, sizeof(sokaka_st));								\
	if (A == NULL) {														\
		RLC_THROW(ERR_NO_MEMORY);											\
	}																		\
	g1_new((A)->s1);														\
	g2_new((A)->s2);														\

#define sokaka_null(A)			

#define mt_free(A)															\
	if (A != NULL) {														\
		bn_free((A)->a);													\
		bn_free((A)->b);													\
		bn_free((A)->c);													\
		free(A);															\
		A = NULL;															\
	}
#define mt_new(A)															\
	A = (mt_t)calloc(1, sizeof(mt_st));										\
	if ((A) == NULL) {														\
		RLC_THROW(ERR_NO_MEMORY);											\
	}																		\
	bn_null((A)->a);														\
	bn_null((A)->b);														\
	bn_null((A)->c);														\
	bn_new((A)->a);															\
	bn_new((A)->b);															\
	bn_new((A)->c);															\

#define mt_null(A)			A = NULL;
#define pt_free(A)															\
	if (A != NULL) {														\
		g1_free((A)->a);													\
		g2_free((A)->b);													\
		gt_free((A)->c);													\
		free(A);															\
		A = NULL;															\
	}
#define pt_new(A)															\
	A = (pt_t)calloc(1, sizeof(pt_st));										\
	if (A == NULL) {														\
		RLC_THROW(ERR_NO_MEMORY);											\
	}																		\
	g1_new((A)->a);															\
	g2_new((A)->b);															\
	gt_new((A)->c);															\

#define pt_null(A)				

#define g1_add(R, P, Q)		RLC_CAT(RLC_G1_LOWER, add)(R, P, Q)
 #define g1_blind(R, P)		RLC_CAT(RLC_G1_LOWER, blind)(R, P)
#define g1_cmp(P, Q)		RLC_CAT(RLC_G1_LOWER, cmp)(P, Q)
#define g1_copy(R, P)		RLC_CAT(RLC_G1_LOWER, copy)(R, P)
#define g1_dbl(R, P)		RLC_CAT(RLC_G1_LOWER, dbl)(R, P)
#define g1_free(A)			RLC_CAT(RLC_G1_LOWER, free)(A)
#define g1_get_gen(G)		RLC_CAT(RLC_G1_LOWER, curve_get_gen)(G)
#define g1_is_infty(P)		RLC_CAT(RLC_G1_LOWER, is_infty)(P)
#define g1_map(P, M, L);	RLC_CAT(RLC_G1_LOWER, map)(P, M, L)
#define g1_mul_dig(R, P, K)		RLC_CAT(RLC_G1_LOWER, mul_dig)(R, P, K)
#define g1_mul_fix(R, T, K)	RLC_CAT(RLC_G1_LOWER, mul_fix)(R, T, K)
#define g1_mul_key(R, P, K)		RLC_CAT(RLC_G1_LOWER, mul_lwreg)(R, P, K)
#define g1_mul_pre(T, P)	RLC_CAT(RLC_G1_LOWER, mul_pre)(T, P)
#define g1_mul_sim(R, P, K, Q, L)	RLC_CAT(RLC_G1_LOWER, mul_sim)(R, P, K, Q, L)
#define g1_mul_sim_dig(R, P, K, L)	RLC_CAT(RLC_G1_LOWER, mul_sim_dig)(R, P, K, L)
#define g1_mul_sim_gen(R, K, Q, L)	RLC_CAT(RLC_G1_LOWER, mul_sim_gen)(R, K, Q, L)
#define g1_neg(R, P)		RLC_CAT(RLC_G1_LOWER, neg)(R, P)
#define g1_new(A)			RLC_CAT(RLC_G1_LOWER, new)(A)
#define g1_norm(R, P)		RLC_CAT(RLC_G1_LOWER, norm)(R, P)
#define g1_norm_sim(R, P, N)	RLC_CAT(RLC_G1_LOWER, norm_sim)(R, P, N)
#define g1_null(A)			RLC_CAT(RLC_G1_LOWER, null)(A)
#define g1_print(P)			RLC_CAT(RLC_G1_LOWER, print)(P)
#define g1_rand(P)			RLC_CAT(RLC_G1_LOWER, rand)(P)
#define g1_read_bin(P, B, L) 	RLC_CAT(RLC_G1_LOWER, read_bin)(P, B, L)
#define g1_set_infty(P)		RLC_CAT(RLC_G1_LOWER, set_infty)(P)
#define g1_size_bin(P, C)	RLC_CAT(RLC_G1_LOWER, size_bin)(P, C)
#define g1_sub(R, P, Q)		RLC_CAT(RLC_G1_LOWER, sub)(R, P, Q)
#define g1_write_bin(B, L, P, C)	RLC_CAT(RLC_G1_LOWER, write_bin)(B, L, P, C)
#define g2_add(R, P, Q)		RLC_CAT(RLC_G2_LOWER, add)(R, P, Q)
#define g2_blind(R, P)		RLC_CAT(RLC_G2_LOWER, blind)(R, P)
#define g2_cmp(P, Q)		RLC_CAT(RLC_G2_LOWER, cmp)(P, Q)
#define g2_copy(R, P)		RLC_CAT(RLC_G2_LOWER, copy)(R, P)
#define g2_dbl(R, P)		RLC_CAT(RLC_G2_LOWER, dbl)(R, P)
#define g2_free(A)			RLC_CAT(RLC_G2_LOWER, free)(A)
#define g2_get_gen(G)		RLC_CAT(RLC_G2_LOWER, curve_get_gen)(G)
#define g2_is_infty(P)		RLC_CAT(RLC_G2_LOWER, is_infty)(P)
#define g2_map(P, M, L);	RLC_CAT(RLC_G2_LOWER, map)(P, M, L)
#define g2_mul_dig(R, P, K)		RLC_CAT(RLC_G2_LOWER, mul_dig)(R, P, K)
#define g2_mul_fix(R, T, K)	RLC_CAT(RLC_G2_LOWER, mul_fix)(R, T, K)
#define g2_mul_pre(T, P)	RLC_CAT(RLC_G2_LOWER, mul_pre)(T, P)
#define g2_mul_sim(R, P, K, Q, L)	RLC_CAT(RLC_G2_LOWER, mul_sim)(R, P, K, Q, L)
#define g2_mul_sim_dig(R, P, K, L)	RLC_CAT(RLC_G2_LOWER, mul_sim_dig)(R, P, K, L)
#define g2_mul_sim_gen(R, K, Q, L)	RLC_CAT(RLC_G2_LOWER, mul_sim_gen)(R, K, Q, L)
#define g2_mul_sim_lot(R, P, K, N)	RLC_CAT(RLC_G2_LOWER, mul_sim_lot)(R, P, K, N)
#define g2_neg(R, P)		RLC_CAT(RLC_G2_LOWER, neg)(R, P)
#define g2_new(A)			RLC_CAT(RLC_G2_LOWER, new)(A)
#define g2_norm(R, P)		RLC_CAT(RLC_G2_LOWER, norm)(R, P)
#define g2_norm_sim(R, P, N)	RLC_CAT(RLC_G2_LOWER, norm_sim)(R, P, N)
#define g2_null(A)			RLC_CAT(RLC_G2_LOWER, null)(A)
#define g2_print(P)			RLC_CAT(RLC_G2_LOWER, print)(P)
#define g2_rand(P)			RLC_CAT(RLC_G2_LOWER, rand)(P)
#define g2_read_bin(P, B, L) 	RLC_CAT(RLC_G2_LOWER, read_bin)(P, B, L)
#define g2_set_infty(P)		RLC_CAT(RLC_G2_LOWER, set_infty)(P)
#define g2_size_bin(P, C)	RLC_CAT(RLC_G2_LOWER, size_bin)(P, C)
#define g2_sub(R, P, Q)		RLC_CAT(RLC_G2_LOWER, sub)(R, P, Q)
#define g2_write_bin(B, L, P, C)	RLC_CAT(RLC_G2_LOWER, write_bin)(B, L, P, C)
#define gt_cmp(A, B)		RLC_CAT(RLC_GT_LOWER, cmp)(A, B)
#define gt_cmp_dig(A, D)	RLC_CAT(RLC_GT_LOWER, cmp_dig)(A, D)
#define gt_copy(C, A)		RLC_CAT(RLC_GT_LOWER, copy)(C, A)
#define gt_exp_dig(C, A, B)		RLC_CAT(RLC_GT_LOWER, exp_dig)(C, A, B)
#define gt_free(A)			RLC_CAT(RLC_GT_LOWER, free)(A)
#define gt_inv(C, A)		RLC_CAT(RLC_GT_LOWER, inv_cyc)(C, A)
#define gt_is_unity(A)		(RLC_CAT(RLC_GT_LOWER, cmp_dig)(A, 1) == RLC_EQ)
#define gt_mul(C, A, B)		RLC_CAT(RLC_GT_LOWER, mul)(C, A, B)
#define gt_new(A)			RLC_CAT(RLC_GT_LOWER, new)(A)
#define gt_null(A)			RLC_CAT(RLC_GT_LOWER, null)(A)
#define gt_print(A)			RLC_CAT(RLC_GT_LOWER, print)(A)
#define gt_read_bin(A, B, L) 	RLC_CAT(RLC_GT_LOWER, read_bin)(A, B, L)
#define gt_set_unity(A)		RLC_CAT(RLC_GT_LOWER, set_dig)(A, 1)
#define gt_size_bin(A, C)	RLC_CAT(RLC_GT_LOWER, size_bin)(A, C)
#define gt_sqr(C, A)		RLC_CAT(RLC_GT_LOWER, sqr)(C, A)
#define gt_write_bin(B, L, A, C)	RLC_CAT(RLC_GT_LOWER, write_bin)(B, L, A, C)
#define gt_zero(A)			RLC_CAT(RLC_GT_LOWER, zero)(A)
#define pc_exp(C, A);			RLC_CAT(RLC_PC_LOWER, exp_k12)(C, A)
#define pc_get_ord(N)		RLC_CAT(RLC_G1_LOWER, curve_get_ord)(N)
#define pc_map(R, P, Q);		RLC_CAT(RLC_PC_LOWER, map_k12)(R, P, Q)
#define pc_map_is_type1()	(0)
#define pc_map_is_type3()	(1)
#define pc_map_sim(R, P, Q, M);	RLC_CAT(RLC_PC_LOWER, map_sim_k12)(R, P, Q, M)
#define pc_param_level()	RLC_CAT(RLC_G1_LOWER, param_level)()
#define pc_param_print()	RLC_CAT(RLC_G1_LOWER, param_print)()
#define pc_param_set_any()	ep_param_set_any_pairf()
#define RLC_CAT(A, B)			_RLC_CAT(A, B)
#define RLC_CEIL(A, B)			(((A) - 1) / (B) + 1)
#define RLC_ECHO(A) 			A
#define RLC_HIGH(D)				(D >> (RLC_DIG >> 1))
#define RLC_LOW(D)				(D & RLC_LMASK)
#define RLC_MASK(B)															\
	((-(dig_t)((B) >= WSIZE)) | (((dig_t)1 << ((B) % WSIZE)) - 1))
#define RLC_MAX(A, B)			((A) > (B) ? (A) : (B))
#define RLC_MIN(A, B)			((A) < (B) ? (A) : (B))
#define RLC_OPT(...)			_OPT(__VA_ARGS__, _imp, _basic, _error)
#define RLC_RIP(B, D, V)													\
	D = (V) >> (RLC_DIG_LOG); B = (V) - ((D) * (1 << RLC_DIG_LOG));
#define RLC_SEL(A, B, C) 		((-(C) & ((A) ^ (B))) ^ (A))
#define RLC_SWAP(A, B) 			((A) ^= (B), (B) ^= (A), (A) ^= (B))
#define RLC_UPP(C)				((C) - 0x20 * (((C) >= 'a') && ((C) <= 'z')))

#define _OPT(...)				RLC_ECHO(__OPT(__VA_ARGS__))
#define _RLC_CAT(A, B)			A ## B
#define __OPT(_1, _2, N, ...)	N
#define util_banner(L, I)													\
	if (!I) {																\
		util_print("\n-- " L "\n");											\
	} else {																\
		util_print("\n** " L "\n\n");										\
	}																		\

#define util_print(F, ...)		

#define RLC_GET(S, ID, L)		arch_copy_rom(S, RLC_STR(ID), L);
#define RLC_STR(S)				PSTR(S)
#define RLC_BN_BITS 	((int)BN_PRECI)

#define bn_free(A)															\
	if (A != NULL) {														\
		bn_clean(A);														\
		free(A);															\
		A = NULL;															\
	}
#define bn_gcd(C, A, B)		bn_gcd_basic(C, A, B)
#define bn_gcd_ext(C, D, E, A, B)		bn_gcd_ext_basic(C, D, E, A, B)
#define bn_mod_imp(C, A, M, U)	bn_mod_basic(C, A, M)
#define bn_mod_pre(U, M)	(void)(U), (void)(M)
#define bn_mul(C, A, B)		bn_mul_karat(C, A, B)
#define bn_new(A)															\
	A = (bn_t)calloc(1, sizeof(bn_st));										\
	if ((A) == NULL) {														\
		RLC_THROW(ERR_NO_MEMORY);												\
	}																		\
	bn_init(A, RLC_BN_SIZE);												\

#define bn_new_size(A, D)													\
	A = (bn_t)calloc(1, sizeof(bn_st));										\
	if (A == NULL) {														\
		RLC_THROW(ERR_NO_MEMORY);												\
	}																		\
	bn_init(A, D);															\

#define bn_null(A)				
#define bn_sqr(C, A)		bn_mul(C, A, A)

#define pp_add_k12(L, R, Q, P)		pp_add_k12_basic(L, R, Q, P)
#define pp_add_k2(L, R, P, Q)		pp_add_k2_basic(L, R, P, Q)
#define pp_add_k2_projc(L, R, P, Q)		pp_add_k2_projc_basic(L, R, P, Q)
#define pp_add_k8(L, R, Q, P)		pp_add_k8_basic(L, R, Q, P)
#define pp_dbl_k12(L, R, Q, P)			pp_dbl_k12_basic(L, R, Q, P)
#define pp_dbl_k2(L, R, P, Q)			pp_dbl_k2_basic(L, R, P, Q)
#define pp_dbl_k2_projc(L, R, P, Q)		pp_dbl_k2_projc_basic(L, R, P, Q)
#define pp_dbl_k8(L, R, Q, P)			pp_dbl_k8_basic(L, R, Q, P)
#define pp_dbl_k8_projc(L, R, Q, P)		pp_dbl_k8_projc_basic(L, R, Q, P)
#define pp_map_k12(R, P, Q)				pp_map_tatep_k12(R, P, Q)
#define pp_map_k2(R, P, Q)				pp_map_tatep_k2(R, P, Q)
#define pp_map_sim_k12(R, P, Q, M)		pp_map_sim_tatep_k12(R, P, Q, M)
#define pp_map_sim_k2(R, P, Q, M)		pp_map_sim_weilp_k2(R, P, Q, M)

#define RLC_EPX_TABLE			RLC_EPX_TABLE_BASIC
#define RLC_EPX_TABLE_COMBS      (1 << EP_DEPTH)
#define RLC_EPX_TABLE_MAX 	RLC_EPX_TABLE
#define ep2_add(R, P, Q)		ep2_add_basic(R, P, Q);
#define ep2_dbl(R, P)			ep2_dbl_basic(R, P);
#define ep2_free(A)															\
	if (A != NULL) {														\
		fp2_free((A)->x);													\
		fp2_free((A)->y);													\
		fp2_free((A)->z);													\
		free(A);															\
		A = NULL;															\
	}																		\

#define ep2_mul(R, P, K)		ep2_mul_basic(R, P, K)
#define ep2_mul_pre(T, P)		ep2_mul_pre_basic(T, P)
#define ep2_new(A)															\
	A = (ep2_t)calloc(1, sizeof(ep2_st));									\
	if (A == NULL) {														\
		RLC_THROW(ERR_NO_MEMORY);												\
	}																		\
	fp2_null((A)->x);														\
	fp2_null((A)->y);														\
	fp2_null((A)->z);														\
	fp2_new((A)->x);														\
	fp2_new((A)->y);														\
	fp2_new((A)->z);														\

#define ep2_null(A)				
#define RLC_EP_CTMAP_MAX   16

#define RLC_EP_TABLE			RLC_EP_TABLE_BASIC
#define RLC_EP_TABLE_COMBS      (1 << EP_DEPTH)
#define RLC_EP_TABLE_MAX 	RLC_EP_TABLE
#define ep_add(R, P, Q)		ep_add_basic(R, P, Q)
#define ep_dbl(R, P)		ep_dbl_basic(R, P)
#define ep_free(A)															\
	if (A != NULL) {														\
		free(A);															\
		A = NULL;															\
	}
#define ep_mul(R, P, K)		ep_mul_basic(R, P, K)
#define ep_mul_fix(R, T, K)		ep_mul_fix_basic(R, T, K)
#define ep_mul_pre(T, P)		ep_mul_pre_basic(T, P)
#define ep_new(A)															\
	A = (ep_t)calloc(1, sizeof(ep_st));										\
	if (A == NULL) {														\
		RLC_THROW(ERR_NO_MEMORY);												\
	}																		\

#define ep_null(A)				
#define RLC_FP_BITS 	((int)FP_PRIME)
#define RLC_FP_BYTES 	((int)RLC_CEIL(RLC_FP_BITS, 8))
#define RLC_FP_DIGS 	((int)RLC_CEIL(RLC_FP_BITS, RLC_DIG))


#define fp_add(C, A, B)		fp_add_basic(C, A, B)
#define fp_dbl(C, A)		fp_dbl_basic(C, A)
#define fp_exp(C, A, B)		fp_exp_basic(C, A, B)
#define fp_free(A)			dv_free_dynam((dv_t *)&(A))
#define fp_hlv(C, A)		fp_hlv_basic(C, A)
#define fp_mul(C, A, B)		fp_mul_karat(C, A, B)
#define fp_neg(C, A)		fp_neg_basic(C, A)
#define fp_new(A)			dv_new_dynam((dv_t *)&(A), RLC_FP_DIGS)
#define fp_null(A)			
#define fp_rdc(C, A)		fp_rdc_basic(C, A)
#define fp_sqr(C, A)		fp_mul(C, A, A)
#define fp_sub(C, A, B)		fp_sub_basic(C, A, B)

#define dv_free(A)			(void)A
#define dv_new(A)			
#define dv_null(A)			

#define dv12_free(A)														\
		dv6_free(A[0]); dv6_free(A[1]);										\

#define dv12_new(A)															\
		dv6_new(A[0]); dv6_new(A[1]);										\

#define dv12_null(A)														\
		dv6_null(A[0]); dv6_null(A[1]);										\

#define dv18_free(A)														\
		dv9_free(A[0]); dv9_free(A[1]);										\

#define dv18_new(A)															\
		dv9_new(A[0]); dv9_new(A[1]);										\

#define dv18_null(A)														\
		dv9_null(A[0]); dv9_null(A[1]);										\

#define dv24_free(A)														\
		dv8_free(A[0]); dv8_free(A[1]); dv8_free(A[2]); 					\

#define dv24_new(A)															\
		dv8_new(A[0]); dv8_new(A[1]); dv8_new(A[2]);						\

#define dv24_null(A)														\
		dv8_null(A[0]); dv8_null(A[1]); dv8_null(A[2]);						\

#define dv2_free(A)															\
		dv_free(A[0]); dv_free(A[1]); 										\

#define dv2_new(A)															\
		dv_new(A[0]); dv_new(A[1]);											\

#define dv2_null(A)															\
		dv_null(A[0]); dv_null(A[1]);										\

#define dv3_free(A)															\
		dv_free(A[0]); dv_free(A[1]); dv_free(A[2]);						\

#define dv3_new(A)															\
		dv_new(A[0]); dv_new(A[1]);	dv_new(A[2]);							\

#define dv3_null(A)															\
		dv_null(A[0]); dv_null(A[1]); dv_null(A[2]);						\

#define dv48_free(A)														\
		dv24_free(A[0]); dv24_free(A[1]);									\

#define dv48_new(A)															\
		dv24_new(A[0]); dv24_new(A[1]);										\

#define dv48_null(A)														\
		dv24_null(A[0]); dv24_null(A[1]);									\

#define dv4_free(A)															\
		dv2_free(A[0]); dv2_free(A[1]);										\

#define dv4_new(A)															\
		dv2_new(A[0]); dv2_new(A[1]);										\

#define dv4_null(A)															\
		dv2_null(A[0]); dv2_null(A[1]);										\

#define dv54_free(A)														\
		dv18_free(A[0]); dv18_free(A[1]); dv18_free(A[2]);					\

#define dv54_new(A)															\
		dv18_new(A[0]); dv18_new(A[1]);	dv18_new(A[2]);						\

#define dv54_null(A)														\
		dv18_null(A[0]); dv18_null(A[1]); dv18_null(A[2]);					\

#define dv6_free(A)															\
		dv2_free(A[0]); dv2_free(A[1]); dv2_free(A[2]); 					\

#define dv6_new(A)															\
		dv2_new(A[0]); dv2_new(A[1]); dv2_new(A[2]);						\

#define dv6_null(A)															\
		dv2_null(A[0]); dv2_null(A[1]); dv2_null(A[2]);						\

#define dv8_free(A)															\
		dv4_free(A[0]); dv4_free(A[1]);										\

#define dv8_new(A)															\
		dv4_new(A[0]); dv4_new(A[1]);										\

#define dv8_null(A)															\
		dv4_null(A[0]); dv4_null(A[1]);										\

#define dv9_free(A)															\
		dv3_free(A[0]); dv3_free(A[1]); dv3_free(A[2]);						\

#define dv9_new(A)															\
		dv3_new(A[0]); dv3_new(A[1]); dv3_new(A[2]);						\

#define dv9_null(A)															\
		dv3_null(A[0]); dv3_null(A[1]);	dv3_null(A[2]);						\

#define fp12_free(A)														\
		fp6_free(A[0]); fp6_free(A[1]); 									\

#define fp12_mul(C, A, B)		fp12_mul_basic(C, A, B)
#define fp12_new(A)															\
		fp6_new(A[0]); fp6_new(A[1]);										\

#define fp12_null(A)														\
		fp6_null(A[0]); fp6_null(A[1]);										\

#define fp12_sqr(C, A)			fp12_sqr_basic(C, A)
#define fp12_sqr_cyc(C, A)		fp12_sqr_cyc_basic(C, A)
#define fp12_sqr_pck(C, A)		fp12_sqr_pck_basic(C, A)
#define fp18_free(A)														\
		fp9_free(A[0]); fp9_free(A[1]);										\

#define fp18_mul(C, A, B)		fp18_mul_basic(C, A, B)
#define fp18_new(A)															\
		fp9_new(A[0]); fp9_new(A[1]);										\

#define fp18_null(A)														\
		fp9_null(A[0]); fp9_null(A[1]);										\

#define fp18_sqr(C, A)			fp18_sqr_basic(C, A)
#define fp24_free(A)														\
		fp8_free(A[0]); fp8_free(A[1]); fp8_free(A[2]); 					\

#define fp24_mul(C, A, B)		fp24_mul_basic(C, A, B)
#define fp24_new(A)															\
		fp8_new(A[0]); fp8_new(A[1]); fp8_new(A[2]);						\

#define fp24_null(A)														\
		fp8_null(A[0]); fp8_null(A[1]); fp8_null(A[2]);						\

#define fp24_sqr(C, A)			fp24_sqr_basic(C, A)
#define fp2_dbl(C, A)		fp2_dbl_basic(C, A)
#define fp2_free(A)															\
		fp_free(A[0]); fp_free(A[1]); 										\

#define fp2_new(A)															\
		fp_new(A[0]); fp_new(A[1]);											\

#define fp2_null(A)															\
		fp_null(A[0]); fp_null(A[1]);										\

#define fp2_sqr(C, A)		fp2_sqr_basic(C, A)
#define fp3_dbl(C, A)		fp3_dbl_basic(C, A)
#define fp3_free(A)															\
		fp_free(A[0]); fp_free(A[1]); fp_free(A[2]);						\

#define fp3_new(A)															\
		fp_new(A[0]); fp_new(A[1]);	fp_new(A[2]);							\

#define fp3_null(A)															\
		fp_null(A[0]); fp_null(A[1]); fp_null(A[2]);						\

#define fp3_sqr(C, A)		fp3_sqr_basic(C, A)
#define fp48_free(A)														\
		fp24_free(A[0]); fp24_free(A[1]); 									\

#define fp48_mul(C, A, B)		fp48_mul_basic(C, A, B)
#define fp48_new(A)															\
		fp24_new(A[0]); fp24_new(A[1]);										\

#define fp48_null(A)														\
		fp24_null(A[0]); fp24_null(A[1]);									\

#define fp48_sqr(C, A)			fp48_sqr_basic(C, A)
#define fp48_sqr_cyc(C, A)		fp48_sqr_cyc_basic(C, A)
#define fp48_sqr_pck(C, A)		fp48_sqr_pck_basic(C, A)
#define fp4_free(A)															\
		fp2_free(A[0]); fp2_free(A[1]);										\

#define fp4_new(A)															\
		fp2_new(A[0]); fp2_new(A[1]);										\

#define fp4_null(A)															\
		fp2_null(A[0]); fp2_null(A[1]);										\

#define fp4_sqr(C, A)		fp4_sqr_basic(C, A)
#define fp54_free(A)														\
		fp18_free(A[0]); fp18_free(A[1]); fp18_free(A[2]);					\

#define fp54_mul(C, A, B)		fp54_mul_basic(C, A, B)
#define fp54_new(A)															\
		fp18_new(A[0]); fp18_new(A[1]);	fp18_new(A[2]);						\

#define fp54_null(A)														\
		fp18_null(A[0]); fp18_null(A[1]); fp18_null(A[2]);					\

#define fp54_sqr(C, A)			fp54_sqr_basic(C, A)
#define fp54_sqr_cyc(C, A)		fp54_sqr_cyc_basic(C, A)
#define fp54_sqr_pck(C, A)		fp54_sqr_pck_basic(C, A)
#define fp6_free(A)															\
		fp2_free(A[0]); fp2_free(A[1]); fp2_free(A[2]); 					\

#define fp6_new(A)															\
		fp2_new(A[0]); fp2_new(A[1]); fp2_new(A[2]);						\

#define fp6_null(A)															\
		fp2_null(A[0]); fp2_null(A[1]); fp2_null(A[2]);						\

#define fp6_sqr(C, A)		fp6_sqr_basic(C, A)
#define fp8_free(A)															\
		fp4_free(A[0]); fp4_free(A[1]);										\

#define fp8_new(A)															\
		fp4_new(A[0]); fp4_new(A[1]);										\

#define fp8_null(A)															\
		fp4_null(A[0]); fp4_null(A[1]);										\

#define fp8_sqr(C, A)		fp8_sqr_basic(C, A)
#define fp9_free(A)															\
		fp3_free(A[0]); fp3_free(A[1]); fp3_free(A[2]);						\

#define fp9_new(A)															\
		fp3_new(A[0]); fp3_new(A[1]); fp3_new(A[2]);						\

#define fp9_null(A)															\
		fp3_null(A[0]); fp3_null(A[1]); fp3_null(A[2]);						\

#define fp9_sqr(C, A)		fp9_sqr_basic(C, A)

#define RLC_EB_TABLE			RLC_EB_TABLE_BASIC
#define RLC_EB_TABLE_COMBS      (1 << EB_DEPTH)
#define RLC_EB_TABLE_MAX 		RLC_EB_TABLE
#define eb_add(R, P, Q)		eb_add_basic(R, P, Q);
#define eb_dbl(R, P)		eb_dbl_basic(R, P);
#define eb_frb(R, P)		eb_frb_basic(R, P)
#define eb_free(A)															\
	if (A != NULL) {														\
		free(A);															\
		A = NULL;															\
	}																		\

#define eb_mul(R, P, K)		eb_mul_basic(R, P, K)
#define eb_mul_fix(R, T, K)		eb_mul_fix_basic(R, T, K)
#define eb_mul_pre(T, P)		eb_mul_pre_basic(T, P)
#define eb_neg(R, P)		eb_neg_basic(R, P)
#define eb_new(A)															\
	A = (eb_t)calloc(1, sizeof(eb_st));										\
	if (A == NULL) {														\
		RLC_THROW(ERR_NO_MEMORY);												\
	}																		\

#define eb_null(A)				
#define eb_sub(R, P, Q)		eb_sub_basic(R, P, Q)
#define RLC_FB_BITS 	((int)FB_POLYN)
#define RLC_FB_BYTES 	((int)RLC_CEIL(RLC_FB_BITS, 8))

#define RLC_FB_TABLE			RLC_FB_TABLE_QUICK
#define RLC_FB_TABLE_MAX 		RLC_FB_TABLE
#define RLC_FB_TABLE_QUICK      ((RLC_DIG / 4) * RLC_FB_DIGS * 16)
#define fb_exp(C, A, B)		fb_exp_basic(C, A, B)
#define fb_free(A)			dv_free_dynam((dv_t *)&(A))
#define fb_inv(C, A)		fb_inv_basic(C, A)
#define fb_itr_imp(C, A, B, T)		fb_itr_basic(C, A, B)
#define fb_itr_pre(T, B)	(void)(T), (void)(B)
#define fb_mul(C, A, B)		fb_mul_karat(C, A, B)
#define fb_new(A)			dv_new_dynam((dv_t *)&(A), RLC_FB_DIGS)
#define fb_null(A)				
#define fb_rdc(C, A)		fb_rdc_basic(C, A)
#define fb_slv(C, A)		fb_slv_basic(C, A)
#define fb_sqr(C, A)		fb_sqr_basic(C, A)
#define fb_srt(C, A)		fb_srt_basic(C, A)
#define fb_trc(A)			fb_trc_basic(A)

#define fb2_add(C, A, B)													\
		fb_add(C[0], A[0], B[0]); fb_add(C[1], A[1], B[1]);					\

#define fb2_cmp(A, B)														\
		((fb_cmp(A[0], B[0]) == RLC_EQ) && (fb_cmp(A[1], B[1]) == RLC_EQ)	\
		? RLC_EQ : RLC_NE)													\

#define fb2_copy(C, A)														\
		fb_copy(C[0], A[0]); fb_copy(C[1], A[1]); 							\

#define fb2_free(A)															\
		fb_free(A[0]); fb_free(A[1]); 										\

#define fb2_is_zero(A)														\
		(fb_is_zero(A[0]) && fb_is_zero(A[1]))								\

#define fb2_neg(C, A)														\
		fb_neg(C[0], A[0]); fb_neg(C[1], A[1]); 							\

#define fb2_new(A)															\
		fb_new(A[0]); fb_new(A[1]);											\

#define fb2_null(A)															\
		fb_null(A[0]); fb_null(A[1]);										\

#define fb2_print(A)														\
		fb_print(A[0]); fb_print(A[1]);										\

#define fb2_rand(A)															\
		fb_rand(A[0]); fb_rand(A[1]);										\

#define fb2_zero(A)															\
		fb_zero(A[0]); fb_zero(A[1]); 										\


#define RLC_EC_LOWER      		ed_
#define RLC_EC_UPPER      		ED_
#define ec_add(R, P, Q)			RLC_CAT(RLC_EC_LOWER, add)(R, P, Q)
#define ec_blind(R, P)				RLC_CAT(RLC_EC_LOWER, blind)(R, P)
#define ec_cmp(P, Q)			RLC_CAT(RLC_EC_LOWER, cmp)(P, Q)
#define ec_copy(R, P)			RLC_CAT(RLC_EC_LOWER, copy)(R, P)
#define ec_curve_get_cof(H) 	RLC_CAT(RLC_EC_LOWER, curve_get_cof)(H)
#define ec_curve_get_gen(G)		RLC_CAT(RLC_EC_LOWER, curve_get_gen)(G)
#define ec_curve_get_ord(N)		RLC_CAT(RLC_EC_LOWER, curve_get_ord)(N)
#define ec_curve_get_tab()		RLC_CAT(RLC_EC_LOWER, curve_get_tab)()
#define ec_dbl(R, P)			RLC_CAT(RLC_EC_LOWER, dbl)(R, P)
#define ec_free(A)				RLC_CAT(RLC_EC_LOWER, free)(A)
#define ec_get_x(X, P)			fp_prime_back(X, P->x)
#define ec_get_y(Y, P)			fp_prime_back(Y, (P)->y)
#define ec_is_infty(P)			RLC_CAT(RLC_EC_LOWER, is_infty)(P)
#define ec_map(P, M, L)			RLC_CAT(RLC_EC_LOWER, map)(P, M, L)
#define ec_mul(R, P, K)			RLC_CAT(RLC_EC_LOWER, mul)(R, P, K)
#define ec_mul_dig(R, P, K)		RLC_CAT(RLC_EC_LOWER, mul_dig)(R, P, K)
#define ec_mul_fix(R, T, K)		RLC_CAT(RLC_EC_LOWER, mul_fix)(R, T, K)
#define ec_mul_gen(R, K)		RLC_CAT(RLC_EC_LOWER, mul_gen)(R, K)
#define ec_mul_pre(T, P)		RLC_CAT(RLC_EC_LOWER, mul_pre)(T, P)
#define ec_mul_sim(R, P, K, Q, L)	RLC_CAT(RLC_EC_LOWER, mul_sim)(R, P, K, Q, L)
#define ec_mul_sim_gen(R, K, Q, L)	RLC_CAT(RLC_EC_LOWER, mul_sim_gen)(R, K, Q, L)
#define ec_neg(R, P)			RLC_CAT(RLC_EC_LOWER, neg)(R, P)
#define ec_new(A)				RLC_CAT(RLC_EC_LOWER, new)(A)
#define ec_norm(R, P)			RLC_CAT(RLC_EC_LOWER, norm)(R, P)
#define ec_null(A)				RLC_CAT(RLC_EC_LOWER, null)(A)
#define ec_on_curve(P)			RLC_CAT(RLC_EC_LOWER, on_curve)(P)
#define ec_param_get()			RLC_CAT(RLC_EC_LOWER, param_get)()
#define ec_param_level()		RLC_CAT(RLC_EC_LOWER, param_level)()
#define ec_param_print()		RLC_CAT(RLC_EC_LOWER, param_print)()
#define ec_param_set_any()		ep_param_set_any_endom()
#define ec_pck(R, P)			RLC_CAT(RLC_EC_LOWER, pck)(R, P)
#define ec_print(P)				RLC_CAT(RLC_EC_LOWER, print)(P)
#define ec_rand(P)				RLC_CAT(RLC_EC_LOWER, rand)(P)
#define ec_read_bin(A, B, L)	RLC_CAT(RLC_EC_LOWER, read_bin)(A, B, L)
#define ec_set_infty(P)			RLC_CAT(RLC_EC_LOWER, set_infty)(P)
#define ec_size_bin(A, P)		RLC_CAT(RLC_EC_LOWER, size_bin)(A, P)
#define ec_sub(R, P, Q)			RLC_CAT(RLC_EC_LOWER, sub)(R, P, Q)
#define ec_upk(R, P)			RLC_CAT(RLC_EC_LOWER, upk)(R, P)
#define ec_write_bin(B, L, A, P)	RLC_CAT(RLC_EC_LOWER, write_bin)(B, L, A, P)

#define RLC_ED_TABLE			RLC_ED_TABLE_COMBS
#define RLC_ED_TABLE_BASIC    (RLC_FP_BITS + 1)
#define RLC_ED_TABLE_COMBS    (1 << ED_DEPTH)
#define RLC_ED_TABLE_MAX    RLC_ED_TABLE
#define ed_add(R, P, Q)		ed_add_basic(R, P, Q)
#define ed_dbl(R, P)		ed_dbl_basic(R, P)
#define ed_free(A)															\
	if (A != NULL) {														\
    	free(A);															\
    	A = NULL;															\
	}
#define ed_mul(R, P, K)   ed_mul_basic(R, P, K)
#define ed_mul_fix(R, T, K)   ed_mul_fix_basic(R, T, K)
#define ed_mul_pre(T, P)    ed_mul_pre_basic(T, P)
#define ed_mul_sim(R, P, K, Q, M) ed_mul_sim_basic(R, P, K, Q, M)
#define ed_neg(R, P)		ed_neg_basic(R, P)
#define ed_new(A)															\
    A = (ed_t)calloc(1, sizeof(ed_st));										\
    if (A == NULL) {														\
        RLC_THROW(ERR_NO_MEMORY);												\
    }
#define ed_null(A)        
#define ed_sub(R, P, Q)		ed_sub_basic(R, P, Q)

#define RLC_RAND_SIZE      0

#define RLC_ALLOCA(T, S)		(T*) calloc((S), sizeof(T))
#define RLC_FREE(A)															\
	if (A != NULL) {														\
		free(A);															\
		A = NULL;															\
	}
#define BENCH_ADD(FUNCTION)													\
	FUNCTION;																\
	bench_before();															\
	for (int _b = 0; _b < BENCH; _b++) {										\
		FUNCTION;															\
	}																		\
	bench_after();															\

#define BENCH_BEGIN(LABEL)													\
	bench_reset();															\
	util_print("BENCH: " LABEL "%*c = ", (int)(32 - strlen(LABEL)), ' ');	\
	for (int _b = 0; _b < BENCH; _b++)	{									\

#define BENCH_DIV(N)														\
	}																		\
	bench_compute(BENCH * BENCH * N);										\
	bench_print()															\

#define BENCH_ONCE(LABEL, FUNCTION)											\
	bench_reset();															\
	util_print("BENCH: " LABEL "%*c = ", (int)(32 - strlen(LABEL)), ' ');	\
	bench_before();															\
	FUNCTION;																\
	bench_after();															\
	bench_compute(1);														\
	bench_print();															\

#define BENCH_SMALL(LABEL, FUNCTION)										\
	bench_reset();															\
	util_print("BENCH: " LABEL "%*c = ", (int)(32 - strlen(LABEL)), ' ');	\
	bench_before();															\
	for (int i = 0; i < BENCH; i++)	{										\
		FUNCTION;															\
	}																		\
	bench_after();															\
	bench_compute(BENCH);													\
	bench_print();															\


#define RLC_CATCH(E)			RLC_ERR_CATCH(&(E))
#define RLC_ERROR(LABEL)		goto LABEL
#define RLC_ERR_CATCH(ADDR)												\
					else { } 											\
					_ctx->caught = 0; 									\
				} else {												\
					_ctx->caught = 1; 									\
				}														\
				_ctx->last = _last;										\
				break; 													\
			} else {													\
				_this.error = ADDR; 									\
			}															\
	} 																	\
	for (int _z = 0; _z < 2; _z++) 										\
		if (_z == 1 && core_get()->caught) 								\


#define RLC_ERR_PRINT(ERROR)												\
	err_full_msg(__func__, RLC_FILE, "__LINE__", ERROR)						\

#define RLC_ERR_THROW(E)												\
	{																	\
		ctx_t *_ctx = core_get();										\
		_ctx->code = RLC_ERR;											\
		if (_ctx->last != NULL && _ctx->last->block == 0) {				\
			exit(E);													\
		}																\
		if (_ctx->last == NULL) {										\
			_ctx->last = &(_ctx->error);								\
			_ctx->error.error = &(_ctx->number);						\
			_ctx->error.block = 0;										\
			_ctx->number = E;											\
			RLC_ERR_PRINT(E);											\
		} else {														\
			for (; ; longjmp(_ctx->last->addr, 1)) {					\
				RLC_ERR_PRINT(E);										\
				if (_ctx->last->error) {								\
					if (E != ERR_CAUGHT) {								\
						*(_ctx->last->error) = E;						\
					}													\
				}														\
			}															\
		}																\
	}																	\

#define RLC_THROW(E)			core_get()->code = RLC_ERR;
