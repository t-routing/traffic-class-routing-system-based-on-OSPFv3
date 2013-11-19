/*
 *  Author: Shu Yang
 *  Email: yangshu1988@gmail.com
 *  Reference: 1. draft-acee-ospfv3-lsa-extend-00
 *             2. draft-baker-ipv6-ospf-dst-flowlabel-routing-02
 *             3. draft-baker-fun-routing-class-00
 *  This document implement the mechanism in 2, 3, based on packet for
 *  -mat defined in 1
 */
#ifndef OSPF6_TRC_LSA_H
#define OSPF6_TRC_LSA_H

#define OSPF6_LSTYPE_INTRA_TCR     0x2029

/* Debug option */
extern unsigned char conf_debug_ospf6_tcr;
#define OSPF6_DEBUG_TCR_PROCESS   0x01
#define OSPF6_DEBUG_TCR_ON(level) \
  (conf_debug_ospf6_tcr |= (level))
#define OSPF6_DEBUG_TCR_OFF(level) \
  (conf_debug_ospf6_tcr &= ~(level))
#define IS_OSPF6_DEBUG_TCR(level) \
  (conf_debug_ospf6_tcr & OSPF6_DEBUG_TCR_ ## level)


#define OSPF6_INTRA_TCR_LSA_SCHEDULE(oa) \
  do { \
    if (! (oa)->thread_intra_tcr_lsa) \
      (oa)->thread_intra_tcr_lsa = \
        thread_add_event (master, ospf6_intra_multi_tcr_lsa_originate, \
                          oa, 0); \
  } while (0)

/* Intra-Area-Tcr-LSA */
#define OSPF6_INTRA_TCR_LSA_MIN_SIZE       12U /* w/o 1st IPv6 prefix */
struct ospf6_intra_tcr_lsa
{
  u_int16_t prefix_num;
  u_int16_t ref_type;
  u_int32_t ref_id;
  u_int32_t ref_adv_router;
  /* followed by ospf6 prefix(es) */
};

/*
struct ospf6_intra_tcr_label_tlv
{
  u_int16_t type;
  u_int16_t tlv_length;
  u_int32_t flow_label;
};
*/


extern int ospf6_intra_multi_tcr_lsa_originate (struct thread *);
extern int ospf6_intra_tcr_lsa_show (struct ospf6_lsa *lsa);
extern void ospf6_intra_traffic_class_calculation (struct ospf6_area *oa);
extern void ospf6_intra_tcr_lsa_add (struct ospf6_lsa *lsa);

#endif
