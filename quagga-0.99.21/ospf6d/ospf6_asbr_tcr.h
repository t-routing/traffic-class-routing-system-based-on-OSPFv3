#ifndef OSPF6_ASBR_TCR_H
#define OSPF6_ASBR_TCR_H

/* for struct ospf6_prefix */
#include "ospf6_proto.h"
/* for struct ospf6_lsa */
#include "ospf6_lsa.h"
/* for struct ospf6_route */
#include "ospf6_route.h"

//The extended lsa code refer to draft-acee-ospfv3-lsa-extend-00
//will be updated according to draft-acee-ospfv3-lsa-extend-02
#define OSPF6_LSTYPE_AS_EXTERNAL_TCR     0x4025

/* Debug option */
extern unsigned char conf_debug_ospf6_asbr_tcr;
#define OSPF6_DEBUG_ASBR_TCR_ON() \
  (conf_debug_ospf6_asbr_tcr = 1)
#define OSPF6_DEBUG_ASBR_TCR_OFF() \
  (conf_debug_ospf6_asbr_tcr = 0)
#define IS_OSPF6_DEBUG_ASBR_TCR \
  (conf_debug_ospf6_asbr_tcr)

/* AS-External-LSA */
#define OSPF6_AS_EXTERNAL_TCR_LSA_MIN_SIZE         4U /* w/o IPv6 prefix */
struct ospf6_as_external_tcr_lsa
{
  u_int32_t bits_metric;

  struct ospf6_prefix prefix;
  /* followed by none or one forwarding address */
  /* followed by none or one external route tag */
  /* followed by none or one referenced LS-ID */
  /* followed by extended source tlv and label tlv */
};

#define OSPF6_ASBR_TCR_BIT_T  ntohl (0x01000000)
#define OSPF6_ASBR_TCR_BIT_F  ntohl (0x02000000)
#define OSPF6_ASBR_TCR_BIT_E  ntohl (0x04000000)

#define OSPF6_ASBR_TCR_METRIC(E) (ntohl ((E)->bits_metric & htonl (0x00ffffff)))
#define OSPF6_ASBR_TCR_METRIC_SET(E,C) \
  { (E)->bits_metric &= htonl (0xff000000); \
    (E)->bits_metric |= htonl (0x00ffffff) & htonl (C); }

/*
extern void ospf6_asbr_lsa_add (struct ospf6_lsa *lsa);
extern void ospf6_asbr_lsa_remove (struct ospf6_lsa *lsa);
extern void ospf6_asbr_lsentry_add (struct ospf6_route *asbr_entry);
extern void ospf6_asbr_lsentry_remove (struct ospf6_route *asbr_entry);

extern int ospf6_asbr_is_asbr (struct ospf6 *o);
extern void ospf6_asbr_redistribute_add (int type, int ifindex,
                                         struct prefix *prefix,
                                         u_int nexthop_num,
                                         struct in6_addr *nexthop);
extern void ospf6_asbr_redistribute_remove (int type, int ifindex,
                                            struct prefix *prefix);

extern int ospf6_redistribute_config_write (struct vty *vty);

extern void ospf6_asbr_init (void);
extern void ospf6_asbr_terminate (void);

extern int config_write_ospf6_debug_asbr (struct vty *vty);
extern void install_element_ospf6_debug_asbr (void);
*/

#endif /* OSPF6_ASBR_H */
