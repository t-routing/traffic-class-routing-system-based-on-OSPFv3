#ifndef OSPF6_ABR_TCR_H
#define OSPF6_ABR_TCR_H

/* for struct ospf6_route */
//#include "ospf6_route.h"

#define OSPF6_LSTYPE_INTER_TCR     0x2023

/* Debug option */
extern unsigned char conf_debug_ospf6_abr_tcr;
#define OSPF6_DEBUG_ABR_TCR_ON() \
  (conf_debug_ospf6_abr_tcr = 1)
#define OSPF6_DEBUG_ABR_TCR_OFF() \
  (conf_debug_ospf6_abr_tcr = 0)
#define IS_OSPF6_DEBUG_ABR_TCR \
  (conf_debug_ospf6_abr_tcr)

/* Inter-Area-Prefix-LSA */
#define OSPF6_INTER_TCR_LSA_MIN_SIZE        4U /* w/o IPv6 prefix */
struct ospf6_inter_tcr_lsa
{
  u_int32_t metric;
  struct ospf6_prefix prefix;
};

extern void ospf6_abr_tcr_originate_summary_to_area (struct ospf6_tcr_route *tcr_route, struct ospf6_area *area);
extern void ospf6_abr_tcr_originate_summary (struct ospf6_tcr_route *tcr_route);

#define OSPF6_ABR_TCR_SUMMARY_METRIC(E) (ntohl ((E)->metric & htonl (0x00ffffff)))
#define OSPF6_ABR_TCR_SUMMARY_METRIC_SET(E,C) \
  { (E)->metric &= htonl (0x00000000); \
    (E)->metric |= htonl (0x00ffffff) & htonl (C); }

extern void install_element_ospf6_debug_abr_tcr (void);

extern void ospf6_abr_tcr_examin_brouter (u_int32_t router_id);
/*
extern int ospf6_is_router_abr (struct ospf6 *o);

extern void ospf6_abr_enable_area (struct ospf6_area *oa);
extern void ospf6_abr_disable_area (struct ospf6_area *oa);

                                                struct ospf6_area *area);
extern void ospf6_abr_originate_summary (struct ospf6_route *route);
extern void ospf6_abr_examin_summary (struct ospf6_lsa *lsa, struct ospf6_area *oa);
extern void ospf6_abr_examin_brouter (u_int32_t router_id);
extern void ospf6_abr_reimport (struct ospf6_area *oa);

extern int config_write_ospf6_debug_abr (struct vty *vty);
extern void install_element_ospf6_debug_abr (void);
extern int ospf6_abr_config_write (struct vty *vty);

extern void ospf6_abr_init (void);
*/

#endif /*OSPF6_ABR_H*/
