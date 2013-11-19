/*
 * Area Border Router function for traffic class routing.
 */

#include <zebra.h>

#include "log.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "linklist.h"
#include "command.h"
#include "thread.h"
#include "plist.h"
#include "filter.h"

#include "ospf6_proto.h"
#include "ospf6_route.h"
#include "ospf6_lsa.h"
#include "ospf6_route.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"

#include "ospf6_flood.h"
#include "ospf6_intra.h"
#include "ospf6d.h"
//Note, ospf6_tcr_route.h must be before ospf6_abr_tcr.h
#include "ospf6_tcr_route.h"
#include "ospf6_abr_tcr.h"
#include "ospf6_tcr_lsa.h"

unsigned char conf_debug_ospf6_abr_tcr = 0;

void ospf6_abr_tcr_originate_summary_to_area (struct ospf6_tcr_route *tcr_route, struct ospf6_area *area)
{
  struct ospf6_lsa *lsa, *old = NULL;
  struct ospf6_interface *oi;
  struct ospf6_tcr_route *tcr_summary;
  //struct ospf6_route *range = NULL;
  struct ospf6_area *route_area;
  char buffer[OSPF6_MAX_LSASIZE];
  struct ospf6_lsa_header *lsa_header;
  caddr_t p;
  struct ospf6_inter_tcr_lsa *tcr_lsa;
  struct ospf6_tcr_route_table *summary_table = NULL;
  u_int16_t type;
  char buf1[64], buf2[64];
  int is_debug = 1;
  struct ospf6_tcr_tlv *tlv;
  struct ospf6_prefix *tlv_prefix;
  u_int32_t *tlv_label;

  if (IS_OSPF6_DEBUG_ABR_TCR)
    {
      prefix2str (&tcr_route->dst_prefix, buf1, sizeof (buf1));
      prefix2str (&tcr_route->src_prefix, buf2, sizeof (buf2));
      zlog_debug ("Originating summary in area %s for <%s, %s>",
		  area->name, buf1, buf2);
    }	
  summary_table = area->summary_tcr;

  //TBD.....
  tcr_summary = ospf6_tcr_route_lookup (tcr_route->dst_prefix, tcr_route->src_prefix, tcr_route->flow_label, summary_table);
 
  if (tcr_summary)
    old = ospf6_lsdb_lookup (tcr_summary->path.origin.type,
                             tcr_summary->path.origin.id,
                             area->ospf6->router_id, area->lsdb);
  
  /* if this route has just removed, remove corresponding LSA */
  if (CHECK_FLAG (tcr_route->flag, OSPF6_ROUTE_REMOVE))
    {
      if (is_debug)
        zlog_debug ("The route has just removed, purge previous LSA");
      if (tcr_summary)
        ospf6_tcr_route_remove (tcr_summary, summary_table);
      if (old)
        ospf6_lsa_purge (old);
      return;
    }

  if (IS_OSPF6_DEBUG_ABR_TCR)
    zlog_debug ("After checking flag!");

  /* Only destination type network, range or ASBR are considered */
  //Although range has not been implemented, but it does not change the result
  if (tcr_route->type != OSPF6_DEST_TYPE_NETWORK &&
      tcr_route->type != OSPF6_DEST_TYPE_RANGE &&
      (tcr_route->type != OSPF6_DEST_TYPE_ROUTER ||
       ! CHECK_FLAG (tcr_route->path.router_bits, OSPF6_ROUTER_BIT_E)))
    {
      if (is_debug)
        zlog_debug ("Route type is none of network, range nor ASBR, withdraw");
      if (tcr_summary)
        ospf6_tcr_route_remove (tcr_summary, summary_table);
      if (old)
        ospf6_lsa_purge (old);
      return;
    }

  if (IS_OSPF6_DEBUG_ABR_TCR)
    zlog_debug ("After checking route type!");

  /* AS External routes are never considered */
  if (tcr_route->path.type == OSPF6_PATH_TYPE_EXTERNAL1 ||
      tcr_route->path.type == OSPF6_PATH_TYPE_EXTERNAL2)
    {
      if (is_debug)
        zlog_debug ("Path type is external, withdraw");
      if (tcr_summary)
        ospf6_tcr_route_remove (tcr_summary, summary_table);
      if (old)
        ospf6_lsa_purge (old);
      return;
    }

  if (IS_OSPF6_DEBUG_ABR_TCR)
    zlog_debug ("After checking path type!");

  /* do not generate if the path's area is the same as target area */
  if (tcr_route->path.area_id == area->area_id)
    {
      if (is_debug)
        zlog_debug ("The route is in the area itself, ignore");
      if (tcr_summary)
        ospf6_tcr_route_remove (tcr_summary, summary_table);
      if (old)
        ospf6_lsa_purge (old);
      return;
    }

  if (IS_OSPF6_DEBUG_ABR_TCR)
    zlog_debug ("After checking area id!");

  /* do not generate if the nexthops belongs to the target area */
  oi = ospf6_interface_lookup_by_ifindex (tcr_route->nexthop[0].ifindex);
  if (oi && oi->area && oi->area == area)
    {
      if (is_debug)
        zlog_debug ("The route's nexthop is in the same area, ignore");
      if (tcr_summary)
        ospf6_tcr_route_remove (tcr_summary, summary_table);
      if (old)
        ospf6_lsa_purge (old);
      return;
    }

  /* do not generate if the route cost is greater or equal to LSInfinity */
  if (tcr_route->path.cost >= LS_INFINITY)
    {
      if (is_debug)
        zlog_debug ("The cost exceeds LSInfinity, withdraw");
      if (tcr_summary)
        ospf6_tcr_route_remove (tcr_summary, summary_table);
      if (old)
        ospf6_lsa_purge (old);
      return;
    }

  /* if this is a route to ASBR */
  if (tcr_route->type == OSPF6_DEST_TYPE_ROUTER)
    {
      /* Only the prefered best path is considered */
      if (! CHECK_FLAG (tcr_route->flag, OSPF6_ROUTE_BEST))
        {
          if (is_debug)
            zlog_debug ("This is the secondary path to the ASBR, ignore");
          if (tcr_summary)
            ospf6_tcr_route_remove (tcr_summary, summary_table);
          if (old)
            ospf6_lsa_purge (old);
          return;
        }

      /* Do not generate if the area is stub */
      /* XXX */
    }

  if (IS_OSPF6_DEBUG_ABR_TCR)
    zlog_debug ("After checking tcr_summary == NULL!");

  /* the route is going to be originated. store it in area's summary_table */
  if (tcr_summary == NULL)
    {
      tcr_summary = ospf6_tcr_route_copy (tcr_route);
      tcr_summary->lock = 0;
     
      tcr_summary->path.origin.type = htons (OSPF6_LSTYPE_INTER_TCR);
      tcr_summary->path.origin.adv_router = area->ospf6->router_id;
      tcr_summary->path.origin.id =
        ospf6_new_ls_id (tcr_summary->path.origin.type,
                         tcr_summary->path.origin.adv_router, area->lsdb);
      tcr_summary = ospf6_tcr_route_add (tcr_summary, summary_table);
    }
  else
    {
      tcr_summary->type = tcr_route->type;
      quagga_gettime (QUAGGA_CLK_MONOTONIC, &tcr_summary->changed);
    }

  if (IS_OSPF6_DEBUG_ABR_TCR)
    zlog_debug ("Before generating the lsa!");

  tcr_summary->path.router_bits = tcr_route->path.router_bits;
  tcr_summary->path.options[0] = tcr_route->path.options[0];
  tcr_summary->path.options[1] = tcr_route->path.options[1];
  tcr_summary->path.options[2] = tcr_route->path.options[2];
  tcr_summary->path.prefix_options = tcr_route->path.prefix_options;
  tcr_summary->path.area_id = area->area_id;
  tcr_summary->path.type = OSPF6_PATH_TYPE_INTER;
  tcr_summary->path.cost = tcr_route->path.cost;
  tcr_summary->nexthop[0] = tcr_route->nexthop[0];
  /* prepare buffer */
  memset (buffer, 0, sizeof (buffer));
  lsa_header = (struct ospf6_lsa_header *) buffer;

  tcr_lsa = (struct ospf6_inter_tcr_lsa *)
    ((caddr_t) lsa_header + sizeof (struct ospf6_lsa_header));
  p = (caddr_t) tcr_lsa + sizeof (struct ospf6_inter_tcr_lsa);
  /* Fill Inter-Area-Tcr-LSA */
  OSPF6_ABR_TCR_SUMMARY_METRIC_SET (tcr_lsa, tcr_route->path.cost);
  tcr_lsa->prefix.prefix_length = tcr_route->dst_prefix.prefixlen;
  tcr_lsa->prefix.prefix_options = tcr_route->path.prefix_options;
  
  /* set Prefix */
  memcpy (p, &tcr_route->dst_prefix.u.prefix6,
	  OSPF6_PREFIX_SPACE (tcr_route->dst_prefix.prefixlen));
  ospf6_prefix_apply_mask (&tcr_lsa->prefix);
  p += OSPF6_PREFIX_SPACE (tcr_route->dst_prefix.prefixlen);
  type = htons (OSPF6_LSTYPE_INTER_TCR);
  
  tlv = (struct ospf6_tcr_tlv *) ((caddr_t) p);
  tlv->type = SRC_TLV;
  tlv->tlv_length = 20;
  tlv_prefix = (struct ospf6_prefix *) ((caddr_t) tlv + sizeof (struct ospf6_tcr_tlv));
  tlv_prefix->prefix_length = tcr_route->src_prefix.prefixlen;
  tlv_prefix->prefix_options = 0;
  tlv_prefix->prefix_metric = htons(0);
  memcpy (OSPF6_PREFIX_BODY (tlv_prefix), &tcr_route->src_prefix.u.prefix6,
	  OSPF6_PREFIX_SPACE (tlv_prefix->prefix_length));
  p += (sizeof (struct ospf6_tcr_tlv) + 20);

  tlv = (struct ospf6_tcr_tlv *) ((caddr_t) p);
  tlv->type = LABEL_TLV;
  tlv->tlv_length = 4;
  tlv_label = (u_int32_t *) ((caddr_t) tlv + sizeof (struct ospf6_tcr_tlv));
  * tlv_label = tcr_route->flow_label;
  p += (sizeof (struct ospf6_tcr_tlv) + 4);

  /* Fill LSA Header */
  lsa_header->age = 0;
  lsa_header->type = type;
  lsa_header->id = tcr_summary->path.origin.id;
  lsa_header->adv_router = area->ospf6->router_id;
  lsa_header->seqnum =
    ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id,
                         lsa_header->adv_router, area->lsdb);
  lsa_header->length = htons ((caddr_t) p - (caddr_t) lsa_header);

  /* LSA checksum */
  ospf6_lsa_checksum (lsa_header);

  /* create LSA */
  lsa = ospf6_lsa_create (lsa_header);

  /* Originate */
  ospf6_lsa_originate_area (lsa, area);
}

void
ospf6_abr_tcr_originate_summary (struct ospf6_tcr_route *tcr_route)
{
  struct listnode *node, *nnode;
  struct ospf6_area *oa;
  //struct ospf6_route *range = NULL;

  /*We have not implemented the range in this version, TBD*/
  /*
  if (route->type == OSPF6_DEST_TYPE_NETWORK)
    {
      oa = ospf6_area_lookup (route->path.area_id, ospf6);
      range = ospf6_route_lookup_bestmatch (&route->prefix, oa->range_table);
      if (range)
        ospf6_abr_range_update (range);
    }
  */
  if (IS_OSPF6_DEBUG_ABR_TCR)
    zlog_debug ("%s: start!", __FUNCTION__);

  for (ALL_LIST_ELEMENTS (ospf6->area_list, node, nnode, oa))
    ospf6_abr_tcr_originate_summary_to_area (tcr_route, oa);
  
  if (IS_OSPF6_DEBUG_ABR_TCR)
    zlog_debug ("%s: end!", __FUNCTION__);
}


/* Display functions */
static int
ospf6_inter_area_tcr_lsa_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  struct ospf6_inter_tcr_lsa *tcr_lsa;
  struct in6_addr in6;
  char buf[64];
  struct ospf6_tcr_tlv *tlv;
  u_int32_t * tlv_label;
  struct ospf6_prefix *prefix;
  char *start, *end;
  tcr_lsa = (struct ospf6_inter_tcr_lsa *)
    OSPF6_LSA_HEADER_END (lsa->header);

  vty_out (vty, "     Metric: %lu%s",
           (u_long) OSPF6_ABR_SUMMARY_METRIC (tcr_lsa), VNL);

  ospf6_prefix_options_printbuf (tcr_lsa->prefix.prefix_options,
                                 buf, sizeof (buf));
  vty_out (vty, "     Dst Prefix Options: %s%s", buf, VNL);

  ospf6_prefix_in6_addr (&in6, &tcr_lsa->prefix);
  inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
  vty_out (vty, "     Dst Prefix: %s/%d%s", buf,
           tcr_lsa->prefix.prefix_length, VNL);
  
  start = (char *) tcr_lsa + sizeof (struct ospf6_inter_tcr_lsa);
  end = (char *) lsa->header + ntohs (lsa->header->length);
  tlv = (struct ospf6_tcr_tlv *) start;
  
  while ((int)((char *) end - (char *) tlv) > 0){
    zlog_debug ("	TLV type: %d, Length: %d", tlv->type, tlv->tlv_length);
    if (tlv->type == SRC_TLV)
      {
	prefix = (struct ospf6_prefix *) ((caddr_t) tlv + sizeof (struct ospf6_tcr_tlv));
	//zlog_debug ("Remaining bytes: %d, %d", (char*) end - (char *) prefix, sizeof (struct ospf6_tcr_tlv));
	memset (&in6, 0, sizeof (in6));
	memcpy (&in6, OSPF6_PREFIX_BODY (prefix),
		OSPF6_PREFIX_SPACE (prefix->prefix_length));
	inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
	zlog_debug ("     Source TLV Prefix: %s/%d",
               buf, prefix->prefix_length);
	tlv = (struct ospf6_tcr_tlv *) ((caddr_t) prefix + 20);
      }
    
    else if (tlv->type == LABEL_TLV)
      {
	tlv_label = (u_int32_t *) ((caddr_t) tlv + sizeof (struct ospf6_tcr_tlv));
	
	zlog_debug ("Lable Value: %lu", *tlv_label);
	tlv = (struct ospf6_tcr_tlv *) ((caddr_t) tlv_label + 4);
      }
  }

  return 0;
}

void
ospf6_abr_tcr_examin_summary (struct ospf6_lsa *lsa, struct ospf6_area *oa)
{
  struct prefix  abr_prefix, dst_prefix, src_prefix;
  struct ospf6_prefix * ospf6_dst_prefix, *ospf6_src_prefix;
  struct ospf6_tcr_route_table *tcr_table = NULL;
  struct ospf6_tcr_route *range;
  struct ospf6_tcr_route *tcr_route, *old = NULL;
  struct ospf6_route *abr_entry;
  u_char type = 0;
  char options[3] = {0, 0, 0};
  u_int8_t prefix_options = 0;
  u_int32_t cost = 0, * tlv_label;
  u_char router_bits = 0;
  int i;
  char buf[64];
  int is_debug = 0;
  struct ospf6_inter_tcr_lsa *tcr_lsa;
  char *start, *current, *end;
  struct ospf6_tcr_tlv *tlv;

  if (IS_OSPF6_DEBUG_ABR_TCR)
    zlog_debug ("%s: start!", __FUNCTION__);

  if (IS_OSPF6_DEBUG_ABR_TCR)
    {
      is_debug++;
      zlog_debug ("Examin %s in area %s", lsa->name, oa->name);
    }
  
  tcr_lsa = (struct ospf6_inter_tcr_lsa *)
    OSPF6_LSA_HEADER_END (lsa->header);
  //dst_prefix.family = AF_INET6;
  //dst_prefix.prefixlen = tcr_lsa->prefix.prefix_length;
  //ospf6_prefix_in6_addr (&ospf6_dst_prefix.u.prefix6, &tcr_lsa->prefix);
  ospf6_dst_prefix = & tcr_lsa->prefix;
  
  tcr_table = oa->ospf6->tcr_route_table;
  type = OSPF6_DEST_TYPE_NETWORK;
  prefix_options = tcr_lsa->prefix.prefix_options;
  cost = OSPF6_ABR_TCR_SUMMARY_METRIC (tcr_lsa);

  if (IS_OSPF6_DEBUG_ABR_TCR)
    zlog_debug ("Begin Generating the tcr route");

  start = (caddr_t) tcr_lsa +
    sizeof (struct ospf6_inter_tcr_lsa) + OSPF6_PREFIX_SPACE (ospf6_dst_prefix->prefix_length);
  end = OSPF6_LSA_END (lsa->header);
  
  tlv = (struct ospf6_tcr_tlv *) (caddr_t) start;
  
  if (IS_OSPF6_DEBUG_ABR_TCR)
    zlog_debug ("Check the tlvs");

  while ((int)((char *) end - (char *) tlv) > 0){
    if (tlv->type == SRC_TLV)
      {
	ospf6_src_prefix = (struct ospf6_prefix *) ((caddr_t) tlv + sizeof (struct ospf6_tcr_tlv));
	tlv = (struct ospf6_tcr_tlv *) ((caddr_t) ospf6_src_prefix + 20);
      }
    else if (tlv->type == LABEL_TLV)
      {
	tlv_label = (u_int32_t *) ((caddr_t) tlv + sizeof (struct ospf6_tcr_tlv));
	tlv = (struct ospf6_tcr_tlv *) ((caddr_t) tlv_label + 4);
      }
    else{
      zlog_err ("Encounter an unknown tlv, exit!");
    }
  }
  
  if (IS_OSPF6_DEBUG_ABR_TCR)
    zlog_debug ("Have processed the tlvs");

  memset (&dst_prefix, 0, sizeof(struct prefix));
  dst_prefix.family = AF_INET6;
  dst_prefix.prefixlen = ospf6_dst_prefix->prefix_length;
  ospf6_prefix_in6_addr (&dst_prefix.u.prefix6, ospf6_dst_prefix);

  memset (&src_prefix, 0, sizeof(struct prefix));
  src_prefix.family = AF_INET6;
  src_prefix.prefixlen = ospf6_src_prefix->prefix_length;
  ospf6_prefix_in6_addr (&src_prefix.u.prefix6, ospf6_src_prefix);

  /* Find existing tcr route */
  tcr_route = ospf6_tcr_route_lookup (dst_prefix, src_prefix, *tlv_label, tcr_table);
  if (tcr_route)
    {
      ospf6_tcr_route_lock (tcr_route);
      if (tcr_route->path.area_id == oa->area_id &&
	  tcr_route->path.origin.type == lsa->header->type &&
	  tcr_route->path.origin.id == lsa->header->id &&
	  tcr_route->path.origin.adv_router == lsa->header->adv_router &&
	  ! CHECK_FLAG (tcr_route->flag, OSPF6_ROUTE_WAS_REMOVED))
	old = tcr_route;
    }
  if (IS_OSPF6_DEBUG_ABR_TCR)
    zlog_debug ("Finding existing tcr route");

  /* (1) if cost == LSInfinity or if the LSA is MaxAge */
  if (cost == LS_INFINITY)
    {
      if (is_debug)
        zlog_debug ("cost is LS_INFINITY, ignore");
      if (old)
        ospf6_tcr_route_remove (old, tcr_table);
      return;
    }
  if (OSPF6_LSA_IS_MAXAGE (lsa))
    {
      if (is_debug)
        zlog_debug ("LSA is MaxAge, ignore");
      if (old)
        ospf6_tcr_route_remove (old, tcr_table);
      return;
    }

  /* (2) if the LSA is self-originated, ignore */
  if (lsa->header->adv_router == oa->ospf6->router_id)
    {
      if (is_debug)
        zlog_debug ("LSA is self-originated, ignore");
      if (old)
        ospf6_tcr_route_remove (old, tcr_table);
      return;
    }

  /* (4) if the routing table entry for the ABR does not exist */
  ospf6_linkstate_prefix (lsa->header->adv_router, htonl (0), &abr_prefix);
  abr_entry = ospf6_route_lookup (&abr_prefix, oa->ospf6->brouter_table);
  if (abr_entry == NULL || abr_entry->path.area_id != oa->area_id ||
      CHECK_FLAG (abr_entry->flag, OSPF6_ROUTE_REMOVE) ||
      ! CHECK_FLAG (abr_entry->path.router_bits, OSPF6_ROUTER_BIT_B))
    {
      if (is_debug)
        zlog_debug ("ABR router entry does not exist, ignore");
      if (old)
        ospf6_tcr_route_remove (old, tcr_table);
      return;
    }

  if (old ==NULL)
    tcr_route = ospf6_tcr_route_create ();

  /*(6) if the paths present in the table are intra-area
    paths, do nothing with the LSA (intra-area paths are always
    preferred.*/
  
  if(tcr_route->path.type == OSPF6_PATH_TYPE_INTER)
    {
      if (is_debug)
        zlog_debug ("The path present is intra-area!");
      return;
    }

  /*(7) the paths present in the routing table are also
    inter-area paths. and the old path is cheaper*/
  if (tcr_route->path.type == OSPF6_PATH_TYPE_INTER &&
      tcr_route->path.cost <= abr_entry->path.cost + cost)
    {
      if (is_debug)
	zlog_debug ("The path present is inter-area and is cheaper!");
      return;
    }

  if (IS_OSPF6_DEBUG_ABR_TCR)
    zlog_debug ("Assign value to tcr route");

  tcr_route->type = type;
  memcpy (&tcr_route->dst_prefix, &dst_prefix, sizeof(struct prefix));
  memcpy (&tcr_route->src_prefix, &src_prefix, sizeof(struct prefix));
  //tcr_route->src_prefix = *src_prefix;
  tcr_route->flow_label = *tlv_label;
  tcr_route->path.origin.type = lsa->header->type;
  tcr_route->path.origin.id = lsa->header->id;
  tcr_route->path.origin.adv_router = lsa->header->adv_router;
  tcr_route->path.router_bits = router_bits;
  tcr_route->path.options[0] = options[0];
  tcr_route->path.options[1] = options[1];
  tcr_route->path.options[2] = options[2];
  tcr_route->path.prefix_options = prefix_options;
  tcr_route->path.area_id = oa->area_id;
  tcr_route->path.type = OSPF6_PATH_TYPE_INTER;
  tcr_route->path.cost = abr_entry->path.cost + cost;
  for (i = 0; i < OSPF6_MULTI_PATH_LIMIT; i++)
    tcr_route->nexthop[i] = abr_entry->nexthop[i];

  ospf6_tcr_route_add (tcr_route, tcr_table);

  if (IS_OSPF6_DEBUG_ABR_TCR)
    zlog_debug ("%s: end!", __FUNCTION__);
}

void
ospf6_abr_tcr_examin_brouter (u_int32_t router_id)
{
  struct ospf6_lsa *lsa;
  struct ospf6_area *oa;
  struct listnode *node, *nnode;
  u_int16_t type;

  for (ALL_LIST_ELEMENTS (ospf6->area_list, node, nnode, oa))
    {
      type = htons (OSPF6_LSTYPE_INTER_TCR);
      for (lsa = ospf6_lsdb_type_router_head (type, router_id, oa->lsdb); lsa;
           lsa = ospf6_lsdb_type_router_next (type, router_id, lsa))
        ospf6_abr_tcr_examin_summary (lsa, oa);
    }
}

/* Debug commands */
DEFUN (debug_ospf6_abr_tcr,
       debug_ospf6_abr_tcr_cmd,
       "debug ospf6 abr tcr",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 ABR TCR function\n"
      )
{
  OSPF6_DEBUG_ABR_TCR_ON ();
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_abr_tcr,
       no_debug_ospf6_abr_tcr_cmd,
       "no debug ospf6 abr tcr",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 ABR TCR function\n"
      )
{
  OSPF6_DEBUG_ABR_TCR_OFF ();
  return CMD_SUCCESS;
}

int
config_write_ospf6_debug_abr_tcr (struct vty *vty)
{
  if (IS_OSPF6_DEBUG_ABR_TCR)
    vty_out (vty, "debug ospf6 abr tcr%s", VNL);
  return 0;
}

void
install_element_ospf6_debug_abr_tcr (void)
{
  install_element (ENABLE_NODE, &debug_ospf6_abr_tcr_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_abr_tcr_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_abr_tcr_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_abr_tcr_cmd);
}
