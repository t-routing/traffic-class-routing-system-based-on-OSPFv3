/*
 * AS Border Router function for traffic class routing.
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "command.h"
#include "vty.h"
#include "routemap.h"
#include "table.h"
#include "plist.h"
#include "thread.h"
#include "linklist.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6_zebra.h"
#include "ospf6_message.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_asbr.h"
#include "ospf6_intra.h"
#include "ospf6_flood.h"
#include "ospf6d.h"

#include "ospf6_tcr_route.h"
#include "ospf6_asbr_tcr.h"
#include "ospf6_tcr_lsa.h"

unsigned char conf_debug_ospf6_asbr_tcr = 0;

/* AS External LSA origination */
static void
ospf6_as_external_tcr_lsa_originate (struct ospf6_tcr_route *tcr_route)
{
  char buffer[OSPF6_MAX_LSASIZE];
  struct ospf6_lsa_header *lsa_header;
  struct ospf6_lsa *old, *lsa;
  struct ospf6_external_info *info = tcr_route->route_option;

  struct ospf6_as_external_tcr_lsa *as_external_tcr_lsa;
  char buf[64];
  caddr_t p;

  struct ospf6_tcr_tlv *tlv;
  struct ospf6_prefix *tlv_prefix;
  u_int32_t *tlv_label;

  /* find previous LSA */
  old = ospf6_lsdb_lookup (htons (OSPF6_LSTYPE_AS_EXTERNAL_TCR),
                           tcr_route->path.origin.id, ospf6->router_id,
                           ospf6->lsdb);

  if (IS_OSPF6_DEBUG_ASBR_TCR || IS_OSPF6_DEBUG_ORIGINATE (AS_EXTERNAL_TCR))
    {
      prefix2str (&tcr_route->dst_prefix, buf, sizeof (buf));
      zlog_debug ("Originate AS-External-LSA with dst prefix %s", buf);
      prefix2str (&tcr_route->src_prefix, buf, sizeof (buf));
      zlog_debug ("Originate AS-External-LSA with src prefix %s", buf);
      zlog_debug ("Originate AS-External-LSA with flow label %lu", tcr_route->flow_label);
    }

  /* prepare buffer */
  memset (buffer, 0, sizeof (buffer));
  lsa_header = (struct ospf6_lsa_header *) buffer;
  as_external_tcr_lsa = (struct ospf6_as_external_tcr_lsa *)
    ((caddr_t) lsa_header + sizeof (struct ospf6_lsa_header));
  p = (caddr_t)
    ((caddr_t) as_external_tcr_lsa + sizeof (struct ospf6_as_external_tcr_lsa));

  /* Fill AS-External-LSA */
  /* Metric type */
  if (tcr_route->path.metric_type == 2)
    SET_FLAG (as_external_tcr_lsa->bits_metric, OSPF6_ASBR_BIT_E);
  else
    UNSET_FLAG (as_external_tcr_lsa->bits_metric, OSPF6_ASBR_BIT_E);

  /* forwarding address */
  if (! IN6_IS_ADDR_UNSPECIFIED (&info->forwarding))
    SET_FLAG (as_external_tcr_lsa->bits_metric, OSPF6_ASBR_BIT_F);
  else
    UNSET_FLAG (as_external_tcr_lsa->bits_metric, OSPF6_ASBR_BIT_F);

  /* external route tag */
  UNSET_FLAG (as_external_tcr_lsa->bits_metric, OSPF6_ASBR_BIT_T);

  /* Set metric */
  OSPF6_ASBR_TCR_METRIC_SET (as_external_tcr_lsa, tcr_route->path.cost);

  /* prefixlen */
  as_external_tcr_lsa->prefix.prefix_length = tcr_route->dst_prefix.prefixlen;

  /* PrefixOptions */
  as_external_tcr_lsa->prefix.prefix_options = tcr_route->path.prefix_options;

  /* don't use refer LS-type */
  as_external_tcr_lsa->prefix.prefix_refer_lstype = htons (0);

  /* set Prefix */
  memcpy (p, &tcr_route->dst_prefix.u.prefix6,
          OSPF6_PREFIX_SPACE (tcr_route->dst_prefix.prefixlen));
  ospf6_prefix_apply_mask (&as_external_tcr_lsa->prefix);
  p += OSPF6_PREFIX_SPACE (tcr_route->dst_prefix.prefixlen);

  /* Forwarding address */
  if (CHECK_FLAG (as_external_tcr_lsa->bits_metric, OSPF6_ASBR_BIT_F))
    {
      memcpy (p, &info->forwarding, sizeof (struct in6_addr));
      p += sizeof (struct in6_addr);
    }

  /* External Route Tag */
  if (CHECK_FLAG (as_external_tcr_lsa->bits_metric, OSPF6_ASBR_BIT_T))
    {
      /* xxx */
    }

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
  lsa_header->type = htons (OSPF6_LSTYPE_AS_EXTERNAL_TCR);
  lsa_header->id = tcr_route->path.origin.id;
  lsa_header->adv_router = ospf6->router_id;
  lsa_header->seqnum =
    ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id,
                         lsa_header->adv_router, ospf6->lsdb);

  
  lsa_header->length = htons ((caddr_t) p - (caddr_t) lsa_header);

  /* LSA checksum */
  ospf6_lsa_checksum (lsa_header);

  /* create LSA */
  lsa = ospf6_lsa_create (lsa_header);

  /* Originate */
  ospf6_lsa_originate_process (lsa, ospf6);
}


void
ospf6_asbr_tcr_lsa_add (struct ospf6_lsa *lsa)
{
  struct ospf6_as_external_tcr_lsa *external_tcr;
  struct prefix asbr_id;
  struct ospf6_tcr_route *tcr_route;
  struct ospf6_route * asbr_entry;
  char buf[64];
  int i;

  char *start, *end;
  struct ospf6_tcr_tlv *tlv;
  u_int32_t * tlv_label;
  struct ospf6_prefix *prefix;
  struct in6_addr in6;

  external_tcr = (struct ospf6_as_external_tcr_lsa *)
    OSPF6_LSA_HEADER_END (lsa->header);

  if (IS_OSPF6_DEBUG_EXAMIN (AS_EXTERNAL_TCR))
    zlog_debug ("Calculate AS-External-TCR route for %s", lsa->name);

  if (lsa->header->adv_router == ospf6->router_id)
    {
      if (IS_OSPF6_DEBUG_EXAMIN (AS_EXTERNAL_TCR))
        zlog_debug ("Ignore self-originated AS-External-TCR-LSA");
      return;
    }

  if (OSPF6_ASBR_TCR_METRIC (external_tcr) == LS_INFINITY)
    {
      if (IS_OSPF6_DEBUG_EXAMIN (AS_EXTERNAL_TCR))
        zlog_debug ("Ignore TCR LSA with LSInfinity Metric");
      return;
    }

  ospf6_linkstate_prefix (lsa->header->adv_router, htonl (0), &asbr_id);
  asbr_entry = ospf6_route_lookup (&asbr_id, ospf6->brouter_table);
  if (asbr_entry == NULL ||
      ! CHECK_FLAG (asbr_entry->path.router_bits, OSPF6_ROUTER_BIT_E))
    {
      if (IS_OSPF6_DEBUG_EXAMIN (AS_EXTERNAL_TCR))
        {
          prefix2str (&asbr_id, buf, sizeof (buf));
          zlog_debug ("ASBR entry not found: %s", buf);
        }
      return;
    }

  tcr_route = ospf6_tcr_route_create ();
  tcr_route->type = OSPF6_DEST_TYPE_NETWORK;
  tcr_route->dst_prefix.family = AF_INET6;
  tcr_route->dst_prefix.prefixlen = external_tcr->prefix.prefix_length;
  ospf6_prefix_in6_addr (&tcr_route->dst_prefix.u.prefix6, &external_tcr->prefix);

  tcr_route->path.area_id = asbr_entry->path.area_id;
  tcr_route->path.origin.type = lsa->header->type;
  tcr_route->path.origin.id = lsa->header->id;
  tcr_route->path.origin.adv_router = lsa->header->adv_router;

  tcr_route->path.prefix_options = external_tcr->prefix.prefix_options;
  if (CHECK_FLAG (external_tcr->bits_metric, OSPF6_ASBR_BIT_E))
    {
      tcr_route->path.type = OSPF6_PATH_TYPE_EXTERNAL2;
      tcr_route->path.metric_type = 2;
      tcr_route->path.cost = asbr_entry->path.cost;
      tcr_route->path.cost_e2 = OSPF6_ASBR_METRIC (external_tcr);
    }
  else
    {
      tcr_route->path.type = OSPF6_PATH_TYPE_EXTERNAL1;
      tcr_route->path.metric_type = 1;
      tcr_route->path.cost = asbr_entry->path.cost + OSPF6_ASBR_METRIC (external_tcr);
      tcr_route->path.cost_e2 = 0;
    }

  for (i = 0; i < OSPF6_MULTI_PATH_LIMIT; i++)
    ospf6_nexthop_copy (&tcr_route->nexthop[i], &asbr_entry->nexthop[i]);

  if (IS_OSPF6_DEBUG_EXAMIN (AS_EXTERNAL_TCR))
    {
      prefix2str (&tcr_route->dst_prefix, buf, sizeof (buf));
      zlog_debug ("AS-External-TCR route add: %s", buf);
    }

  /***********set the src prefix & flow label**************/
  start = (char *) external_tcr + sizeof (struct ospf6_as_external_tcr_lsa);
  end = (char *) lsa->header + ntohs (lsa->header->length);

  /* Forwarding-Address */
  if (CHECK_FLAG (external_tcr->bits_metric, OSPF6_ASBR_BIT_F))
      start += sizeof (struct in6_addr);

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
    else{
      zlog_err ("Encounter an unknown tlv, exit!");
    }
  }

  tcr_route->src_prefix.family = AF_INET6;
  tcr_route->src_prefix.prefixlen = prefix->prefix_length;
  ospf6_prefix_in6_addr (&tcr_route->dst_prefix.u.prefix6, prefix);
  
  tcr_route->flow_label = *tlv_label;

  ospf6_tcr_route_add (tcr_route, ospf6->tcr_route_table);
}


/* Display functions */
static int
ospf6_as_external_tcr_lsa_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  struct ospf6_as_external_tcr_lsa *external_tcr;
  char buf[64];
  struct in6_addr in6, *forwarding;
  char *start, *end;
  struct ospf6_tcr_tlv *tlv;
  u_int32_t * tlv_label;
  struct ospf6_prefix *prefix;
  
  assert (lsa->header);
  external_tcr = (struct ospf6_as_external_tcr_lsa *)
    OSPF6_LSA_HEADER_END (lsa->header);
  
  /* bits */
  snprintf (buf, sizeof (buf), "%c%c%c",
    (CHECK_FLAG (external_tcr->bits_metric, OSPF6_ASBR_BIT_E) ? 'E' : '-'),
    (CHECK_FLAG (external_tcr->bits_metric, OSPF6_ASBR_BIT_F) ? 'F' : '-'),
    (CHECK_FLAG (external_tcr->bits_metric, OSPF6_ASBR_BIT_T) ? 'T' : '-'));

  vty_out (vty, "     Bits: %s%s", buf, VNL);
  vty_out (vty, "     Metric: %5lu%s", (u_long) OSPF6_ASBR_TCR_METRIC (external_tcr),
           VNL);

  ospf6_prefix_options_printbuf (external_tcr->prefix.prefix_options,
                                 buf, sizeof (buf));
  vty_out (vty, "     Prefix Options: %s%s", buf,
           VNL);

  vty_out (vty, "     Referenced LSType: %d%s",
           ntohs (external_tcr->prefix.prefix_refer_lstype),
           VNL);

  ospf6_prefix_in6_addr (&in6, &external_tcr->prefix);
  inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
  vty_out (vty, "     Dst Prefix: %s/%d%s", buf,
           external_tcr->prefix.prefix_length, VNL);
  
  start = (char *) external_tcr + sizeof (struct ospf6_as_external_tcr_lsa);
  end = (char *) lsa->header + ntohs (lsa->header->length);

  /* Forwarding-Address */
  if (CHECK_FLAG (external_tcr->bits_metric, OSPF6_ASBR_BIT_F))
    {
      forwarding = (struct in6_addr *)
        ((caddr_t) external_tcr + sizeof (struct ospf6_as_external_tcr_lsa) +
         OSPF6_PREFIX_SPACE (external_tcr->prefix.prefix_length));
      inet_ntop (AF_INET6, forwarding, buf, sizeof (buf));
      vty_out (vty, "     Forwarding-Address: %s%s", buf, VNL);
      
      start += sizeof (struct in6_addr);
    }

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

static void
ospf6_asbr_external_tcr_route_show (struct vty *vty, struct ospf6_tcr_route *tcr_route)
{
  struct ospf6_external_info *info = tcr_route->route_option;
  char prefix[64], id[16], forwarding[64];
  u_int32_t tmp_id;

  prefix2str (&tcr_route->dst_prefix, prefix, sizeof (prefix));
  tmp_id = ntohl (info->id);
  inet_ntop (AF_INET, &tmp_id, id, sizeof (id));
  if (! IN6_IS_ADDR_UNSPECIFIED (&info->forwarding))
    inet_ntop (AF_INET6, &info->forwarding, forwarding, sizeof (forwarding));
  else
    snprintf (forwarding, sizeof (forwarding), ":: (ifindex %d)",
              tcr_route->nexthop[0].ifindex);

  vty_out (vty, "%c %-32s %-15s type-%d %5lu %s%s",
           zebra_route_char(info->type),
           prefix, id, tcr_route->path.metric_type,
           (u_long) (tcr_route->path.metric_type == 2 ?
                     tcr_route->path.cost_e2 : tcr_route->path.cost),
           forwarding, VNL);
}


DEFUN (debug_ospf6_asbr_tcr,
       debug_ospf6_asbr_tcr_cmd,
       "debug ospf6 asbr tcr",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 ASBR TCR function\n"
      )
{
  OSPF6_DEBUG_ASBR_TCR_ON ();
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_asbr_tcr,
       no_debug_ospf6_asbr_tcr_cmd,
       "no debug ospf6 asbr tcr",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 ASBR TCR function\n"
      )
{
  OSPF6_DEBUG_ASBR_TCR_OFF ();
  return CMD_SUCCESS;
}

int
config_write_ospf6_debug_asbr_tcr (struct vty *vty)
{
  if (IS_OSPF6_DEBUG_ASBR_TCR)
    vty_out (vty, "debug ospf6 asbr tcr%s", VNL);
  return 0;
}

void
install_element_ospf6_debug_asbr_tcr (void)
{
  install_element (ENABLE_NODE, &debug_ospf6_asbr_tcr_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_asbr_tcr_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_asbr_tcr_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_asbr_tcr_cmd);
}
