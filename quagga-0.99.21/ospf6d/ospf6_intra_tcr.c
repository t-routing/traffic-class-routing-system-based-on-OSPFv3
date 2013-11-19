#include <zebra.h>

#include "log.h"
#include "linklist.h"
#include "thread.h"
#include "memory.h"
#include "if.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "command.h"
#include "memtypes.h"

#include "ospf6_proto.h"
#include "ospf6_message.h"
#include "ospf6_route.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_intra.h"
#include "ospf6_asbr.h"
#include "ospf6_abr.h"
#include "ospf6_flood.h"
#include "ospf6d.h"
#include "ospf6_tcr_lsa.h"
#include "ospf6_intra_tcr.h"
#include "ospf6_tcr_class.h"
#include "ospf6_tcr_route.h"

unsigned char conf_debug_ospf6_tcr = 0;

DEFUN (debug_ospf6_tcr_process,
       debug_ospf6_tcr_process_cmd,
       "debug ospf6 tcr process",
       DEBUG_STR
       OSPF6_STR
       "Debug TCR Process\n"
       "Debug Detailed TCR Process\n"
      )
{
  unsigned char level = 0;
  level = OSPF6_DEBUG_TCR_PROCESS;
  OSPF6_DEBUG_TCR_ON (level);
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_tcr_process,
       no_debug_ospf6_tcr_process_cmd,
       "no debug ospf6 tcr process",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Quit Debugging TCR Process\n"
       "Quit Debugging Detailed TCR Process\n"
      )
{
  unsigned char level = 0;
  level = OSPF6_DEBUG_TCR_PROCESS;
  OSPF6_DEBUG_TCR_OFF (level);
  return CMD_SUCCESS;
}


void
install_element_ospf6_debug_tcr (void)
{
  install_element (ENABLE_NODE, &debug_ospf6_tcr_process_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_tcr_process_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_tcr_process_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_tcr_process_cmd);
}

/*****************************************/
// Added by Shu Yang
// Intra area trc lsa 
/*****************************************/

/*****************************************/
/* RFC2740 3.4.3.7 Intra-Area-Prefix-LSA */
/* Draft-acee-ospfv3-lsa-extend          */
/*****************************************/

int
ospf6_intra_tcr_lsa_show (struct ospf6_lsa *lsa)
{
  char *start, *end, *current;
  struct ospf6_intra_tcr_lsa *intra_tcr_lsa;
  int prefixnum, cur_num;
  char buf[128];
  struct ospf6_prefix *prefix;
  char id[16], adv_router[16];
  const char *p, *mc, *la, *nu;
  struct in6_addr in6;
  struct ospf6_tcr_tlv *tlv;
  u_int32_t * tlv_label;

  intra_tcr_lsa = (struct ospf6_intra_tcr_lsa *)
    ((caddr_t) lsa->header + sizeof (struct ospf6_lsa_header));

  prefixnum = ntohs (intra_tcr_lsa->prefix_num);

  zlog_debug ("     Number of Dst Prefix: %d", prefixnum);

  inet_ntop (AF_INET, &intra_tcr_lsa->ref_id, id, sizeof (id));
  inet_ntop (AF_INET, &intra_tcr_lsa->ref_adv_router,
             adv_router, sizeof (adv_router));
  zlog_debug ("     Reference: %s Id: %s Adv: %s",
           ospf6_lstype_name (intra_tcr_lsa->ref_type), id, adv_router);

  start = (char *) intra_tcr_lsa + sizeof (struct ospf6_intra_tcr_lsa);
  end = (char *) lsa->header + ntohs (lsa->header->length);
  zlog_debug ("Packet length: %d, tcr lsa size: %d, header size: %d", ntohs (lsa->header->length), sizeof (struct ospf6_intra_tcr_lsa), sizeof (struct ospf6_lsa_header));

  for (current = start, cur_num = 0; cur_num < prefixnum && current < end; current += OSPF6_PREFIX_SIZE (prefix), cur_num++)
    {
      prefix = (struct ospf6_prefix *) current;
      zlog_debug ("prefix size: %d, prefix length: %d, prefix index: %d", OSPF6_PREFIX_SIZE (prefix), prefix->prefix_length, cur_num);
      if (prefix->prefix_length == 0 ||
          current + OSPF6_PREFIX_SIZE (prefix) > end)
        break;

      p = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_P) ?
           "P" : "--");
      mc = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_MC) ?
           "MC" : "--");
      la = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_LA) ?
           "LA" : "--");
      nu = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_NU) ?
           "NU" : "--");
      zlog_debug ("     Prefix Options: %s|%s|%s|%s",
               p, mc, la, nu);

      memset (&in6, 0, sizeof (in6));
      memcpy (&in6, OSPF6_PREFIX_BODY (prefix),
              OSPF6_PREFIX_SPACE (prefix->prefix_length));
      inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
      zlog_debug ("     Prefix: %s/%d",
               buf, prefix->prefix_length);
    }

  tlv = (struct ospf6_tcr_tlv *) current;
  //zlog_debug ("Remaining bytes: %d", (char*) end - (char *) tlv);
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
	//zlog_debug ("Remaining bytes: %d", (char*) end - (char *) tlv);
      }
    
    else if (tlv->type == LABEL_TLV)
      {
	tlv_label = (u_int32_t *) ((caddr_t) tlv + sizeof (struct ospf6_tcr_tlv));
	
	zlog_debug ("Lable Value: %lu", *tlv_label);
	tlv = (struct ospf6_tcr_tlv *) ((caddr_t) tlv_label + 4);
	//zlog_debug ("Remaining bytes: %d", (char*) end - (char *) tlv);
      }
    else
      {
	zlog_err ("Encounter an unknown tlv, exit!");
      }
    //zlog_debug ("Remaining bytes: %d", (char*) end - (char *) tlv);
  }
  
  return 0;
}


int
ospf6_intra_single_tcr_lsa_originate (struct ospf6_area *oa, struct list *selected_tcr_list, struct prefix src_prefix, u_int32_t flow_label, u_int32_t link_state_id)
{

  char buffer[OSPF6_MAX_LSASIZE];
  struct ospf6_lsa_header *lsa_header;
  struct ospf6_lsa *old, *lsa;

  struct ospf6_intra_tcr_lsa *intra_tcr_lsa;
  struct ospf6_prefix *op;
  unsigned short prefix_num = 0;
  char buf[BUFSIZ];
  char area_id[16];
  struct ospf6_tcr_tlv *tlv;
  u_int32_t *tlv_label;
  struct ospf6_prefix *tlv_prefix;
  struct ospf6_traffic_class *class;
  struct listnode *node;
  struct prefix dst_prefix;

  zlog_debug ("link state id: %d", link_state_id);
  /* find previous LSA */
  old = ospf6_lsdb_lookup (htons (OSPF6_LSTYPE_INTRA_TCR),
                           htonl (0), oa->ospf6->router_id, oa->lsdb);

  if (! IS_AREA_ENABLED (oa))
    {
      if (old)
        ospf6_lsa_purge (old);
      return 0;
    }

  /* prepare buffer */
  memset (buffer, 0, sizeof (buffer));
  lsa_header = (struct ospf6_lsa_header *) buffer;
  intra_tcr_lsa = (struct ospf6_intra_tcr_lsa *)
    ((caddr_t) lsa_header + sizeof (struct ospf6_lsa_header));

  /* Fill Intra-Area-Prefix-LSA */
  intra_tcr_lsa->ref_type = htons (OSPF6_LSTYPE_ROUTER);
  intra_tcr_lsa->ref_id = htonl (0);
  intra_tcr_lsa->ref_adv_router = oa->ospf6->router_id;

  /* put prefixes to advertise */
  prefix_num = 0;
  op = (struct ospf6_prefix *)
    ((caddr_t) intra_tcr_lsa + sizeof (struct ospf6_intra_tcr_lsa));

  zlog_debug ("There are %d destination prefixes", listcount (selected_tcr_list));
  
  if (listcount (selected_tcr_list) == 0)
    {
      zlog_debug ("There should be at least one dst prefix!");
      return 0;
    }

  for (ALL_LIST_ELEMENTS_RO (selected_tcr_list, node, class))
    {
      dst_prefix = class->dst_prefix;
      op->prefix_length = class->dst_prefix.prefixlen;
      // Have to figure out how to set prefix options
      // But we should first refer to RFC 5340 section A.4.1.1
      op->prefix_options = 0;
      op->prefix_metric = htons(class->metric_cost);
      memcpy (OSPF6_PREFIX_BODY (op), &class->dst_prefix.u.prefix6, OSPF6_PREFIX_SPACE (op->prefix_length));
      op = OSPF6_PREFIX_NEXT (op);
      prefix_num++;
    }

  if (prefix_num == 0)
    {
      if (IS_OSPF6_DEBUG_TCR (PROCESS))
	zlog_debug ("ospf6_intra_single_tcr_lsa_originate: There should be at least one such dst prefix!");
      return 0;
    }

  intra_tcr_lsa->prefix_num = htons (prefix_num);

  tlv = (struct ospf6_tcr_tlv *) ((caddr_t) op);
  tlv->type = SRC_TLV;
  tlv->tlv_length = 20;
  //src_tlv->flow_label = 0;
  tlv_prefix = (struct ospf6_prefix *) ((caddr_t) tlv + sizeof (struct ospf6_tcr_tlv));
  tlv_prefix->prefix_length = src_prefix.prefixlen;
  tlv_prefix->prefix_options = 0;
  tlv_prefix->prefix_metric = htons(0);
  memcpy (OSPF6_PREFIX_BODY (tlv_prefix), &src_prefix.u.prefix6,
		  OSPF6_PREFIX_SPACE (tlv_prefix->prefix_length));
  //prefix2str (&src_prefix, buf, sizeof (buf));
  //zlog_debug ("    src prefix padded %s", buf);
	      
  tlv = (struct ospf6_tcr_tlv *) ((caddr_t) tlv_prefix + 20);
  zlog_debug ("ospf6_prefix length: %d, %d", sizeof (struct ospf6_prefix), OSPF6_PREFIX_SPACE (tlv_prefix->prefix_length));
  
  tlv->type = LABEL_TLV;
  tlv->tlv_length = 4;
  //src_tlv->flow_label = 0;
  tlv_label = (u_int32_t *) ((caddr_t) tlv + sizeof (struct ospf6_tcr_tlv));
  * tlv_label = flow_label; 
  tlv = (struct ospf6_tcr_tlv *) ((caddr_t) tlv_label + 4);
  zlog_debug ("Unsigned long int size: %d", sizeof (u_int32_t));
  /* Fill LSA Header */
  lsa_header->age = 0;
  lsa_header->type = htons (OSPF6_LSTYPE_INTRA_TCR);
  lsa_header->id = htonl (link_state_id);
  lsa_header->adv_router = oa->ospf6->router_id;
  lsa_header->seqnum =
    ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id,
			 lsa_header->adv_router, oa->lsdb);
  lsa_header->length = htons ((caddr_t) tlv - (caddr_t) lsa_header);

  /* LSA checksum */
  ospf6_lsa_checksum (lsa_header);

  /* create LSA */
  lsa = ospf6_lsa_create (lsa_header);

  /* Originate */
  ospf6_lsa_originate_area (lsa, oa);
  
  if (IS_OSPF6_DEBUG_TCR (PROCESS) )
    {
      inet_ntop (AF_INET, &oa->area_id, area_id, sizeof (area_id));
      zlog_debug ("Area_Id: %s", area_id);
      zlog_debug ("LSA number: %d", oa->lsdb->count);
    }
    
  return 0;
}

int
ospf6_intra_multi_tcr_lsa_originate (struct thread *thread)
{
  struct ospf6_area *oa;

  char buffer[OSPF6_MAX_LSASIZE];
  struct ospf6_lsa *old, *lsa;

  struct ospf6_intra_tcr_lsa *intra_tcr_lsa;
  struct ospf6_interface *oi;
  struct ospf6_neighbor *on;
  struct ospf6_prefix *op;
  int full_count = 0;
  char buf[BUFSIZ];
  char area_id[16];
  struct prefix prefix, dst_prefix;
  u_int32_t flow_label, link_state_id = 0;
  struct list *tcr_list;
  struct ospf6_traffic_class *class;
  struct listnode *node, *nnode;
  struct list *selected_tcr_list;

  oa = (struct ospf6_area *) THREAD_ARG (thread);
  oa->thread_intra_tcr_lsa = NULL;

  zlog_debug ("LSA number in this area: %d", oa->lsdb->count);

  if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_TCR))
    zlog_debug ("Originate Intra-Area-TCR-LSA for area %s's stub prefix",
               oa->name);

  //TBD, by Shu Yang
  tcr_list = list_new ();

  for (ALL_LIST_ELEMENTS_RO (oa->if_list, node, oi))
    {
      if (oi->state == OSPF6_INTERFACE_DOWN)
        {
          if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_TCR))
            zlog_debug ("  Interface %s is down, ignore", oi->interface->name);
          continue;
        }

      
      if (IS_OSPF6_DEBUG_TCR (PROCESS))
        zlog_debug ("  Interface %s:", oi->interface->name);

      /* connected prefix to advertise */
      for (ALL_LIST_ELEMENTS_RO (oi->if_traffic_classes, node, class))
        {
          if (IS_OSPF6_DEBUG_TCR (PROCESS))
            {
              prefix2str (&class->dst_prefix, buf, sizeof (buf));
              zlog_debug ("    dst prefix %s", buf);
	      prefix2str (&class->src_prefix, buf, sizeof (buf));
              zlog_debug ("    src prefix %s", buf);
	      zlog_debug ("    flow label: %d", class->flow_label);
	      zlog_debug ("    metric cost: %d", class->metric_cost);
            }
	  listnode_add (tcr_list, class);
        }
    }

  if (listcount (tcr_list) == 0)
    {
      zlog_debug ("There is not any tcr!");
      list_delete (tcr_list);
      return 0;
    }

  /* put prefixes to advertise */
  
  op = (struct ospf6_prefix *)
    ((caddr_t) intra_tcr_lsa + sizeof (struct ospf6_intra_tcr_lsa));

  zlog_debug ("There are %d tcr class", listcount (tcr_list));
  while (listcount (tcr_list) != 0)
    {
      zlog_debug ("Loop Begin!");
      prefix = ((struct ospf6_traffic_class *) listgetdata (listhead (tcr_list)))->src_prefix;
      flow_label = ((struct ospf6_traffic_class *) listgetdata (listhead (tcr_list)))->flow_label;

      //We use a list here, because a TCR LSA may contain multiple TCRs, but at this moment, it only contains one
      selected_tcr_list = list_new ();
      for (ALL_LIST_ELEMENTS_RO (tcr_list, node, class))
	{
	  zlog_debug ("Number of tcr: %d", listcount (tcr_list));
	  
	  //prefix2str (&class->src_prefix, buf, sizeof (buf));
	  //zlog_debug ("    class dst prefix %s", buf);
	  //prefix2str (&prefix, buf, sizeof (buf));
	  //zlog_debug ("    prefix %s", buf);
	  
	  if (prefix_same (&prefix, &class->src_prefix))
	    zlog_debug ("Preifxes are the same");
	  if (flow_label == class->flow_label)
	    zlog_debug ("Flow labels are the same");

	  if (prefix_same (&prefix, &class->src_prefix) && flow_label == class->flow_label)
	    {
	      listnode_add (selected_tcr_list, class);
	      //(nnode) = (node) ? ((node)->prev) : NULL;
	      //list_delete_node (tcr_list, node);
	      //node = nnode;
	    }
	  break; //IF adding break, the LSA only contains one TCR, else, it may contain multiple TCRs
	}

      if (listcount (selected_tcr_list) == 0)
	{
	  if (IS_OSPF6_DEBUG_TCR (PROCESS))
	    zlog_debug ("ospf6_intra_multi_tcr_lsa_originate: There should be at least one such dst prefix!");
	  return 0;
	}

      ospf6_intra_single_tcr_lsa_originate (oa, selected_tcr_list, prefix, flow_label, link_state_id);
      link_state_id++;

      for (ALL_LIST_ELEMENTS_RO (selected_tcr_list, node, class))
	{
	  listnode_delete (tcr_list, class);
	}

      zlog_debug ("List count: %d", listcount (tcr_list));
      list_delete (selected_tcr_list);

      if (listcount (tcr_list) == 0)
	break;
    }

  zlog_debug ("ospf6_intra_multi_tcr_lsa_originate: End!");
  list_delete (tcr_list);
  /***********************Over*****************/

  return 0;
}


void
ospf6_intra_tcr_lsa_add (struct ospf6_lsa *lsa)
{
  struct ospf6_area *oa;
  struct ospf6_intra_tcr_lsa *intra_tcr_lsa;
  struct prefix ls_prefix;
  struct ospf6_tcr_route *tcr_route;
  struct ospf6_route *ls_entry;
  int i, prefix_num;
  struct ospf6_prefix *op;
  char *start, *current, *end;
  char buf[64];
  struct ospf6_tcr_tlv *tlv;
  u_int32_t * tlv_label;
  struct ospf6_prefix *src_prefix;
  struct in6_addr in6;

  if (OSPF6_LSA_IS_MAXAGE (lsa))
    return;

  oa = OSPF6_AREA (lsa->lsdb->data);

  intra_tcr_lsa = (struct ospf6_intra_tcr_lsa *)
    OSPF6_LSA_HEADER_END (lsa->header);

  ospf6_linkstate_prefix (intra_tcr_lsa->ref_adv_router,
			  htonl (0), &ls_prefix);
  
  if (IS_OSPF6_DEBUG_TCR (PROCESS))
    zlog_debug ("There are %d items in the spf table", oa->spf_table->count);

  // ls_entry is used to compute the cost towards the originated node
  ls_entry = ospf6_route_lookup (&ls_prefix, oa->spf_table);

  if (ls_entry == NULL)
    {
      if (IS_OSPF6_DEBUG_TCR (PROCESS))
      {
          ospf6_linkstate_prefix2str (&ls_prefix, buf, sizeof (buf));
          zlog_debug ("LS entry does not exist: %s", buf);
        }
      return;
    }

  if (IS_OSPF6_DEBUG_TCR (PROCESS))
    {
      ospf6_linkstate_prefix2str (&ls_prefix, buf, sizeof (buf));
      zlog_debug ("LS entry exists: %s", buf);
    }

  prefix_num = ntohs (intra_tcr_lsa->prefix_num);
  if (IS_OSPF6_DEBUG_TCR (PROCESS))
    zlog_debug ("There are %d prefixes in this lsa!", prefix_num);
  
  /**************Obtain the src prefix and flow label: start!*/
  start = (caddr_t) intra_tcr_lsa +
          sizeof (struct ospf6_intra_tcr_lsa);
  end = OSPF6_LSA_END (lsa->header);
  zlog_debug ("start: %lu, end: %lu", start, end);

  for (current = start; current < end; current += OSPF6_PREFIX_SIZE (op))
    {
      op = (struct ospf6_prefix *) current;
      if (prefix_num == 0)
        break;
      if (end < current + OSPF6_PREFIX_SIZE (op))
        break;
      prefix_num -- ;
    }

  tlv = (struct ospf6_tcr_tlv *) (caddr_t) current;
  while ((int)((char *) end - (char *) tlv) > 0){
    if (tlv->type == SRC_TLV)
      {
	src_prefix = (struct ospf6_prefix *) ((caddr_t) tlv + sizeof (struct ospf6_tcr_tlv));
	tlv = (struct ospf6_tcr_tlv *) ((caddr_t) src_prefix + 20);
      }
    else if (tlv->type == LABEL_TLV)
      {
	tlv_label = (u_int32_t *) ((caddr_t) tlv + sizeof (struct ospf6_tcr_tlv));
	tlv = (struct ospf6_tcr_tlv *) ((caddr_t) tlv_label + 4);
      }
  }

  memset (&in6, 0, sizeof (in6));
  memcpy (&in6, OSPF6_PREFIX_BODY (src_prefix),
	  OSPF6_PREFIX_SPACE (src_prefix->prefix_length));
  inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
  zlog_debug ("add route, src Prefix: %s/%d",
	      buf, src_prefix->prefix_length);

  if ((char *) tlv != (char *) end && IS_OSPF6_DEBUG_TCR (PROCESS) )
    zlog_debug ("Trailing garbage ignored");
  /******************Obtain src prefix and label: end!*****/

  start = (caddr_t) intra_tcr_lsa +
          sizeof (struct ospf6_intra_tcr_lsa);
  end = OSPF6_LSA_END (lsa->header);
  prefix_num = ntohs (intra_tcr_lsa->prefix_num);

  for (current = start; current < end; current += OSPF6_PREFIX_SIZE (op))
    {
      zlog_debug ("There are %d prefixes in this lsa!", prefix_num);
      op = (struct ospf6_prefix *) current;

      if (prefix_num == 0)
        break;
      if (end < current + OSPF6_PREFIX_SIZE (op))
        break;

      zlog_debug ("length of prefix: %d", OSPF6_PREFIX_SIZE(op));
      memset (&in6, 0, sizeof (in6));
      memcpy (&in6, OSPF6_PREFIX_BODY (op),
	      OSPF6_PREFIX_SPACE (op->prefix_length));
      inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
      zlog_debug ("add route, dst Prefix: %s/%d",
	      buf, op->prefix_length);

      
      tcr_route = ospf6_tcr_route_create ();
      //tcr_route = XCALLOC (MTYPE_OSPF6_TCR_ROUTE, sizeof (struct ospf6_tcr_route));
      //tcr_route = (struct ospf6_tcr_route *) malloc (sizeof (struct ospf6_tcr_route));
      
      // Source Prefix
      memset (&tcr_route->src_prefix, 0, sizeof (struct prefix));
      tcr_route->src_prefix.family = AF_INET6;
      tcr_route->src_prefix.prefixlen = src_prefix->prefix_length;
      ospf6_prefix_in6_addr (&tcr_route->src_prefix.u.prefix6, src_prefix);

      // Destination Prefix
      memset (&tcr_route->dst_prefix, 0, sizeof (struct prefix));
      tcr_route->dst_prefix.family = AF_INET6;
      tcr_route->dst_prefix.prefixlen = op->prefix_length;
      ospf6_prefix_in6_addr (&tcr_route->dst_prefix.u.prefix6, op);

      // Flow Label
      tcr_route->flow_label = * tlv_label;

      tcr_route->type = OSPF6_DEST_TYPE_NETWORK;
      tcr_route->path.origin.type = lsa->header->type;
      tcr_route->path.origin.id = lsa->header->id;
      tcr_route->path.origin.adv_router = lsa->header->adv_router;
      tcr_route->path.prefix_options = op->prefix_options;
      tcr_route->path.area_id = oa->area_id;
      tcr_route->path.type = OSPF6_PATH_TYPE_INTRA;
      tcr_route->path.metric_type = 1;
      tcr_route->path.cost = ls_entry->path.cost +
	ntohs (op->prefix_metric);
      if (IS_OSPF6_DEBUG_TCR (PROCESS))
	{
          zlog_debug ("LS entry cost: %d", ls_entry->path.cost);
        }


      for (i = 0; ospf6_nexthop_is_set (&ls_entry->nexthop[i]) &&
           i < OSPF6_MULTI_PATH_LIMIT; i++)
        ospf6_nexthop_copy (&tcr_route->nexthop[i], &ls_entry->nexthop[i]);
      
      if (IS_OSPF6_DEBUG_TCR (PROCESS) )
        {
          prefix2str (&tcr_route->dst_prefix, buf, sizeof (buf));
          zlog_debug ("  add dst %s", buf);
	  prefix2str (&tcr_route->src_prefix, buf, sizeof (buf));
          zlog_debug ("  add src %s", buf);
	  zlog_debug ("	 add flow lable %d", tcr_route->flow_label);
	  zlog_debug ("	 cost %d", tcr_route->path.cost);
        }

      ospf6_tcr_route_add (tcr_route, oa->tcr_route_table);
      prefix_num--;
    }
}

void
ospf6_intra_traffic_class_calculation (struct ospf6_area *oa)
{
  struct ospf6_tcr_route * tcr_route;
  u_int16_t type;
  struct ospf6_lsa * lsa;

  if (IS_OSPF6_DEBUG_TCR (PROCESS))
    {
    zlog_debug ("Re_examin intra traffic class for area %s", oa->name);
    zlog_debug ("Number of LSAs in this area: %d", oa->lsdb->count);
    }
  type = htons (OSPF6_LSTYPE_INTRA_TCR);

  for (lsa = ospf6_lsdb_type_head (type, oa->lsdb); lsa;
       lsa = ospf6_lsdb_type_next (type, lsa))
    ospf6_intra_tcr_lsa_add (lsa);

  if (IS_OSPF6_DEBUG_TCR (PROCESS))
    zlog_debug ("Re_examin intra traffic class for area %s: Done", oa->name);
}
