#include <zebra.h>

#include "prefix.h"
#include "memory.h"
#include "linklist.h"
#include "memtypes.h"
#include "ospf6_proto.h"
#include "ospf6_tcr_class.h"
#include "ospf6_intra_tcr.h"

struct ospf6_traffic_class * ospf6_traffic_class_new (void)
{
  struct ospf6_traffic_class *new_class;
  
  new_class = XCALLOC (MTYPE_OSPF6_TRAFFIC_CLASS, sizeof (struct ospf6_traffic_class));

  new_class->metric_cost = -1;
  
  return new_class;
}

struct ospf6_traffic_class * ospf6_traffic_class_set (struct list * ospf6_traffic_class, struct prefix *dst_prefix, struct prefix *src_prefix, int flow_label)
{
  struct ospf6_traffic_class * cur_class;
  
  cur_class = ospf6_traffic_class_new ();

  prefix_copy (&cur_class->dst_prefix, dst_prefix);
  prefix_copy (&cur_class->src_prefix, src_prefix);
  cur_class->flow_label = flow_label;
  
  return cur_class;
}

struct ospf6_traffic_class * ospf6_traffic_class_get (struct list * ospf6_traffic_classes, struct prefix *dst_prefix, struct prefix *src_prefix, int flow_label)
{
  struct ospf6_traffic_class *cur_class;
  struct listnode *node;
  struct ospf6_traffic_class *new;

  for (ALL_LIST_ELEMENTS_RO (ospf6_traffic_classes, node, cur_class))
    {
      if (prefix_same (&cur_class->dst_prefix, dst_prefix) == 1 && 
	  prefix_same (&cur_class->src_prefix, src_prefix) == 1 &&
	  cur_class->flow_label == flow_label)
	return cur_class;
    }

  if (IS_OSPF6_DEBUG_TCR (PROCESS) )
    zlog_debug ("ospf6_traffic_class_get: Generate a new traffic class!");

  new = ospf6_traffic_class_set (ospf6_traffic_classes, dst_prefix, src_prefix, flow_label);
  listnode_add (ospf6_traffic_classes, new);

  return new;
}
