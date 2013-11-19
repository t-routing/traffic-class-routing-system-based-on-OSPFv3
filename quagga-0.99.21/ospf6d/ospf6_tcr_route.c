#include <zebra.h>

#include "prefix.h"
#include "memory.h"
#include "linklist.h"
#include "memtypes.h"
#include "thread.h"
#include "ospf6_route.h"
#include "ospf6_tcr_class.h"
#include "ospf6_intra_tcr.h"
#include "ospf6_tcr_route.h"

static void tcr_route_node_free (struct tcr_route_node * tcr_node);

struct tcr_route_table * tcr_route_table_init (void)
{
  struct tcr_route_table *trt;
  if (IS_OSPF6_DEBUG_TCR (PROCESS) )
    {
      zlog_debug ("%s", __FUNCTION__);
    }
  
  trt = XCALLOC (MTYPE_TCR_ROUTE_TABLE, sizeof (struct tcr_route_table));
  trt->tcr_route_node_list = list_new ();
  trt->tcr_route_node_list->del = tcr_route_node_free;
  
  return trt;
}

struct tcr_route_node *
tcr_route_node_new (void)
{
  struct tcr_route_node * tcr_node;
  
  tcr_node = XCALLOC (MTYPE_TCR_ROUTE_NODE, sizeof (struct tcr_route_node));

  return tcr_node;
}

static void tcr_route_node_free (struct tcr_route_node * tcr_node)
{
  XFREE (MTYPE_TCR_ROUTE_NODE, tcr_node);
}

static void tcr_route_table_free (struct tcr_route_table *trt)
{
  if (IS_OSPF6_DEBUG_TCR (PROCESS) )
    zlog_debug ("TCR ROUTE TABLE FREE!");
  list_delete_all_node (trt->tcr_route_node_list);
  XFREE (MTYPE_TCR_ROUTE_TABLE, trt);
}

void ospf6_tcr_route_table_free (struct ospf6_tcr_route_table *otrt)
{
  if (IS_OSPF6_DEBUG_TCR (PROCESS) )
    zlog_debug ("OSPF6 TCR ROUTE TABLE FREE!");
  tcr_route_table_free (otrt->table);
  XFREE (MTYPE_OSPF6_TCR_ROUTE_TABLE, otrt);
}

static void tcr_route_table_delete_nodes (struct tcr_route_table *trt)
{
  if (IS_OSPF6_DEBUG_TCR (PROCESS) )
    zlog_debug ("TCR ROUTE TABLE DELETE NODES!");
  list_delete_all_node (trt->tcr_route_node_list);
  //XFREE (MTYPE_TCR_ROUTE_TABLE, trt);
}

void ospf6_tcr_route_table_delete_nodes (struct ospf6_tcr_route_table *otrt)
{
  if (IS_OSPF6_DEBUG_TCR (PROCESS) )
    zlog_debug ("OSPF6 TCR ROUTE TABLE DELETE NODES!");
  tcr_route_table_delete_nodes (otrt->table);
  //XFREE (MTYPE_OSPF6_TCR_ROUTE_TABLE, otrt);
}


struct tcr_route_node *
tcr_route_node_set (struct prefix dst_prefix, struct prefix src_prefix, u_int32_t flow_label)
{
  struct tcr_route_node * tcr_node;
  
  tcr_node = tcr_route_node_new ();

  prefix_copy (& tcr_node->dst_prefix, & dst_prefix);
  prefix_copy (& tcr_node->src_prefix, & src_prefix);

  tcr_node->flow_label = flow_label;

  return tcr_node;
}

struct tcr_route_node *
tcr_route_node_get (struct tcr_route_table *tcr_table, struct prefix dst_prefix, struct prefix src_prefix, u_int32_t flow_label)
{
  struct tcr_route_node * trn;
  struct listnode *node;
  struct tcr_route_node *new;

  for (ALL_LIST_ELEMENTS_RO(tcr_table->tcr_route_node_list, node, trn))
    {
      if (prefix_same (& trn->dst_prefix, & dst_prefix) && 
	  prefix_same (& trn->src_prefix, & src_prefix) &&
	  trn->flow_label == flow_label)
	{
	  return trn;
	}
    }

  if (IS_OSPF6_DEBUG_TCR (PROCESS) )
    {
      zlog_debug ("We are going to generate a new tcr node in the tcr table");
    }

  new = tcr_route_node_set (dst_prefix, src_prefix, flow_label);

  listnode_add (tcr_table->tcr_route_node_list, new);

  if (IS_OSPF6_DEBUG_TCR (PROCESS) )
    {
      zlog_debug ("We have generated a new tcr node");
    }

  return new;
}

/* Delete node from the tcr routing table (a linklist temporarily). */
void
tcr_route_node_delete (struct tcr_route_node *tcr_node)
{
  assert (tcr_node->lock == 0);
  assert (tcr_node->info == NULL);

  listnode_delete (tcr_node->table->tcr_route_node_list, tcr_node);
  tcr_route_node_free (tcr_node);
}

/* Lock tcr node. */
struct tcr_route_node *
tcr_route_lock_node (struct tcr_route_node *tcr_node)
{
  tcr_node->lock++;
  return tcr_node;
}

/* Unlock tcr node. */
void
tcr_route_unlock_node (struct tcr_route_node *tcr_node)
{
  tcr_node->lock--;

  if (tcr_node->lock == 0)
    tcr_route_node_delete (tcr_node);
}

struct tcr_route_node *
tcr_route_next (struct tcr_route_node *tcr_node)
{
  struct listnode *node;
  node = listnode_lookup (tcr_node->table->tcr_route_node_list, tcr_node);
  
  return (struct tcr_route_node *) (node->next->data);
}

struct tcr_route_node *
tcr_route_prev (struct tcr_route_node *tcr_node)
{
  struct listnode *node;
  node = listnode_lookup (tcr_node->table->tcr_route_node_list, tcr_node);
  
  return (struct tcr_route_node *) (node->prev->data);
} 
/***********The above is for routing table organzation**********/


void
ospf6_tcr_route_lock (struct ospf6_tcr_route *tcr_route)
{
  tcr_route->lock++;
}

void
ospf6_tcr_route_unlock (struct ospf6_tcr_route *tcr_route)
{
  //assert (tcr_route->lock > 0);
  tcr_route->lock--;
  if (tcr_route->lock == 0)
    {
      /* Can't detach from the table until here
         becasue ospf6_route_next () will use
         the 'route->table' pointer for logging */
      tcr_route->table = NULL;
      ospf6_tcr_route_delete (tcr_route);
    }
}

void
ospf6_tcr_route_delete (struct ospf6_tcr_route *tcr_route)
{
  XFREE (MTYPE_OSPF6_TCR_ROUTE, tcr_route);
}


struct ospf6_tcr_route *
ospf6_tcr_route_create (void)
{
  struct ospf6_tcr_route * tcr_route;
  tcr_route = XCALLOC (MTYPE_OSPF6_TCR_ROUTE, sizeof (struct ospf6_tcr_route));
  return tcr_route;
}

/*
struct tcr_route_table *
tcr_route_table_init (void)
{
  struct tcr_route_table *trt;

  trt = XCALLOC (MTYPE_TCR_ROUTE_TABLE, sizeof (struct tcr_route_table));
  return trt;
}
*/


struct ospf6_tcr_route_table *
ospf6_tcr_route_table_create (int s, int t)
{
  struct ospf6_tcr_route_table *new;
  new = XCALLOC (MTYPE_OSPF6_TCR_ROUTE_TABLE, sizeof (struct ospf6_tcr_route_table));
  new->table = tcr_route_table_init ();
  new->scope_type = s;
  new->table_type = t;
  return new;
}

/* Unlock current node and lock next node then return it. */
/*
struct tcr_route_node *
tcr_route_next (struct tcr_route_node *tcr_node)
{
  struct tcr_route_node *next;
  struct tcr_route_node *start;

  if (node->l_left)
    {
      next = node->l_left;
      route_lock_node (next);
      route_unlock_node (node);
      return next;
    }
  if (node->l_right)
    {
      next = node->l_right;
      route_lock_node (next);
      route_unlock_node (node);
      return next;
    }

  start = node;
  while (node->parent)
    {
      if (node->parent->l_left == node && node->parent->l_right)
	{
	  next = node->parent->l_right;
	  route_lock_node (next);
	  route_unlock_node (start);
	  return next;
	}
      node = node->parent;
    }
  route_unlock_node (start);
  return NULL;
}
*/


/* TCR Route compare function. If ra is more preferred, it returns
   less than 0. If rb is more preferred returns greater than 0.
   Otherwise (neither one is preferred), returns 0 */

int ospf6_tcr_route_cmp (struct ospf6_tcr_route *rta, struct ospf6_tcr_route *rtb)
{
  assert (ospf6_tcr_route_is_same (rta, rtb));
  assert (OSPF6_PATH_TYPE_NONE < rta->path.type &&
          rta->path.type < OSPF6_PATH_TYPE_MAX);
  assert (OSPF6_PATH_TYPE_NONE < rtb->path.type &&
          rtb->path.type < OSPF6_PATH_TYPE_MAX);

  if (rta->type != rtb->type)
    return (rta->type - rtb->type);

  if (rta->path.type != rtb->path.type)
    return (rta->path.type - rtb->path.type);

  if (rta->path.type == OSPF6_PATH_TYPE_EXTERNAL2)
    {
      if (rta->path.cost_e2 != rtb->path.cost_e2)
        return (rta->path.cost_e2 - rtb->path.cost_e2);
    }
  else
    {
      if (rta->path.cost != rtb->path.cost)
        return (rta->path.cost - rtb->path.cost);
    }

  if (rta->path.area_id != rtb->path.area_id)
    return (ntohl (rta->path.area_id) - ntohl (rtb->path.area_id));

  return 0;
}


struct ospf6_tcr_route *
ospf6_tcr_route_add (struct ospf6_tcr_route *tcr_route,
                 struct ospf6_tcr_route_table *tcr_table)
{
  struct tcr_route_node *node, *nextnode, *prevnode;
  struct ospf6_tcr_route *current = NULL;
  struct ospf6_tcr_route *prev = NULL, *old = NULL, *next = NULL;
  char buf[64];
  struct timeval now;
  int i;

  assert (tcr_route->lock == 0);
  /*
  if (route->type == OSPF6_DEST_TYPE_LINKSTATE)
    ospf6_linkstate_prefix2str (&route->prefix, buf, sizeof (buf));
  else
    prefix2str (&route->prefix, buf, sizeof (buf));

  if (IS_OSPF6_DEBUG_ROUTE (MEMORY))
    zlog_debug ("%s %p: route add %p: %s", ospf6_route_table_name (table),
                table, route, buf);
  else if (IS_OSPF6_DEBUG_ROUTE (TABLE))
    zlog_debug ("%s: route add: %s", ospf6_route_table_name (table), buf);
 */
  
  if (IS_OSPF6_DEBUG_TCR (PROCESS) )
    zlog_debug ("ospf6_tcr_route_add: begin!");

  quagga_gettime (QUAGGA_CLK_MONOTONIC, &now);

  if (tcr_table == NULL)
    zlog_debug("tcr route table is null!");
  
  node = tcr_route_node_get (tcr_table->table, tcr_route->dst_prefix, tcr_route->src_prefix, tcr_route->flow_label);
  //route->rnode = node;

  current = node->info;
  if (current!=NULL)
    {
      /* if route does not actually change, return unchanged */
      if (ospf6_tcr_route_is_identical (current, tcr_route))
        {
          if (IS_OSPF6_DEBUG_TCR (PROCESS) )
            zlog_debug ("tcr_route add: needless update, the same");

          ospf6_tcr_route_delete (tcr_route);
          
	  SET_FLAG (current->flag, OSPF6_ROUTE_ADD);
          //ospf6_route_table_assert (tcr_table);
	  
          return current;
        }
      
      if (ospf6_tcr_route_cmp (current, tcr_route) <= 0)
	{
	  if (IS_OSPF6_DEBUG_TCR (PROCESS) )
            zlog_debug ("tcr_route add: needless update, smaller");

          ospf6_tcr_route_delete (tcr_route);
          SET_FLAG (current->flag, OSPF6_ROUTE_ADD);
          //ospf6_route_table_assert (tcr_table);

          return current;
	}

      if (IS_OSPF6_DEBUG_TCR (PROCESS) )
	zlog_debug ("tcr_route add: update, larger");
      
      current->type = tcr_route->type;
      current->path.origin.type = tcr_route->path.origin.type;
      current->path.origin.id = tcr_route->path.origin.id;
      current->path.origin.adv_router = tcr_route->path.origin.adv_router;
      current->path.prefix_options = tcr_route->path.prefix_options;
      current->path.area_id = tcr_route->path.area_id;
      current->path.type = tcr_route->path.type;
      current->path.metric_type = tcr_route->path.metric_type;
      current->path.cost = tcr_route->path.cost;
      for (i = 0; ospf6_nexthop_is_set (&tcr_route->nexthop[i]) &&
           i < OSPF6_MULTI_PATH_LIMIT; i++)
        ospf6_nexthop_copy (&current->nexthop[i], &tcr_route->nexthop[i]);
      SET_FLAG (current->flag, OSPF6_ROUTE_CHANGE);

      if (tcr_table->hook_add)
	(*tcr_table->hook_add) (tcr_route);

      return current;
    }

  if (IS_OSPF6_DEBUG_TCR (PROCESS) )
    zlog_debug ("this is a new tcr node");
      
  node->info = tcr_route;
  tcr_table->count++;
  //ospf6_route_table_assert (table);

  SET_FLAG (tcr_route->flag, OSPF6_ROUTE_ADD);
  if (tcr_table->hook_add)
    (*tcr_table->hook_add) (tcr_route);

  if (IS_OSPF6_DEBUG_TCR (PROCESS) )
    zlog_debug ("ospf6_tcr_route_add: end!");
  
  return tcr_route;
}


struct ospf6_tcr_route *
ospf6_tcr_route_lookup (struct prefix dst_prefix, struct prefix src_prefix, u_int32_t flow_label, struct ospf6_tcr_route_table *ospf6_tcr_table)
{
  struct tcr_route_node *trn;
  struct ospf6_tcr_route *tcr_route;
  struct listnode *node;

  for (ALL_LIST_ELEMENTS_RO(ospf6_tcr_table->table->tcr_route_node_list, node, trn))
    {
      if (prefix_same (& trn->dst_prefix, & dst_prefix) && 
	  prefix_same (& trn->src_prefix, & src_prefix) &&
	  trn->flow_label == flow_label)
	{
	  return (struct ospf6_tcr_route *) trn->info;
	}
    }

  return NULL;
}

void
ospf6_tcr_route_table_print (struct ospf6_tcr_route_table *ospf6_tcr_table)
{
  struct tcr_route_node *trn;
  struct ospf6_tcr_route *tcr_route;
  struct listnode *node;
  char buf[BUFSIZ];
  int cur_item = 0;

  zlog_debug ("ospf6_tcr_route_table_print: start!");
  for (ALL_LIST_ELEMENTS_RO(ospf6_tcr_table->table->tcr_route_node_list, node, trn))
    {
      zlog_debug ("The %d routing entry is as follows:", cur_item++);

      tcr_route =  (struct ospf6_tcr_route *) trn->info;
      prefix2str (&tcr_route->dst_prefix, buf, sizeof (buf));
      zlog_debug ("    dst prefix %s", buf);
      prefix2str (&tcr_route->src_prefix, buf, sizeof (buf));
      zlog_debug ("    src prefix %s", buf);
      zlog_debug ("    flow label: %d", tcr_route->flow_label);
      zlog_debug ("    path cost: %d", tcr_route->path.cost);
    }

  zlog_debug ("ospf6_tcr_route_table_print: end!");
}

void
ospf6_mark_tcr_route_remove (struct ospf6_tcr_route_table *ospf6_tcr_table)
{
  struct tcr_route_node *trn;
  struct ospf6_tcr_route *tcr_route;
  struct listnode *node;

  for (ALL_LIST_ELEMENTS_RO(ospf6_tcr_table->table->tcr_route_node_list, node, trn))
    {
      tcr_route = (struct ospf6_tcr_route *) trn->info;
      tcr_route->flag = OSPF6_ROUTE_REMOVE;
    }
}

void
ospf6_tcr_route_remove (struct ospf6_tcr_route *tcr_route,
                    struct ospf6_tcr_route_table *tcr_table)
{
  struct tcr_route_node *trn;
  struct tcr_ospf6_route *current;
  char buf[64];
  struct listnode *node;

  for (ALL_LIST_ELEMENTS_RO(tcr_table->table->tcr_route_node_list, node, trn))
    {
      if (prefix_same (& trn->dst_prefix, & tcr_route->dst_prefix) && 
	  prefix_same (& trn->src_prefix, & tcr_route->src_prefix) &&
	  trn->flow_label == tcr_route->flow_label)
	{
	  current =  (struct ospf6_tcr_route *) trn->info;
	  listnode_delete (tcr_table->table->tcr_route_node_list, trn);
	  break;
	}
    }
  
  tcr_table->count--;
  
  SET_FLAG (tcr_route->flag, OSPF6_ROUTE_WAS_REMOVED);
  
  if (tcr_table->hook_remove)
    (*tcr_table->hook_remove) (tcr_route);

  ospf6_tcr_route_unlock (tcr_route);
}

struct ospf6_tcr_route *
ospf6_tcr_route_copy (struct ospf6_tcr_route *tcr_route)
{
  struct ospf6_tcr_route *new;

  new = ospf6_tcr_route_create ();
  memcpy (new, tcr_route, sizeof (struct ospf6_tcr_route));
  return new;
}
