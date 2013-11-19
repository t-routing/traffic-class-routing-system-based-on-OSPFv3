/***********Added by Shu Yang*******************/

#ifndef OSPF6_TCR_ROUTE_H
#define OSPF6_TCR_ROUTE_H

// The relation between tcr_route_node, tcr_route_table, ospf6_tcr_route, ospf6_tcr_route_table
// 1. ospf6_tcr_route_table contains a tcr_route_table
// 2. tcr_route_table contains tcr_route_node
// 3. tcr_route_node contains ospf6_tcr_route

struct tcr_route_node
{
  struct prefix dst_prefix;
  struct prefix src_prefix;
  u_int32_t flow_label;

  struct tcr_route_table *table;
  
  unsigned int lock;

  void *info;
  //the info contains ospf6_tcr_route
};

struct tcr_route_table
{
  struct list * tcr_route_node_list;
};

/*************The above is for routing table organization************/

struct ospf6_tcr_route
{
  //struct tcr_route_node *rnode;
  struct ospf6_tcr_route_table *table;
  struct ospf6_tcr_route *prev;
  struct ospf6_tcr_route *next;

  unsigned int lock;

  /* Destination Type */
  u_char type;

  /* Destination ID, Source ID, Flow label */
  struct prefix dst_prefix;
  struct prefix src_prefix;
  u_int32_t flow_label;

  /* Time */
  struct timeval installed;
  struct timeval changed;

  /* flag */
  u_char flag;

  /* path */
  struct ospf6_path path;

  /* nexthop */
  struct ospf6_nexthop nexthop[OSPF6_MULTI_PATH_LIMIT];

  /* route option */
  void *route_option;

  /* link state id for advertising */
  u_int32_t linkstate_id;
};

struct ospf6_tcr_route_table
{
  int scope_type;
  int table_type;
  void *scope;

  struct tcr_route_table *table;

  u_int32_t count;

  /* hooks */
  void (*hook_add) (struct ospf6_tcr_route *);
  void (*hook_change) (struct ospf6_tcr_route *);
  void (*hook_remove) (struct ospf6_tcr_route *);
};

#define ospf6_tcr_route_is_same(ra, rb) \
  ((prefix_same (&(ra)->dst_prefix, &(rb)->dst_prefix))&&(prefix_same (&(ra)->src_prefix, &(rb)->src_prefix))&&(ra->flow_label == rb->flow_label))

#define ospf6_tcr_route_is_same_origin(ra, rb) \
  ospf6_route_is_same_origin (ra, rb)

#define ospf6_tcr_route_is_identical(ra, rb) \
  ((ra)->type == (rb)->type && \
   memcmp (&(ra)->dst_prefix, &(rb)->dst_prefix, sizeof (struct prefix)) == 0 && \
   memcmp (&(ra)->src_prefix, &(rb)->src_prefix, sizeof (struct prefix)) == 0 && \
   ra->flow_label == rb->flow_label && \
   memcmp (&(ra)->path, &(rb)->path, sizeof (struct ospf6_path)) == 0 && \
   memcmp (&(ra)->nexthop, &(rb)->nexthop,                               \
           sizeof (struct ospf6_nexthop) * OSPF6_MULTI_PATH_LIMIT) == 0)

struct ospf6_tcr_route * ospf6_tcr_route_create (void);
struct ospf6_tcr_route_table * ospf6_tcr_route_table_create (int s, int t);

#define OSPF6_TCR_ROUTE_TABLE_CREATE(s, t) \
  ospf6_tcr_route_table_create (OSPF6_SCOPE_TYPE_ ## s, \
                            OSPF6_TABLE_TYPE_ ## t)

extern void ospf6_tcr_route_table_free (struct ospf6_tcr_route_table *trt);
extern void ospf6_tcr_route_table_print (struct ospf6_tcr_route_table *);
extern void ospf6_tcr_route_table_delete_nodes (struct ospf6_tcr_route_table *trt);

extern struct ospf6_tcr_route * ospf6_tcr_route_copy (struct ospf6_tcr_route *tcr_route);

extern struct ospf6_tcr_route * ospf6_tcr_route_add (struct ospf6_tcr_route *, struct ospf6_tcr_route_table *);

extern struct ospf6_tcr_route * ospf6_tcr_route_lookup (struct prefix , struct prefix, u_int32_t, struct ospf6_tcr_route_table *);

#endif
