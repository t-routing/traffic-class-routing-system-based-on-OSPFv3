/*
 *  Author: Shu Yang
 *  Email: yangshu1988@gmail.com
 *  Reference: 1. draft-baker-fun-routing-class-00
 *  This document define traffic class
 *  A traffic class is defined as: <dst_prefix, src_prefix, flow_label *  , ....>, and a traffic class is associated with a metric cost
 */
#ifndef OSPF6_TCR_CLASS_H
#define OSPF6_TCR_CLASS_H

struct ospf6_traffic_class
{
  struct prefix dst_prefix;
  struct prefix src_prefix;
  u_int32_t flow_label;
  unsigned long int metric_cost;
};

extern struct ospf6_traffic_class * ospf6_traffic_class_new (void);

extern struct ospf6_traffic_class * ospf6_traffic_class_set (struct list * ospf6_traffic_class, struct prefix *dst_prefix, struct prefix *src_prefix, int flow_label);

extern struct ospf6_traffic_class * ospf6_traffic_class_get (struct list * ospf6_traffic_classes, struct prefix *dst_prefix, struct prefix *src_prefix, int flow_label);

#endif
