#ifndef OSPF6_TCR_LSA_H
#define OSPF6_TCR_LSA_H

struct ospf6_tcr_tlv
{
  u_int16_t type;
  u_int16_t tlv_length;
  //struct ospf6_prefix src_prefix;
  /* followed by an ospf6 prefix */
};

#define SRC_TLV 1
#define LABEL_TLV 2

#endif
