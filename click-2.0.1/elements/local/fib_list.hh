/*
 * fib_list.hh
 *
 *  Created on: Sep 20, 2013
 *      Author: gautier
 */

#ifndef CLICK_FIB_LIST_HH
#define CLICK_FIB_LIST_HH
//#include <click/ip6address.hh>
#include <click/element.hh>
#include <click/ip6address.hh>
#include "fib.hh"

CLICK_DECLS

// IP6 routing table decribed in:
//		IPv6 Source/Destination Routing using OSPFv3
//		draft-baker-ipv6-ospf-dst-src-routing-02

using namespace std;

class FIB_List : public Element { public:

  FIB_List();
  ~FIB_List();
  //These are the mandatory functions for an customized element in click
  const char *class_name() const { return "FIB_List";}
  const char *port_count() const { return "1/-"; }
  const char *processing() const { return PUSH; }
  int configure(Vector<String>&, ErrorHandler*);
  void add_handlers();

  void push(int, Packet *);

  bool lookup(const IP6Address &dst, const IP6Address &source, const uint32_t flow_label,
		  	  	  IP6Address &gw, int &index) const;

  void add(const IP6Address &dst, const IP6Address &dst_mask, const IP6Address &src,
		  	  const IP6Address &src_mask, const uint32_t flow_label, const IP6Address &gw, int index);
  void del(const IP6Address &dst, const IP6Address &dst_mask, const IP6Address &src,
		  	  const IP6Address &src_mask, const uint32_t flow_label);
  void clear()				{ list_FIB.clear(); gen.clear();}
  void deal_with_ambiguities(const IP6Address &dst, const IP6Address &dst_mask, const IP6Address &src,
		  	  const IP6Address &src_mask, const uint32_t flow_label, const IP6Address &gw, int index);

  String dump(){return "";};//TODO complete this

  static int add_route_handler(const String &conf, Element *e, void *, ErrorHandler *errh);
  static int remove_route_handler(const String &conf, Element *e, void *, ErrorHandler *errh);
  static int ctrl_handler(const String &conf_in, Element *e, void *thunk, ErrorHandler *errh);
  static String table_handler(Element *e, void *);


 private:

  struct Spec_FIB{	//Specific FIB
	  IP6Address src;
	  IP6Address mask;
	  FIB *fib;
	  bool used; //when we remove, we just set this variable to false
  };

  vector<Spec_FIB> list_FIB;	//The list of FIBs associated with a source prefix
  FIB gen;					//The general FIB
};

CLICK_ENDDECLS
#endif
