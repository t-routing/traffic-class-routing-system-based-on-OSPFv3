/*
 * fib.hh
 *
 *  Created on: Sep 18, 2013
 *      Author: gautier
 */

#ifndef CLICK_FIB_HH
#define CLICK_FIB_HH
#include <click/element.hh>
#include <click/ip6address.hh>
#include <boost/unordered/unordered_map.hpp>

CLICK_DECLS

using namespace std;

#define DEFAULT_SIZE 10

class FIB : public Element{

public :
	FIB();
	~FIB();

  const char *class_name() const { return "FIB";}

  bool lookup(const IP6Address &dst, const uint32_t flow_label, IP6Address &gw,
		  	  int &index, IP6Address &dst_mask) const;

  void add(const IP6Address &dst, const IP6Address &dst_mask, const uint32_t flow_label,
		  	  const IP6Address &gw, const int index);
  void del(const IP6Address &dst, const IP6Address &dst_mask, const uint32_t flow_label);
  void clear()				{ root.children.clear(); root.valid=false; root._gw = IP6Address();}
  String dump();


  //We use a Patricia trie to store the table
  struct Leaf{
	  uint32_t _flow_label;
	  IP6Address _gw;
	  int _index; // This is the output associated with the route
	  bool used;
  };

  struct Node{
	  IP6Address _addr;
	  IP6Address _mask;
	  IP6Address _gw;	//This is the gateway
	  bool valid;	//True if the gw is valid
	  bool used;
	  vector<Leaf*> children;
	  int _index;
  };

  struct Root{
	  IP6Address _gw;
	  int _index;
	  bool valid;
	  vector<Node*>	children;
  };

  Root root;
  IP6Address src, mask;

};

CLICK_ENDDECLS
#endif
